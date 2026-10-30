from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.netutil import client_ip
from backend.app.core.ratelimit import SlidingWindowLimiter
from backend.app.core.security import (
    verify_password, create_access_token, get_password_hash, check_password_policy,
)
from pydantic import BaseModel, Field
from backend.app.models.entities import User, AuditLog, DEFAULT_PERMISSIONS, DEFAULT_WIDGETS
from backend.app.api.deps import get_current_user

router = APIRouter()

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)

# Attempts, not failures: a burst of either kind from one address or against one account is refused
# before any password is checked. Per-address stops one machine trying many accounts, per-account
# stops many machines (or one behind a proxy) hammering a single account.
_login_ip_limit = SlidingWindowLimiter(30, 60)
_login_user_limit = SlidingWindowLimiter(10, 60)
_password_change_limit = SlidingWindowLimiter(5, 60)

_dummy_hash = None


def _timing_hash() -> str:
    """A real bcrypt hash to check against when the account does not exist, so an unknown user costs
    as much time as a wrong password and the response time does not reveal which accounts exist."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = get_password_hash("not-a-real-account-password")
    return _dummy_hash


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def log_auth_event(db: Session, actor: str, action: str, result: str, ip: str):
    try:
        log = AuditLog(
            actor_email=(actor or "")[:255],
            action=action,
            target=(actor or "")[:255],
            result=result,
            ip_address=ip or "internal",
            details={}
        )
        db.add(log)
        db.commit()
    except Exception:
        db.rollback()


def _profile(user: User) -> dict:
    role_str = (user.role or "OPERATOR").upper()
    effective_perms = user.permissions if (user.permissions and isinstance(user.permissions, list)) else DEFAULT_PERMISSIONS.get(role_str, [])
    effective_widgets = user.widget_permissions if (user.widget_permissions and isinstance(user.widget_permissions, dict)) else DEFAULT_WIDGETS.get(role_str, {})
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name or "",
        "role": role_str,
        "permissions": effective_perms,
        "widget_permissions": effective_widgets,
        "must_change_password": bool(getattr(user, "must_change_password", False)),
    }


@router.post("/login")
def login(request: Request, db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    ip = client_ip(request) or "unknown"
    username = (form_data.username or "").strip()

    if not _login_ip_limit.allow(ip) or not _login_user_limit.allow(username.lower()):
        log_auth_event(db, username, "LOGIN_RATE_LIMITED", "DENIED", ip)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many login attempts. Wait a minute and try again.",
                            headers={"Retry-After": "60"})

    user = db.query(User).filter(func.lower(User.email) == username.lower()).first()
    now = datetime.now(timezone.utc)

    if user and user.locked_until and _aware(user.locked_until) <= now:
        # The lock has run out: start counting from zero again, otherwise the very next typo would re-lock.
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    # Check the password (or a stand-in) in every case, so the work done does not depend on the account.
    password_ok = verify_password(form_data.password, user.hashed_password if user else _timing_hash())

    if user and user.locked_until and _aware(user.locked_until) > now:
        # Locked: the attempt is refused whatever the password was, and does not extend the lock.
        log_auth_event(db, user.email, "LOGIN_BLOCKED_LOCKED", "DENIED", ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account temporarily locked. Try again later.")

    if not user or not password_ok:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_LOGINS:
                user.locked_until = now + LOCKOUT
            db.commit()
        log_auth_event(db, username, "LOGIN_FAILED", "FAILED", ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_auth_event(db, user.email, "LOGIN_BLOCKED_INACTIVE", "DENIED", ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled. Contact Main Admin.")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()

    token = create_access_token(user.email, token_version=user.token_version or 0)
    log_auth_event(db, user.email, "LOGIN_SUCCESS", "SUCCESS", ip)

    return {"access_token": token, "token_type": "bearer", "user": _profile(user)}


@router.get("/me")
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return _profile(current_user)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request, current_user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    ip = client_ip(request) or "unknown"
    # Only wrong guesses of the current password count: a stolen token must not be able to grind through them.
    if _password_change_limit.is_limited(current_user.email.lower()):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many attempts. Wait a minute and try again.", headers={"Retry-After": "60"})
    if not verify_password(body.current_password, current_user.hashed_password):
        _password_change_limit.record(current_user.email.lower())
        log_auth_event(db, current_user.email, "PASSWORD_CHANGE_FAILED", "FAILED", ip)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    problem = check_password_policy(body.new_password, current_user.email)
    if problem:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)
    if verify_password(body.new_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The new password must be different from the current one")

    current_user.hashed_password = get_password_hash(body.new_password)
    current_user.must_change_password = False
    # Every other session (including a thief's) ends; this one carries on with the fresh token below.
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    log_auth_event(db, current_user.email, "PASSWORD_CHANGED", "SUCCESS", ip)
    return {"ok": True, "access_token": create_access_token(current_user.email, token_version=current_user.token_version)}


@router.post("/logout-all")
def logout_everywhere(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Ends every session of the calling user, on all devices, including this one."""
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    log_auth_event(db, current_user.email, "LOGOUT_ALL", "SUCCESS", client_ip(request) or "unknown")
    return {"ok": True}
