from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import verify_password, create_access_token, get_password_hash
from pydantic import BaseModel
from backend.app.core.config import settings
from backend.app.models.entities import User, AuditLog, DEFAULT_PERMISSIONS, DEFAULT_WIDGETS
from backend.app.api.deps import get_current_user

router = APIRouter()


def log_auth_event(db: Session, actor: str, action: str, result: str, ip: str):
    try:
        log = AuditLog(
            actor_email=actor,
            action=action,
            target=actor,
            result=result,
            ip_address=ip or "internal",
            details={}
        )
        db.add(log)
        db.commit()
    except Exception:
        db.rollback()


@router.post("/login")
def login(request: Request, db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host if request.client else "unknown"
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.commit()
        log_auth_event(db, form_data.username, "LOGIN_FAILED", "FAILED", client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_auth_event(db, user.email, "LOGIN_BLOCKED_INACTIVE", "DENIED", client_ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled. Contact Main Admin.")

    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        log_auth_event(db, user.email, "LOGIN_BLOCKED_LOCKED", "DENIED", client_ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account temporarily locked. Try again later.")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(user.email)
    log_auth_event(db, user.email, "LOGIN_SUCCESS", "SUCCESS", client_ip)

    # Role string normalization
    role_str = (user.role or "OPERATOR").upper()
    effective_perms = user.permissions if (user.permissions and isinstance(user.permissions, list)) else DEFAULT_PERMISSIONS.get(role_str, [])
    effective_widgets = user.widget_permissions if (user.widget_permissions and isinstance(user.widget_permissions, dict)) else DEFAULT_WIDGETS.get(role_str, {})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name or "",
            "role": role_str,
            "permissions": effective_perms,
            "widget_permissions": effective_widgets,
            "must_change_password": bool(getattr(user, "must_change_password", False))
        }
    }


@router.get("/me")
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    role_str = (current_user.role or "OPERATOR").upper()
    effective_perms = current_user.permissions if (current_user.permissions and isinstance(current_user.permissions, list)) else DEFAULT_PERMISSIONS.get(role_str, [])
    effective_widgets = current_user.widget_permissions if (current_user.widget_permissions and isinstance(current_user.widget_permissions, dict)) else DEFAULT_WIDGETS.get(role_str, {})
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name or "",
        "role": role_str,
        "permissions": effective_perms,
        "widget_permissions": effective_widgets,
        "must_change_password": bool(getattr(current_user, "must_change_password", False))
    }


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(body: PasswordChange, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be at least 6 characters")
    current_user.hashed_password = get_password_hash(body.new_password)
    current_user.must_change_password = False
    db.commit()
    return {"ok": True}
