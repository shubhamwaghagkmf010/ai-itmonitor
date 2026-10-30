from datetime import datetime, timezone
from typing import Generator, List, Callable
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models.entities import User, UserRole, AuditLog, DEFAULT_PERMISSIONS

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def record_audit_event(
    db: Session, 
    actor_email: str, 
    action: str, 
    target: str = None, 
    result: str = "SUCCESS", 
    ip_address: str = None,
    details: dict = None
):
    try:
        entry = AuditLog(
            actor_email=actor_email,
            action=action,
            target=target,
            result=result,
            ip_address=ip_address or "internal",
            details=details or {}
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        db.rollback()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                             options={"require_exp": True, "require_sub": True})
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_version = int(payload.get("tv", 0))  # tokens issued before versions existed count as 0
    except (JWTError, ValueError, TypeError):
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    if token_version != (user.token_version or 0):
        raise credentials_exception  # revoked: the password changed, the account was disabled, or logged out everywhere
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
    # Not checked here: locked_until throttles *logging in*. Enforcing it on live sessions would let anyone
    # who types five wrong passwords for an administrator throw that administrator out.

    return user


def has_permission(user: User, permission: str) -> bool:
    if user.role == UserRole.ADMIN:
        return True
    return permission in (user.permissions or DEFAULT_PERMISSIONS.get(user.role, []))


def require_permission(required_permission: str) -> Callable:
    def permission_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if getattr(current_user, "must_change_password", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password change required before continuing")
        if not has_permission(current_user, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Missing required permission [{required_permission}]"
            )
        return current_user
    return permission_checker
