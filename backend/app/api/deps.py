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
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is temporarily locked due to security policy")

    return user


def require_permission(required_permission: str) -> Callable:
    def permission_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if getattr(current_user, "must_change_password", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password change required before continuing")
        if current_user.role == UserRole.ADMIN:
            return current_user

        user_perms = current_user.permissions or DEFAULT_PERMISSIONS.get(current_user.role, [])
        if required_permission not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Missing required permission [{required_permission}]"
            )
        return current_user
    return permission_checker
