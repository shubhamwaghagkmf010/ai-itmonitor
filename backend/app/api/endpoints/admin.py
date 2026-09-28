from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.security import get_password_hash
from backend.app.models.entities import (
    User, AuditLog, DEFAULT_PERMISSIONS, DEFAULT_WIDGETS
)
from backend.app.api.deps import get_current_user, require_permission, record_audit_event
from backend.app.core.config import settings
from backend.app.services.retention import purge_old_data

router = APIRouter()

class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: Optional[str] = "OPERATOR"
    permissions: Optional[List[str]] = None
    widget_permissions: Optional[Dict[str, Any]] = None

class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    permissions: Optional[List[str]] = None
    widget_permissions: Optional[Dict[str, Any]] = None

class ResetPasswordRequest(BaseModel):
    new_password: str

@router.get("/users")
@router.get("/users/")
def list_users(
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("admin.users_manage"))
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    results = []
    for u in users:
        role_str = (u.role or "OPERATOR").upper()
        effective_perms = u.permissions if (u.permissions and isinstance(u.permissions, list)) else DEFAULT_PERMISSIONS.get(role_str, [])
        effective_widgets = u.widget_permissions if (u.widget_permissions and isinstance(u.widget_permissions, dict)) else DEFAULT_WIDGETS.get(role_str, {})
        
        last_login_str = u.last_login.isoformat() if u.last_login else None
        created_at_str = u.created_at.isoformat() if u.created_at else datetime.now(timezone.utc).isoformat()

        results.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name or "",
            "role": role_str,
            "is_active": bool(u.is_active),
            "permissions": effective_perms,
            "widget_permissions": effective_widgets,
            "last_login": last_login_str,
            "created_at": created_at_str
        })
    return results

@router.post("/users", status_code=status.HTTP_201_CREATED)
@router.post("/users/", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users_manage"))
):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"User with email '{payload.email}' already exists")

    role_str = (payload.role or "OPERATOR").upper()
    perms = payload.permissions if payload.permissions is not None else DEFAULT_PERMISSIONS.get(role_str, [])
    widgets = payload.widget_permissions if payload.widget_permissions is not None else DEFAULT_WIDGETS.get(role_str, {})

    new_user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=role_str,
        is_active=True,
        permissions=perms,
        widget_permissions=widgets
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else "internal"
    record_audit_event(
        db, 
        actor_email=current_user.email,
        action="USER_CREATED",
        target=new_user.email,
        ip_address=client_ip,
        details={"role": role_str, "assigned_widgets": widgets}
    )

    return {"status": "success", "message": "User created successfully", "user_id": new_user.id}

@router.patch("/users/{user_id}")
@router.patch("/users/{user_id}/")
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users_manage"))
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if payload.full_name is not None:
        target_user.full_name = payload.full_name
        changes["full_name"] = payload.full_name
    if payload.role is not None:
        role_str = payload.role.upper()
        target_user.role = role_str
        changes["role"] = role_str
        if payload.permissions is None:
            target_user.permissions = DEFAULT_PERMISSIONS.get(role_str, [])
        if payload.widget_permissions is None:
            target_user.widget_permissions = DEFAULT_WIDGETS.get(role_str, {})
    if payload.is_active is not None:
        target_user.is_active = payload.is_active
        changes["is_active"] = payload.is_active
    if payload.password and payload.password.strip():
        target_user.hashed_password = get_password_hash(payload.password)
        changes["password_reset"] = True
    if payload.permissions is not None:
        target_user.permissions = payload.permissions
        changes["permissions_updated"] = True
    if payload.widget_permissions is not None:
        target_user.widget_permissions = payload.widget_permissions
        changes["widgets_updated"] = True

    db.commit()

    client_ip = request.client.host if request.client else "internal"
    record_audit_event(
        db,
        actor_email=current_user.email,
        action="USER_UPDATED",
        target=target_user.email,
        ip_address=client_ip,
        details=changes
    )

    return {"status": "success", "message": "User updated successfully"}

@router.post("/users/{user_id}/reset-password")
@router.post("/users/{user_id}/reset-password/")
def reset_user_password(
    user_id: int,
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users_manage"))
):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    target_user.hashed_password = get_password_hash(payload.new_password)
    target_user.failed_login_attempts = 0
    target_user.locked_until = None
    db.commit()

    client_ip = request.client.host if request.client else "internal"
    record_audit_event(
        db,
        actor_email=current_user.email,
        action="PASSWORD_RESET_BY_ADMIN",
        target=target_user.email,
        ip_address=client_ip
    )

    return {"status": "success", "message": f"Password reset successfully for user {target_user.email}"}

@router.get("/audit-logs")
@router.get("/audit-logs/")
def get_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.audit_view"))
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "",
            "actor": l.actor_email,
            "action": l.action,
            "target": l.target or "-",
            "result": l.result,
            "ip": l.ip_address or "-",
            "details": l.details or {}
        }
        for l in logs
    ]


@router.get("/retention")
def get_retention(current_user: User = Depends(require_permission("admin.users_manage"))):
    return {"retention_days": settings.METRIC_RETENTION_DAYS}


@router.post("/retention/run")
def run_retention(current_user: User = Depends(require_permission("admin.users_manage"))):
    """Manually trigger a retention cleanup now."""
    return purge_old_data()
