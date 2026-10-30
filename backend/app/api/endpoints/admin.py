from datetime import datetime, timezone
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.netutil import client_ip
from backend.app.core.security import get_password_hash, check_password_policy
from backend.app.models.entities import (
    User, UserRole, AuditLog, DEFAULT_PERMISSIONS, DEFAULT_WIDGETS
)
from backend.app.api.deps import get_current_user, has_permission, require_permission, record_audit_event
from backend.app.core.config import settings
from backend.app.services.retention import purge_old_data

router = APIRouter()

VALID_ROLES = {UserRole.ADMIN, UserRole.MANAGER, UserRole.OPERATOR, UserRole.VIEWER, UserRole.CUSTOM}
# Everything the system knows how to check. The administrator's default list is, by definition, all of it.
ALL_PERMISSIONS = frozenset(DEFAULT_PERMISSIONS["ADMIN"])
ALL_WIDGETS = frozenset(DEFAULT_WIDGETS["ADMIN"])


class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(max_length=255)
    password: str = Field(max_length=1024)
    role: Optional[str] = Field(default="OPERATOR", max_length=20)
    permissions: Optional[List[str]] = Field(default=None, max_length=100)
    widget_permissions: Optional[Dict[str, bool]] = None

class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=255)
    role: Optional[str] = Field(default=None, max_length=20)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, max_length=1024)
    permissions: Optional[List[str]] = Field(default=None, max_length=100)
    widget_permissions: Optional[Dict[str, bool]] = None

class ResetPasswordRequest(BaseModel):
    new_password: str = Field(max_length=1024)


def _audit(db: Session, request: Request, actor: User, action: str, target: str, result: str = "SUCCESS",
           details: Optional[dict] = None):
    record_audit_event(db, actor_email=actor.email, action=action, target=target, result=result,
                       ip_address=client_ip(request) or "internal", details=details or {})


def _deny(db: Session, request: Request, actor: User, action: str, target: str, reason: str, code: int = 403):
    _audit(db, request, actor, action, target, "DENIED", {"reason": reason})
    raise HTTPException(status_code=code, detail=reason)


def _effective_permissions(role: str, permissions: Optional[List[str]]) -> List[str]:
    return list(permissions) if permissions else list(DEFAULT_PERMISSIONS.get(role, []))


def _validate_role_and_permissions(role: Optional[str], permissions: Optional[List[str]],
                                   widgets: Optional[Dict[str, bool]]) -> None:
    if role is not None and role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Unknown role '{role[:20]}'. Use one of: {', '.join(sorted(VALID_ROLES))}.")
    unknown = sorted(set(permissions or []) - ALL_PERMISSIONS)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown permission(s): {', '.join(p[:40] for p in unknown[:5])}")
    bad_widgets = sorted(set(widgets or {}) - ALL_WIDGETS)
    if bad_widgets:
        raise HTTPException(status_code=422, detail=f"Unknown widget(s): {', '.join(w[:40] for w in bad_widgets[:5])}")


def _check_may_grant(db: Session, request: Request, actor: User, target_label: str, role: str,
                     permissions: List[str]) -> None:
    """Nobody hands out more than they hold. Administrators hold everything; anyone else with the
    user-management permission may not create administrators or give a permission they lack themselves
    (otherwise that permission alone would be a way to become an administrator)."""
    if actor.role == UserRole.ADMIN:
        return
    if role == UserRole.ADMIN:
        _deny(db, request, actor, "USER_GRANT", target_label, "Only an administrator can grant the administrator role.")
    missing = sorted(set(permissions) - {p for p in ALL_PERMISSIONS if has_permission(actor, p)})
    if missing:
        _deny(db, request, actor, "USER_GRANT", target_label,
              f"You cannot grant permissions you do not have yourself: {', '.join(missing[:5])}")


def _check_may_touch(db: Session, request: Request, actor: User, target: User, action: str) -> None:
    if target.role == UserRole.ADMIN and actor.role != UserRole.ADMIN:
        _deny(db, request, actor, action, target.email, "Only an administrator can change an administrator's account.")


def _active_admins_other_than(db: Session, user_id: int) -> int:
    return db.query(User).filter(User.role == UserRole.ADMIN, User.is_active.is_(True), User.id != user_id).count()


def _password_or_400(password: str, email: str) -> None:
    problem = check_password_policy(password, email)
    if problem:
        raise HTTPException(status_code=400, detail=problem)


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
    email = str(payload.email).strip().lower()
    role_str = (payload.role or "OPERATOR").upper()
    _validate_role_and_permissions(role_str, payload.permissions, payload.widget_permissions)
    _password_or_400(payload.password, email)

    if db.query(User).filter(func.lower(User.email) == email).first():
        raise HTTPException(status_code=400, detail=f"User with email '{email}' already exists")

    perms = _effective_permissions(role_str, payload.permissions)
    _check_may_grant(db, request, current_user, email, role_str, perms)
    widgets = payload.widget_permissions if payload.widget_permissions is not None else DEFAULT_WIDGETS.get(role_str, {})

    new_user = User(
        email=email,
        full_name=payload.full_name.strip(),
        hashed_password=get_password_hash(payload.password),
        role=role_str,
        is_active=True,
        # The administrator typed this password, so the person it is for must choose their own at first login.
        must_change_password=True,
        permissions=perms,
        widget_permissions=widgets
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    _audit(db, request, current_user, "USER_CREATED", new_user.email,
           details={"role": role_str, "permissions": perms, "assigned_widgets": widgets})

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
    action = "USER_UPDATED"
    _check_may_touch(db, request, current_user, target_user, action)

    new_role = payload.role.upper() if payload.role is not None else None
    _validate_role_and_permissions(new_role, payload.permissions, payload.widget_permissions)

    role_after = new_role if new_role is not None else target_user.role
    perms_before = _effective_permissions(target_user.role, target_user.permissions)
    if payload.permissions is not None:
        perms_after = _effective_permissions(role_after, payload.permissions)
    elif new_role is not None:
        perms_after = _effective_permissions(new_role, None)  # a new role brings that role's default permissions
    else:
        perms_after = perms_before
    active_after = payload.is_active if payload.is_active is not None else bool(target_user.is_active)

    role_changes = role_after != target_user.role
    perms_change = set(perms_after) != set(perms_before)
    deactivates = bool(target_user.is_active) and not active_after

    # An account that can change its own role, permissions or status can escalate itself or lock itself out.
    if target_user.id == current_user.id and (role_changes or perms_change or deactivates):
        _deny(db, request, current_user, action, target_user.email,
              "You cannot change your own role, permissions or status; ask another administrator.", 400)

    if target_user.role == UserRole.ADMIN and target_user.is_active and (role_changes or deactivates):
        if _active_admins_other_than(db, target_user.id) == 0:
            _deny(db, request, current_user, action, target_user.email,
                  "This is the last active administrator; the system must keep at least one.", 400)

    if role_changes or perms_change:
        _check_may_grant(db, request, current_user, target_user.email, role_after, perms_after)

    changes = {}
    if payload.full_name is not None:
        target_user.full_name = payload.full_name.strip()
        changes["full_name"] = target_user.full_name
    if role_changes:
        changes["role"] = {"from": target_user.role, "to": role_after}
        target_user.role = role_after
        target_user.permissions = perms_after
        if payload.widget_permissions is None:
            target_user.widget_permissions = DEFAULT_WIDGETS.get(role_after, {})
    if payload.permissions is not None and not role_changes:
        target_user.permissions = perms_after
    if perms_change:
        changes["permissions"] = {"added": sorted(set(perms_after) - set(perms_before)),
                                  "removed": sorted(set(perms_before) - set(perms_after))}
    if payload.is_active is not None and payload.is_active != bool(target_user.is_active):
        target_user.is_active = payload.is_active
        changes["is_active"] = payload.is_active
        if not payload.is_active:
            target_user.token_version = (target_user.token_version or 0) + 1  # sign them out everywhere now
    if payload.password and payload.password.strip():
        _password_or_400(payload.password, target_user.email)
        target_user.hashed_password = get_password_hash(payload.password)
        target_user.must_change_password = True
        target_user.failed_login_attempts = 0
        target_user.locked_until = None
        target_user.token_version = (target_user.token_version or 0) + 1
        changes["password_reset"] = True
    if payload.widget_permissions is not None:
        target_user.widget_permissions = payload.widget_permissions
        changes["widgets_updated"] = True

    db.commit()
    _audit(db, request, current_user, action, target_user.email, details=changes)

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
    _check_may_touch(db, request, current_user, target_user, "PASSWORD_RESET_BY_ADMIN")
    _password_or_400(payload.new_password, target_user.email)

    target_user.hashed_password = get_password_hash(payload.new_password)
    target_user.failed_login_attempts = 0
    target_user.locked_until = None
    target_user.must_change_password = True
    target_user.token_version = (target_user.token_version or 0) + 1  # whoever held the old password is signed out
    db.commit()

    _audit(db, request, current_user, "PASSWORD_RESET_BY_ADMIN", target_user.email)

    return {"status": "success", "message": f"Password reset successfully for user {target_user.email}"}

@router.get("/audit-logs")
@router.get("/audit-logs/")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.audit_view"))
):
    logs = (db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .offset(offset).limit(limit).all())
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
def run_retention(request: Request, db: Session = Depends(get_db),
                  current_user: User = Depends(require_permission("admin.users_manage"))):
    """Manually trigger a retention cleanup now (this deletes data, so it is audited)."""
    result = purge_old_data()
    _audit(db, request, current_user, "RETENTION_RUN", "metrics and logs", details=result if isinstance(result, dict) else {})
    return result
