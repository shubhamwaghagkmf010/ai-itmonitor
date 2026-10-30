"""Creates the first administrator (and, optionally, an operator) so a fresh installation can be logged into.

    ADMIN_PASSWORD=...  python scripts/seed_users.py

Passwords come from ADMIN_PASSWORD / OPERATOR_PASSWORD. If one is not set, a random one is generated
and printed ONCE - there is no built-in default password. Either way the account must choose its own
password at first login. Existing accounts are never modified."""
import os
import secrets
import sys

# Set root directory in Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import func

from backend.app.core.database import SessionLocal
from backend.app.core.security import check_password_policy, get_password_hash
from backend.app.models.entities import DEFAULT_PERMISSIONS, DEFAULT_WIDGETS, User, UserRole


def _password(env_names, email: str):
    """Returns (password, generated?). An invalid password given in the environment is an error, not
    something to quietly replace."""
    for name in env_names:
        supplied = os.getenv(name, "")
        if supplied:
            problem = check_password_policy(supplied, email)
            if problem:
                raise SystemExit(f"{name}: {problem}")
            return supplied, False
    return secrets.token_urlsafe(15), True


def _create(db, email, full_name, role, env_names):
    if db.query(User).filter(func.lower(User.email) == email.lower()).first():
        print(f"{role.title()} user {email} already exists; left unchanged.")
        return
    password, generated = _password(env_names, email)
    db.add(User(
        email=email.lower(),
        hashed_password=get_password_hash(password),
        full_name=full_name,
        role=role,
        is_active=True,
        must_change_password=True,
        permissions=list(DEFAULT_PERMISSIONS[role]),
        widget_permissions=dict(DEFAULT_WIDGETS[role]),
    ))
    print(f"Created {role.lower()} user: {email}")
    if generated:
        print(f"  One-time password (shown only now, change it at first login): {password}")


def seed_users(session_factory=SessionLocal):
    admin_email = os.getenv("ADMIN_EMAIL", "admin@ai-itmonitor.local")
    operator_email = os.getenv("OPERATOR_EMAIL", os.getenv("ENGINEER_EMAIL", "engineer@ai-itmonitor.local"))
    with_operator = os.getenv("SEED_OPERATOR", "1") != "0"

    db = session_factory()
    try:
        _create(db, admin_email, "System Administrator", UserRole.ADMIN, ("ADMIN_PASSWORD",))
        if with_operator:
            _create(db, operator_email, "Operations Engineer", UserRole.OPERATOR,
                    ("OPERATOR_PASSWORD", "ENGINEER_PASSWORD"))
        db.commit()
        print("Database user seeding completed successfully.")
    except Exception:
        db.rollback()
        raise  # a failed seed must fail loudly, not look like success
    finally:
        db.close()


if __name__ == "__main__":
    seed_users()
