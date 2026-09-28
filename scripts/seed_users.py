import sys
import os

# Set root directory in Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal
from backend.app.models.entities import User, UserRole
from backend.app.core.security import get_password_hash

def seed_users():
    db = SessionLocal()
    try:
        # Check if default admin exists
        admin_email = os.getenv("ADMIN_EMAIL", "admin@ai-itmonitor.local")
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                email=admin_email,
                hashed_password=get_password_hash(os.getenv("ADMIN_PASSWORD", "ChangeMe#Admin1")),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin)
            print(f"Created default Admin user: {admin_email} (set ADMIN_PASSWORD env to choose the password)")
        else:
            print(f"Admin user {admin_email} already exists.")

        # Check if default engineer exists
        engineer_email = os.getenv("ENGINEER_EMAIL", "engineer@ai-itmonitor.local")
        engineer = db.query(User).filter(User.email == engineer_email).first()
        if not engineer:
            engineer = User(
                email=engineer_email,
                hashed_password=get_password_hash(os.getenv("ENGINEER_PASSWORD", "ChangeMe#Eng1")),
                full_name="Operations Engineer",
                role=UserRole.ENGINEER,
                is_active=True
            )
            db.add(engineer)
            print(f"Created default Engineer user: {engineer_email} (set ENGINEER_PASSWORD env to choose the password)")
        else:
            print(f"Engineer user {engineer_email} already exists.")

        db.commit()
        print("Database user seeding completed successfully.")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_users()
