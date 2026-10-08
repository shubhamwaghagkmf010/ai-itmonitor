# AI-ITMonitor — Setup

A fresh deployment, step by step. No real IPs, emails, or credentials are stored in this
repository — you supply your own below.

## Requirements
- Docker and Docker Compose

## Steps

1. Clone and enter the project:
   ```
   git clone https://github.com/shubhamwaghagkmf010/ai-itmonitor.git && cd ai-itmonitor
   ```

2. Create your own environment file (never commit it) and set your secrets:
   ```
   cp backend/.env.example backend/.env
   ```
   Edit `backend/.env` and set at least `SECRET_KEY` and `POSTGRES_PASSWORD`.

3. Build and start the stack:
   ```
   docker compose up --build -d
   ```

4. Create the database tables:
   ```
   docker exec -e PYTHONPATH=/app ai_itmonitor_backend python -c "from backend.app.core.database import Base, engine; import backend.app.models.entities; Base.metadata.create_all(bind=engine); print('schema ready')"
   ```

5. Create the admin user (choose YOUR own password in place of YOUR_ADMIN_PASSWORD). The
   user is flagged to change the password on first login:
   ```
   docker exec -e PYTHONPATH=/app ai_itmonitor_backend python -c "from sqlalchemy.orm import Session; from backend.app.core.database import engine; from backend.app.models.entities import User, DEFAULT_PERMISSIONS, DEFAULT_WIDGETS; from backend.app.core.security import get_password_hash; db=Session(engine); e='admin@ai-itmonitor.local'; u=db.query(User).filter(User.email==e).first() or User(email=e); u.full_name='Administrator'; u.role='ADMIN'; u.is_active=True; u.permissions=DEFAULT_PERMISSIONS['ADMIN']; u.widget_permissions=DEFAULT_WIDGETS['ADMIN']; u.must_change_password=True; u.hashed_password=get_password_hash('YOUR_ADMIN_PASSWORD'); db.add(u); db.commit(); print('admin ready', e)"
   ```
   On first login the app forces this user to set a new password before anything else.

6. Open the dashboard:
   ```
   docker compose port frontend 80
   ```
   Browse to `http://YOUR_SERVER_IP:<port>` and log in with `admin@ai-itmonitor.local` / `YOUR_ADMIN_PASSWORD`.

## Pushing changes safely
Use the bundled helper, which scans for secrets before committing and never force-pushes:
```
python3 scripts/git_auto_push.py
```

## Notes
- Never commit `backend/.env` or any file containing real secrets, IPs, or credentials.
- Change the admin password after the first login.
