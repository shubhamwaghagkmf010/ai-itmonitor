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

2. Create your settings file (never commit it). This generates a real `SECRET_KEY`, mode 600:
   ```
   python3 scripts/init_env.py --with-agent-key
   ```
   Then edit `backend/.env` and set `POSTGRES_PASSWORD` to a strong password. Every agent will need the
   same `AGENT_API_KEY`.

3. Put your TLS certificate files in `./certs` (see `scripts/setup_tls.sh`), then build and start the stack.
   Compose reads the passwords from the settings file, so name it:
   ```
   docker compose --env-file backend/.env up -d --build
   ```
   The database schema is created (or brought up to date) automatically when the backend starts, and the
   backend runs as an unprivileged user. Compose refuses to start if `POSTGRES_PASSWORD` is not set.

4. Create the first administrator. Set your own password, or leave `ADMIN_PASSWORD` out and a random one is
   printed once. Either way the account must choose a new password at first login:
   ```
   docker compose --env-file backend/.env exec -e ADMIN_PASSWORD='a long passphrase' backend python scripts/seed_users.py
   ```

5. Check that everything is healthy:
   ```
   docker compose --env-file backend/.env ps
   ```
   `backend` and `postgres` should say `healthy`.

6. Open the dashboard:
   ```
   docker compose port frontend 80
   ```
   Browse to `http://YOUR_SERVER_IP:<port>` and log in with `admin@ai-itmonitor.local` and the password from step 4 (you will be required to set a new password on first login).

## Pushing changes safely
Use the bundled helper, which scans for secrets before committing and never force-pushes:
```
python3 scripts/git_auto_push.py
```

## Notes
- To enable **network discovery**, set `SCAN_SUBNET` to your LAN range in a root `.env` file (e.g. `SCAN_SUBNET=192.168.1.0/24`), then `docker compose up -d`. The root `.env` is gitignored.
- Never commit `backend/.env` or any file containing real secrets, IPs, or credentials.
- Change the admin password after the first login.
