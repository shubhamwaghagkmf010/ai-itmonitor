# Security Policy

AI-ITMonitor can execute remote actions and hold infrastructure credentials, so please
report vulnerabilities privately rather than in a public issue.

- Open a confidential issue on this project, or contact the maintainers directly.

Include what you found, how to reproduce it, and the impact. You will get an acknowledgement
within a few working days.

## Deploying safely

- Run `python scripts/init_env.py --with-agent-key` to create `backend/.env` with a generated
  `SECRET_KEY` and `AGENT_API_KEY`, and set `ENVIRONMENT=production`. In production the server
  refuses to start with a placeholder or short `SECRET_KEY`, an empty `AGENT_API_KEY` or a default
  database password; the signing key is never accepted if it is the placeholder from the example file.
- Rotate `SECRET_KEY` if it was ever the example value or has been shared: every issued token
  is invalidated by changing it.
- Keep `backend/.env` readable by the service account only (`chmod 600`); the server warns otherwise.
- Agents get a per-agent token when they enrol. Upgrade the whole fleet, then set `REQUIRE_AGENT_TOKEN=true`.
  A reinstalled machine can enrol again once it has been silent for 5 minutes (at once if the old agent
  presents its token); while the agent is live, a second enrolment is refused.
- Terminate TLS in front of the API and dashboard.
- Give the database and agent accounts least privilege.
- Do not expose the API to an untrusted network; it can run remote actions.
