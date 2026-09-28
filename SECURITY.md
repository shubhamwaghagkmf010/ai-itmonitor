# Security Policy

AI-ITMonitor can execute remote actions and hold infrastructure credentials, so please
report vulnerabilities privately rather than in a public issue.

- Open a confidential issue on this project, or contact the maintainers directly.

Include what you found, how to reproduce it, and the impact. You will get an acknowledgement
within a few working days.

## Deploying safely

- Set a unique `SECRET_KEY` and a non-empty `AGENT_API_KEY`.
- Terminate TLS in front of the API and dashboard.
- Give the database and agent accounts least privilege.
- Do not expose the API to an untrusted network; it can run remote actions.
