# Single source of truth for the agent version.
#
# Bump this (e.g. "1.1.0" -> "1.2.0") WHENEVER you change anything under agent/.
# The server reads this same file to tell every running agent what the latest
# version is, so a bump here is the signal that makes all PCs auto-update:
#   * within ~10s via the /metrics heartbeat response, and
#   * as an hourly fallback via GET /agents/version.
# The launcher (run.bat) then swaps in the new code and restarts the agent.
AGENT_VERSION = "1.2.1"
