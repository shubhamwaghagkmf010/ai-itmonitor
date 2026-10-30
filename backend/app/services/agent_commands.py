"""Rules for the agent channel: per-agent tokens and the commands the server may queue.

Kept free of FastAPI so the rules can be tested without a request."""
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

TOKEN_PREFIX = "agt_"

# A command that was not picked up (or not answered) in time is dropped, so a "reboot" queued
# while a machine was off cannot run hours later when it boots.
COMMAND_TTL = timedelta(minutes=5)
COMMAND_TTL_BY_TYPE = {"UPDATE_AGENT": timedelta(minutes=15)}
# Time an agent gets to report back after the command was handed to it.
RESULT_GRACE = timedelta(minutes=10)

# A heartbeat this recent means the agent is alive and owns its identity, so a second
# registration for the same machine is refused unless it proves it holds the token.
REENROLL_AFTER = timedelta(minutes=5)

MAX_SHELL_LENGTH = 2000
MAX_OUTPUT_LENGTH = 64 * 1024
MAX_PID = 4_194_304  # Linux pid_max upper bound; Windows pids are far smaller

FINAL_STATUSES = {"COMPLETED", "FAILED", "EXPIRED", "TIMEOUT", "CANCELLED"}
REPORTABLE_STATUSES = {"COMPLETED", "FAILED"}

SERVICE_COMMANDS = {"SERVICE_START", "SERVICE_STOP", "SERVICE_RESTART", "SERVICE_STATUS"}
# What an operator may queue through /remote-action. UPDATE_AGENT is only queued by push-update.
REMOTE_ACTIONS = {"EXECUTE_SHELL", "KILL_PROCESS", "REBOOT_SYSTEM", "DIAGNOSE_SYSTEM"} | SERVICE_COMMANDS

_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@:\- ]{1,128}$")


class CommandRejected(ValueError):
    """The requested action is not allowed or is malformed."""


def new_agent_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_agent_token(token: str) -> str:
    # The token is 256 random bits, so a fast hash is enough; it only has to keep a copy of the
    # database from being a copy of the credentials.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: Optional[str], stored_hash: Optional[str]) -> bool:
    if not token or not stored_hash:
        return False
    return secrets.compare_digest(hash_agent_token(token), stored_hash)


def validate_pid(pid) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise CommandRejected("pid must be a whole number")
    if pid <= 1 or pid > MAX_PID:
        raise CommandRejected("pid is out of range (system processes cannot be targeted)")
    return pid


def validate_remote_action(command_type: str, command_str: Optional[str], pid: Optional[int]) -> Tuple[str, dict]:
    """Returns (command_type, payload) for an allowed action, otherwise raises CommandRejected."""
    ctype = (command_type or "").strip().upper()
    if ctype not in REMOTE_ACTIONS:
        raise CommandRejected(f"Unsupported action '{(command_type or '')[:40]}'")

    if ctype == "KILL_PROCESS":
        return ctype, {"pid": validate_pid(pid)}

    if ctype == "EXECUTE_SHELL":
        cmd = (command_str or "").strip()
        if not cmd:
            raise CommandRejected("A command is required")
        if len(cmd) > MAX_SHELL_LENGTH:
            raise CommandRejected(f"Command is longer than {MAX_SHELL_LENGTH} characters")
        if "\x00" in cmd:
            raise CommandRejected("Command contains an invalid character")
        return ctype, {"command_str": cmd}

    if ctype in SERVICE_COMMANDS:
        name = (command_str or "").strip()
        if not _SERVICE_NAME.match(name):
            raise CommandRejected("Service name may only contain letters, digits and . _ @ : - (max 128)")
        return ctype, {"command_str": name}

    return ctype, {}  # REBOOT_SYSTEM, DIAGNOSE_SYSTEM take no arguments


def expiry_for(command_type: str, now: datetime) -> datetime:
    return now + COMMAND_TTL_BY_TYPE.get(command_type, COMMAND_TTL)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def effective_expiry(cmd) -> datetime:
    """Commands queued before expiry existed have no expires_at; they age from creation."""
    exp = _aware(cmd.expires_at)
    if exp is not None:
        return exp
    created = _aware(cmd.created_at) or datetime.now(timezone.utc)
    return created + COMMAND_TTL_BY_TYPE.get(cmd.command_type, COMMAND_TTL)


def expire_stale_commands(db, machine_id: Optional[int] = None, now: Optional[datetime] = None) -> int:
    """Closes commands nobody will answer: never delivered in time -> EXPIRED, delivered but never
    reported -> TIMEOUT. Returns how many were closed. The caller commits."""
    from backend.app.models.entities import AgentCommand

    now = now or datetime.now(timezone.utc)
    q = db.query(AgentCommand).filter(AgentCommand.status.in_(("PENDING", "DISPATCHED")))
    if machine_id is not None:
        q = q.filter(AgentCommand.machine_id == machine_id)
    closed = 0
    for cmd in q.all():
        exp = effective_expiry(cmd)
        if cmd.status == "PENDING" and exp < now:
            cmd.status = "EXPIRED"
            cmd.result_output = "Not delivered: the machine did not check in before the command expired."
            cmd.executed_at = now
            closed += 1
        elif cmd.status == "DISPATCHED" and exp + RESULT_GRACE < now:
            cmd.status = "TIMEOUT"
            cmd.result_output = "No result was reported by the machine."
            cmd.executed_at = now
            closed += 1
    if closed:
        db.flush()  # sessions here do not autoflush, and the caller queries for PENDING next
    return closed
