"""Server side of the signatures agents check (see agent/signing.py for the reasoning).

The message formats are duplicated from agent/signing.py - the agent cannot import the backend - and
tests/test_update_security.py fails if the two ever disagree."""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

from backend.app.core.config import settings


def canonical_payload(payload) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def command_message(agent_id: str, command_id, command_type: str, payload, expires_at: str) -> str:
    return f"cmd|{agent_id}|{command_id}|{command_type}|{canonical_payload(payload)}|{expires_at}"


def bundle_message(os_name: str, version: str, sha256_hex: str) -> str:
    return f"bundle|{os_name}|{version}|{sha256_hex}"


def hint_message(hint: str) -> str:
    return f"hint|{hint}"


def sign(message: str, key: Optional[str] = None) -> Optional[str]:
    """HMAC-SHA256 with the shared agent key; None when no key is configured (development)."""
    key = settings.AGENT_API_KEY if key is None else key
    if not key:
        return None
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def format_expiry(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign_command(agent_id: str, command_id, command_type: str, payload, expires_at: str) -> Optional[str]:
    return sign(command_message(agent_id, command_id, command_type, payload, expires_at))


def sign_hint(hint: str) -> Optional[str]:
    return sign(hint_message(hint))


def sign_bundle(os_name: str, version: str, content: bytes) -> Optional[str]:
    return sign(bundle_message(os_name, version, hashlib.sha256(content).hexdigest()))
