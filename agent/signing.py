"""Signatures on what the server tells an agent to do.

Agents talk to the server over plain HTTP on many networks, and what comes back can run code on the
machine (shell commands, a new copy of the agent). Every such instruction therefore carries an
HMAC-SHA256 made with the shared AGENT_API_KEY, and the agent refuses anything that does not verify.
Only the standard library is used so the agent needs nothing extra.

This file exists twice on purpose: agent/signing.py (the agent has no access to the backend package)
and backend/app/services/agent_signing.py. tests/test_update_security.py checks they agree."""
import hashlib
import hmac
import json
from typing import Optional


def canonical_payload(payload) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def command_message(agent_id: str, command_id, command_type: str, payload, expires_at: str) -> str:
    return f"cmd|{agent_id}|{command_id}|{command_type}|{canonical_payload(payload)}|{expires_at}"


def bundle_message(os_name: str, version: str, sha256_hex: str) -> str:
    return f"bundle|{os_name}|{version}|{sha256_hex}"


def hint_message(hint: str) -> str:
    return f"hint|{hint}"


def sign(message: str, key: str) -> Optional[str]:
    if not key:
        return None
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(message: str, signature: Optional[str], key: str) -> bool:
    if not key or not signature:
        return False
    expected = sign(message, key)
    return hmac.compare_digest(expected.encode("ascii"), str(signature).encode("utf-8", "ignore"))
