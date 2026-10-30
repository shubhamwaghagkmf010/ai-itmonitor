"""Checks applied to an agent update before any of it is unpacked. Standard library only."""
import hashlib
import io
import os
import zipfile
from pathlib import PurePosixPath
from typing import Tuple

from agent.signing import bundle_message, verify

MAX_FILES = 500
MAX_TOTAL_BYTES = 50 * 1024 * 1024
# Local state that an update must never replace.
PROTECTED_NAMES = {"agent_config.json"}


def parse_version(v) -> tuple:
    parts = []
    for piece in str(v).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def verify_bundle(content: bytes, headers, os_name: str, current_version: str,
                  key: str, server_url: str) -> Tuple[bool, str]:
    """Decides whether a downloaded bundle may be installed.

    With a shared key configured the bundle must carry a signature over (os, version, sha256) made
    with that key, so a copy altered or substituted on the way is refused; the version must also be
    newer than the one running, so an old signed bundle cannot be replayed to downgrade the agent.
    Without a key there is no way to authenticate the content, so the only acceptable source is a
    certificate-verified HTTPS connection."""
    digest = hashlib.sha256(content).hexdigest()
    claimed_hash = (headers.get("x-bundle-sha256") or "").lower()
    version = headers.get("x-bundle-version") or ""
    if claimed_hash and claimed_hash != digest:
        return False, "bundle does not match its advertised hash"

    if key:
        signature = headers.get("x-bundle-signature")
        if not version or not verify(bundle_message(os_name, version, digest), signature, key):
            return False, "bundle signature is missing or invalid"
    elif not server_url.lower().startswith("https://"):
        return False, "no AGENT_API_KEY to authenticate the bundle and the server URL is not HTTPS"

    if version and parse_version(version) <= parse_version(current_version):
        return False, f"bundle version {version} is not newer than {current_version}"
    return True, "ok"


def safe_extract(content: bytes, dest) -> int:
    """Unpacks only the agent/ part of the bundle into dest, refusing absolute paths, '..', links,
    absurd sizes and anything that would overwrite local state. Returns the number of files written."""
    dest = os.path.abspath(str(dest))
    written = 0
    total = 0
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("bundle has too many files")
        for info in infos:
            name = info.filename.replace("\\", "/")
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or (len(name) > 1 and name[1] == ":"):
                raise ValueError(f"unsafe path in bundle: {info.filename!r}")
            if not path.parts or path.parts[0] != "agent":
                continue  # run.bat, README and the like are not part of an in-place update
            if info.is_dir():
                continue
            if (info.external_attr >> 28) == 0xA:  # symlink
                raise ValueError(f"link in bundle: {info.filename!r}")
            if path.name in PROTECTED_NAMES:
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("bundle is too large")
            target = os.path.abspath(os.path.join(dest, *path.parts))
            if not target.startswith(dest + os.sep):
                raise ValueError(f"unsafe path in bundle: {info.filename!r}")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                out.write(src.read(info.file_size + 1)[: info.file_size])
            written += 1
    return written
