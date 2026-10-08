#!/usr/bin/env python3
"""Production-quality Git helper for AI-ITMonitor.

It does NOT blindly run `git add . && git commit -m update && git push`. Instead it:

  1. verifies this is a git repository and finds the current branch and remote,
  2. detects added / modified / deleted / untracked files (respecting .gitignore),
  3. scans everything that would be committed for secrets and private data,
  4. generates a meaningful Conventional-Commits message from the actual changes,
  5. shows you the summary and asks for explicit confirmation,
  6. commits, verifies the commit, pushes to the correct remote, verifies the push,
  7. prints a final summary.

It never force-pushes, rewrites history, or deletes branches.

Usage:
    python scripts/git_auto_push.py              # interactive
    python scripts/git_auto_push.py --message "feat: ..."   # override message
    python scripts/git_auto_push.py --yes        # skip the confirmation prompt
    python scripts/git_auto_push.py --dry-run    # analyse only, do not commit/push
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Secret / private-data detection
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Generic API/secret assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|secret|password|passwd|token|access[_-]?token"
        r"|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("Bearer token literal", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("Postgres URL with password", re.compile(r"postgres(?:ql)?://[^:/\s]+:[^@/\s]+@")),
    ("Private IPv4 address", re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
]

# Values that are safe even though they match a pattern above (placeholders, examples).
ALLOWLIST = {
    "YOUR_SECRET_KEY", "YOUR_DB_PASSWORD", "YOUR_API_KEY", "change_me",
    "ChangeMe123!", "replace_this", "example", "localhost", "192.168.1.0",
    # Documentation examples of private ranges are allowed in markdown only (handled below).
}

# Files/paths that are examples or docs where a sample private IP is acceptable.
DOC_SUFFIXES = {".md", ".example"}

TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".env", ".sh", ".bat", ".ps1", ".txt", ".md", ".html", ".css",
    ".example", ".dockerfile", "", ".go", ".mod",
}


def run(args: list[str], check: bool = True) -> str:
    res = subprocess.run(["git", *args], capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed:\n{res.stderr.strip()}")
    return res.stdout


def repo_root() -> Path:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("Not a git repository. Run `git init` first (or the setup steps in the README).")
    return Path(out.stdout.strip())


def current_branch() -> str:
    # `git branch --show-current` works even on an unborn branch (no commits yet).
    out = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True)
    name = out.stdout.strip()
    if name:
        return name
    ref = subprocess.run(["git", "symbolic-ref", "--short", "HEAD"], capture_output=True, text=True)
    return ref.stdout.strip() or "main"


def remote_url() -> str | None:
    out = subprocess.run(["git", "remote", "get-url", "origin"],
                         capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


def changed_files() -> list[tuple[str, str]]:
    """Return (status, path) for every change git sees, respecting .gitignore."""
    out = run(["status", "--porcelain=v1", "--untracked-files=all"])
    files: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        status, path = line[:2].strip(), line[3:].strip()
        if " -> " in path:  # renames
            path = path.split(" -> ", 1)[1]
        files.append((status or "?", path))
    return files


def scan_for_secrets(root: Path, files: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    for status, rel in files:
        if status == "D":
            continue
        p = root / rel
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES and p.suffix != "":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        is_doc = p.suffix.lower() in DOC_SUFFIXES
        for lineno, line in enumerate(text.splitlines(), 1):
            for label, pat in SECRET_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                hit = m.group(0)
                if any(a in line for a in ALLOWLIST):
                    continue
                # Allow sample private IPs in docs/examples only.
                if label == "Private IPv4 address" and is_doc:
                    continue
                findings.append(f"{rel}:{lineno}: {label}: {hit}")
    return findings


def generate_message(files: list[tuple[str, str]]) -> str:
    paths = [p for _, p in files]
    statuses = {s for s, _ in files}

    def all_in(prefixes):
        return paths and all(any(p.startswith(x) or p == x for x in prefixes) for p in paths)

    only_md = paths and all(p.lower().endswith(".md") for p in paths)
    docker_ish = all_in(("docker/", "compose.yaml", "compose.yml", ".dockerignore", "Dockerfile"))
    ci_ish = all_in((".github/",))
    test_ish = all_in(("tests/", "test_"))

    if only_md:
        ctype, scope = "docs", None
    elif ci_ish:
        ctype, scope = "ci", None
    elif docker_ish:
        ctype, scope = "build", "docker"
    elif test_ish:
        ctype, scope = "test", None
    else:
        if statuses == {"A"} or statuses <= {"A", "?"}:
            ctype = "feat"
        elif "D" in statuses and len(statuses) == 1:
            ctype = "chore"
        else:
            ctype = "chore"
        if all(p.startswith("backend/") for p in paths):
            scope = "backend"
        elif all(p.startswith("frontend/") for p in paths):
            scope = "frontend"
        elif all(p.startswith("agent/") for p in paths):
            scope = "agent"
        else:
            scope = None

    head = f"{ctype}({scope}): " if scope else f"{ctype}: "
    if only_md:
        subject = "update documentation"
    elif docker_ish:
        subject = "update Docker configuration"
    elif len(paths) == 1:
        subject = f"update {paths[0]}"
    else:
        subject = f"update {len(paths)} files across the project"

    body_lines = [f"- {s} {p}" for s, p in sorted(files)][:40]
    return head + subject + "\n\n" + "\n".join(body_lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Safe, analysing git commit+push helper.")
    ap.add_argument("--message", "-m", help="override the generated commit message")
    ap.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--dry-run", action="store_true", help="analyse only; do not commit or push")
    args = ap.parse_args()

    root = repo_root()
    branch = current_branch()
    remote = remote_url()
    files = changed_files()

    print("=" * 60)
    print(f"Repository : {root}")
    print(f"Branch     : {branch}")
    print(f"Remote     : {remote or '(none configured)'}")
    print("=" * 60)

    if not files:
        print("Nothing to commit. Working tree is clean.")
        return

    print(f"\nChanges ({len(files)}):")
    for status, path in sorted(files):
        print(f"  {status:<2} {path}")

    print("\nScanning for secrets / private data…")
    findings = scan_for_secrets(root, files)
    if findings:
        print("\n  SECRET SCAN FAILED — these must be removed before committing:")
        for f in findings:
            print(f"    !! {f}")
        sys.exit("\nAborted. No commit was made.")
    print("  OK  no secrets or private data detected.")

    message = args.message or generate_message(files)
    print("\nProposed commit message:")
    print("-" * 60)
    print(message)
    print("-" * 60)

    if args.dry_run:
        print("\n[dry-run] Stopping before any commit/push.")
        return

    if not remote:
        print("\nNo 'origin' remote is configured, so there is nothing to push to yet.")
        print("Add one first, e.g.:  git remote add origin <your repo URL>")
        sys.exit(1)

    if not args.yes:
        ans = input("\nCommit and push these changes? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Cancelled. Nothing was committed.")
            return

    run(["add", "-A"])
    run(["commit", "-m", message])
    head = run(["rev-parse", "HEAD"]).strip()
    print(f"\n  OK  committed {head[:10]}")

    print(f"  …  pushing to origin/{branch}")
    run(["push", "origin", branch])

    local = run(["rev-parse", branch]).strip()
    remote_head = run(["rev-parse", f"origin/{branch}"]).strip()
    if local == remote_head:
        print(f"  OK  push verified (origin/{branch} = {remote_head[:10]})")
    else:
        sys.exit("  !! push verification failed: local and remote heads differ.")

    print("\n" + "=" * 60)
    print("DONE")
    print(f"  commit : {head[:10]}")
    print(f"  branch : {branch}")
    print(f"  remote : {remote}")
    print("=" * 60)


if __name__ == "__main__":
    main()
