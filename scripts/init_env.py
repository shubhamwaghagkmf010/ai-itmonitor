"""Create backend/.env from backend/.env.example with a real signing key.

    python scripts/init_env.py                    # new SECRET_KEY, other values as in the example
    python scripts/init_env.py --with-agent-key   # also a random AGENT_API_KEY (agents must then send it)
    python scripts/init_env.py --force            # replace an existing backend/.env

The file is created readable by its owner only. The generated values are written to the file and
not printed. This script imports nothing from the application, so it still works when the current
configuration is one the server refuses to start with.
"""
import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]


def build_env_text(example: str, secret_key: str, agent_key: Optional[str] = None) -> str:
    """The example file with the SECRET_KEY (and, if given, the AGENT_API_KEY) line filled in."""
    out = []
    for line in example.splitlines():
        if line.startswith("SECRET_KEY="):
            line = f'SECRET_KEY="{secret_key}"'
        elif agent_key and line.startswith("AGENT_API_KEY="):
            line = f'AGENT_API_KEY="{agent_key}"'
        out.append(line)
    return "\n".join(out) + "\n"


def main(argv: Optional[Sequence[str]] = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description="Create backend/.env with a generated SECRET_KEY.")
    parser.add_argument("--force", action="store_true", help="replace an existing backend/.env")
    parser.add_argument("--with-agent-key", action="store_true",
                        help="also generate AGENT_API_KEY; every agent must then be given the same key")
    args = parser.parse_args(argv)

    example = root / "backend" / ".env.example"
    target = root / "backend" / ".env"

    if not example.exists():
        print(f"Cannot find {example}", file=sys.stderr)
        return 1
    if target.exists() and not args.force:
        print(f"{target} already exists; nothing was changed. Use --force to replace it "
              "(this would also replace its SECRET_KEY and sign everyone out).", file=sys.stderr)
        return 1

    text = build_env_text(
        example.read_text(encoding="utf-8"),
        secret_key=secrets.token_urlsafe(48),
        agent_key=secrets.token_urlsafe(32) if args.with_agent_key else None,
    )

    # Created with mode 600 from the start, so the secrets are never readable by others, not even briefly.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(target, 0o600)

    print(f"Wrote {target} (readable by its owner only) with a new SECRET_KEY.")
    if args.with_agent_key:
        print("AGENT_API_KEY is set: give the same value to every agent as the AGENT_API_KEY environment variable.")
    else:
        print("AGENT_API_KEY is still empty, so any machine can enrol as an agent. "
              "Re-run with --with-agent-key, or set one yourself.")
    print("Still to set by hand: POSTGRES_PASSWORD (it must match the database).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
