"""Run effective access-denial qualification as the actual configured serving UID.

This command qualifies existing deployment files; it creates no accounts, keys,
permissions or activation records. A missing deployment or wrong UID is a failure.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def denied(path: Path, flags: int) -> bool:
    """Require kernel access denial, rather than absence or a mode-bit inference."""
    try:
        descriptor = os.open(path, flags)
    except PermissionError:
        return True
    else:
        os.close(descriptor)
        return False


def main() -> None:
    """Verify seed-read and issuer-write denial, then open the real public verifier."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--seed-file", type=Path, required=True)
    parser.add_argument("--issuer-db", type=Path, required=True)
    parser.add_argument("--public-state", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != args.expected_uid or os.geteuid() == 0:
        raise SystemExit("qualification requires the actual non-root serving identity")
    if not denied(args.seed_file, os.O_RDONLY) or not denied(args.issuer_db, os.O_RDWR):
        raise SystemExit("serving identity has forbidden authority access")
    from phylax import GrantVerifierConfig, open_effect_grant_verifier
    verifier = open_effect_grant_verifier(GrantVerifierConfig(state_dir=args.public_state))
    try:
        database = args.public_state / "grants.sqlite3"
        if not denied(database, os.O_RDWR):
            raise SystemExit("serving identity can write the public verifier database")
        print(json.dumps({"uid": os.geteuid(), "seed_read_denied": True, "issuer_write_denied": True, "public_verifier_opened": True, "public_write_denied": True}))
    finally:
        verifier.close()


if __name__ == "__main__":
    main()
