#!/usr/bin/env bash
set -euo pipefail

# The second source checkout pins probe bytes only, never a runtime dependency.
if [ "$#" -ne 2 ]; then
  printf 'usage: %s RUNTIME_PEER_ROOT SLICE2_PROBE_PEER_ROOT\n' "$0" >&2
  exit 64
fi
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cmp "$repo_root/src/tests/interop/c2_interop_probe.py" "$1/src/tests/interop/c2_interop_probe.py"
cmp "$repo_root/src/tests/interop/c2_slice2_probe.py" "$2/src/tests/interop/c2_slice2_probe.py"
