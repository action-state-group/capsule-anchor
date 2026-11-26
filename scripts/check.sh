#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs locally what CI runs on pull requests and main: python.yml on Python
# 3.11 and 3.12, hostname-lint.yml, neutrality.yml's scanner self-test and
# local-witness.yml (without its /etc/hosts block, which needs sudo).
# Not run: neutrality.yml's scan itself, which needs the NEUTRALITY_TERMS
# repository secret, dco.yml's sign-off check, and python.yml's test-postgres
# job, which needs a Postgres database (CONTRIBUTING.md, Dev setup, says how
# to run it). Needs uv, which provides both Pythons.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# python.yml, on Python 3.11 and 3.12.
for py in 3.11 3.12; do
  uv venv -q -p "$py" "$tmp/py$py"
  VIRTUAL_ENV="$tmp/py$py" uv pip install -q -e ".[dev]"
  "$tmp/py$py/bin/python" -m ruff check .
  "$tmp/py$py/bin/python" -m pytest -q
done

# hostname-lint.yml and neutrality.yml's scanner self-test.
"$tmp/py3.12/bin/python" .github/hostname_lint.py .
"$tmp/py3.12/bin/python" .github/neutrality_scan.py --self-test

# local-witness.yml: start ci/local-witness, register a checkpoint over TLS,
# check the authority key and the log.
mkdir -p "$tmp/lw"
# Set before the start, so a start that fails after launching the service still stops it.
trap 'kill "$(cat "$tmp/lw/local-witness/pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$tmp"' EXIT
RUNNER_TEMP="$tmp/lw" GITHUB_OUTPUT="$tmp/lw/out" SRC="$PWD" BLOCK=false PYTHON="$tmp/py3.12/bin/python" \
  bash ci/local-witness/start.sh
out() { sed -n "s/^$1=//p" "$tmp/lw/out"; }
SSL_CERT_FILE="$(out ca-bundle)" "$tmp/py3.12/bin/python" examples/cross-witness-checkpoint-smoke/submit_checkpoint.py \
  --host "$(out url)" --log-id ci-local-witness/v1 > /dev/null
SSL_CERT_FILE="$(out ca-bundle)" URL="$(out url)" KEY="$(out public-key)" "$tmp/py3.12/bin/python" -c '
import os, httpx
got = httpx.get(os.environ["URL"] + "/anchor/authority-pubkey").json()["pubkey_hex"]
assert got == os.environ["KEY"], (got, os.environ["KEY"])'
grep -qE '"POST /checkpoints HTTP/[0-9.]+" 2[0-9][0-9]' "$(out log)"
echo "local witness: ok"
