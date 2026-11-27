#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs locally what CI runs on pull requests and main: python.yml on Python
# 3.11 and 3.12, hostname-lint.yml, neutrality.yml's scanner self-test and
# local-witness.yml (without its /etc/hosts block, which needs sudo),
# python.yml's test-postgres job and dco.yml's sign-off check.
# test-postgres uses CAPSULE_ANCHOR_TEST_DATABASE_URL when set; otherwise it
# starts a throwaway Postgres from the local initdb/pg_ctl (Homebrew
# postgresql@17 on a Mac), and the check fails when neither is available.
# neutrality.yml's scan runs only when NEUTRALITY_TERMS is set: its terms are
# a repository secret, and the script says when it did not run the scan.
# Needs uv, which provides both Pythons.
set -euo pipefail
cd "$(dirname "$0")/.."
# Only the scanner sees the reserved terms, and only the Postgres phase sees
# a test database: the in-memory phases must run without one, as in CI.
neutrality_terms="${NEUTRALITY_TERMS:-}"
test_db_url="${CAPSULE_ANCHOR_TEST_DATABASE_URL:-}"
unset NEUTRALITY_TERMS CAPSULE_ANCHOR_TEST_DATABASE_URL
tmp="$(mktemp -d)"
cleanup() {
  kill "$(cat "$tmp/lw/local-witness/pid" 2>/dev/null)" 2>/dev/null || true
  # A throwaway Postgres that will not stop fails the check and keeps its
  # directory (data and log) for diagnosis instead of being left running unseen.
  if [ -f "$tmp/pg/data/postmaster.pid" ] \
    && ! pg_ctl -D "$tmp/pg/data" -m immediate -w stop > /dev/null 2>&1; then
    echo "test-postgres: could not stop the throwaway server; see $tmp/pg" >&2
    exit 1
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

# dco.yml: every commit not yet on origin/main carries a sign-off.
# Any failure here (no origin/main, a broken rev-list) stops the check: set -e
# with pipefail covers both assignments.
base="$(git merge-base HEAD origin/main)"
missing="$(git rev-list "$base..HEAD" | while read -r sha; do
  git log --format=%B -n 1 "$sha" | grep -qiE "^Signed-off-by: .+ <.+@.+>" \
    || git log --format='  %h %s' -n 1 "$sha"
done)"
if [ -n "$missing" ]; then
  printf 'dco: missing Signed-off-by on:\n%s\nFix: git rebase --signoff %s\n' "$missing" "$base" >&2
  exit 1
fi
echo "dco: ok"

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

# neutrality.yml's scan, when its terms are at hand. As in CI, the terms go
# only to origin/main's copy of the scanner, run by an isolated interpreter
# that has not installed this checkout: the checkout is only scanned as data.
if [ -n "$neutrality_terms" ]; then
  git show origin/main:.github/neutrality_scan.py > "$tmp/neutrality_scan.py"
  NEUTRALITY_TERMS="$neutrality_terms" "$(uv python find 3.12)" -I "$tmp/neutrality_scan.py" .
else
  echo "neutrality scan: NOT RUN (no local term list: NEUTRALITY_TERMS unset; CI runs it)"
fi

# python.yml's test-postgres job: the whole suite again, against Postgres.
VIRTUAL_ENV="$tmp/py3.12" uv pip install -q -e ".[dev,postgres]"
db_url="$test_db_url"
if [ -z "$db_url" ]; then
  if ! command -v initdb > /dev/null || ! command -v pg_ctl > /dev/null; then
    echo "test-postgres: no CAPSULE_ANCHOR_TEST_DATABASE_URL and no initdb/pg_ctl" \
      "(brew install postgresql@17)" >&2
    exit 1
  fi
  mkdir -p "$tmp/pg"
  # LC_ALL=C: on macOS the postmaster refuses to start ("became multithreaded
  # during startup") under a locale it cannot resolve.
  LC_ALL=C initdb -A trust -U postgres --no-sync --locale=C -E UTF8 -D "$tmp/pg/data" \
    > "$tmp/pg/initdb.log" 2>&1
  # Unix socket only, in the temp directory: no TCP port to collide with
  # another run or a local server. No durability: the server is thrown away,
  # and each test creates and drops a schema, which fsync makes slow on macOS.
  LC_ALL=C pg_ctl -D "$tmp/pg/data" -l "$tmp/pg/log" -w \
    -o "-c listen_addresses='' -k $tmp/pg -c fsync=off -c synchronous_commit=off -c full_page_writes=off" \
    start > /dev/null
  createdb -h "$tmp/pg" -U postgres capsule_anchor_test
  db_url="postgresql://postgres@/capsule_anchor_test?host=$tmp/pg"
fi
# libpq bounds a connection and every statement, so an unresponsive database
# fails the phase instead of hanging the check.
CAPSULE_ANCHOR_TEST_DATABASE_URL="$db_url" PGCONNECT_TIMEOUT=10 PGOPTIONS="-c statement_timeout=120s" \
  "$tmp/py3.12/bin/python" -m pytest -q -rs

# local-witness.yml: start ci/local-witness, register a checkpoint over TLS,
# check the authority key and the log. The two CAPSULE_ANCHOR_* settings are
# the ones local-witness.yml sets for the witness to ignore. Its production
# block is not run: it appends to /etc/hosts with sudo.
mkdir -p "$tmp/lw"
CAPSULE_ANCHOR_DATABASE_URL=postgresql://nobody:nothing@127.0.0.1:1/none CAPSULE_ANCHOR_PUBLIC_LOG=rekor \
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
echo "local witness production block: NOT RUN (it edits /etc/hosts with sudo; CI runs it)"
