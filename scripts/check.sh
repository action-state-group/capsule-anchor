#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs locally what CI runs on pull requests and main: python.yml on Python
# 3.11 and 3.12, hostname-lint.yml and neutrality.yml's scanner self-test.
# Not run: neutrality.yml's scan itself, which needs the NEUTRALITY_TERMS
# repository secret, and dco.yml's sign-off check. Needs uv, which provides both Pythons.
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
