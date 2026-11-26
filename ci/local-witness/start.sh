#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Starts capsule-anchor from $SRC on https://localhost:<free port> for the rest
# of a GitHub Actions job (ci/local-witness/action.yml). Everything lives under
# $RUNNER_TEMP/local-witness; the service gets its own venv, so the caller's
# Python and its pinned packages are left as they were. The store is in memory
# and the signing seed is thrown away with the runner: this witness exists only
# for the job.
set -euo pipefail

dir="$RUNNER_TEMP/local-witness"
mkdir -p "$dir"
# PYTHON picks the interpreter the venv is made from (scripts/check.sh passes
# its uv-provisioned 3.12); the service needs 3.11 or later (pyproject.toml).
base="${PYTHON:-python3}"
"$base" -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || { echo "::error::$base is older than Python 3.11, which capsule-anchor needs; set PYTHON"; exit 1; }
"$base" -m venv "$dir/venv"
"$dir/venv/bin/pip" install --quiet --disable-pip-version-check "$SRC"
py="$dir/venv/bin/python"

# Go ignores a certificate's common name, so the name the URL uses is in the SAN.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj /CN=localhost -addext "subjectAltName=DNS:localhost" \
  -keyout "$dir/tls.key" -out "$dir/tls.crt" 2>/dev/null
# The system roots stay in the bundle, so other HTTPS in the job keeps working
# (Ubuntu's file; macOS's when scripts/check.sh runs this locally).
roots=/etc/ssl/certs/ca-certificates.crt
[ -f "$roots" ] || roots=/etc/ssl/cert.pem
cat "$roots" "$dir/tls.crt" > "$dir/ca-bundle.pem"

seed="$("$py" -c 'import os; print(os.urandom(32).hex())')"
public_key="$("$py" - "$seed" <<'PY'
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[1]))
print(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
PY
)"
port="$("$py" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
url="https://localhost:$port"

# capsule-anchor's own entry point has no TLS options (packages/capsule_anchor/app.py,
# main), so uvicorn serves the app factory directly. The three variables are the
# ones create_app requires; in-memory storage is right for a witness that lives
# only as long as the job.
# Every other CAPSULE_ANCHOR_* setting the calling job may carry is dropped, so
# none reaches this witness: a database URL would replace the in-memory store
# and CAPSULE_ANCHOR_PUBLIC_LOG=rekor would publish to a real external log.
unset $(compgen -e | grep '^CAPSULE_ANCHOR_' || true)
CAPSULE_ANCHOR_SIGNING_KEY="$seed" CAPSULE_ANCHOR_PUBLIC_HOST=localhost CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1 \
  nohup "$py" -m uvicorn --factory capsule_anchor.app:create_app --host 127.0.0.1 --port "$port" \
  --ssl-keyfile "$dir/tls.key" --ssl-certfile "$dir/tls.crt" > "$dir/witness.log" 2>&1 &
echo $! > "$dir/pid"

for _ in $(seq 1 60); do
  if curl -sf --cacert "$dir/tls.crt" "$url/health" > /dev/null; then break; fi
  if ! kill -0 "$(cat "$dir/pid")" 2> /dev/null; then
    cat "$dir/witness.log"
    echo "::error::the local witness exited before answering /health"
    exit 1
  fi
  sleep 1
done
curl -sf --cacert "$dir/tls.crt" "$url/health" > /dev/null || { cat "$dir/witness.log"; echo "::error::the local witness did not answer /health in 60 s"; exit 1; }

# The key the service signs with is the one we derived (a mismatch would mean
# capsulectl pins a key the receipts are not signed under).
"$py" - "$url" "$dir/tls.crt" "$public_key" <<'PY'
import base64, json, ssl, sys, urllib.request
url, cafile, want = sys.argv[1:]
with urllib.request.urlopen(f"{url}/.well-known/did.json", context=ssl.create_default_context(cafile=cafile)) as r:
    x = json.load(r)["verificationMethod"][0]["publicKeyJwk"]["x"]
got = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).hex()
if got != want:
    sys.exit(f"::error::the local witness signs under {got}, not the derived key {want}")
PY

if [ "$BLOCK" = "true" ]; then
  # 0.0.0.0 is this host on Linux, where nothing listens on 443: a call to production is refused, failing the step that makes it.
  printf '0.0.0.0 %s\n' witness.agentactioncapsule.org anchor.agentactioncapsule.org ts.agentactioncapsule.org \
    | sudo tee -a /etc/hosts > /dev/null
  echo "production witness hostnames blocked for the rest of the job"
fi

echo "local witness: $url, authority key $public_key"
{
  echo "url=$url"
  echo "public-key=$public_key"
  echo "ca-bundle=$dir/ca-bundle.pem"
  echo "log=$dir/witness.log"
} >> "$GITHUB_OUTPUT"
