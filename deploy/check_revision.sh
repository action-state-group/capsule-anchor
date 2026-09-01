#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Confirms the deployed Cloud Run revision matches origin/main -- the
# 2026-08-27 stale-deploy rule (fetch, fast-forward, THEN deploy) as a
# mechanical check instead of an eyeballed timestamp comparison.
#
# A `gcloud run deploy --source .` build has no git SHA baked into the image
# by default, so this compares the SERVING revision's creation time against
# origin/main's latest commit time as a sanity floor, and -- when the image
# tag DOES carry a commit SHA (see cloudbuild.yaml's _TAG usage) -- does an
# exact tag comparison. Exits non-zero (and says so) when it cannot prove
# freshness, rather than reporting a false pass.
#
# Usage:
#   PROJECT_ID=fluxxom deploy/check_revision.sh

set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
SERVICE="${SERVICE:-capsule-witness}"
REGION="${REGION:-us-central1}"

git fetch origin --quiet
REMOTE_MAIN=$(git rev-parse origin/main)
REMOTE_MAIN_SHORT=$(git rev-parse --short origin/main)
REMOTE_MAIN_TIME=$(git show -s --format=%cI origin/main)

echo "origin/main: ${REMOTE_MAIN} (${REMOTE_MAIN_TIME})"

IMAGE=$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" \
  --format="value(spec.template.spec.containers[0].image)")
REVISION=$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" \
  --format="value(status.latestReadyRevisionName)")
REVISION_TIME=$(gcloud run revisions describe "${REVISION}" --project="${PROJECT_ID}" --region="${REGION}" \
  --format="value(metadata.creationTimestamp)")

echo "deployed revision: ${REVISION}"
echo "deployed image: ${IMAGE}"
echo "revision created: ${REVISION_TIME}"

IMAGE_TAG="${IMAGE##*:}"
if [[ "${IMAGE_TAG}" == "${REMOTE_MAIN_SHORT}" || "${IMAGE_TAG}" == "${REMOTE_MAIN}" ]]; then
  echo "PASS: deployed image tag exactly matches origin/main (${IMAGE_TAG})."
  exit 0
fi

REVISION_AFTER_MAIN=$(python3 -c "
import datetime, sys
a = datetime.datetime.fromisoformat('${REVISION_TIME}'.replace('Z', '+00:00'))
b = datetime.datetime.fromisoformat('${REMOTE_MAIN_TIME}'.replace('Z', '+00:00'))
print('yes' if a > b else 'no')
")
if [[ "${REVISION_AFTER_MAIN}" == "yes" ]]; then
  echo "PASS (inferred): revision ${REVISION} was created after origin/main's latest commit."
  echo "NOTE: image tag '${IMAGE_TAG}' does not carry a commit SHA, so this is a timestamp"
  echo "inference, not a cryptographic match. Redeploy with cloudbuild.yaml's _TAG=\$(git rev-parse --short HEAD)"
  echo "to make future checks exact."
  exit 0
fi

echo "FAIL: revision ${REVISION} (${REVISION_TIME}) predates origin/main's latest commit"
echo "(${REMOTE_MAIN_TIME}). Fetch + fast-forward, then redeploy before trusting this service."
exit 1
