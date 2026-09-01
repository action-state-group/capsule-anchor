#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Monitoring-as-code for the witness deployment (capsule-witness Cloud Run
# service). Encodes as a script -- not manual Cloud Console clicks -- so the
# monitoring setup is reviewable, repeatable, and re-runnable in a new
# project. Idempotent to run: `gcloud monitoring uptime create` fails loudly
# on a duplicate display name rather than silently double-creating.
#
# Covers BOTH the read path (GET /health) and the checkpoint-submit path
# (POST /checkpoints). Uptime checks are GET/HEAD-oriented in most tooling,
# but Cloud Monitoring's HTTP check supports POST + a body + an expected
# status code, so the submit-path check reuses the SAME "one named refusal"
# behavior already documented in DEPLOY.md's verification curl: posting a
# non-checkpoint body to /checkpoints returns a clean 400 without ever
# touching the log or the signing key. That is enough to prove the write
# path is alive and enforcing its input contract, without needing a
# real allowlisted submitter identity (see [witness-external-submitter]).
#
# Usage:
#   PROJECT_ID=fluxxom NOTIFICATION_CHANNEL=projects/fluxxom/notificationChannels/8460546284925165830 \
#     deploy/monitoring.sh

set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
HOST="${WITNESS_HOST:-witness.agentactioncapsule.org}"
NOTIFICATION_CHANNEL="${NOTIFICATION_CHANNEL:?set NOTIFICATION_CHANNEL (existing notification channel resource name)}"

echo "== Creating read-path uptime check (GET /health) on ${HOST} =="
READ_CHECK_ID=$(gcloud monitoring uptime create "witness.aac /health (read)" \
  --resource-type=uptime-url \
  --resource-labels="host=${HOST},project_id=${PROJECT_ID}" \
  --path=/health --period=1 --timeout=10 --project="${PROJECT_ID}" \
  --format="value(name)" | sed 's#.*/##')
echo "created: ${READ_CHECK_ID}"

echo "== Creating submit-path uptime check (POST /checkpoints, named-refusal canary) on ${HOST} =="
SUBMIT_CHECK_ID=$(gcloud monitoring uptime create "witness.aac /checkpoints (submit, named-refusal canary)" \
  --resource-type=uptime-url \
  --resource-labels="host=${HOST},project_id=${PROJECT_ID}" \
  --path=/checkpoints --request-method=post \
  --content-type=user-provided --custom-content-type=application/cll-checkpoint+cbor \
  --body="nope" --status-codes=400 \
  --period=1 --timeout=10 --project="${PROJECT_ID}" \
  --format="value(name)" | sed 's#.*/##')
echo "created: ${SUBMIT_CHECK_ID}"

AGG='{"alignmentPeriod":"60s","crossSeriesReducer":"REDUCE_COUNT_FALSE","perSeriesAligner":"ALIGN_NEXT_OLDER","groupByFields":["resource.label.host"]}'

echo "== Wiring alerting policy for the read-path check =="
gcloud alpha monitoring policies create \
  --project="${PROJECT_ID}" \
  --display-name="witness.aac /health (read) down" \
  --notification-channels="${NOTIFICATION_CHANNEL}" \
  --condition-display-name="Uptime check failing" \
  --condition-filter="resource.type = \"uptime_url\" AND metric.type = \"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.labels.check_id = \"${READ_CHECK_ID}\"" \
  --aggregation="${AGG}" \
  --if=">1" --duration=60s --combiner=OR

echo "== Wiring alerting policy for the submit-path check =="
gcloud alpha monitoring policies create \
  --project="${PROJECT_ID}" \
  --display-name="witness.aac /checkpoints (submit) down" \
  --notification-channels="${NOTIFICATION_CHANNEL}" \
  --condition-display-name="Uptime check failing" \
  --condition-filter="resource.type = \"uptime_url\" AND metric.type = \"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.labels.check_id = \"${SUBMIT_CHECK_ID}\"" \
  --aggregation="${AGG}" \
  --if=">1" --duration=60s --combiner=OR

echo "Done. Both checks page ${NOTIFICATION_CHANNEL} within ~2 minutes of a failure."
