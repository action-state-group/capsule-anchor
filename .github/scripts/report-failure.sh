#!/usr/bin/env bash
# Copied from action-state-group/evidencebook main be757b81c7f29530066f275023f67551b610f6c8 (.github/scripts/report-failure.sh); keep in sync.
# Reports a red run on main or a nightly so it reaches a person the same day
# (evidencebook#925): comments the run link $RUN on the one open issue titled
# $TITLE, or opens it. The issue carries the ci-red label (the coordinator's
# watchdog lists open ci-red issues) and is assigned to $ASSIGNEE when that is
# set; a failure to label or assign only warns, since the run link is already
# on the issue. Two reporters racing can both open one: after opening, the
# reporter waits for search to settle and, when an older open issue exists,
# puts its run there and closes its own. Needs GH_TOKEN with issues: write.
set -euo pipefail
: "${TITLE:?}" "${RUN:?}"
repo=$GITHUB_REPOSITORY

open_issues() {
  gh issue list --repo "$repo" --state open --search "\"$TITLE\" in:title" --json number,title \
    --jq "map(select(.title == env.TITLE) | .number) | sort | .[]"
}

# Whether the ci-red label exists: created when missing and checked after, since
# creating it can fail (an HTTP 500) and the report must go out regardless.
have_label=0
ensure_label() {
  local try names
  for try in 1 2; do
    gh label create ci-red --repo "$repo" --color B60205 \
      --description "A workflow failed on main or a nightly" > /dev/null 2>&1 || true
    if names=$(gh label list --repo "$repo" --search ci-red --json name --jq '.[].name') &&
      grep -qx ci-red <<<"$names"; then
      have_label=1
      return
    fi
    echo "::warning::the ci-red label is missing (attempt $try)"
  done
}

# Label and assign an issue, also one an earlier reporter opened without them.
mark() {
  local args=()
  ((have_label)) && args+=(--add-label ci-red)
  [[ -z "${ASSIGNEE:-}" ]] || args+=(--add-assignee "$ASSIGNEE")
  ((${#args[@]})) || return 0
  gh issue edit "$1" --repo "$repo" "${args[@]}" > /dev/null || echo "::warning::could not label or assign #$1"
}

ensure_label
found=$(open_issues)
n=${found%%$'\n'*}
if [[ -n "$n" ]]; then
  gh issue comment "$n" --repo "$repo" --body "Failed again: $RUN"
  mark "$n"
  exit 0
fi
url=$(gh issue create --repo "$repo" --title "$TITLE" \
  --body "Failed: $RUN. Close this issue once the workflow passes again.")
echo "$url"
mine=${url##*/}
mark "$mine"

# Search is eventually consistent: give a racing reporter's issue time to show.
sleep "${REPORT_SETTLE_SECONDS:-20}"
found=$(open_issues)
keep=${found%%$'\n'*}
# Only an older issue displaces ours. Search may still miss ours, or show only
# a newer one, whose reporter finds ours older and closes its own.
if [[ -z "$keep" ]] || ((keep >= mine)); then
  exit 0
fi
gh issue comment "$keep" --repo "$repo" --body "Also failed: $RUN"
mark "$keep"
gh issue close "$mine" --repo "$repo" --comment "Duplicate of #$keep."
