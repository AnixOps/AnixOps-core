#!/usr/bin/env bash
set -euo pipefail

cut=$(date -u -d '-1 day' +%FT%TZ)
endpoint="repos/${GITHUB_REPOSITORY:?}/actions/artifacts"
# Finish pagination before mutating the result set. A failed list stops cleanup.
ids=$(gh api --paginate "$endpoint?per_page=100" \
  --jq ".artifacts[] | select(.expired | not) | select(.created_at < \"$cut\") | .id")

while IFS= read -r id; do
  [[ -n "$id" ]] || continue
  [[ "$id" =~ ^[0-9]+$ ]] || { echo "Invalid artifact ID in list response" >&2; exit 1; }
  if response=$(gh api --include -X DELETE "$endpoint/$id" 2>/dev/null); then
    continue
  else
    result=$?
  fi
  # gh --include prints the HTTP status line before headers and body.
  status_line=${response%%$'\n'*}
  if [[ "$result" == 1 && "$status_line" =~ ^HTTP/[0-9.]+\ 404([[:space:]]|$) ]]; then
    echo "Artifact $id is already absent (DELETE HTTP 404)"
    continue
  fi
  if [[ "$status_line" =~ ^HTTP/[0-9.]+\ ([0-9]{3})([[:space:]]|$) ]]; then
    echo "DELETE failed for artifact $id (HTTP ${BASH_REMATCH[1]})" >&2
  else
    echo "DELETE failed for artifact $id (gh exit $result, no HTTP status)" >&2
  fi
  exit "$result"
done <<< "$ids"
