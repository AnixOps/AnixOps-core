#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export PATH="$tmp:$PATH"
export GITHUB_REPOSITORY=example/repo
export CALLS="$tmp/calls"

cat > "$tmp/gh" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  "api --paginate repos/example/repo/actions/artifacts?per_page=100 --jq "*)
    printf '101\n102\n'
    [[ "$SCENARIO" != list-failure ]]
    ;;
  'api --include -X DELETE repos/example/repo/actions/artifacts/101')
    echo 101 >> "$CALLS"
    case "$SCENARIO" in
      absent) printf 'HTTP/2.0 404 Not Found\r\n'; exit 1 ;;
      forbidden) printf 'HTTP/2.0 403 Forbidden\r\n'; exit 1 ;;
      server) printf 'HTTP/2.0 500 Internal Server Error\r\n'; exit 1 ;;
      network) echo 'transport failure: HTTP 404' >&2; exit 1 ;;
      *) exit 99 ;;
    esac
    ;;
  'api --include -X DELETE repos/example/repo/actions/artifacts/102')
    echo 102 >> "$CALLS"
    printf 'HTTP/2.0 204 No Content\r\n'
    ;;
  *) exit 99 ;;
esac
MOCK
chmod +x "$tmp/gh"

for scenario in absent list-failure forbidden server network; do
  : > "$CALLS"
  expected_status=1
  expected_calls=101
  case "$scenario" in
    absent) expected_status=0; expected_calls=$'101\n102' ;;
    list-failure) expected_calls='' ;;
  esac
  status=0
  SCENARIO="$scenario" bash .github/scripts/artifact-cleanup.sh || status=$?
  if [[ "$status" != "$expected_status" || $(cat "$CALLS") != "$expected_calls" ]]; then
    echo "Unexpected cleanup result for $scenario (exit $status)" >&2
    exit 1
  fi
done
