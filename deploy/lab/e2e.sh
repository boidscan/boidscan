#!/bin/sh
# Scans the isolated lab network and checks results through the public API. Needs docker, curl and yq.
set -eu

cd "$(dirname "$0")"
compose="docker compose -f compose.yaml"
api=http://localhost:8080

cleanup() {
	if [ "${KEEP_LAB:-}" != 1 ]; then
		$compose --profile scan down -v >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	$compose logs --tail=50 >&2 || true
	exit 1
}

check() {
	desc=$1
	shift
	if "$@"; then echo "ok   $desc"; else fail "$desc"; fi
}

$compose --profile scan down -v >/dev/null 2>&1 || true
$compose up -d --build --wait db serve web sshd redis
$compose run --rm --build scan

host() { curl -fsS "$api/api/v1/host/$1"; }

ssh_banner() { host 172.30.0.11 | yq -p json '.services[] | select(.name == "ssh22") | .data.result.server_id.software'; }
banner=$(ssh_banner) || fail "ssh host lookup"
check "ssh banner recorded ($banner)" test -n "$banner" -a "$banner" != null

names=$(curl -fsS "$api/api/v1/search?cert=www.lab.test" | yq -p json '.results[0].cert_names | join(",")')
check "tls certificate indexed by SAN ($names)" test "$names" = "web.lab.test,www.lab.test"

redis=$(host 172.30.0.12 | yq -p json '[.services[].name] | join(",")') || fail "redis host lookup"
check "redis recorded ($redis)" test "$redis" = "redis6379"

ua=$($compose logs web | grep -c 'boidscan/.*abuse: abuse@lab.invalid' || true)
check "targets see the identifying user agent" test "$ua" -gt 0

code=$(curl -s -o /dev/null -w '%{http_code}' -d cidr=172.30.0.12 "$api/optout")
check "opt-out form accepted" test "$code" = 200
code=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/host/172.30.0.12")
check "opted-out host purged" test "$code" = 404

$compose run --rm scan
code=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/host/172.30.0.12")
check "opted-out host skipped on rescan" test "$code" = 404
seen=$(curl -fsS "$api/api/v1/search?cidr=172.30.0.11/32" | yq -p json '.results | length')
check "other hosts scanned again ($seen observations)" test "$seen" = 2

lines=$($compose exec -T serve boidscan export ivre 2>/dev/null | wc -l)
check "ivre export has http records ($lines)" test "$lines" -gt 0

echo "e2e passed"
