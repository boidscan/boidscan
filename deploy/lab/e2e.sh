#!/bin/sh
# Forms the lab flock, scans the isolated lab network, sweeps it with a worker
# per boid and checks the results through the public API.
set -eu
. "$(dirname "$0")/lib.sh"

cleanup() {
	if [ "${KEEP_LAB:-}" != 1 ]; then
		lab_down >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	$compose logs --tail=50 >&2 || true
	echo "debug logs: $PWD/logs" >&2
	exit 1
}

check() {
	desc=$1
	shift
	if "$@"; then echo "ok   $desc"; else fail "$desc"; fi
}

lab_down >/dev/null 2>&1 || true
reset_logs
$compose up -d --build --wait db boid-a boid-b boid-c web sshd redis

check "flock formed through the DNS seed" wait_for 60 flock_formed
$compose stop boid-c >/dev/null
check "boid-a marks a stopped boid down" wait_for 60 sees boid-a boid-c down
$compose start boid-c >/dev/null
check "a restarted boid rejoins" wait_for 30 flock_formed
scanners=$(curl -fsS "$(boid_url boid-b)/fed/v1/scanners" | tr '\n' ' ')
check "scanner list names every boid ($scanners)" test "$scanners" = "172.30.0.3 172.30.0.5 172.30.0.6 "

# Two of the three boids hold each block. One home scans, the third boid answers from the homes.
ip=172.30.0.11
homes=$(homes_of $ip | tr '\n' ' ')
scanner=${homes%% *}
other=$(echo "$homes" | cut -d' ' -f2)
for b in boid-a boid-b boid-c; do
	case " $homes" in *" $b "*) ;; *) viewer=$b ;; esac
done
echo "     $ip is held by $homes; $scanner scans it, $viewer is not a home"
SCAN_BOID=${scanner#boid-} $compose run --rm scan scan -lab -ip-layer -interface eth0 -rate 200 -ports 22 $ip/32
has_copy() { test "$(services "$1" "$2" local)" -gt 0; }
check "$other got the results from $scanner" wait_for 20 has_copy "$other" $ip
check "$viewer holds no copy" test "$(services "$viewer" $ip local)" = 0
check "$viewer answers from the homes" test "$(services "$viewer" $ip)" -gt 0
$compose stop "$scanner" >/dev/null
check "$viewer still answers with $scanner stopped" test "$(services "$viewer" $ip)" -gt 0
$compose start "$scanner" >/dev/null
check "$scanner rejoins" wait_for 30 flock_formed

$compose run --rm scan

host() { curl -fsS "$api/api/v1/host/$1"; }

ssh_banner() { host 172.30.0.11 | yq -p json '.services[] | select(.name == "ssh22") | .data.result.server_id.software'; }
banner=$(ssh_banner) || fail "ssh host lookup"
check "ssh banner recorded ($banner)" test -n "$banner" -a "$banner" != null

names=$(curl -fsS "$api/api/v1/search?cert=www.lab.test" | yq -p json '.results[0].cert_names | join(",")')
check "tls certificate indexed by SAN ($names)" test "$names" = "web.lab.test,www.lab.test"

generic=$(host 172.30.0.11 | yq -p json '.services[] | select(.port == 2200 and .name == "banner") | .data.result.banner | test("^SSH-2.0-")') || fail "generic banner lookup"
check "unknown port grabbed with banner module" test "$generic" = true

names=$(curl -fsS "$api/api/v1/search?cert=www.lab.test&port=9443" | yq -p json '.results[0].name + " " + (.results[0].cert_names | join(","))')
check "unknown port retried as https ($names)" test "$names" = "http web.lab.test,www.lab.test"

id=$(curl -fsS "$api/fed/v1/node" | yq -p json '.record.id')
signed=$(host 172.30.0.11 | yq -p json "[.services[] | select(.node_id == \"$id\" and .signature != null)] | length")
check "observations signed by boid-a ($signed)" test "$signed" -gt 0

redis=$(host 172.30.0.12 | yq -p json '[.services[].name] | join(",")') || fail "redis host lookup"
check "redis recorded ($redis)" test "$redis" = "redis6379"

ua=$($compose logs web | grep -c 'boidscan/.*abuse: abuse@lab.invalid' || true)
check "targets see the identifying user agent" test "$ua" -gt 0

check "operator excludes a host" $compose exec -T boid-a boidscan exclude -note "e2e" add 172.30.0.12
code=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/host/172.30.0.12")
check "excluded host purged" test "$code" = 404

count11() { curl -fsS "$api/api/v1/search?cidr=172.30.0.11/32" | yq -p json '.results | length'; }
before=$(count11)
$compose run --rm scan
code=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/host/172.30.0.12")
check "excluded host skipped on rescan" test "$code" = 404
after=$(count11)
check "other hosts scanned again ($before, then $after observations)" test "$((after - before))" = 2

lines=$($compose exec -T boid-a boidscan export ivre 2>/dev/null | wc -l)
check "ivre export has http records ($lines)" test "$lines" -gt 0

$compose --profile sweep up -d worker-a worker-b worker-c
# 16 blocks of /30, two port groups each.
units=32
swept() { test "$(units_scanned | wc -l)" -eq $units; }
check "the sweep covers all $units units of 172.30.0.0/26" wait_for 240 swept
total=$(sweep_runs boid-a boid-b boid-c | wc -l)
distinct=$(sweep_runs boid-a boid-b boid-c | sort -u | wc -l)
check "no unit was scanned twice ($total runs, $distinct units)" test "$total" -eq "$distinct" -a "$total" -ge "$units"
for b in boid-a boid-b boid-c; do
	n=$(sweep_runs "$b" | wc -l)
	check "$b's worker took part ($n units)" test "$n" -gt 0
done
sleep 5
check "nothing is scanned again within min-rescan" test "$(sweep_runs boid-a boid-b boid-c | wc -l)" -eq "$total"

echo "e2e passed"
