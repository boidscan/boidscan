#!/bin/sh
# Forms the lab flock, scans the isolated lab network, sweeps it under signed
# flock policies, checks that boids judge a blocked and a forging boid, and
# checks the results through the public API.
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
$compose --progress quiet build boid-a
lab_root
reset_policies
$compose up -d --wait db boid-a boid-b boid-c boid-d boid-e web sshd redis

check "flock formed through the DNS seed" wait_for 60 flock_formed
case $(policy_halt boid-b) in
"no flock policy") echo "ok   without a policy the boids do not sweep" ;;
*) fail "boid-b sweeps without a policy: $(policy_halt boid-b)" ;;
esac
$compose stop boid-c >/dev/null
check "boid-a marks a stopped boid down" wait_for 60 sees boid-a boid-c down
$compose start boid-c >/dev/null
check "a restarted boid rejoins" wait_for 30 flock_formed
scanners=$(curl -fsS "$(boid_url boid-b)/fed/v1/scanners" | tr '\n' ' ')
check "scanner list names every boid ($scanners)" test "$scanners" = "172.30.0.3 172.30.0.5 172.30.0.6 172.30.0.7 172.30.0.8 "

# Three of the five boids hold each block. One home scans, a boid that is not a home answers from the homes.
ip=172.30.0.11
homes=$(homes_of $ip | tr '\n' ' ')
scanner= other= viewer=
for b in $homes; do
	# The target's firewall drops boid-d.
	if [ -z "$scanner" ] && [ "$b" != boid-d ]; then scanner=$b; elif [ -z "$other" ]; then other=$b; fi
done
for b in $boids; do
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
seen11() { curl -fsS "$api/api/v1/search?cidr=172.30.0.11/32" | yq -p json '[.results[].seen_at] | sort | .[-1]'; }
before=$(count11)
before_seen=$(seen11)
$compose run --rm scan
code=$(curl -s -o /dev/null -w '%{http_code}' "$api/api/v1/host/172.30.0.12")
check "excluded host skipped on rescan" test "$code" = 404
after=$(count11)
after_seen=$(seen11)
check "unchanged hosts are seen again without new entries ($before, then $after)" test "$after" = "$before"
check "the rescan moved their last sighting ($before_seen, then $after_seen)" expr "$after_seen" \> "$before_seen"

lines=$($compose exec -T boid-a boidscan export ivre 2>/dev/null | wc -l)
check "ivre export has http records ($lines)" test "$lines" -gt 0

runs() { sweep_runs boid-a boid-b boid-c | wc -l; }
$compose --profile sweep up -d worker-a worker-b worker-c
halted() { $compose logs worker-a | grep -q "sweep halted: $1"; }
check "workers wait for a policy" wait_for 30 halted "no flock policy"
check "no sweep without a policy" test "$(runs)" -eq 0

check "paused policy 1 installed on boid-a" install_policy boid-a "$(sign_policy '.policy.pause = true')"
check "policy 1 reached every boid through gossip" wait_for 30 all_hold 1
check "workers stay idle while the flock is paused" wait_for 30 halted "flock policy 1 pauses the flock"
check "no sweep while paused" test "$(runs)" -eq 0

check "policy 2 lifts the pause" install_policy boid-a "$(sign_policy '.policy.pause = false')"
check "policy 2 reached every boid" wait_for 30 all_hold 2
# 16 blocks of /30, two port groups each.
units=32
swept() { test "$(units_scanned | wc -l)" -eq $units; }
check "the sweep covers all $units units of 172.30.0.0/26" wait_for 240 swept
total=$(sweep_runs boid-a boid-b boid-c | wc -l)
distinct=$(sweep_runs boid-a boid-b boid-c | sort -u | wc -l)
# Homes move while the boids come to trust each other, so a unit may be scanned twice.
check "units are scanned once, apart from a few during trust changes ($total runs, $distinct units)" test "$distinct" -eq "$units" -a "$((total - distinct))" -le 4
for b in boid-a boid-b boid-c; do
	n=$(sweep_runs "$b" | wc -l)
	check "$b's worker took part ($n units)" test "$n" -gt 0
done
sleep 5
check "nothing is scanned again within min-rescan" test "$(sweep_runs boid-a boid-b boid-c | wc -l)" -eq "$total"

if install_policy boid-b policy/1.json >/dev/null 2>&1; then fail "boid-b took policy 1 again"; fi
echo "ok   an older policy is rejected"
tampered=$(sign_policy)
cp "$tampered" policy/tampered.json
rm "$tampered"
yq -i -p json -o json '.policy.max_rate_pps = 9999' policy/tampered.json
out=$(install_policy boid-b policy/tampered.json 2>&1 || true)
rm policy/tampered.json
case $out in
*"signed by 0 maintainers"*) echo "ok   a policy edited after signing is rejected" ;;
*) fail "tampered policy: $out" ;;
esac

trusts() { test "$(judges "$1" "$2")" = "trusted false"; }
honest_trust() {
	for v in boid-a boid-b boid-c; do
		for p in boid-a boid-b boid-c; do
			[ "$v" = "$p" ] || trusts "$v" "$p" || return 1
		done
	done
}
check "boid-a, boid-b and boid-c trust each other after checking samples" wait_for 120 honest_trust

# From here on one worker sweeps at a time, so it covers every unit itself.
$compose stop worker-a worker-b worker-c >/dev/null
check "policy 3 lets each unit be scanned every 10s" install_policy boid-a "$(sign_policy '.policy.min_rescan = "10s"')"
check "policy 3 reached every boid" wait_for 30 all_hold 3

$compose --profile sweep up -d worker-d
low_reach() {
	for v in boid-a boid-b boid-c; do
		case $(judges "$v" boid-d) in *shunned*) return 1 ;; *" true") ;; *) return 1 ;; esac
	done
}
check "the targets' firewalls drop boid-d: it loses reach, not trust" wait_for 240 low_reach
$compose stop worker-d >/dev/null

$compose --profile sweep up -d worker-e
shunned() {
	for v in boid-a boid-b boid-c boid-d; do
		case $(judges "$v" boid-e) in shunned*) ;; *) return 1 ;; esac
	done
}
check "boid-e forges results: every other boid shuns it" wait_for 240 shunned
$compose stop worker-e >/dev/null
e_id=$(curl -fsS "$(boid_url boid-e)/fed/v1/node" | yq -p json '.record.id')
# Results of boid-e that checks confirmed stay; its forged certificates and
# services nobody else found must be gone.
forged_by_e() {
	curl -fsS "$(boid_url "$1")/api/v1/search?cidr=172.30.0.0/24&limit=1000" | yq -p json "
		.results as \$r |
		[\$r[] | select(.node_id == \"$e_id\" and .cert_sha256 != null)] +
		([\$r[] | select(.node_id == \"$e_id\") | .ip + \":\" + (.port | tostring)] -
		 [\$r[] | select(.node_id != \"$e_id\") | .ip + \":\" + (.port | tostring)]) | length"
}
for b in boid-a boid-b boid-c boid-d; do
	check "$b holds no forged result of boid-e" test "$(forged_by_e "$b")" = 0
done
e_home=0
for i in $(seq 1 4 61); do
	homes_of 172.30.0.$i | grep -q boid-e && e_home=$((e_home + 1))
done
check "boid-e holds no block for boid-a" test "$e_home" = 0

check "policy 4 revokes boid-e" install_policy boid-a "$(sign_policy ".policy.revoked_nodes = [{\"id\": \"$e_id\", \"reason\": \"forged results in the e2e test\"}]")"
check "policy 4 reached every boid, boid-e too" wait_for 30 all_hold 4
check "boid-a marks boid-e revoked" wait_for 10 sees boid-a boid-e revoked
revoked=$(curl -fsS "$api/fed/v1/revoked" | tr '\n' ' ')
check "boid-e is on the revoked list ($revoked)" test "$revoked" = "172.30.0.8 "

$compose --profile sweep up -d worker-a
check "policy 5 expires after 20s" install_policy boid-a "$(sign_policy . -for 20s)"
check "policy 5 reached boid-b" wait_for 30 sh -c 'test "$(curl -fsS http://localhost:8081/fed/v1/policy/status | yq -p json .serial)" = 5'
expired() { case $(policy_halt "$1") in *"policy 5 expired"*) ;; *) return 1 ;; esac; }
check "boid-b stops granting leases once policy 5 expires" wait_for 40 expired boid-b
check "boid-a's worker stops" wait_for 30 halted "flock policy 5 expired"

echo "e2e passed"
