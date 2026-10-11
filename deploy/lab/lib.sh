# Shared by flock.sh and e2e.sh. Needs docker, curl and yq.

cd "$(dirname "$0")"
compose="docker compose -f compose.yaml"
api=http://localhost:${LAB_PORT:-8080}

boid_url() {
	case $1 in
	boid-a) echo "$api" ;;
	boid-b) echo http://localhost:8081 ;;
	boid-c) echo http://localhost:8082 ;;
	boid-d) echo http://localhost:8083 ;;
	boid-e) echo http://localhost:8084 ;;
	esac
}

# peer_state VIEWER PEER prints how VIEWER sees PEER: alive, suspect, down, unverified or nothing.
peer_state() {
	curl -fsS "$(boid_url "$1")/fed/v1/peers" 2>/dev/null |
		yq -p json ".peers[] | select(.name == \"$2\") | (select(.verified) | .state) // \"unverified\"" 2>/dev/null
}

# wait_for SECONDS COMMAND... retries COMMAND once a second.
wait_for() {
	limit=$1
	shift
	i=0
	until "$@" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt "$limit" ] || return 1
		sleep 1
	done
}

sees() { test "$(peer_state "$1" "$2")" = "$3"; }

boids="boid-a boid-b boid-c boid-d boid-e"

# judges VIEWER PEER prints VIEWER's trust in PEER and whether it has low
# reach, e.g. "trusted false".
judges() {
	curl -fsS "$(boid_url "$1")/fed/v1/peers" 2>/dev/null |
		yq -p json ".peers[] | select(.name == \"$2\") | .trust + \" \" + (.low_reach | tostring)" 2>/dev/null
}

flock_formed() {
	for v in $boids; do
		for p in $boids; do
			[ "$v" = "$p" ] || sees "$v" "$p" alive || return 1
		done
	done
}

# homes_of IP prints the boids that hold IP's block, as boid-a sees them.
homes_of() { curl -fsS "$api/fed/v1/homes?ip=$1" | yq -p json '.homes[].name'; }

# services BOID IP [local] prints how many services BOID reports for IP; with
# "local" only from its own copy.
services() {
	url="$(boid_url "$1")/api/v1/host/$2"
	[ "${3:-}" = local ] && url="$url?local=1"
	n=$(curl -fsS "$url" 2>/dev/null | yq -p json '.services | length' 2>/dev/null)
	echo "${n:-0}"
}

# units_scanned prints each unit that a home reports as scanned, once.
units_scanned() {
	for b in boid-a boid-b boid-c; do
		curl -fsS "$(boid_url "$b")/fed/v1/units" | yq -p json '.[] | select(.scanned_at) | .block + " " + (.group | tostring)'
	done | sort -u
}

# sweep_runs BOID... prints the finished sweep runs of those boids, one unit per line.
sweep_runs() {
	for b in "$@"; do
		curl -fsS "$(boid_url "$b")/fed/v1/runs" | yq -p json '.[] | select(.finished_at and .error == null) | .block + " " + (.group | tostring)'
	done
}

lab_down() { $compose --profile scan --profile sweep down -v; }

# Logs are written by root inside the containers, so they are removed from one.
reset_logs() {
	mkdir -p logs
	docker run --rm -v "$PWD/logs:/logs" alpine:3.22.1 sh -c 'rm -f /logs/*.jsonl'
}

# A fresh lab starts without policies; the maintainer key stays.
reset_policies() { rm -f policy/[0-9]*.json; }

# The lab flock trusts its own maintainer key, kept in ./policy and created on
# first use. Needs the boidscan:lab image.
policy_tool() {
	docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/policy:/policy" boidscan:lab policy "$@"
}

lab_root() {
	mkdir -p policy
	if [ ! -f policy/root.txt ]; then
		id=$(policy_tool keygen -out /policy/maintainer.key)
		echo "$id:1" >policy/root.txt
	fi
	LAB_POLICY_ROOT=$(cat policy/root.txt)
	export LAB_POLICY_ROOT
}

# latest_policy prints the serial of the newest policy in ./policy, or 0.
latest_policy() {
	ls policy | sed -n 's/^\([0-9]*\)\.json$/\1/p' | sort -n | tail -1 | grep . || echo 0
}

# sign_policy [YQ-EDIT [NEW-FLAGS...]] writes and signs the next policy and prints its file.
sign_policy() {
	edit=${1:-.}
	[ $# -gt 0 ] && shift
	prev=$(latest_policy)
	next=$((prev + 1))
	if [ "$prev" = 0 ]; then
		from="-policy-root $LAB_POLICY_ROOT"
	else
		from="-from /policy/$prev.json"
	fi
	# shellcheck disable=SC2086
	policy_tool new -lab -lab-range 172.30.0.0/26 $from -out "/policy/$next.json" "$@" >/dev/null 2>&1
	yq -i -p json -o json ".policy.min_rescan = \"1h\" | $edit" "policy/$next.json"
	policy_tool sign -key /policy/maintainer.key "/policy/$next.json" >/dev/null 2>&1
	echo "policy/$next.json"
}

# install_policy BOID FILE stores a policy on BOID; gossip takes it to the others.
install_policy() { $compose exec -T "$1" boidscan policy install - <"$2"; }

policy_serial() { curl -fsS "$(boid_url "$1")/fed/v1/policy/status" | yq -p json '.serial'; }
policy_halt() { curl -fsS "$(boid_url "$1")/fed/v1/policy/status" | yq -p json '.halt // ""'; }

# all_hold SERIAL succeeds once every boid holds that policy.
all_hold() {
	for b in $boids; do
		test "$(policy_serial "$b")" = "$1" || return 1
	done
}
