# Shared by flock.sh and e2e.sh. Needs docker, curl and yq.

cd "$(dirname "$0")"
compose="docker compose -f compose.yaml"
api=http://localhost:${LAB_PORT:-8080}

boid_url() {
	case $1 in
	boid-a) echo "$api" ;;
	boid-b) echo http://localhost:8081 ;;
	boid-c) echo http://localhost:8082 ;;
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

flock_formed() {
	for v in boid-a boid-b boid-c; do
		for p in boid-a boid-b boid-c; do
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
