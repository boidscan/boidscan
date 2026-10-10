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

# Logs are written by root inside the containers, so they are removed from one.
reset_logs() {
	mkdir -p logs
	docker run --rm -v "$PWD/logs:/logs" alpine:3.22.1 sh -c 'rm -f /logs/*.jsonl'
}
