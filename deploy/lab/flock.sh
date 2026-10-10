#!/bin/sh
# Starts three boids that find each other through the lab DNS seed and shows what they say.
set -eu
. "$(dirname "$0")/lib.sh"

usage() {
	cat <<USAGE
usage: ./flock.sh [command]

  watch   start the flock and follow its console output; Ctrl-C stops following,
          the boids keep running (default)
  up      start the flock in the background
  demo    start the flock, then stop and restart boid-c so you can watch the
          others notice it leave and return
  logs    follow the console output of a running flock
  down    stop the lab and delete its data

Debug logs for later analysis: deploy/lab/logs/<boid>.jsonl
Each boid's view: http://localhost:8080, :8081, :8082 and /fed/v1/peers
USAGE
}

say() { printf '\n\033[1m=== %s\033[0m\n\n' "$*"; }

start() {
	$compose down -v >/dev/null 2>&1 || true
	reset_logs
	echo "Building the image and starting the database..."
	$compose --progress quiet build boid-a
	$compose --progress quiet up -d --wait db
	say "Starting boid-a, boid-b and boid-c. Each knows only the DNS seed seeds.boidscan.lab."
	$compose --progress quiet up -d boid-a boid-b boid-c
}

follow() { $compose logs -f --no-color boid-a boid-b boid-c; }

demo() {
	start
	follow &
	logs=$!
	trap 'kill $logs 2>/dev/null' EXIT

	wait_for 60 flock_formed || { say "The flock did not form within 60s."; exit 1; }
	say "Every boid has verified the other two. Stopping boid-c: the others mark it suspect after 5s and down after 30s."
	$compose stop boid-c >/dev/null
	wait_for 60 sees boid-a boid-c down
	wait_for 10 sees boid-b boid-c down
	say "boid-c is down for both. Starting it again: it gossips with the peers it remembers."
	$compose start boid-c >/dev/null
	wait_for 30 flock_formed
	sleep 2
	say "boid-c is back. Done. The flock keeps running: ./flock.sh logs to watch, ./flock.sh down to stop."
}

case "${1:-watch}" in
watch) start && follow ;;
up) start ;;
demo) demo ;;
logs) follow ;;
down) $compose --profile scan down -v ;;
-h | --help | help) usage ;;
*) usage >&2; exit 2 ;;
esac
