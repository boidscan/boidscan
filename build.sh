#!/bin/sh
# Builds and tests boidscan with Docker only; no local Go toolchain needed.
set -eu

cd "$(dirname "$0")"

GO_IMAGE=golang:1.27.1-bookworm
PG_IMAGE=postgres:17.6-bookworm
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}

usage() {
	cat <<EOF
usage: ./build.sh [command]

  test    gofmt check, go vet and all tests, including store tests against Postgres
  bin     build ./dist/boidscan for this machine
  image   build the boidscan:$VERSION container image
  e2e     scan the isolated Docker lab and check the results
  all     test, then bin (default)
EOF
}

gorun() {
	docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
		-v boidscan-gocache:/cache -v "$PWD":/src -w /src "$@"
}

cmd_test() {
	docker volume create boidscan-gocache >/dev/null
	docker run --rm -v boidscan-gocache:/cache "$GO_IMAGE" chown "$(id -u):$(id -g)" /cache

	unformatted=$(gorun "$GO_IMAGE" gofmt -l .)
	if [ -n "$unformatted" ]; then
		echo "gofmt needed:" >&2
		echo "$unformatted" >&2
		exit 1
	fi
	gorun "$GO_IMAGE" go vet ./...

	net=boidscan-test-$$
	db=boidscan-test-db-$$
	docker network create "$net" >/dev/null
	trap 'docker rm -f "$db" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1' EXIT
	docker run -d --name "$db" --network "$net" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=boidscan_test "$PG_IMAGE" >/dev/null
	until docker exec "$db" pg_isready -U postgres -d boidscan_test >/dev/null 2>&1; do sleep 1; done

	gorun --network "$net" -e BOIDSCAN_TEST_DB="postgres://postgres:test@$db/boidscan_test?sslmode=disable" \
		"$GO_IMAGE" go test -count=1 -race ./...
}

cmd_bin() {
	docker build --target bin --build-arg VERSION="$VERSION" --output type=local,dest=dist .
	echo "built dist/boidscan ($VERSION)"
}

cmd_image() {
	docker build --build-arg VERSION="$VERSION" -t "boidscan:$VERSION" .
}

case "${1:-all}" in
test) cmd_test ;;
bin) cmd_bin ;;
image) cmd_image ;;
e2e) ./deploy/lab/e2e.sh ;;
all) cmd_test && cmd_bin ;;
-h | --help | help) usage ;;
*) usage >&2; exit 2 ;;
esac
