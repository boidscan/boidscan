# Run a test flock on your own servers

A test flock is a flock of boids on public servers that scans only a list of addresses you give it, usually the servers themselves. It has its own maintainer key, so it never takes the real flock's policy and the real flock never takes its. [demo.md](demo.md) describes the first run.

Only list addresses you are allowed to scan, and check your hosting provider's terms first. Every boid probes every listed address on the ports of the default catalog (Shodan's list, several thousand ports).

## What you need

- Three or more servers with Ubuntu 26.04 and a public IPv4 address, amd64 or arm64. Five work well: every address has three homes, and a check counts only when two boids besides the scanner answer.
- Port 80 open between the servers. It carries the info page and the federation endpoint, and `-endpoint` must be `http://<IPv4>` without a port.
- On your machine: Docker, `ssh` access to the servers as root, `curl` and [yq](https://github.com/mikefarah/yq).

The shell snippets work in bash and zsh. Set the server addresses once:

```sh
IPS=(203.0.113.10 203.0.113.11 203.0.113.12 203.0.113.13 203.0.113.14)
RANGE=203.0.113.10,203.0.113.11,203.0.113.12,203.0.113.13,203.0.113.14
SEED=203.0.113.10
```

`SEED` is any one of the servers; new boids find the others through it.

## 1. Create the servers

Create the servers with [cloud-init.yaml](cloud-init.yaml) as user data. It installs Docker and Compose from the Ubuntu archive and writes `/opt/boidscan/compose.yaml` with `serve` and `worker`, both on the host network. It does not start anything.

Wait until cloud-init has finished on all of them:

```sh
for h in "${IPS[@]}"; do ssh root@$h cloud-init status --wait; done
```

## 2. Create a maintainer key and the first policy

On your machine, in an empty folder:

```sh
mkdir -p testflock
boidscan() { docker run --rm -u "$(id -u)" -v "$PWD/testflock:/policy" ghcr.io/boidscan/boidscan:0.0.3 "$@"; }

ROOT="$(boidscan policy keygen -out /policy/maintainer.key):1"
boidscan policy new -test-range $RANGE -policy-root $ROOT -out /policy/1.json
yq -i -p json -o json ".policy.min_rescan = \"1h\" | .policy.seeds = [\"http://$SEED\"]" testflock/1.json
boidscan policy sign -key /policy/maintainer.key /policy/1.json
boidscan policy verify -policy-root $ROOT /policy/1.json
```

A new policy is valid for 14 days and is not paused. `min_rescan` 1h lets you watch units come due again; the default is 7 days.

Keep `testflock/maintainer.key` private. Whoever holds it controls the test flock.

## 3. Configure the servers

Every boid needs the same range, maintainer key and seed. `NAME` and `ENDPOINT` differ per server and are derived on the server itself:

```sh
cat > testflock/flock.env <<EOF
RANGE=$RANGE
ROOT=$ROOT
SEEDS=http://$SEED
ABUSE_CONTACT=abuse@your.domain
IMAGE=ghcr.io/boidscan/boidscan:0.0.3
EOF

for h in "${IPS[@]}"; do
  scp testflock/flock.env root@$h:/opt/boidscan/flock.env
  ssh root@$h 'cd /opt/boidscan &&
    ip=$(ip -4 route get 1.1.1.1 | sed -n "s/.* src \([0-9.]*\).*/\1/p") &&
    { cat flock.env; echo "NAME=$(hostname -s | cut -c1-32)"; echo "ENDPOINT=http://$ip"; } > .env &&
    grep -E "NAME|ENDPOINT" .env'
done
```

Put your real contact into `ABUSE_CONTACT`. Scanned hosts see it, and boidscan refuses example.org addresses. Each server must print its own public address as `ENDPOINT`.

## 4. Start the boids

```sh
for h in "${IPS[@]}"; do ssh root@$h 'cd /opt/boidscan && docker compose up -d'; done
```

Within a minute every boid should list the others as `alive`:

```sh
for h in "${IPS[@]}"; do curl -s http://$h/fed/v1/peers | yq -p json -o json -I0 '[.peers[] | [.name, .state]]'; done
```

Nothing is scanned yet: `/fed/v1/policy/status` says `no flock policy`.

## 5. Install the policy

Install it on one boid; the others fetch it from there.

```sh
ssh root@$SEED 'cd /opt/boidscan && docker compose exec -T serve boidscan policy install -' < testflock/1.json
for h in "${IPS[@]}"; do curl -s http://$h/fed/v1/policy/status | yq -p json -o json -I0 '[.serial, .halt]'; done
```

Every boid should report `[1, null]`. A worker that looked before the policy arrived waits its idle time (1 minute) before it starts.

## 6. Watch

- `docker compose logs -f serve worker` in `/opt/boidscan` on any server: leases, scans, pushes and checks.
- `/fed/v1/runs`: the units this boid scanned. `/fed/v1/units`: the units it holds as a home.
- `/fed/v1/homes?ip=<address>`: which boids hold an address.
- `/api/v1/host/<address>`: the merged results from the address's homes.
- `/fed/v1/peers`: each boid's own judgement of the others. `trust` goes from `probation` to `trusted` once a boid's results passed two checks; `low_reach` means others found services it missed.

A boid gains trust only after it has scanned something checkable, so a boid that only got port groups without open ports stays on probation longer.

## 7. Add addresses

The range is part of the catalog hash, so the policy and every boid must change together. Install the new policy first: boids still on the old range then stop sweeping until they are switched.

```sh
RANGE=$RANGE,198.51.100.7
boidscan policy new -from /policy/1.json -test-range $RANGE -policy-root $ROOT -out /policy/2.json
boidscan policy sign -key /policy/maintainer.key /policy/2.json
ssh root@$SEED 'cd /opt/boidscan && docker compose exec -T serve boidscan policy install -' < testflock/2.json

for h in "${IPS[@]}"; do
  ssh root@$h "cd /opt/boidscan && sed -i 's/^RANGE=.*/RANGE=$RANGE/' flock.env .env && docker compose up -d"
done
```

The first boids to restart see nobody else on the new range and lease units from themselves, so a few units get scanned twice.

## 8. Pause, stop and tear down

- Pause the flock with the next policy:
  ```sh
  boidscan policy new -from /policy/2.json -test-range $RANGE -policy-root $ROOT -out /policy/3.json
  yq -i -p json -o json '.policy.pause = true' testflock/3.json
  boidscan policy sign -key /policy/maintainer.key /policy/3.json
  ssh root@$SEED 'cd /opt/boidscan && docker compose exec -T serve boidscan policy install -' < testflock/3.json
  ```
- Stop one boid's scanning at once: `docker compose stop worker`.
- When the policy expires, every worker stops on its own.
- Tear down by deleting the servers.

## Troubleshooting

- `-test-range: ParseAddr("IP1")`: the template's placeholders are still in `.env`. Redo step 3.
- `-test-range needs the test flock's maintainer keys in -policy-root`: `ROOT` is empty.
- A boid is missing from the others' peer lists: compare `/fed/v1/node` on each boid. The `catalog` and `root` values must be equal everywhere.
- `halt` says "this boid's catalog ... differs from the policy's": the boid's range does not match the policy's. Check `RANGE` in its `.env`.
