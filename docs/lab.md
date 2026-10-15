# The lab

The lab needs a copy of this repository (`git clone https://github.com/boidscan/boidscan`) and Docker. It runs Postgres, five boids and three target containers on a private Docker network.

> [!NOTE]
> Nothing outside the lab network is scanned.

## Try it without scanning anything real

```sh
./deploy/lab/flock.sh up      # start the flock
docker compose -f deploy/lab/compose.yaml run --rm scan
curl localhost:8080/api/v1/host/172.30.0.11
curl 'localhost:8080/api/v1/search?cert=www.lab.test'
```

Open http://localhost:8080 and search for `172.30.0.11` or `nginx`. The scan runs on behalf of boid-a, so its results are on boid-a only. Stop everything with `./deploy/lab/flock.sh down`.

`./deploy/lab/flock.sh help` lists every lab command.

## Watch boids find each other

Boids find each other like this:

1. A new boid knows one or more seeds: boid URLs, or a DNS name whose A records point at boids.
2. It sends its node record (name, address, abuse contact, signed with its own key) to a seed and gets back the boids the seed knows.
3. Before it trusts a record, it asks the boid at that address to sign a random challenge. Only the owner of the key can, so nobody can point a record at someone else's server.
4. Every second (in the lab; 30 seconds by default) each boid swaps what it knows with a few random peers. A boid that has not been heard from for 5 rounds is marked suspect, after 30 rounds down.

The lab runs five boids that only know the DNS seed `seeds.boidscan.lab`:

```sh
./deploy/lab/flock.sh demo
```

The demo starts the flock, stops boid-c, waits until the others mark it down and starts it again. You see each step in the console:

```text
boid-c-1  | 2026-10-15 22:21:32 - boid-c: looking for the flock through seeds: seeds.boidscan.lab -> http://172.30.0.3, http://172.30.0.5, http://172.30.0.6, http://172.30.0.7, http://172.30.0.8
boid-c-1  | 2026-10-15 22:21:32 - boid-c: boid-b (slzd7wwa) introduced itself from http://172.30.0.5
boid-c-1  | 2026-10-15 22:21:32 - boid-c: verified boid-b (slzd7wwa): the boid at http://172.30.0.5 signed a challenge with its key
boid-c-1  | 2026-10-15 22:21:32 - boid-c: my flock: 1 alive (boid-b)
boid-c-1  | 2026-10-15 22:21:33 - boid-c: my flock: 4 alive (boid-a, boid-b, boid-d, boid-e)
boid-a-1  | 2026-10-15 22:21:40 - boid-a: boid-c (t6lltwix) has been quiet for 5s, marking it suspect
boid-a-1  | 2026-10-15 22:22:04 - boid-a: boid-c (t6lltwix) is down: no news for 30s
boid-a-1  | 2026-10-15 22:22:06 - boid-a: boid-c (t6lltwix) is back
```

`./deploy/lab/flock.sh logs` follows a running flock. Each boid's view is on http://localhost:8080 to :8084, and as JSON at [`/fed/v1/peers`](api.md#get-fedv1peers). Everything each boid logs, including every gossip exchange, is in `deploy/lab/logs/<boid>.jsonl`.

## Watch the flock sweep

Each boid can run a worker next to it. Together the workers sweep an address range without anyone in charge:

1. The range is cut into blocks. Every boid ranks the boids for a block the same way, so they agree on which three boids hold it. Those are the block's homes.
2. A unit of work is one block and one group of ports. A worker picks the unit its own blocks have gone without longest. When its own blocks are done, it asks other boids for theirs.
3. Before scanning, the worker asks the unit's homes for a lease. It needs a majority of them, and they refuse a unit that another worker holds or that was scanned recently.
4. After the scan, the boid sends its results and a signed note that the unit was scanned to the homes. Asking any boid about an address returns what the homes hold.

The lab sweeps 172.30.0.0/26 in blocks of four addresses, two port groups each:

```sh
./deploy/lab/flock.sh sweep
```

```text
worker-b-1  | 2026-10-15 22:16:46 - boid-b: claimed 172.30.0.60/30 (core ports) from my own blocks, homes boid-b, boid-d, boid-e
worker-b-1  | 2026-10-15 22:16:46 - boid-b: scanning 172.30.0.60/30 (core ports) on 4 ports at 1000 packets/s
worker-b-1  | 2026-10-15 22:16:47 - boid-b: found 2 open ports in 172.30.0.60/30 (core ports)
worker-b-1  | 2026-10-15 22:16:47 - boid-b: done with run 1: 2 of 2 handshakes answered
worker-b-1  | 2026-10-15 22:16:47 - boid-b: finished 172.30.0.60/30 (core ports) in 1s
worker-b-1  | 2026-10-15 22:17:27 - boid-b: nothing is due for a scan; checking again every 2s
```

Each boid lists the units it holds at [`/fed/v1/units`](api.md#get-fedv1units), its own sweep scans at [`/fed/v1/runs`](api.md#get-fedv1runs), and which boids hold an address at [`/fed/v1/homes?ip=172.30.0.11`](api.md#get-fedv1homes).

The lab flock has its own maintainer key in `deploy/lab/policy/`, created on first start. `flock.sh sweep` signs a first policy and installs it on boid-a; the others fetch it through gossip. To sign and install the next one with a change:

```sh
./deploy/lab/flock.sh policy '.policy.pause = true'
```

[`/fed/v1/policy/status`](api.md#get-fedv1policystatus) shows each boid's policy serial and why it does not sweep, if it does not.

## Watch boids check each other

Anyone can run a boid, so a boid does not take another's results on trust:

1. When a home receives results, it picks some at random and asks the block's other homes, and the boid that reported them, to look again. It only asks about results it holds, so no boid can point another at an arbitrary address.
2. A sample counts only when at least two boids besides the scanner agree. If the scanner now sees what they see, the target changed and nobody is blamed.
3. A boid whose reports others contradict, such as a different certificate or a service nobody else finds, is shunned: its results that no check confirmed are dropped, and it gets no leases.
4. A boid that misses many services others see is probably blocked by many firewalls. It is not called dishonest, but its "nothing here" reports stop counting and it gets no more leases.
5. A boid holds blocks for others only after enough of its results passed. Each boid judges every other boid itself; nobody passes judgements on.

In the lab, the targets' firewalls drop boid-d, and boid-e forges results. After `flock.sh sweep`:

```sh
./deploy/lab/flock.sh misbehave
```

lets each of them sweep alone while the others check their results. Each boid's judgement of the others is in [`/fed/v1/peers`](api.md#get-fedv1peers) (`trust` and `low_reach`).
