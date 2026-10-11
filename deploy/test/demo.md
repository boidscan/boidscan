# Test flock on the internet, 2026-10-11

Five boids on public servers formed a flock, received a signed policy, swept their own addresses and two more servers of the operator, and checked each other's results. Nothing outside these seven addresses was scanned.

## Setup

- Code: v0.0.3 without its last commit, which refuses placeholder abuse contacts and was written after this run. Image `boidscan:test`, built for arm64 with `docker buildx`.
- Five arm64 servers with Ubuntu 26.04, prepared with [cloud-init.yaml](cloud-init.yaml): Docker, Postgres and the boid's `serve` and `worker`, all on the host network.
- Boids: boid-a to boid-e, one per server. boid-a is the seed (`BOIDSCAN_SEEDS`).
- A test maintainer key (threshold 1), passed to every boid as `-policy-root`, so this flock cannot take the real flock's policy and the real flock cannot take this one's.
- `-test-range` listed the five boid addresses. Later two more servers of the operator were added: the host of boidscan.network and a dev server.
- Policy 1: not paused, `min_rescan` 1h, expires 2026-10-25.

## What happened

| Time (UTC) | Event |
|---|---|
| before 15:11 | The flock forms: every boid sees the other four as alive and verified, all on catalog `d9d03382`. No policy, so nobody sweeps. |
| 15:11 | Policy 1 installed on boid-a. Within seconds all five report serial 1 and no halt reason. |
| 15:11:47 | The first workers (boid-d, boid-e) lease units. boid-a, b and c join about a minute later, after their idle wait. |
| 15:15:07 | All 80 units (5 addresses x 16 port groups) scanned. Every address shows `22/ssh` and `80/http`. |
| ~15:20 | boid-a, d and e are trusted by all others. b and c are still on probation. |
| ~15:25 | Policy 2 installed (catalog `2a305ad1`, seven addresses), then every boid restarted with the new range. |
| 15:25:44 | Sweep of the two new addresses starts. |
| 15:27:04 | All 32 new units scanned. |

At 15:31, 117 scans had run: 80 + 32 units, plus 5 double scans (below). No unit was scanned again after its first pass, as `min_rescan` 1h demands. Scans per boid: a 26, b 18, c 15, d 30, e 28.

## Results

Asking boid-a about any address returns the merged view of that address's homes, signed by the scanners:

| Address | Services found |
|---|---|
| five boid servers | 22 ssh, 80 http |
| boidscan.network host | 22, 25, 80, 222, 443, 465, 587, 993, 995, 4190, 10051 |
| dev server | 22, 25, 80, 222, 443, 465, 587, 993, 995, 4190 |

`/api/v1/search?q=cloudron` on boid-a returned 18 results with full raw grabs, about 313 KB; one port 443 result alone is about 43 KB.

## Trust at 15:31

| Peer | Trusted by | On probation at |
|---|---|---|
| boid-a, boid-d, boid-e | all four others | nobody |
| boid-b | a, d, e | c |
| boid-c | a, d, e | b |

Nobody had low reach and nobody was shunned. b and c were slow to gain trust because in the first pass neither of them scanned a port group 0 unit, the only group with open ports on the boid servers. Results that find nothing give a checker nothing to compare.

## Problems found

- **Lone boids lease from themselves after a catalog change.** Boids only see peers with the same catalog. The first boids restarted with the new range saw nobody else, were the only home of every block in their view and granted themselves leases. Three units of the new addresses were scanned twice at the same time (dev server group 0 by a and c, its group 2 by b and c, and the boidscan.network host's group 1 by a and e). Two more double scans happened at the very start, before the flock settled. The design accepts occasional double scans, but a boid that knows of peers on another catalog could wait instead.
- **Placeholders went live.** The first cloud-init template carried example values. A boid started with `RANGE=IP1,...` and refused to run, which is fine, but every boid ran with the abuse contact `you@example.org` until it was corrected. Fixed in v0.0.3: the template leaves the contact empty and compose refuses to start without it, and boidscan now rejects contacts at example.com, example.net and example.org.
- **Workers wait a full idle interval after a policy arrives.** With the default `-idle 1m`, boids that checked just before the policy arrived started a minute late.

## Not covered

- **A worker scanning its own server's port group 0.** No worker got that unit in this run, so it is still open whether zmap reaches its own public address. These units are due again from 16:11 on.
- **Low reach over the internet.** No firewall rule dropped a boid.
- **Forged results, revocation and policy expiry.** Only tested in the lab (`./build.sh e2e`).

## Reproducing

Fill in `flock.env` in [cloud-init.yaml](cloud-init.yaml) and create the servers with it. Load the image on each server (`docker save boidscan:test | ssh root@<ip> docker load`) and run `docker compose up -d` in `/opt/boidscan`. Then sign a policy for the same range with `boidscan policy new -test-range ... -policy-root ...` and `policy sign`, and install it on one boid with `boidscan policy install`.
