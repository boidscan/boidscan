# Boidscan

A free and open source index of publicly reachable services, in the spirit of Shodan and Censys, run by its community.

The name comes from [Boids](https://en.wikipedia.org/wiki/Boids), Craig Reynolds' 1986 flocking simulation. Many simple agents following a few local rules end up behaving like one flock. Boidscan nodes ("boids") are meant to work the same way. Federation between nodes is in progress. In the lab, boids already find each other, share out a sweep of an address range and keep copies of each other's results (see [Watch boids find each other](#watch-boids-find-each-other) and [Watch the flock sweep](#watch-the-flock-sweep)). There is no public flock yet.

## What boidscan is, and what it is not

Boidscan is not a public website like Shodan where you can search the whole internet. You run your own node on your own computer or server. The node scans the addresses you give it and stores what it finds. You then search those results in your browser at http://localhost:8080 or through the JSON API.

Your node only knows about addresses it has scanned itself. There is no shared index of the whole internet yet. That comes with federation.

## What a node does

1. [ZMap](https://github.com/zmap/zmap) finds open TCP ports on the ranges you give it. By default it checks the same ports Shodan does, about 3,800 of them ([list](internal/grab/ports.txt)).
2. [ZGrab2](https://github.com/zmap/zgrab2) records what each service announces during a normal handshake. Well-known ports get a protocol-specific module (SSH, SMTP including 465 and 587, IMAP, Postgres, Redis, SMB, MQTT and others). On any other port boidscan reads the banner and tries HTTP, then HTTPS.
3. Results are stored in PostgreSQL and published through a public JSON API.

Boidscan never tries credentials, never exploits vulnerabilities and never hides who is scanning.

## Rules every node enforces

- **Identity.** A node refuses to scan without an abuse contact. The contact and the project URL (default https://boidscan.network) appear in the HTTP User-Agent and on the info page that `boidscan serve` publishes on port 80.
- **Rate ceiling.** 10,000 packets per second at most. You can configure less, never more.
- **Exclusions.** IANA reserved ranges are always excluded. Operators can exclude more ranges on their own node, for example ones their hosting provider forbids them to scan (`boidscan exclude add`). Exclusions are checked before discovery, again before grabbing, and once more when results are stored. They are never shared with other boids.
- **No opt-out form.** Nobody can check who submits one, so it would let anyone hide any network. Anyone who does not want to be scanned blocks the scanning addresses in their firewall. Each boid lists them at `/fed/v1/scanners`.

How the flock as a whole is kept accountable is described in [GOVERNANCE.md](GOVERNANCE.md).

## Before you run a node

Many hosting providers forbid outbound scanning in their terms of service and act on abuse reports. Check yours first, and use a host and IP address you are allowed to scan from. Laws on scanning differ between countries.

Start by scanning only ranges you own. Scan the wider internet only once your info page and abuse contact are reachable.

## Scan a single address

You need [Docker](https://docs.docker.com/get-started/get-docker/) and an address you are allowed to scan, such as a server you rent. Scan it from a different machine, for example your laptop.

1. Create an empty folder and download the compose file into it:

   ```sh
   mkdir boidscan && cd boidscan
   curl -O https://raw.githubusercontent.com/boidscan/boidscan/main/deploy/node/compose.yaml
   ```

2. Create a file called `.env` in the same folder with an email address where people can reach you. Every node has to name a contact, because the services you scan see it and may want to ask what is going on:

   ```sh
   echo "BOIDSCAN_ABUSE_CONTACT=you@example.org" > .env
   ```

3. Start the database and the web page:

   ```sh
   docker compose up -d
   ```

4. Scan the address. Replace `203.0.113.5` with yours. It takes a few seconds:

   ```sh
   docker compose run --rm scan 203.0.113.5
   ```

   The last line reports how many services answered, for example `scan finished run=1 observations=3 successful=3`.

5. Open http://localhost:8080, type the address into the search box and press Search. Each open port is listed, and "Raw result" shows everything the service announced.

To check other ports, pass `-ports` before the address, for example `-ports 587`, `-ports 22,80,8000-8100` or `-ports 1-65535` for all of them.

To scan a range instead of one address, use CIDR notation: `203.0.113.0/24` covers the 256 addresses from `203.0.113.0` to `203.0.113.255`. Stop everything with `docker compose down`. The results are kept until you run `docker compose down -v`.

The search box takes an IP address, a CIDR range or any text, such as `nginx` or a hostname from a certificate. An optional port narrows the results.

If the scan finishes with `observations=0` although the address has open ports, see [Troubleshooting](#troubleshooting).

## What a result looks like

The same data is available as JSON from `GET /api/v1/host/{ip}`. This is an HTTP server on port 80, trimmed:

```json
{
  "ip": "203.0.113.5",
  "services": [
    {
      "port": 80,
      "name": "http80",
      "protocol": "http",
      "status": "success",
      "seen_at": "2026-10-10T18:42:41Z",
      "data": {
        "result": {
          "response": {
            "status_line": "200 OK",
            "headers": { "server": ["nginx/1.29.1"] }
          }
        }
      }
    }
  ]
}
```

## Try it without scanning anything real

The lab needs a copy of this repository (`git clone https://github.com/boidscan/boidscan`). It runs Postgres, three boids and three target containers on a private Docker network. Nothing outside that network is scanned.

```sh
./deploy/lab/flock.sh up      # start the flock
docker compose -f deploy/lab/compose.yaml run --rm scan
curl localhost:8080/api/v1/host/172.30.0.11
curl 'localhost:8080/api/v1/search?cert=www.lab.test'
```

Open http://localhost:8080 and search for `172.30.0.11` or `nginx`. The scan runs on behalf of boid-a, so its results are on boid-a only. Stop everything with `./deploy/lab/flock.sh down`.

## Watch boids find each other

Boids find each other like this:

1. A new boid knows one or more seeds: boid URLs, or a DNS name whose A records point at boids.
2. It sends its node record (name, address, abuse contact, signed with its own key) to a seed and gets back the boids the seed knows.
3. Before it trusts a record, it asks the boid at that address to sign a random challenge. Only the owner of the key can, so nobody can point a record at someone else's server.
4. Every second (in the lab; 30 seconds by default) each boid swaps what it knows with a few random peers. A boid that has not been heard from for 5 rounds is marked suspect, after 30 rounds down.

The lab runs three boids that only know the DNS seed `seeds.boidscan.lab`:

```sh
./deploy/lab/flock.sh demo
```

The demo starts the flock, stops boid-c, waits until the others mark it down and starts it again. You see each step in the console:

```
boid-c-1  | 21:14:16 INFO  looking for the flock through seeds: seeds.boidscan.lab -> http://172.30.0.3, http://172.30.0.5, http://172.30.0.6
boid-c-1  | 21:14:16 INFO  boid-b (thirhade) introduced itself endpoint=http://172.30.0.5
boid-c-1  | 21:14:17 INFO  verified boid-b (thirhade): the boid at http://172.30.0.5 signed a challenge with its key
boid-c-1  | 21:14:17 INFO  flock: 2 alive (boid-a, boid-b)
boid-a-1  | 21:13:18 INFO  boid-c (ajqxcywu) has been quiet for 5s, marking it suspect
boid-a-1  | 21:13:43 INFO  boid-c (ajqxcywu) is down: no news for 30s
boid-a-1  | 21:13:45 INFO  boid-c (ajqxcywu) is back
```

`./deploy/lab/flock.sh logs` follows a running flock. Each boid's view is on http://localhost:8080, :8081 and :8082, and as JSON at `/fed/v1/peers`. Everything each boid logs, including every gossip exchange, is in `deploy/lab/logs/<boid>.jsonl`.

## Watch the flock sweep

Each boid can run a worker next to it. Together the workers sweep an address range without anyone in charge:

1. The range is cut into blocks. Every boid ranks the boids for a block the same way, so they agree on which two boids (three outside the lab) hold it. Those are the block's homes.
2. A unit of work is one block and one group of ports. A worker picks the unit its own blocks have gone without longest. When its own blocks are done, it asks other boids for theirs.
3. Before scanning, the worker asks the unit's homes for a lease. It needs a majority of them, and they refuse a unit that another worker holds or that was scanned recently.
4. After the scan, the boid sends its results and a signed note that the unit was scanned to the homes. Asking any boid about an address returns what the homes hold.

The lab sweeps 172.30.0.0/26 in blocks of four addresses, two port groups each:

```sh
./deploy/lab/flock.sh sweep
```

```
worker-b-1  | 23:24:11 INFO  leased 172.30.0.40/30 group 1 from its own blocks homes="[boid-b (daeg5oun) boid-a (eiefkz4d)]"
worker-b-1  | 23:24:12 INFO  scanned 172.30.0.40/30 group 1 took=1.078s
worker-b-1  | 23:24:13 INFO  nothing is due for a scan; checking again every 2s
```

Each boid lists the units it holds at `/fed/v1/units`, its own sweep scans at `/fed/v1/runs`, and which boids hold an address at `/fed/v1/homes?ip=172.30.0.11`.

The lab flock has its own maintainer key in `deploy/lab/policy/`, created on first start. `flock.sh sweep` signs a first policy and installs it on boid-a; the others fetch it through gossip. To sign and install the next one with a change:

```sh
./deploy/lab/flock.sh policy '.policy.pause = true'
```

`/fed/v1/policy/status` shows each boid's policy serial and why it does not sweep, if it does not.

## Build from source

You only need Docker:

```sh
./build.sh        # run the tests, then build dist/boidscan
./build.sh image  # build the container image
./build.sh e2e    # form the lab flock, scan the lab and check the results
```

## Commands

```
boidscan migrate                     create or upgrade the database schema
boidscan scan [flags] CIDR...        discover and grab services, store the results
boidscan serve [flags]               info page with search and JSON API
boidscan worker [flags]              take part in the flock's sweep
boidscan export ivre                 HTTP(S) results as zgrab2 JSON for IVRE
boidscan exclude add|rm|list [CIDR]  manage ranges this node never scans
boidscan policy <command>            create, sign, check and install flock policies
```

The worker only sweeps while a valid flock policy is in force; see [GOVERNANCE.md](GOVERNANCE.md).

Settings come from flags or `BOIDSCAN_*` environment variables: `DB`, `PROJECT_URL`, `ABUSE_CONTACT`, `KEY_FILE`, `NODE_NAME`, `LISTEN`, `EXCLUDE_FILE`, `INTERFACE`, `GATEWAY_MAC`, `IP_LAYER`.

Each node signs its results with an Ed25519 key in `KEY_FILE`, created on first start. Its public half is the node ID. `serve` and `scan` must use the same key file.

Federation: `ENDPOINT` (the node's `http://<IPv4>` address, empty disables federation), `SEEDS`, `GOSSIP_INTERVAL`, `LEASE_TTL`, `POLICY_URL` (checked hourly for a newer flock policy), `POLICY_ROOT` (maintainer keys of a separate test flock, `key,key:threshold`), `IDLE` (the worker's wait when nothing is due). `serve` and `worker` must use the same key file and endpoint. Logging: `LOG_LEVEL` (debug, info, warn, error) for the console, and `DEBUG_LOG`, a file that gets every message at debug level as JSON lines.

`scan` and `worker` need the `NET_RAW` and `NET_ADMIN` capabilities for ZMap.

## API

| Endpoint | Returns |
|---|---|
| `GET /api/v1/host/{ip}` | the latest result per port and module for one address |
| `GET /api/v1/search?cidr=&port=&q=&cert=&limit=&before=` | results, newest first; `q` is a substring match on the raw result, `cert` matches a SHA-256 fingerprint or hostname, `before` is the `next` value from the previous page |
| `GET /fed/v1/peers` | this node's record and the boids it knows, with their state |
| `GET /fed/v1/scanners` | the scanning addresses of this boid and every boid it has verified, one per line, for firewall block lists |
| `GET /fed/v1/revoked` | the last known addresses of boids the flock policy has removed, one per line |
| `GET /fed/v1/policy` | the flock policy this boid holds, as a bundle `boidscan policy install` accepts |

Go client: `github.com/boidscan/boidscan/pkg/client`.

```go
c := client.New("https://node.example")
host, err := c.Host(ctx, "192.0.2.10")
err = c.SearchAll(ctx, client.Query{Port: 443, Cert: "example.org"}, func(o client.Observation) bool {
	fmt.Println(o.IP, o.Port, o.Name)
	return true
})
```

## Viewing results in IVRE

[IVRE](https://github.com/ivre/ivre) provides a richer web UI on top of this data:

```sh
boidscan export ivre > boidscan.json
ivre scan2db -c boidscan -s my-node boidscan.json
ivre db2view nmap
```

IVRE's zgrab2 importer only reads HTTP(S) results. The other protocols are available through the Boidscan API. HTTPS certificates import correctly with IVRE's current master branch. The 0.9.20 release on PyPI fails on them because it uses a pyOpenSSL call that newer pyOpenSSL versions removed.

## Troubleshooting

**`required variable BOIDSCAN_ABUSE_CONTACT is missing a value`.** The `.env` file is missing or not in the same folder as `compose.yaml`.

**The scan finishes with `observations=0`.** Either nothing answered on the [ports boidscan checks](internal/grab/ports.txt), or ZMap sent its packets out of the wrong network interface. The scan container uses the host's network. Pass the interface explicitly, for example `docker compose run --rm scan -interface eth0 203.0.113.5`. On VPNs, add `-ip-layer`.

**Nothing on http://localhost:8080.** Check `docker compose ps` and `docker compose logs serve`. Port 8080 may already be in use. Change the left side of `8080:80` in `compose.yaml`.

**Scanning other people's networks.** Scanned hosts look for the info page on port 80 of the scanning address. Before you scan beyond your own addresses, run `serve` on a public host on port 80.

## License

[AGPL-3.0](LICENSE). If you run a modified Boidscan as a network service, you must offer its source code to the people using it.
