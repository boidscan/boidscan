# Configuration

Every setting is a command line flag. Most flags take their default from a `BOIDSCAN_*` environment variable, and a flag given on the command line wins over the variable. `boidscan <command> -h` lists the flags of a command.

Durations use Go's format, such as `90s`, `10m` or `1h30m`. A duration that does not parse falls back to the default without an error. Switches are on only when the variable is exactly `true`.

## Database

| Variable | Flag | Default | Used by |
|---|---|---|---|
| `BOIDSCAN_DB` | `-db` | `postgres:///boidscan` | every command |

A PostgreSQL connection string, for example `postgres://boidscan:boidscan@db/boidscan?sslmode=disable`. Run `boidscan migrate` once before the other commands, and again after an upgrade.

## Identity

Used by `scan`, `serve`, `worker`, and `KEY_FILE` also by `policy`.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_ABUSE_CONTACT` | `-abuse-contact` | none, required | Where people reach you. Shown in the User-Agent and on the info page. Addresses at `example.com`, `example.net` and `example.org` are refused. |
| `BOIDSCAN_PROJECT_URL` | `-project-url` | `https://boidscan.network` | URL explaining the project, shown to scanned hosts |
| `BOIDSCAN_KEY_FILE` | `-key-file` | `boidscan.key` | The node's Ed25519 key, created on first start |

The public half of the key is the node ID. Each node signs its results with it. `scan`, `serve` and `worker` on one node must use the same key file.

## Scanning

Used by `scan` and `worker`.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_EXCLUDE_FILE` | `-exclude-file` | none | Extra ranges never to scan, one CIDR per line. Adds to `boidscan exclude add`. |
| `BOIDSCAN_INTERFACE` | `-interface` | ZMap's choice | Network interface ZMap sends on |
| `BOIDSCAN_GATEWAY_MAC` | `-gateway-mac` | ZMap's choice | Gateway MAC address for ZMap |
| `BOIDSCAN_IP_LAYER` | `-ip-layer` | off | Send IP packets without Ethernet framing (`zmap --iplayer`), for VPNs and container bridges |
| `BOIDSCAN_ZMAP` | `-zmap` | `zmap` | ZMap binary |
| `BOIDSCAN_ZGRAB2` | `-zgrab2` | `zgrab2` | ZGrab2 binary. `serve` uses it too, to check other boids' results. |
| none | `-rate` | `10000` | Packets per second. Values above 10,000 are refused. A worker lowers it to the flock policy's `max_rate_pps`. |
| none | `-cooldown` | ZMap's 8 | Seconds ZMap waits for late replies |

`scan` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `-ports` | the [default list](../internal/grab/ports.txt) | Ports or ranges, such as `22,80,8000-8100` |
| `-lab` | off | Allow RFC 1918 targets, and only those, for testing on your own network |

> [!IMPORTANT]
> `scan` and `worker` need the `NET_RAW` and `NET_ADMIN` capabilities for ZMap. The compose files already add them.

## Flock

Used by `serve` and `worker`. Both processes of one boid must use the same key file and endpoint.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_ENDPOINT` | `-endpoint` | none | `http://<public IPv4>` where other boids reach this node. Empty means `serve` works alone and `worker` refuses to start. |
| `BOIDSCAN_NODE_NAME` | `-name` | the hostname | Name shown to other boids and in the logs, up to 32 characters |
| `BOIDSCAN_POLICY_ROOT` | `-policy-root` | the keys built into boidscan | Maintainer keys of a separate test flock, as `key,key:threshold`. Also used by `policy`. |

`serve` only:

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_LISTEN` | `-listen` | `:80` | Listen address. Scanned hosts expect the info page on port 80. |
| `BOIDSCAN_SEEDS` | `-seeds` | none | Comma-separated boid URLs, or DNS names whose A records are boids. Used together with the seeds the flock policy names. |
| `BOIDSCAN_GOSSIP_INTERVAL` | `-gossip-interval` | `30s` | Time between gossip rounds |
| `BOIDSCAN_LEASE_TTL` | `-lease-ttl` | `10m` | How long a lease this node grants lasts without renewal |
| `BOIDSCAN_POLICY_URL` | `-policy-url` | `https://boidscan.network/policy.json` | Checked hourly for a newer flock policy. Empty disables it. |

`worker` only:

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_IDLE` | `-idle` | `1m` | Wait between rounds that found nothing to scan |

### Test and lab flocks

These are for running a flock of your own, not for the public flock. See [the lab](lab.md).

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `BOIDSCAN_LAB` | `-lab` | off | RFC 1918 endpoints and targets, and the lab catalog |
| `BOIDSCAN_LAB_RANGE` | `-lab-range` | none | The range a lab flock sweeps, such as `172.30.0.0/26`. Required with `LAB`. |
| `BOIDSCAN_TEST_RANGE` | `-test-range` | none | Sweep only these public IPv4 addresses, comma-separated. Needs `POLICY_ROOT`, excludes `LAB`. |
| `BOIDSCAN_FORGE` | `-forge` | off | Lab only: report false results and defend them, to test how other boids catch it |

## Logging

Used by every command.

| Variable | Default | Meaning |
|---|---|---|
| `BOIDSCAN_LOG_LEVEL` | `INFO` | Console level: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. `DEBUG` also shows the details of each line. |
| `BOIDSCAN_DEBUG_LOG` | none | A file that gets every message at debug level as JSON lines |

## Docker Compose

[deploy/node/compose.yaml](../deploy/node/compose.yaml) reads these from `.env` and passes them on:

| `.env` | Default | Meaning |
|---|---|---|
| `BOIDSCAN_ABUSE_CONTACT` | none, required | as above |
| `BOIDSCAN_NODE_NAME` | `my-node` | as above |
| `BOIDSCAN_ENDPOINT` | none | as above |
| `BOIDSCAN_SEEDS` | none | as above |
| `BOIDSCAN_LOG_LEVEL` | `INFO` | as above |
| `BOIDSCAN_PORT` | `8080` | Host port for the web page and API. Set it to `80` to join the flock. |

It sets `BOIDSCAN_DB` and `BOIDSCAN_KEY_FILE` itself. Any other variable in `.env` does not reach the containers. Add it under `environment` of the `x-boidscan` block in `compose.yaml`, or pass a flag:

```sh
docker compose run --rm scan -rate 1000 -interface eth0 203.0.113.5
```

[deploy/node/cloud-init.yaml](../deploy/node/cloud-init.yaml) reads `/opt/boidscan/boid.env` instead:

| `boid.env` | Default | Meaning |
|---|---|---|
| `ABUSE_CONTACT` | none, required | `BOIDSCAN_ABUSE_CONTACT` |
| `RATE` | `10000` | the worker's `-rate` |
| `SEEDS` | none | `BOIDSCAN_SEEDS` |
| `IMAGE` | the release the file was written for | container image |

Cloud-init sets the node name from the hostname and the endpoint from the server's public address.
