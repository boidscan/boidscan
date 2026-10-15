# Running a node

## Before you run a node

> [!CAUTION]
> Many hosting providers forbid outbound scanning in their terms of service and act on abuse reports, up to suspending or closing your account. Check yours first, and use a host and IP address you are allowed to scan from. Laws on scanning differ between countries.

Start by scanning only ranges you own. Scan the wider internet only once your info page and abuse contact are reachable.

To scan a single address first, follow [Scan a single address](../README.md#scan-a-single-address).

## Join the flock

A boid in the flock takes part in the sweep of the whole IPv4 internet. It scans whatever share of the address space the flock gives it, on the ports of the default catalog, at up to 10,000 packets per second.

> [!WARNING]
> Your hosting provider will see this traffic and may get abuse reports about it. Read [Before you run a node](#before-you-run-a-node) again.

You need a server with a public IPv4 address and port 80 reachable from the internet. Other boids talk to yours there, and the scanned hosts find your info page there.

### On a new Ubuntu 26.04 server

Use [deploy/node/cloud-init.yaml](../deploy/node/cloud-init.yaml) as user data. Fill in `ABUSE_CONTACT` first. `RATE` sets your own limit in packets per second. The boid starts when cloud-init finishes.

### On a server you already run

Use the compose file from [Scan a single address](../README.md#scan-a-single-address) and add to `.env`:

```sh
BOIDSCAN_ENDPOINT=http://203.0.113.5
BOIDSCAN_PORT=80
BOIDSCAN_NODE_NAME=my-boid
```

`BOIDSCAN_ENDPOINT` is the server's public address, without a port. Then start the boid with its worker:

```sh
docker compose --profile sweep up -d
```

> [!NOTE]
> The compose file passes only some variables from `.env` into the containers. [Configuration](configuration.md#docker-compose) lists which, and how to set the others.

The boid fetches the [flock policy](https://github.com/boidscan/flock-policy) and finds the other boids through the seeds the policy names. Check it:

```sh
docker compose exec serve boidscan policy show
curl http://203.0.113.5/fed/v1/peers
```

`policy show` should end with `this boid may sweep`. A new boid starts on probation: the others check a sample of its results before they trust it with theirs.

To leave the sweep, stop the worker with `docker compose stop worker`. The boid keeps serving its results.

## Troubleshooting

#### `required variable BOIDSCAN_ABUSE_CONTACT is missing a value`

The `.env` file is missing or not in the same folder as `compose.yaml`.

#### The scan finishes with `observations=0`

Either nothing answered on the [ports boidscan checks](../internal/grab/ports.txt), or ZMap sent its packets out of the wrong network interface. The scan container uses the host's network. Pass the interface explicitly, for example `docker compose run --rm scan -interface eth0 203.0.113.5`. On VPNs, add `-ip-layer`.

#### Nothing on http://localhost:8080

Check `docker compose ps` and `docker compose logs serve`. Port 8080 may already be in use. Set `BOIDSCAN_PORT` in `.env` to another port.

#### Scanning other people's networks

Scanned hosts look for the info page on port 80 of the scanning address. Before you scan beyond your own addresses, run `serve` on a public host on port 80.
