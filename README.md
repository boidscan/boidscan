# Boidscan

A free and open source index of publicly reachable services, in the spirit of Shodan and Censys, run by its community.

The name comes from [Boids](https://en.wikipedia.org/wiki/Boids), Craig Reynolds' 1986 flocking simulation. Many simple agents following a few local rules end up behaving like one flock. Boidscan nodes ("boids") are meant to work the same way: they find each other, share out a sweep of the address space and keep copies of each other's results (see [the lab](docs/lab.md)). The public flock started in October 2026; details are at https://boidscan.network. Its rules are in the signed [flock policy](https://github.com/boidscan/flock-policy).

## What boidscan is, and what it is not

Boidscan is not a public website like Shodan where you can search the whole internet. You run your own node on your own computer or server. The node scans the addresses you give it and stores what it finds. You then search those results in your browser at http://localhost:8080 or through the [JSON API](docs/api.md).

A node on its own only knows about addresses it has scanned itself. A boid in the flock also holds results of other boids, and looking up an address asks the boids that keep that part of the address space. Searching by text or certificate still covers only the boid you ask.

## What a node does

1. [ZMap](https://github.com/zmap/zmap) finds open TCP ports on the ranges you give it. By default it checks the same ports Shodan does, about 3,800 of them ([list](internal/grab/ports.txt)).
2. [ZGrab2](https://github.com/zmap/zgrab2) records what each service announces during a normal handshake. Well-known ports get a protocol-specific module (SSH, SMTP including 465 and 587, IMAP, Postgres, Redis, SMB, MQTT and others). On any other port boidscan reads the banner and tries HTTP, then HTTPS.
3. Results are stored in PostgreSQL and published through a public JSON API.

Boidscan never tries credentials, never exploits vulnerabilities and never hides who is scanning.

## Rules every node enforces

- **Identity.** A node refuses to scan without an abuse contact. The contact and the project URL (default https://boidscan.network) appear in the HTTP User-Agent and on the info page that `boidscan serve` publishes on port 80.
- **Rate ceiling.** 10,000 packets per second at most. You can configure less, never more.
- **Exclusions.** IANA reserved ranges are always excluded. Operators can exclude more ranges on their own node, for example ones their hosting provider forbids them to scan (`boidscan exclude add`). Exclusions are checked before discovery, again before grabbing, and once more when results are stored. They are never shared with other boids.
- **Opt-out from the address itself.** A host stops being scanned by running `curl -X POST http://<any boid>/api/v1/optout`. The opt-out covers exactly the IPv4 address the request comes from, so nobody can opt out an address they do not receive packets on. The boid signs it and every boid in the flock honours it and deletes what it stored for that address. It lasts a year; running the command again renews it, `curl -X DELETE` withdraws it. A boid signs at most 1,000 opt-outs a day. To keep a whole network out, block the scanning addresses in your firewall. Each boid lists them at `/fed/v1/scanners`.

How the flock as a whole is kept accountable is described in [GOVERNANCE.md](GOVERNANCE.md).

## Scan a single address

> [!CAUTION]
> Many hosting providers forbid outbound scanning and act on abuse reports, up to closing your account. Read [Before you run a node](docs/running-a-node.md#before-you-run-a-node) first.

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

   Use your own address: boidscan refuses to start with one at example.org.

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

If the scan finishes with `observations=0` although the address has open ports, see [Troubleshooting](docs/running-a-node.md#troubleshooting).

## Documentation

| Page | Contents |
|---|---|
| [Running a node](docs/running-a-node.md) | Before you run a node, joining the flock, troubleshooting |
| [Configuration](docs/configuration.md) | Every `BOIDSCAN_*` environment variable and flag |
| [API](docs/api.md) | JSON API with `curl` examples and responses, Go client |
| [The lab](docs/lab.md) | A private test flock: watch boids find each other, sweep and check each other |
| [Development](docs/development.md) | Building from source, commands |
| [IVRE](docs/ivre.md) | Viewing results in IVRE |
| [Governance](GOVERNANCE.md) | How the flock is kept accountable |

## License

[AGPL-3.0](LICENSE). If you run a modified Boidscan as a network service, you must offer its source code to the people using it.
