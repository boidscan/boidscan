# Boidscan

A free and open source index of publicly reachable services, in the spirit of Shodan and Censys, run by its community.

The name comes from [Boids](https://en.wikipedia.org/wiki/Boids), Craig Reynolds' 1986 flocking simulation. Many simple agents following a few local rules end up behaving like one flock. Boidscan nodes ("boids") are meant to work the same way. This release is a single node. Federation between nodes is the next milestone.

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
- **Exclusions.** IANA reserved ranges are always excluded. The opt-out list is checked before discovery, again before grabbing, and once more when results are stored.
- **Opt-out.** Anyone can opt out a range of /16 or smaller through the form on the info page. The range is excluded from future scans and its stored results are deleted. Larger ranges go through the operator (`boidscan optout add`).

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

The lab needs a copy of this repository (`git clone https://github.com/boidscan/boidscan`). It runs Postgres, three target containers and a node on a private Docker network. Nothing outside that network is scanned.

```sh
docker compose -f deploy/lab/compose.yaml up -d --build
docker compose -f deploy/lab/compose.yaml run --rm --build scan
curl localhost:8080/api/v1/host/172.30.0.11
curl 'localhost:8080/api/v1/search?cert=www.lab.test'
```

Open http://localhost:8080 and search for `172.30.0.11` or `nginx`.

## Build from source

You only need Docker:

```sh
./build.sh        # run the tests, then build dist/boidscan
./build.sh image  # build the container image
./build.sh e2e    # scan the isolated lab and check the results
```

## Commands

```
boidscan migrate                     create or upgrade the database schema
boidscan scan [flags] CIDR...        discover and grab services, store the results
boidscan serve [flags]               info page with search, opt-out form and JSON API
boidscan export ivre                 HTTP(S) results as zgrab2 JSON for IVRE
boidscan optout add|rm|list [CIDR]   manage opt-outs without the form's size limit
```

Settings come from flags or `BOIDSCAN_*` environment variables: `DB`, `PROJECT_URL`, `ABUSE_CONTACT`, `NODE_ID`, `LISTEN`, `OPTOUT_FILE`, `INTERFACE`, `GATEWAY_MAC`, `IP_LAYER`.

`scan` needs the `NET_RAW` and `NET_ADMIN` capabilities for ZMap.

## API

| Endpoint | Returns |
|---|---|
| `GET /api/v1/host/{ip}` | the latest result per port and module for one address |
| `GET /api/v1/search?cidr=&port=&q=&cert=&limit=&before=` | results, newest first; `q` is a substring match on the raw result, `cert` matches a SHA-256 fingerprint or hostname, `before` is the `next` value from the previous page |
| `GET /api/v1/optouts` | the opt-out list (contacts are not published) |

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
