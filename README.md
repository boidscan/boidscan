# Boidscan

A free and open source index of publicly reachable services, in the spirit of Shodan and Censys, run by its community.

The name comes from [Boids](https://en.wikipedia.org/wiki/Boids), Craig Reynolds' 1986 flocking simulation. Many simple agents following a few local rules end up behaving like one flock. Boidscan nodes ("boids") are meant to work the same way. This release is a single node. Federation between nodes is the next milestone.

## What a node does

1. [ZMap](https://github.com/zmap/zmap) finds open TCP ports on the ranges you give it.
2. [ZGrab2](https://github.com/zmap/zgrab2) records what each service announces during a normal handshake: banners, HTTP responses, TLS certificates, and SSH, Postgres, Redis and similar handshakes.
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

## Install

Each release on GitHub has binaries for Linux and macOS and a container image with ZMap and ZGrab2 included:

```sh
docker pull ghcr.io/boidscan/boidscan
```

To build from source you only need Docker:

```sh
./build.sh        # run the tests, then build dist/boidscan
./build.sh image  # build the container image
./build.sh e2e    # scan the isolated lab and check the results
```

## Quick start (isolated lab)

The lab runs Postgres, three target containers and a node on a private Docker network. Nothing outside that network is scanned.

```sh
docker compose -f deploy/lab/compose.yaml up -d --build
docker compose -f deploy/lab/compose.yaml run --rm --build scan
curl localhost:8080/api/v1/host/172.30.0.11
curl 'localhost:8080/api/v1/search?cert=www.lab.test'
```

Open http://localhost:8080 to see the info page and opt-out form.

## Commands

```
boidscan migrate                     create or upgrade the database schema
boidscan scan [flags] CIDR...        discover and grab services, store the results
boidscan serve [flags]               info page, opt-out form and search API
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

[IVRE](https://github.com/ivre/ivre) provides a web UI on top of this data:

```sh
boidscan export ivre > boidscan.json
ivre scan2db -c boidscan -s my-node boidscan.json
ivre db2view nmap
```

IVRE's zgrab2 importer only reads HTTP(S) results. The other protocols are available through the Boidscan API. HTTPS certificates import correctly with IVRE's current master branch. The 0.9.20 release on PyPI fails on them because it uses a pyOpenSSL call that newer pyOpenSSL versions removed.

## License

[AGPL-3.0](LICENSE). If you run a modified Boidscan as a network service, you must offer its source code to the people using it.
