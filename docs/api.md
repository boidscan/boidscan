# API

Every boid serves a JSON API next to its info page, on the address and port of `boidscan serve`. There is no authentication and no API key.

The examples below ran against boid-a of the [lab flock](lab.md) (`./deploy/lab/flock.sh sweep`), which listens on `localhost:8080`. To try them yourself, start the lab the same way. Long responses are trimmed where marked.

- [Search API](#search-api): `/api/v1/host`, `/api/v1/search`, `/api/v1/progress`
- [Opt-out](#opt-out): `/api/v1/optout`
- [Flock API](#flock-api): `/fed/v1/...`
- [Errors](#errors)
- [Go client](#go-client)

## Search API

`/api/v1` responses carry `Access-Control-Allow-Origin: *`, so a web page on another origin can call them.

### Observations

Both search endpoints return observations. An observation is what one service on one port announced:

| Field | Meaning |
|---|---|
| `id` | Row ID on the boid that answered. Used for paging. |
| `node_id` | The boid that scanned it and signed it |
| `ip`, `port` | Where the service answered |
| `name` | The scan module, such as `http80`, `ssh22` or `banner` |
| `protocol` | `http`, `ssh`, `banner` and so on |
| `status` | `success`, or ZGrab2's reason it failed |
| `first_seen_at` | The first scan that saw the service looking like this |
| `seen_at` | The latest scan that saw it looking like this |
| `cert_sha256`, `cert_names` | TLS certificate fingerprint and names, when there is one |
| `data` | The full ZGrab2 result |
| `signature` | Ed25519 signature by `node_id` |

An observation stays one entry while the service looks the same. A new certificate or host key, status line, page title, server header or banner starts a new entry, and search keeps the older ones as history.

### `GET /api/v1/host/{ip}`

The latest result per port and module for one address. In a flock the boid also asks the boids that hold the address's block and merges their answers. Add `?local=1` to get only what this boid stores.

```sh
curl http://localhost:8080/api/v1/host/172.30.0.26
```

<details>
<summary>Response (trimmed: only port 80, without the raw headers and request)</summary>

```json
{
  "ip": "172.30.0.26",
  "services": [
    {
      "id": 11,
      "run_id": 0,
      "node_id": "slzd7wwazexgrdtnswfbpouaxkpseh2rkvh4xwajxr64bzciatgq",
      "ip": "172.30.0.26",
      "port": 80,
      "name": "http80",
      "protocol": "http",
      "status": "success",
      "first_seen_at": "2026-10-15T22:16:48.91232Z",
      "seen_at": "2026-10-15T22:16:48.91232Z",
      "data": {
        "status": "success",
        "protocol": "http",
        "port": 80,
        "result": {
          "response": {
            "status_line": "200 OK",
            "status_code": 200,
            "protocol": "HTTP/1.1",
            "headers": {
              "content_type": ["application/octet-stream"],
              "date": ["Thu, 15 Oct 2026 22:16:48 GMT"],
              "server": ["nginx/1.29.1"]
            },
            "body_sha256": "c2dd1cd0c4deaaa4b282e37d58b25e6404338e8f15437acb6a8414752436e73c",
            "content_length": 20
          }
        },
        "timestamp": "2026-10-15T22:16:48Z"
      },
      "signature": "tM0+e8vWnGGFnAytFY4orsvx+y97xYsneU8VSenqXNFWohDyLbkimLA7BQeJNOQR5RDEx/3deaUIsSJ5NUX8BA=="
    }
  ]
}
```

</details>

An address nobody has results for returns `404`:

```sh
curl http://localhost:8080/api/v1/host/192.0.2.1
```

```json
{"error":"no data for this host"}
```

### `GET /api/v1/search`

Observations from this boid only, newest first. All parameters are optional and combine with AND.

| Parameter | Meaning |
|---|---|
| `cidr` | An address or range, such as `172.30.0.0/26` |
| `port` | One port, 1 to 65535 |
| `q` | Case-insensitive substring of the raw result |
| `cert` | A certificate's SHA-256 fingerprint or one of its names |
| `limit` | Results per page, 100 by default, 1000 at most |
| `before` | The `next` value of the previous page |

```sh
curl 'http://localhost:8080/api/v1/search?cert=www.lab.test&limit=2'
```

<details>
<summary>Response (trimmed: <code>data</code> and <code>signature</code> left out)</summary>

```json
{
  "results": [
    {
      "id": 50,
      "run_id": 0,
      "node_id": "slzd7wwazexgrdtnswfbpouaxkpseh2rkvh4xwajxr64bzciatgq",
      "ip": "172.30.0.26",
      "port": 9443,
      "name": "http",
      "protocol": "http",
      "status": "success",
      "first_seen_at": "2026-10-15T22:17:22.50639Z",
      "seen_at": "2026-10-15T22:17:22.50639Z",
      "cert_sha256": "5e73f96bfd23969d87ca3e5898c5b4778b2bf897665b70cf42f0465caced674f",
      "cert_names": ["web.lab.test", "www.lab.test"]
    },
    {
      "id": 49,
      "run_id": 0,
      "node_id": "t6lltwixwgvatjo45vmlta3x2prsurz7fz2fbgxc5tfoveknonjq",
      "ip": "172.30.0.30",
      "port": 9443,
      "name": "http",
      "protocol": "http",
      "status": "success",
      "first_seen_at": "2026-10-15T22:17:19.01113Z",
      "seen_at": "2026-10-15T22:17:19.01113Z",
      "cert_sha256": "5e73f96bfd23969d87ca3e5898c5b4778b2bf897665b70cf42f0465caced674f",
      "cert_names": ["web.lab.test", "www.lab.test"]
    }
  ],
  "next": 49
}
```

</details>

`next` is `0` on the last page. Otherwise pass it as `before` to get the next one:

```sh
curl 'http://localhost:8080/api/v1/search?cert=www.lab.test&limit=2&before=49'
```

More examples:

```sh
curl 'http://localhost:8080/api/v1/search?q=nginx'
curl 'http://localhost:8080/api/v1/search?cidr=172.30.0.0/26&port=22'
```

> [!TIP]
> A search that runs longer than 5 seconds is stopped and returns `503`. Narrow it with `port` or `cidr`.

### `GET /api/v1/progress`

How much of its catalog the flock has scanned, summed from the signed counts each boid reports. Recomputed at most once a minute. A node without a flock returns `404`.

```sh
curl http://localhost:8080/api/v1/progress
```

<details>
<summary>Response</summary>

```json
{
  "catalog": "lab",
  "as_of": "2026-10-15T22:20:22Z",
  "estimate": true,
  "fresh_within": "1h0m0s",
  "percent_ever": 100,
  "percent_fresh": 100,
  "units": { "total": 32, "scanned_ever": 32, "fresh": 32 },
  "addresses": { "total": 64, "scanned_ever": 64 },
  "hosts": 0,
  "open_ports": 0,
  "groups": [
    { "group": 0, "name": "core ports", "ports": 4, "percent_ever": 100, "percent_fresh": 100 },
    { "group": 1, "name": "extra ports 1", "ports": 2, "percent_ever": 100, "percent_fresh": 100 }
  ],
  "rate": { "units_last_24h": 32, "eta_full_sweep": "0h" },
  "boids": { "reporting": 3, "known": 3 },
  "scanning_now": []
}
```

</details>

## Opt-out

`/api/v1/optout` acts on the IPv4 address the request comes from, so it has no parameters. Run it on the host that wants to opt out, against any boid.

> [!WARNING]
> `POST` and `DELETE` from a web page are refused with `403`: a browser sends an `Origin` header, and without this check any site could opt out its visitors. Use `curl` on the host itself.

| Method | Effect |
|---|---|
| `GET` | Show whether the address is opted out |
| `POST` | Opt out for a year, or renew |
| `DELETE` | Withdraw the opt-out. `404` if there is none. |

```sh
curl -X POST http://localhost:8080/api/v1/optout
```

```json
{"ip":"172.30.0.1","opted_out":true,"expires":"2027-10-15T22:20:47.900783Z","signer":"ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka"}
```

```sh
curl -X DELETE http://localhost:8080/api/v1/optout
```

```json
{"ip":"172.30.0.1","opted_out":false}
```

Other answers: `400` when the request does not come from a public IPv4 address, `429` after too many requests from one address (try again in an hour), `503` when the boid has signed its 1,000 opt-outs for the day (ask another boid).

## Flock API

`/fed/v1` is how boids talk to each other. The read-only endpoints below are also useful to people, for example for firewall block lists. They exist only on boids with `BOIDSCAN_ENDPOINT` set.

| Endpoint | Returns |
|---|---|
| [`GET /fed/v1/node`](#get-fedv1node) | This boid's signed record |
| [`GET /fed/v1/peers`](#get-fedv1peers) | This boid's record and the boids it knows |
| [`GET /fed/v1/scanners`](#get-fedv1scanners-and-get-fedv1revoked) | Scanning addresses of this boid and every boid it has verified, one per line |
| [`GET /fed/v1/revoked`](#get-fedv1scanners-and-get-fedv1revoked) | Last known addresses of boids the flock policy removed, one per line |
| [`GET /fed/v1/policy`](#get-fedv1policy) | The flock policy this boid holds |
| [`GET /fed/v1/policy/status`](#get-fedv1policystatus) | Policy serial, expiry, and why this boid does not sweep |
| [`GET /fed/v1/homes?ip=`](#get-fedv1homes) | The block an address belongs to and the boids that hold it |
| [`GET /fed/v1/units`](#get-fedv1units) | Units this boid holds that were scanned or are leased |
| [`GET /fed/v1/runs`](#get-fedv1runs) | This boid's last 1,000 sweep scans |
| [`GET /fed/v1/progress`](#get-fedv1progress) | This boid's own signed progress count |
| [`GET /fed/v1/optouts`](#get-fedv1optouts) | Opt-outs in force, each signed by the boid that took it |
| `GET /fed/v1/optouts/heads`, `GET /fed/v1/optouts/log?signer=&from=` | Opt-out sync between boids |

The other routes (`POST /fed/v1/gossip`, `POST /fed/v1/push`, `POST /fed/v1/lease`, `GET /fed/v1/due`, `POST /fed/v1/check`, `GET /fed/v1/check/{key}`) are part of the boid-to-boid protocol and may change between releases.

### `GET /fed/v1/node`

With `?nonce=<up to 64 characters>` the response also carries a signature over the nonce and endpoint. Boids use it to check that a record really belongs to the server at that address.

```sh
curl http://localhost:8080/fed/v1/node
```

```json
{
  "record": {
    "id": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka",
    "name": "boid-a",
    "endpoint": "http://172.30.0.3",
    "contact": "abuse@lab.invalid",
    "project_url": "https://boidscan.network",
    "version": "dev",
    "catalog": "aafc462c37eb7433b24bc89f2211da7e93543c9dfc20bb1353bf6a136f5555af",
    "root": "c70c28a4f61a09a1d9ca92f530b72a5edf934cddbd95a5ae404f1e9ed0fda381",
    "policy_serial": 1,
    "time": "2026-10-15T22:20:22.444412Z",
    "signature": "/j93j6rwFVX0z8hLyxL6Tjk+xt6bjzJP4msqyGkhC3But/xCi3alftxaXhBrYS82TQOLbwg1O/j4KEXYIfAWAA=="
  }
}
```

### `GET /fed/v1/peers`

`self` is the same record as above. Each peer adds what this boid thinks of it: `state` (`new`, `alive`, `suspect`, `down` or `revoked`), `verified`, `trust` (`probation`, `trusted` or `shunned`) and `low_reach`. See [Watch boids check each other](lab.md#watch-boids-check-each-other).

```sh
curl http://localhost:8080/fed/v1/peers
```

<details>
<summary>Response (trimmed: one of four peers)</summary>

```json
{
  "self": { "id": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka", "name": "boid-a", "...": "..." },
  "peers": [
    {
      "id": "slzd7wwazexgrdtnswfbpouaxkpseh2rkvh4xwajxr64bzciatgq",
      "name": "boid-b",
      "endpoint": "http://172.30.0.5",
      "contact": "abuse@lab.invalid",
      "project_url": "https://boidscan.network",
      "version": "dev",
      "catalog": "aafc462c37eb7433b24bc89f2211da7e93543c9dfc20bb1353bf6a136f5555af",
      "root": "c70c28a4f61a09a1d9ca92f530b72a5edf934cddbd95a5ae404f1e9ed0fda381",
      "policy_serial": 1,
      "time": "2026-10-15T22:20:22.001745Z",
      "signature": "JJ3sV5gIoenfXtK+xDaKCifqnWrClINbgltrwAqOA9QLMHqvMI4VSbdstPyY5IIPGQLyJKzQvSwaEJC7MEASDQ==",
      "first_seen": "2026-10-15T22:16:37.58939Z",
      "verified": true,
      "state": "alive",
      "trust": "trusted",
      "low_reach": false
    }
  ]
}
```

</details>

### `GET /fed/v1/scanners` and `GET /fed/v1/revoked`

Plain text, one address per line, ready for a firewall block list. `revoked` was empty in the lab.

```sh
curl http://localhost:8080/fed/v1/scanners
```

```text
172.30.0.3
172.30.0.5
172.30.0.6
172.30.0.7
172.30.0.8
```

### `GET /fed/v1/policy`

The chain of signed policies this boid holds, as a bundle `boidscan policy install` accepts, plus the emergency pause if one is in force. `?after=<serial>` returns only what a boid holding that serial is missing.

```sh
curl http://localhost:8080/fed/v1/policy
```

<details>
<summary>Response</summary>

```json
{
  "chain": [
    {
      "policy": {
        "serial": 1,
        "issued": "2026-10-15T22:16:40Z",
        "expires": "2026-10-29T22:16:40Z",
        "pause": false,
        "min_version": "",
        "max_rate_pps": 10000,
        "min_rescan": "1h",
        "bump_interval": "24h0m0s",
        "catalog": "aafc462c37eb7433b24bc89f2211da7e93543c9dfc20bb1353bf6a136f5555af",
        "revoked_nodes": [],
        "seeds": [],
        "maintainers": {
          "keys": ["ddvvt74oerimndt2woeuyve335nrutlgipgk6fxdughxrflr6nka"],
          "threshold": 1
        }
      },
      "signatures": [
        {
          "key": "ddvvt74oerimndt2woeuyve335nrutlgipgk6fxdughxrflr6nka",
          "sig": "/kwRt+UCa5gT07gj1tDQHLFwbQ4ItD+14tMHZBPwMHYuFwYZscCDpwluXL4nLKxDuvQ+h/MROutTvumO2A/WDg=="
        }
      ]
    }
  ]
}
```

</details>

### `GET /fed/v1/policy/status`

`halt` appears only when the boid does not sweep or grant leases, and says why.

```sh
curl http://localhost:8080/fed/v1/policy/status
```

```json
{
  "root": "c70c28a4f61a09a1d9ca92f530b72a5edf934cddbd95a5ae404f1e9ed0fda381",
  "serial": 1,
  "expires": "2026-10-29T22:16:40Z"
}
```

### `GET /fed/v1/homes`

Takes `?ip=<IPv4 address>`.

```sh
curl 'http://localhost:8080/fed/v1/homes?ip=172.30.0.11'
```

```json
{
  "block": "172.30.0.8/30",
  "homes": [
    { "id": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka", "name": "boid-a", "endpoint": "http://172.30.0.3" },
    { "id": "t6lltwixwgvatjo45vmlta3x2prsurz7fz2fbgxc5tfoveknonjq", "name": "boid-c", "endpoint": "http://172.30.0.6" },
    { "id": "slzd7wwazexgrdtnswfbpouaxkpseh2rkvh4xwajxr64bzciatgq", "name": "boid-b", "endpoint": "http://172.30.0.5" }
  ]
}
```

### `GET /fed/v1/units`

```sh
curl http://localhost:8080/fed/v1/units
```

<details>
<summary>Response (trimmed: two of many units)</summary>

```json
[
  {
    "block": "172.30.0.0/30",
    "group": 0,
    "scanned_at": "2026-10-15T22:16:51.533147Z",
    "scanned_by": "slzd7wwazexgrdtnswfbpouaxkpseh2rkvh4xwajxr64bzciatgq"
  },
  {
    "block": "172.30.0.0/30",
    "group": 1,
    "scanned_at": "2026-10-15T22:16:53.946538Z",
    "scanned_by": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka"
  }
]
```

</details>

### `GET /fed/v1/runs`

Newest first.

```sh
curl http://localhost:8080/fed/v1/runs
```

<details>
<summary>Response (trimmed: two of many runs)</summary>

```json
[
  {
    "id": 11,
    "block": "172.30.0.40/30",
    "group": 1,
    "started_at": "2026-10-15T22:17:15.19786Z",
    "finished_at": "2026-10-15T22:17:21.312826Z"
  },
  {
    "id": 10,
    "block": "172.30.0.36/30",
    "group": 1,
    "started_at": "2026-10-15T22:17:07.320779Z",
    "finished_at": "2026-10-15T22:17:15.175994Z"
  }
]
```

</details>

### `GET /fed/v1/progress`

This boid's count of the units it holds, per port group, signed with its key. [`/api/v1/progress`](#get-apiv1progress) sums these over the flock. Returns `503` until the first count is done.

```sh
curl http://localhost:8080/fed/v1/progress
```

<details>
<summary>Response</summary>

```json
{
  "progress": {
    "node_id": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka",
    "catalog": "aafc462c37eb7433b24bc89f2211da7e93543c9dfc20bb1353bf6a136f5555af",
    "time": "2026-10-15T22:20:18.950904Z",
    "groups": [
      { "ever": 10, "fresh": 10, "day": 10 },
      { "ever": 10, "fresh": 10, "day": 10 }
    ],
    "hosts": 0,
    "open_ports": 0,
    "scanning": []
  },
  "signature": "kg/2s46ZeSiPPVeC7gPGH/pVfvRol5NnCUs9PGsyROa43iQe8XTJyZb+Mn1RPbl7dbwPXAyKr2MbCckVWx9ZAA=="
}
```

</details>

### `GET /fed/v1/optouts`

In address order, 1,000 per page. Pass the last `ip` of a page as `?after=` to get the next one; `?limit=` asks for fewer.

```sh
curl http://localhost:8080/fed/v1/optouts
```

```json
[
  {
    "id": 1,
    "ip": "172.30.0.1",
    "action": "add",
    "expires": "2027-10-15T22:20:47.900783Z",
    "signer": "ca3vyc3u6zgwvu25bgmy5kdvmncauvfzlnjcvxyrxs4qortohnka",
    "time": "2026-10-15T22:20:47.900783Z",
    "signature": "0PDvvgtRXGD1DBfkF40s64fE51WLu6tHvP1fRZt4MYjIgFDQaPBw3v/xQxrlT7u33IVdqqv/X0A+1MVAWDs/DQ=="
  }
]
```

## Errors

Errors are JSON with one field, and the HTTP status says what kind:

```sh
curl 'http://localhost:8080/api/v1/search?port=99999'
```

```json
{"error":"bad query: port out of range"}
```

| Status | Meaning |
|---|---|
| `400` | A parameter is invalid |
| `403` | Opt-out change sent from a web page |
| `404` | No data, or the boid does not offer this |
| `429` | Too many opt-out requests |
| `500` | The boid failed; its log has the details |
| `503` | Search too broad, or the boid is not ready |

`/fed/v1/scanners` and `/fed/v1/revoked` answer errors in plain text.

## Go client

[pkg/client](../pkg/client) wraps the search API:

```go
import "github.com/boidscan/boidscan/pkg/client"

c := client.New("http://localhost:8080")
host, err := c.Host(ctx, "172.30.0.26")
err = c.SearchAll(ctx, client.Query{Port: 9443, Cert: "www.lab.test"}, func(o client.Observation) bool {
	fmt.Println(o.IP, o.Port, o.Name)
	return true
})
```

`SearchAll` follows `next` until the last page or until the callback returns `false`. `Observation.Verify` checks an observation's signature. Errors from the API come back as `*client.APIError` with the status code and message.
