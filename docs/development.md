# Development

## Build from source

You only need Docker:

```sh
./build.sh        # run the tests, then build dist/boidscan
./build.sh image  # build the container image
./build.sh e2e    # form the lab flock, scan the lab and check the results
```

The tests check that every `BOIDSCAN_*` variable is in [configuration.md](configuration.md) and every route is in [api.md](api.md). Update those pages along with the code.

## Commands

```text
boidscan migrate                     create or upgrade the database schema
boidscan scan [flags] CIDR...        discover and grab services, store the results
boidscan serve [flags]               info page with search and JSON API
boidscan worker [flags]              take part in the flock's sweep
boidscan export ivre                 HTTP(S) results as zgrab2 JSON for IVRE
boidscan exclude add|rm|list [CIDR]  manage ranges this node never scans
boidscan policy <command>            create, sign, check and install flock policies
```

`boidscan <command> -h` lists a command's flags. [Configuration](configuration.md) describes them and their environment variables.

The worker only sweeps while a valid flock policy is in force; see [GOVERNANCE.md](../GOVERNANCE.md).
