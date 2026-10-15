# Viewing results in IVRE

[IVRE](https://github.com/ivre/ivre) provides a richer web UI on top of this data:

```sh
boidscan export ivre > boidscan.json
ivre scan2db -c boidscan -s my-node boidscan.json
ivre db2view nmap
```

IVRE's zgrab2 importer only reads HTTP(S) results. The other protocols are available through the [API](api.md).

> [!NOTE]
> HTTPS certificates import correctly with IVRE's current master branch. The 0.9.20 release on PyPI fails on them because it uses a pyOpenSSL call that newer pyOpenSSL versions removed.
