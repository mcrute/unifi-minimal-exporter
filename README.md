# Minimal Unifi Prometheus Exporter

An alternative to [Unpoller](https://github.com/unpoller/unpoller)
that exports only a minimal set of metrics about devices, basically
just enough information to monitor if devices are up or down and have
been reset. Unpoller exports far too many metrics with too many labels
that only consumed Prometheus disk space in our setup when what we
really needed was something much more simple and we can use the Unifi
Controller itself for a deeper dive into the metrics.

## Exported Metrics

These metrics are exported with a label for the Unifi Site, the device
name, and the device MAC address.

 * Unifi Controller is up
 * Device is not adopted
 * Device is in default state
 * Device is disabled
 * Device is isolated
 * Device is unsupported (combines unsupported, EOL, and incompatible)
 * Device has a pending upgrade
 * Unix timestamp for when the device was last seen by Unifi
 * Number of seconds since the device was last seen by Unifi
 * Device uptime in seconds
 * CPU usage percent
 * Total memory on the device
 * Used memory on the device
 * Device load average (for each of 1, 5, 15 minutes)

## Building

A simple `go build` command should be enough to build this package.

```
CGO_ENABLED=0 go build -o unifi-minimal-exporter
```

## Running

This exporter requires a Hashicorp Vault instance that can be queried
for the login credential for the Unifi Controller. It expects the
credential to have a case-sensitive `username` and `password` field. The
code also expects a key-value store to be mounted at `kv/` (this is not
currently configurable). Finally the code expects to authenticate to
Vault with AppRole authentication.

First, create the credential in your Unifi controller that has access
to all of your sites and store it in Vault as noted above. Then run the
following command:

```
VAULT_ROLE_ID="your-role-id" \
VAULT_SECRET_ID="your-secret-id" \
VAULT_ADDR="https://your-vault-host" \
./unifi-minimal-exporter --hostname="https://your-unifi-host" --vault-path="unifi/admin"
```

Note that bind address and port can be specified with the `--bind` flag
but defaults to `:9210`.

Finally, configure Prometheus to scrap the metrics exported at the
`/metrics` endpoint. This will trigger a query of the Unifi controller
and render the metrics for Prometheus.

## Contributing

Contributions are welcomed. Please file a pull request and we'll
consider your changes. Please try to follow the style of the existing
code and do not add additional libraries without justification.

While we appreciate the time and effort of contributors there's not
guarantee that we'll be able to accept all contributions. If you're
interested in making a rather large change then please open an issue
first so we can discuss the implications of the change before you invest
too much time in making those changes.
