# Security

## What this software can reach

It authenticates to a router as an administrator and can change its
configuration. That is the point of it, and it is also the whole risk: anything
that can talk to this server can reconfigure the network it runs on.

## Where the password goes

The setup wizard stores the router password using an operating-system protected
credential store:

- macOS: Keychain Services;
- Windows: DPAPI with `CurrentUser` scope. Only DPAPI ciphertext is stored on
  disk in `secrets.dpapi.json`;
- Linux: Secret Service via `secret-tool`.

There is no plaintext credential fallback. If the operating-system protected
store is unavailable, cannot store the password, or cannot read the stored value
back for verification, setup fails closed and no plaintext password file is
created.

Older versions could fall back to `<configDir>/secrets.json` with mode `0600`.
When such a legacy entry is found, the server performs a one-time migration: it
first stores and verifies the password in the current protected store and only
then removes that legacy plaintext entry. If secure migration cannot complete,
the legacy entry is not deleted and is not silently used as the long-term
credential store.

The password is never written to the normal settings file, never included in a
tool response, and never logged. `KEENETIC_HOST`, `KEENETIC_USER` and
`KEENETIC_PASSWORD` override the stored values, which is what a container wants.

## What it does not do

No cloud, no telemetry, no outbound connection to anything but your router. It
runs on your machine and speaks to the router over your LAN.

## Reducing what it can do

`--read-only` does not register the write tools at all, rather than registering
them and refusing, so an agent never sees them.

Changes apply to the running configuration and are discarded on reboot until
`save_config` is called, which nothing does on its own.

## Reporting something

Open a [security advisory](https://github.com/salatmaster/keenetic-mcp/security/advisories/new)
rather than a public issue, and give the model and KeeneticOS version. Expect a
first reply within a week.

Please do not include real MAC addresses, private IP addresses, SSIDs or keys in
a report. A test in this repository scans every file for them precisely because
they are easy to paste in by accident.
