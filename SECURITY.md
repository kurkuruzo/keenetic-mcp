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
back for verification, setup fails closed and does not create a plaintext
password file.

Older versions could fall back to `<configDir>/secrets.json` with mode `0600`.
When the active legacy credential is found, it is first copied to the protected
store and verified there. The legacy plaintext file is deliberately kept until
the corresponding configuration has also been successfully resolved or written.
Only after both the secure credential and configuration are committed is the old
`secrets.json` removed. The application supports a single stored profile, so any
other entries left in that legacy file are stale credentials from older `init`
runs and are removed with it.

If secure migration cannot complete, the legacy file is not silently adopted as
the long-term credential store. If the protected credential and configuration
are committed but the legacy file cannot be removed, the application reports
that the migration is incomplete so the plaintext file can be removed manually.

The password is never written to the normal settings file, never included in a
tool response, and never logged. `KEENETIC_HOST`, `KEENETIC_USER` and
`KEENETIC_PASSWORD` override the stored values, which is what a container wants.
When `KEENETIC_PASSWORD` is supplied, startup does not access the local password
store or trigger legacy migration.

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
