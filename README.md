# asteriskd v2

`asteriskd` is the single root supervisor for AsteriskNG, AsteriskBOX,
and AsteriskMETA. It owns the selected core process, required helper, optional
matcher, daemon-managed routing/firewall/BPF/TC state, in-memory effect journal, network
reconciliation, structured log, and the local control socket for the whole
runtime lifetime.

The supervisor does not daemonize and does not restart a failed child. A core or
required-helper exit causes a fail-stop: new traffic entry is removed first,
owned effects are cleaned in reverse order, and a non-resident supervisor exits
nonzero. A clean explicit stop succeeds only after telemetry reaches `stopped`.

The source root is build-system agnostic. The Android parent project compiles
every top-level `.c` file as one PIE executable; `tests/` is host-only.

## CLI

```text
asteriskd start --config ABSOLUTE_PATH
asteriskd monitor --config ABSOLUTE_PATH
asteriskd status
asteriskd stop
asteriskd shutdown
asteriskd watch
```

All commands require effective UID 0. `status`, `stop`, and `shutdown` write
exactly one protocol-v1 JSON response line. `stop` ends the active service
cycle while keeping the supervisor available for configured service actions;
`shutdown` also exits the supervisor after the active service has stopped.
`start` launches the supervisor and immediately starts a service cycle;
`monitor` launches it idle and waits for configured service-control actions.
`watch` writes an initial response and then JSON event lines until the final
event or disconnect. CLI usage errors write only to stderr and exit 64.

`start` and `monitor` open and verify the config-parent directory themselves.
They do not accept inherited publication descriptors or acquire a filesystem
lock.
Applications perform a read-only status preflight and publish the latest config
through same-directory temporary files plus atomic rename. The abstract
control-socket bind is the cross-process single-instance authority.

## Control plane

The only endpoint is the Linux abstract Unix-domain socket
`@asteriskd.control`. Peer credentials must report UID 0. The protocol is
newline-delimited UTF-8 JSON, version 1, with closed request/response/event
objects. Each connection sends one request. Limits are enforced for request
size, client count, per-client output, incomplete-input timeout, and stalled
watch output.

Public methods are `status`, `stop`, `shutdown`, and `watch`. `start` and
`monitor` are CLI operations, not server methods. Ordinary publication requires
the control socket to be absent. Explicit boot refresh may publish while the
matching owner reports
`running`; every other owner or phase blocks publication.

Snapshots expose semantic state only: phase, owner/core/mode, supervisor/core/
helper PIDs, matcher status, daemon-rule generation/categories, IPv4/IPv6
readiness, and a sanitized error. Private iptables names, BPF pin paths, argv,
environment, and configuration content are never exposed.

## Configuration v3

The configuration is strict UTF-8 JSON (`schemaVersion: 3`) with a maximum size
of 8 MiB. Every object is closed: unknown, duplicate, or missing keys are
invalid, including keys whose value is nullable. Validation completes before
the logger, state, socket, child, or external network effects are created.

Top-level sections are:

- `schemaVersion`, `owner`, `coreType`, and `mode`;
- `paths` for the core executable/config, working directory, state, and log;
- `core` for the readiness timeout and optional Mihomo AGE secret;
- `modeOptions` for the tproxy port or TUN name;
- `network` for IPv6 intent, DNS/fake-DNS, interface selectors, private CIDRs,
  UID policy, and inline canonical direct CIDRs;
- nullable `helper` (`hev-socks5-tunnel` or `bpf2socks`);
- nullable `matcher`, containing only its executable path.

Direct CIDRs are inline immutable snapshots. The supervisor renders matcher and
bpf2socks policy/config into sealed anonymous descriptors and passes
`/proc/self/fd/N`; it never creates policy, helper-config, direct-CIDR, PID,
ready, stop-script, or boot-log runtime artifacts.

Supported combinations:

| Owner | Core | Runnable modes |
| --- | --- | --- |
| `asteriskng` | `xray` | `tproxy`, `tun2socks`, `bpf2socks` |
| `asteriskbox` | `sing-box` | `tproxy`, `tun`, `tun2socks`, `bpf2socks`, `ebpf` |
| `asteriskmeta` | `mihomo` | `tproxy`, `tun`, `tun2socks`, `bpf2socks` |

`ebpf` is a standalone mode, not the optional matcher. It is parsed for every
owner/core pair, but only AsteriskBOX/sing-box is runnable today. In that mode
sing-box owns its cgroup BPF, route, shared-interface TC, UID/direct policy, and
`route_localnet`; daemon rule state remains inactive. Core-owned eBPF lifecycle
and residue cleanup remain the core's responsibility.

The matcher is an independent required overlay for `tproxy`, `tun`, or
`tun2socks`. For both the matcher and bpf2socks, optional SELinux policy setup
is best-effort and emits a warning when unavailable or unsuccessful. One-shot
loading, complete pin verification, or policy-map verification failure still
aborts startup; there is no silent fallback to non-matcher rules.

## Lifecycle, admission, and cleanup

The abstract control listener is acquired before any ROOT resource operation.
Each service cycle then reconciles the fixed Asterisk-owned catalog: hooks,
private chains, policy rules/routes, `xdummy`, TC filters, and the shared
`/sys/fs/bpf/asterisk` namespace are removed in dependency order and the final
absence is verified. Admission fails closed when a fixed name is occupied by a
foreign object or absence cannot be proved. The catalog is independent of the
current owner, mode, IPv6 setting, matcher setting, saved phase, and saved
configuration. Old per-application names are intentionally ignored.

Core readiness is adapter-specific and identity-bound. TUN/HEV and bpf2socks
modes require the core SOCKS listener before helper readiness. BOX `ebpf`
requires the same verified core identity to survive a fixed 1000 ms window and
does not wait for a shared interface.

The state file is telemetry only. It is replaced through a temp file, file
fsync, rename, and parent-directory fsync; startup never loads it to decide what
to clean or restore. Current-cycle sysctl and tether/dnsmasq original values are
kept only in supervisor memory and are restored best-effort on graceful cleanup.
A crash or `SIGKILL` deliberately leaves those shared values untouched for the
operator or a later normal service action to handle.

## Network and logging

One reactor owns signals, control clients, child setup/log/pidfd events,
route-netlink input, debounce deadlines, readiness, action commands, and stop
deadlines. Netlink subscribes before the initial snapshot, drains to `EAGAIN`,
and performs a full reconcile after the 1500 ms trailing debounce or any
integrity loss. System-IPv6 disablement records original values only in the
resident supervisor's in-memory effect journal.

The daemon is the only writer of `asteriskd.log`. It opens the file through a
no-symlink path, anchors ownership to the pre-existing app-owned log directory,
forces mode 0600, and emits bounded JSONL. Child stdout/stderr are framed,
UTF-8-repaired, control-escaped, truncated at the fixed limit, and redacted for
the exact AGE secret before persistence.

The only persistent runtime artifacts are the app-published core config and
`asteriskd.json`, daemon-owned telemetry file `asteriskd.state`, app-owned
`startup.sh` when boot is enabled, and the single app-level `asteriskd.log`.

## Verification and device boundary

Host tests use explicit fake backends and compile with
`-Wall -Wextra -Werror -std=c17`. Production sources must also compile for
Android API 24 on arm64-v8a, armeabi-v7a, x86, and x86_64. Host tests cannot
prove rooted-device SELinux, abstract-UDS peer credentials, inherited OFD
locking, `/proc` identity races, netlink/BPF/TC kernel ABI, or filesystem label
behavior; those remain mandatory device integration checks.

## License

GPL-3.0. See [LICENSE](LICENSE).
