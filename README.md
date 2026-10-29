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
every `.c` file under the root and its module directories as one PIE executable,
with the source root on the include path (`-I<root>`).

## Source layout

| Path | Responsibility |
| --- | --- |
| `asteriskd.c`, `asteriskd.h` | CLI entry point; the shared module interface |
| `runtime/` | `control.c` control protocol, socket server and CLI client; `runtime.c` platform-neutral reactor, lifecycle driver and event publication; `lifecycle.c` start, stop and pause sequencing of the core, helper and matcher |
| `core/` | Configuration parsing, JSON, structured log, state telemetry, error/string/text helpers, platform capabilities, the Linux system backends |
| `process/` | Core, helper and matcher process specs, child setup, readiness and stop coordination |
| `resources/` | Owned-resource catalog, stateless reconciliation, the in-memory effect journal, BPF map/pin/matcher/bpf2socks verification |
| `rules/` | Rule plans for TPROXY, TUN, local bypass and runtime slots, rule batches, TC install plans and netlink, TUN compatibility |
| `network/` | Network reconciliation, hotspot offload policy, the AEN1 DNS companion client |
| `service/` | Service control: Wi-Fi rules, schedules (cron) and the lock screen (keyguard) listener |
| `supervisor/` | Linux supervisor: reactor backend, children, cleanup (`supervisor.c`); root actions and `iptables-restore --noflush` batches (`supervisor_action.c`); rtnetlink rules/routes and the tethering offload probe (`supervisor_rtnl.c`); iptables rendering and snapshots (`supervisor_xtables.c`); TC (`supervisor_tc.c`); routes, BPF pins and sysctl (`supervisor_rules.c`); matcher/helper start, network open and hotspot offload (`supervisor_network.c`); owned-resource reconciliation (`supervisor_reconcile.c`); DNS enhancement transitions (`supervisor_dns.c`) |
| `shared/` | Contracts kept byte-identical with bpf2socks |

`asteriskd.h` is the shared module interface. `supervisor/supervisor.h` is private
to the runtime and supervisor modules. Every project include names its header from
the source root, for example `#include "supervisor/supervisor.h"`. Non-static
functions use the `asteriskd_<module>_` prefix; file-local helpers carry the module
name without it (`control_`, `config_`), and those in supervisor modules use
`system_`. `.clang-format` records the formatting baseline.

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

Automatic Wi-Fi, schedule, and lock screen actions in TPROXY, TUN2SOCKS and BPF2SOCKS
keep the core alive after the first start. A stop action publishes `paused`
after removing traffic rules and suspending network reconciliation. TUN2SOCKS
also keeps its tunnel helper and interface; BPF2SOCKS stops its helper after
detaching owned TC traffic entry, and starts a new helper on resume. Matcher
state is retained. Resume publishes `running` after traffic verification.
The `paused` event is not a terminal watch event, and snapshots retain the
live core PID while reporting inactive rules and network readiness.
Explicit `stop` and `shutdown` always perform full cleanup, including from
`paused`. TUN and eBPF modes keep their existing full-cycle automatic control.

`start` and `monitor` open and verify the config-parent directory themselves.
They do not accept inherited publication descriptors or acquire a filesystem
lock.
Applications perform a read-only status preflight and publish the latest config
through same-directory temporary files plus atomic rename. The abstract
control-socket bind is the cross-process single-instance authority.

The application supplies all configuration, resource, state and log paths.
`--config` accepts any configuration filename. These files need not share a
directory with each other or with `core.workingDirectory`; the supervisor does
not require product-specific directory names. Paths must be normalized absolute
paths, and the referenced files/directories must satisfy their access needs.
Configuration directories may be read-only. CIDR files are read from the supplied
paths, and telemetry is written to `statePath`. The core's working directory also
sets its asset environment variable. Core/BPF helper stderr (`error.log`) and HEV
logs (`tun2socks.log`) are placed beside the configured supervisor `logPath`.

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

## Native lock screen control

Android 13+ can enable `serviceControl.keyguard`: `enabled`, `lockStart`,
`lockStop`, `unlockStart`, and `unlockStop`. Start/stop for the same event are
mutually exclusive. The initial query validates initialization without triggering
an action or seeding callback deduplication: `isKeyguardLocked()` can differ from
the listener's showing state when another app temporarily disables the keyguard.
The first callback after priming is eligible for an action; later callbacks that
repeat the last callback value do not trigger actions. This follows Keyguard
showing/dismissed state, not display power or credential-storage unlock.

The native supervisor loads `libbinder_ndk` only when this control is enabled,
registers a WindowManager listener, and adds the Binder fd to its existing
blocking reactor. There is no Java helper, timer-based state polling, or extra
listener thread. Transaction constants are resolved once from the device's
`framework.jar`; missing DEX/constants or unavailable platform symbols produce
an explicit startup error instead of guessing method numbers. Binder death is
fatal to this event source; the supervisor cleans up and requires a fresh start.
Normal shutdown unregisters the listener. This is a private platform Binder
interface, not a public NDK lock-screen API. Registration and baseline query
are not atomic in the platform API; transitions during that short initial
window cannot be given an exact event boundary.

Android builds link `libdl` and `libz`; `libbinder_ndk` is loaded dynamically so
older Android devices retain their existing runtime support. The application
hides this control and publishes it disabled below API 33.

## Configuration v6

The configuration is strict UTF-8 JSON (`schemaVersion: 6`) with a maximum size
of 8 MiB. Every object is closed: unknown, duplicate, or missing keys are
invalid, including keys whose value is nullable. Other schema versions are
rejected. Validation completes before the logger, state, socket, child, or
external network effects are created.

Top-level sections are:

- `schemaVersion`, `owner`, `coreType`, and `mode`;
- `paths` for the core executable/config, working directory, state, and log;
- `core` for the readiness timeout and optional Mihomo AGE secret;
- `modeOptions` for the tproxy port or TUN name;
- `network` for IPv6 intent, DNS/fake-DNS, interface selectors, private CIDRs,
  UID policy, and inline canonical direct CIDRs; `hotspotInterfaces` entries
  are exact names such as `ap0` or prefix selectors ending in `+` such as
  `wlan+`;
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

`tun` is also core-managed: sing-box/Mihomo owns routing, firewall policy,
UID selection, DNS and shared-interface traffic. asteriskd waits for the named
TUN interface, supervises the core and stops it before cleanup; daemon rule
state remains inactive. The daemon network contract accepts only IPv6 intent
and shared-interface selectors used for Android tethering offload preparation.
Matcher, local/fake DNS, ignored/virtual interfaces, private CIDRs and UID/direct
policy must be empty. `tun2socks` retains the daemon-owned TUN rules.

The matcher is an independent required overlay for `tproxy` or `tun2socks`. For both the matcher and bpf2socks, optional SELinux policy setup
is best-effort and emits a warning when unavailable or unsuccessful. One-shot
loading, complete pin verification, or policy-map verification failure still
aborts startup; there is no silent fallback to non-matcher rules.

## Lifecycle, admission, and cleanup

The abstract control listener is acquired before any ROOT resource operation.
Each service cycle then reconciles the fixed Asterisk-owned catalog: hooks,
private chains, policy rules/routes, TC filters, and the shared
`/sys/fs/bpf/asterisk` namespace are removed in dependency order and the final
absence is verified. Admission fails closed when a fixed name is occupied by a
foreign object or absence cannot be proved. The catalog is independent of the
current owner, mode, IPv6 setting, matcher setting, saved phase, and saved
configuration. Old per-application names are intentionally ignored.

Readiness is adapter-specific and requires a live child. TPROXY waits for
the configured TCP port; TUN2SOCKS and bpf2socks wait for the core SOCKS
port, and the bpf2socks helper waits for its bridge port. Port checks
search for the four-digit hexadecimal port
marker in /proc/<child-pid>/net/tcp6, then tcp. They do not filter TCP state
or local versus remote ports, and read failures remain pending until timeout.
Checks run on every reactor event and at least every 20 ms.
Socket ownership and process-group file descriptors are not inspected. Native TUN
and the HEV helper wait for the named interface. BOX `ebpf` requires the core
to survive a fixed 1000 ms window and does not wait for a shared interface.
Identity checks used to protect process-group termination remain separate.

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
and performs a full reconcile for routing changes after the 1500 ms trailing
debounce or any integrity loss. Events used only by the system IPv6 guard do
not schedule a full rules reconcile.

`disableSystemIpv6` disables IPv6 only on netd data networks available to
ordinary applications. The guard identifies them from IPv6 FIB rules: a global
explicit-network fwmark rule with a nonzero netId, permission `NONE`, and no UID
range, plus an `oif` rule for the same table. The table must be in the range
`1000 < table < 1000000000`, and `table - 1000` must equal the named interface's
ifindex when entering the guarded set. Classification does not
depend on rule priority or interface-name prefixes. Restricted `NETWORK` or
`SYSTEM` networks, including IMS, emergency and background networks, remain
untouched, as do interfaces outside netd's data-network set, including the
core's TUN. Loopback and `ipsec+` interfaces are always excluded.

The existing netlink socket watches IPv6 rule changes. Startup obtains one
`RTM_GETRULE` snapshot through a separate socket with a one-second receive
timeout; integrity loss or a socket reopen requests another snapshot after
pending events drain. There is no polling or child process for classification.
Rule membership is deduplicated by identity, so a snapshot and a queued event
for the same rule do not count it twice. Interrupted dumps preserve the previous
set and report a sync failure.
Entering the data-network set disables IPv6. Link and IPv6 address events
reapply the guard only to interfaces whose name and ifindex match that set, including when
Android re-enables IPv6. Pending disable/restore requests for the same
interface use the latest requested state.

Original `disable_ipv6` values exist only in the resident supervisor's
in-memory effect journal. Leaving the data-network set, including a change to
restricted permission, restores the recorded value so a persistent cellular
interface can be reused by IMS. Graceful cleanup also restores recorded values.
A vanished interface is skipped on apply and its journal entry is discarded
on restore. A failed restore logs a warning and remains journaled for graceful
cleanup to retry; no value is recovered from disk after a crash. Startup logs
the detected network classifications, and guard changes log the interface
whose IPv6 was disabled or restored.

The daemon is the only writer of `asteriskd.log`. It opens the file through a
no-symlink path, anchors ownership to the pre-existing app-owned log directory,
forces mode 0600, and emits bounded JSONL with the exact AGE secret redacted.
Core and bpf2socks helper stdout/stderr are appended directly to `error.log`;
matcher and HEV helper output is discarded.

The only persistent runtime artifacts are the app-published core config and
`asteriskd.json`, daemon-owned telemetry file `asteriskd.state`, app-owned
`startup.sh` when boot is enabled, and the single app-level `asteriskd.log`.

## Application-list DNS routing

With application-list enhancement enabled, the module classifies system resolver
requests by their original application UID and isolates the selected resolver
cache. The daemon consumes explicit proxy/direct marks before ordinary routing;
unmarked DNS, including resolver-owned sockets, follows ordinary traffic policy.
The DNS-specific OUTPUT rules do not
expand the application UID list.

`rules/marks.h` defines the numeric marks and their xtables match strings.
The classified bit is reserved for enhancement DNS decisions. The module sets
proxy mark `0x21000000` before the first route lookup. OUTPUT returns both proxy
and direct decisions through one classified-bit rule per protocol. The fixed
resolver classifier has four rules per address family; core and forced-bypass
owner guards remain separate. Enhanced IPv4 TPROXY gives its existing local
route preferred source `127.0.0.1`; startup verifies that source before activation.
Stateless cleanup recognizes both owned route forms. Ordinary routing with
enhancement disabled retains its original route without a preferred source.

Application-owned TCP/UDP 53 sockets use the existing application traffic policy,
including UID selection, CIDR and interface bypasses, matcher decisions, and the
IPv6 switch. They do not receive a separate DNS classification or an exemption
from address bypasses. Marked system DNS retains its dedicated routing path even
when ordinary IPv6 proxying is disabled. Core identity bypasses and the existing
hotspot DNS policy remain in effect. Disabling system IPv6 also disables IPv6
DNS transport on guarded data networks; this differs from disabling ordinary
IPv6 proxying.

Startup and resume verify consumers, installed rules, and the module
PREPARE/ACTIVATE exchange. They do not send synthetic DNS queries or inject
probe answers into core configurations. A changed network snapshot is drained
and prepared again within a bounded startup window. The legacy mode is unchanged.

## Verification and device boundary

Production sources compile with `-Wall -Wextra -std=c17` for Android API 26 on
arm64-v8a, armeabi-v7a, x86, and x86_64. Compilation cannot prove rooted-device
SELinux, abstract-UDS peer credentials, inherited OFD locking, `/proc` identity
races, netlink/BPF/TC kernel ABI, or filesystem label behavior; those remain
mandatory device integration checks.

## License

GPL-3.0. See [LICENSE](LICENSE).
