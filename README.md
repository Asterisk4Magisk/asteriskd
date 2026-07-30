# asteriskd

`asteriskd` is a small root daemon for Android that watches netlink address and interface events, keeps local-address bypass rules or pinned eBPF maps synchronized, and restores IPv6 state during shutdown or fail-stop handling.

The source root is intentionally build-system agnostic. A parent Android project is expected to compile every top-level `.c` file as one PIE executable and package it under a name such as `libasteriskd.so`. The `tests` directory is not part of the production translation units.

## Command line

```text
asteriskd --prepare --config FILE
asteriskd --start --config FILE --pid FILE --log FILE
```

All paths must be absolute.

| Option | Description |
| --- | --- |
| `--prepare` | Validate the configuration and prepare iptables bypass marker chains before the daemon starts. |
| `--start` | Start the netlink monitor and initial synchronization. |
| `--config FILE` | Version 3 JSON configuration. |
| `--pid FILE` | PID file maintained by the caller and daemon. Required by `--start`. |
| `--log FILE` | Append-only daemon log. Required by `--start`. |

Exit status is `0` on success, `64` for invalid command-line arguments, and `1` for configuration or runtime failure.

## Configuration version 3

```json
{
  "version": 3,
  "mode": "tproxy",
  "enableIpv6": true,
  "disableSystemIpv6": false,
  "readyPath": "/data/local/tmp/example/asteriskd.ready",
  "stopScriptPath": "/data/local/tmp/example/stop.sh",
  "statePath": "/data/local/tmp/example/asteriskd.state",
  "ignoredInterfaces": ["lo"],
  "virtualInterfaces": ["tun0"],
  "hotspotInterfacePrefixes": ["wlan+"],
  "ipv4Bypass": {
    "beginChain": "ASTERISKD_LOCAL4_BEGIN",
    "endChain": "ASTERISKD_LOCAL4_END",
    "consumerChains": ["ASTERISK_TPROXY_PREROUTING", "ASTERISK_TPROXY_OUTPUT"]
  },
  "ipv6Bypass": {
    "beginChain": "ASTERISKD_LOCAL6_BEGIN",
    "endChain": "ASTERISKD_LOCAL6_END",
    "consumerChains": ["ASTERISK_TPROXY6_PREROUTING", "ASTERISK_TPROXY6_OUTPUT"]
  },
  "bpfLocalMaps": null,
  "bpf2socksTc": null,
  "emergencyProcesses": [
    {
      "pidPath": "/data/local/tmp/example/proxy.pid",
      "commandMarker": "/data/local/tmp/example/proxy-config.json"
    }
  ]
}
```

| Field | Required | Description |
| --- | --- | --- |
| `version` | yes | Must be `3`. |
| `mode` | yes | `tproxy`, `tun`, `tun2socks`, or `bpf2socks`. |
| `enableIpv6` | yes | Synchronize IPv6 addresses and IPv6 bypass state. |
| `disableSystemIpv6` | yes | Temporarily disable system IPv6 interfaces and restore their previous values on exit. |
| `readyPath` | yes | Absolute ready-marker path written after the initial synchronization. |
| `stopScriptPath` | yes | Absolute shell script path executed with `--from-asteriskd` after fail-stop recovery. |
| `statePath` | yes | Absolute file used to persist IPv6 values that must be restored. |
| `ignoredInterfaces` | yes | Exact interface names excluded from address tracking; up to 64 entries. |
| `virtualInterfaces` | yes | Exact virtual interface names excluded from local-address bypass collection; up to 64 entries. |
| `hotspotInterfacePrefixes` | yes | Interface selectors; a final `+` enables prefix matching. |
| `ipv4Bypass` | yes | Bypass-chain object or `null`. Required and non-null outside `bpf2socks` mode. |
| `ipv6Bypass` | yes | Bypass-chain object or `null`. Required and non-null when IPv6 is enabled outside `bpf2socks` mode. |
| `bpfLocalMaps` | yes | Pinned-map object or `null`. Required and non-null in `bpf2socks` mode. |
| `bpf2socksTc` | yes | TC attachment object or `null`. Required and non-null in `bpf2socks` mode. |
| `emergencyProcesses` | yes | Zero to eight validated fallback processes. Use `[]` to disable emergency process termination. |

A bypass object contains `beginChain`, `endChain`, and one to four `consumerChains`. The App places adjacent jumps to the empty marker chains in each consumer. The daemon owns only the direct host-destination `RETURN` rules between those markers. Chain names accept uppercase ASCII letters, digits, `_`, and `-`, and must fit the kernel/iptables name limit used by the daemon.

A BPF map object contains an absolute `ipv4Path` and either an absolute `ipv6Path` or `null`:

```json
{
  "ipv4Path": "/sys/fs/bpf/example/local_addr_v4",
  "ipv6Path": "/sys/fs/bpf/example/local_addr_v6"
}
```

Each emergency entry contains an absolute `pidPath` and a non-empty `commandMarker` of at most 255 bytes. It is used only if execution of the normal stop script fails. Before signaling a PID, the daemon verifies that `/proc/PID/cmdline` contains the marker; it sends `SIGTERM` first and `SIGKILL` only if the process remains alive.

## Platform requirements and safety

The executable needs root privileges, netlink access, iptables/ip6tables availability for bypass modes, and BPF map access for `bpf2socks` mode. `/proc`, `/sys/class/net`, `/proc/sys/net/ipv6/conf`, and `/system/bin/sh` are Android/Linux platform interfaces rather than application-specific paths.

The stop script and emergency markers are security boundaries. Generate them from trusted absolute runtime paths and do not accept untrusted configuration.

## Parent-project integration

Mount the repository root directly at `asteriskd/src/main/native`. Keep Android ABI selection, NDK discovery, compiler flags, packaging, and task wiring in the parent project.

## License

GPL-3.0. See [LICENSE](LICENSE).
