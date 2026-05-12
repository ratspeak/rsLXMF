<div align="center">

# rsLXMF

**Rust LXMF messaging and propagation for Reticulum.**

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![LXMF 0.9.8](https://img.shields.io/badge/target-LXMF%200.9.8-success.svg)](https://github.com/markqvist/LXMF)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#feature-status)

[LXMF Reference](https://github.com/markqvist/LXMF) |
[Reticulum Manual](https://reticulum.network/manual/) |
[rsReticulum](https://github.com/ratspeak/rsReticulum) |
[Ratspeak](https://github.com/ratspeak/Ratspeak)

</div>

---

rsLXMF is a Rust implementation of LXMF, the Reticulum messaging layer. This is not a fork of LXMF, this is LXMF written in a different language focused on staying interoperable. This is not a source of truth implementation, do not use it as such.

Commands are intentionally namespaced for Rust with the Rust-specific `lxmd-rs` command, so rsLXMF can live beside other
LXMF daemons on `PATH` without worry.

## Contents

- [Build It](#build-it)
- [Operating lxmd-rs](#operating-lxmd-rs)
- [Configuration](#configuration)
- [Delivery Model](#delivery-model)
- [Feature Status](#feature-status)
- [Compatibility Notes](#compatibility-notes)
- [Contributing](#contributing)
- [License](#license)

## Build It

The current development layout for rsLXMF requires
rsReticulum as a sibling directory/repo next to it, such as:

```text
ratspeak-src/
|-- rsReticulum/
`-- rsLXMF/
```
If you're starting fresh:
```bash
mkdir ratspeak-src
cd ratspeak-src
git clone https://github.com/ratspeak/rsReticulum
git clone https://github.com/ratspeak/rsLXMF
cd rsLXMF
```

### macOS

Install Rust with `rustup`, then install Apple's build tools:

```bash
xcode-select --install
```

Build from the sibling checkout:

```bash
cd rsLXMF
cargo build --release
```

### Linux / Raspberry Pi

#### Install Rust with `rustup`, then install the needed packages:

Debian, Ubuntu, and Raspberry Pi OS:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libudev-dev
```

Fedora:

```bash
sudo dnf install gcc make pkgconf-pkg-config systemd-devel
```

Arch:

```bash
sudo pacman -S --needed base-devel pkgconf systemd
```

#### Build the daemon:

```bash
cd rsLXMF
cargo build --release
```

### Windows

Install Rust with the MSVC toolchain. If Rust or Cargo asks for Visual Studio
Build Tools, install the "Desktop development with C++" workload.

Build from PowerShell:

```powershell
cd rsLXMF
cargo build --release
```

After the build, use the commands below with `./target/release/lxmd-rs` on
macOS/Linux or `.\target\release\lxmd-rs.exe` on Windows.

## Operating lxmd-rs

`lxmf-tools` builds one public command name:

| Binary | Purpose |
| --- | --- |
| lxmd-rs | Rust LXMF daemon and control utility. |



Generate the example config:

```bash
lxmd-rs --exampleconfig
```

Run a regular LXMF daemon:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum
```

Run a propagation node:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --propagation-node
```

Send a message and exit:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send <destination_hash> "message body"
```

The `--send` flag is an rsLXMF convenience. Normal
daemon and propagation-control operation does not require it for anything.

Send UTF-8 file content or select a delivery method:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send <destination_hash> --send-file ./message.txt --send-method direct
```

Supported `--send-method` values are `opportunistic`, `direct`, and
`propagated`. Paper messages aren't supported yet in the CLI.

Attach custom LXMF fields from scripts:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send <destination_hash> "with fields" \
  --send-fields-json '{"1":"aGVsbG8=","42":"AAECAw=="}'
```

The JSON object maps field IDs to base64-encoded bytes. It is only a shell
convenience; LXMF fields remain MessagePack field maps on the wire.

Control a propagation node:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --status
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --peers
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --sync <peer_hash>
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --break <peer_hash>
```

These commands query an `lxmf.propagation.control` endpoint over Reticulum.
They do not inspect local files and do not start local daemon state. If no
reachable daemon answers, they time out with compatibility-oriented control
exit behavior.

For a remote propagation node, pass the node's propagation destination hash:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --status --peers --remote <propagation_destination_hash> --timeout 5
```

Control queries use `<config-dir>/identity` by default. Use `--identity PATH`
when the query should authenticate as a different LXMF identity.

Run an inbound hook:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --on-inbound /path/to/handler
```

The handler receives the saved `.lxm` message path as an argument.

## Configuration

`lxmd-rs --config <dir>` expects a directory and reads `<dir>/config`.
`lxmd-rs --rnsconfig <dir>` expects a Reticulum config directory.

If no LXMF config directory is supplied, the default is:

| Platform | Default LXMF config file |
| --- | --- |
| Linux/macOS | `/etc/rsLXMF/config`, then `~/.config/rsLXMF/config`, then `~/.rsLXMF/config` |
| Windows | `%APPDATA%\rsLXMF\config` |


If `--rnsconfig` is omitted, Reticulum config resolution follows
rsReticulum-specific defaults.

Recommended standalone locations:

| Environment | LXMF config | Reticulum config |
| --- | --- | --- |
| macOS/Linux desktop | `~/.rsLXMF/config` | `~/.rsReticulum/config` |
| Windows desktop | `%APPDATA%\rsLXMF\config` | `%APPDATA%\rsReticulum\config` |
| Linux service | `/var/lib/rsLXMF/config` | `/etc/rsReticulum/config` or another explicit Reticulum directory |

Use existing LXMF or Reticulum directories, such as `~/.lxmd`, `~/.lxmf`, or
`~/.reticulum`, only by passing them explicitly. That keeps the default install
isolated while still allowing deliberate drop-in and migration tests.

Minimal config:

```ini
[lxmf]
display_name = Rat
announce_at_start = no
delivery_transfer_max_accepted_size = 1000
# stamp_cost = 8
# on_inbound = /path/to/handler

[propagation]
enable_node = no
announce_at_start = yes
autopeer = yes
autopeer_maxdepth = 6
auth_required = no
# node_name = Rat Nest
# static_peers = e17f833c4ddf8890dd3a79a6fea8161d
# outbound_node = e17f833c4ddf8890dd3a79a6fea8161d
# max_peers = 20
# propagation_stamp_cost_target = 16
# propagation_stamp_cost_flexibility = 3

[logging]
loglevel = 4
```

Supported sections:

| Section | Keys |
| --- | --- |
| `[lxmf]` | `display_name`, `announce_at_start`, `announce_interval`, `delivery_transfer_max_accepted_size`, `stamp_cost`, `on_inbound` |
| `[propagation]` | `enable_node`, `node_name`, `auth_required`, `announce_at_start`, `announce_interval`, `autopeer`, `autopeer_maxdepth`, `message_storage_limit`, `propagation_message_max_accepted_size`, `propagation_sync_max_accepted_size`, `propagation_stamp_cost_target`, `propagation_stamp_cost_flexibility`, `peering_cost`, `remote_peering_cost_max`, `max_peers`, `static_peers`, `prioritise_destinations`, `control_allowed`, `from_static_only`, `outbound_node`, `propagation_stamp_cost`, `propagation_limit`, `enforce_ratchets`, `enforce_stamps` |
| `[control]` | `auth_required`, `allowed` |
| `[logging]` | `loglevel` |

Optional hash-list files live next to `<config-dir>/config`:

| File | Meaning |
| --- | --- |
| `ignored` | Hashes loaded into the router ignored list. |
| `allowed` | Hashes loaded into the router delivery allow-list. Empty means no allow-list restriction. |

Hash-list files accept one raw 32-character hex destination hash per line.

## Delivery Model

LXMF supports several delivery shapes. rsLXMF exposes them through the router
and, where network-backed, through `lxmd-rs --send-method`.

| Method | Behavior |
| --- | --- |
| Opportunistic | Single-packet delivery when the packed message fits the Reticulum packet path. Oversized opportunistic messages are downgraded to Direct by the router. |
| Direct | Link-backed delivery over a Reticulum Link, with resource transfer for larger content. |
| Propagated | Store-and-forward delivery through a propagation node, including deposit, retrieve, peer sync, stamps, and tickets. |
| Paper | Library support for `lxm://` URI generation and ingest. The CLI does not generate QR images. |

An ordinary direct or opportunistic LXMF message is a signed Reticulum payload:

```text
destination_hash  16 bytes
source_hash       16 bytes
signature         64 bytes
payload           MessagePack([timestamp, title, content, fields, optional_stamp])
```

`title` and `content` are bytes on the wire. `fields` is a `map<u8, bytes>` for
application-defined data such as tickets, attachments, location data, or
application envelopes.


## Feature Status

| Area | Current behavior |
| --- | --- |
| Message format | Signed LXMF envelopes, custom field maps, propagation wrappers, `.lxm` containers, and paper URI encode/decode. |
| Delivery | Opportunistic, Direct, Propagated, callbacks, failure callbacks, cancellation, progress state, and opportunistic-to-direct downgrade. |
| Propagation | Disk-backed store, deposit, retrieve, peer sync, autopeer/static peers, weighted culling, duplicate checks, size checks, and stamp checks. |
| Stamps and tickets | Soft/hard stamp validation, HKDF-expanded workblocks, cached destination stamp costs, propagation tickets, and restart-safe ticket persistence. |
| Control | `--status`, `--peers`, `--sync`, and `--break` over the propagation-control link. |
| Access lists | `ignored` and `allowed` hash-list files in the LXMF config directory. |

## Compatibility Notes

Most daemon and control flags are implemented: `--config`, `--rnsconfig`,
`--propagation-node`, `--on-inbound`, `--status`, `--peers`, `--sync`,
`--break`, `--remote`, `--identity`, `--timeout`, `--exampleconfig`, and
`--version`.

Additional rsLXMF-only flags: `--send`, `--send-file`, `--send-method`,
`--send-timeout-secs`, and `--send-fields-json`.

## Contributing

If the issue or contribution belongs upstream as well, start there. Python LXMF
and Reticulum remain the reference implementations.

PRs are closed for now until I have time to catch up on everything. I'm tired.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
