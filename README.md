<div align="center">

# rsLXMF

**Rust LXMF messaging and propagation for Reticulum.**

[![License: Reticulum License](https://img.shields.io/badge/license-Reticulum%20License-blue.svg)](LICENSE)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)
[![Baseline: LXMF 1.3.1](https://img.shields.io/badge/baseline-LXMF%201.3.1-success.svg)](https://github.com/markqvist/LXMF)
[![Reticulum 1.6.1](https://img.shields.io/badge/reticulum-1.6.1-blue.svg)](https://reticulum.network/)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#feature-status)

[LXMF Reference](https://github.com/markqvist/LXMF) |
[Reticulum Manual](https://reticulum.network/manual/) |
[rsReticulum](https://github.com/ratspeak/rsReticulum) |
[Ratspeak](https://github.com/ratspeak/Ratspeak)

</div>

---

rsLXMF is a Rust port of [LXMF](https://github.com/markqvist/LXMF), the
Reticulum messaging layer, from the reference implementation by Mark Qvist. It
was written from the reference source, not from a specification, and tracks the
reference's wire behavior release by release.

## Contents

- [Build It](#build-it)
- [Rust API](api/README.md)
- [Operating lxmd-rs](#operating-lxmd-rs)
- [Configuration](#configuration)
- [Delivery Model](#delivery-model)
- [Feature Status](#feature-status)
- [Compatibility Notes](#compatibility-notes)
- [License](#license)

## Build It

This guide describes the 1.5.1 release, [v1.5.1](https://github.com/ratspeak/rsLXMF/releases/tag/v1.5.1), built with rsReticulum [v1.5.1](https://github.com/ratspeak/rsReticulum/releases/tag/v1.5.1), the source line Ratspeak builds from.

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
git -C rsReticulum checkout --detach v1.5.1
git -C rsLXMF checkout --detach v1.5.1
cd rsLXMF
```

Run the build commands below from that `rsLXMF` directory. The host crates require Rust 1.89 or newer. The default build compiles a bundled SQLite, so it also needs a C compiler; the build tools below provide one.

### macOS

Install Rust with `rustup`, then install Apple's build tools:

```bash
xcode-select --install
```

Build from the sibling checkout:

```bash
cargo build --release --locked
```

### Linux / Raspberry Pi

#### Install Rust with `rustup`, then install the needed packages:

Debian, Ubuntu, and Raspberry Pi OS:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config
```

Fedora:

```bash
sudo dnf install gcc make pkgconf-pkg-config
```

Arch:

```bash
sudo pacman -S --needed base-devel pkgconf
```

#### Build the daemon:

```bash
cargo build --release --locked
```

### Windows

Install Rust with the MSVC toolchain. If Rust or Cargo asks for Visual Studio
Build Tools, install the "Desktop development with C++" workload.

Build from PowerShell:

```powershell
cargo build --release --locked
```

After the build, use the commands below with `./target/release/lxmd-rs` on
macOS/Linux or `.\target\release\lxmd-rs.exe` on Windows.

## Operating lxmd-rs

`lxmf-tools` builds one public command name:

| Binary | Purpose |
| --- | --- |
| lxmd-rs | Rust LXMF daemon and control utility. |



Print the example configuration to standard output:

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

Send a message and exit. Replace uppercase hash placeholders with the appropriate 32-character hexadecimal destination hash:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send "DELIVERY_DESTINATION_HASH" "message body"
```

The `--send` flag is an rsLXMF convenience. Normal
daemon and propagation-control operation does not require it for anything.

Send UTF-8 file content or select a delivery method:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send "DELIVERY_DESTINATION_HASH" --send-file ./message.txt --send-method direct
```

Supported `--send-method` values are `opportunistic`, `direct`, and
`propagated`. Paper messages aren't supported yet in the CLI.

Attach custom LXMF fields from scripts:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --send "DELIVERY_DESTINATION_HASH" "with fields" \
  --send-fields-json '{"200":"aGVsbG8=","201":"AAECAw=="}'
```

The CLI JSON object maps IDs from 0 to 255 to base64-encoded binary values.
Choose IDs and schemas agreed with the receiving application. This option
does not construct structured MessagePack fields such as an LRGP envelope;
use the library’s typed field API for those. The library supports a wider
integer ID range than this CLI convenience.

Control a propagation node:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --status
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --peers
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --sync "PEER_PROPAGATION_HASH"
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum --break "PEER_PROPAGATION_HASH"
```

These commands query an `lxmf.propagation.control` endpoint over Reticulum.
They do not inspect local files and do not start local daemon state. If no
reachable daemon answers, they time out with compatibility-oriented control
exit behavior.

For a remote propagation node, pass the node's propagation destination hash:

```bash
lxmd-rs --config ~/.rsLXMF --rnsconfig ~/.rsReticulum \
  --status --peers --remote "PROPAGATION_DESTINATION_HASH" --timeout 5
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

On Linux/macOS, the first two locations are selected only when their `config` file exists; otherwise the home-directory fallback is used.


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
isolated.

Minimal config:

```ini
[lxmf]
display_name = Rat
announce_at_start = no
# stamp_cost = 12
delivery_transfer_max_accepted_size = 1
# on_inbound = /path/to/handler

[propagation]
enable_node = no
announce_at_start = yes
autopeer = yes
autopeer_maxdepth = 6
auth_required = no
# node_name = Rat Nest
# static_peers = 0123456789abcdef0123456789abcdef
# outbound_node = 0123456789abcdef0123456789abcdef
# max_peers = 20
# propagation_stamp_cost_target = 16
# propagation_stamp_cost_flexibility = 3

[logging]
loglevel = 4
```

`delivery_transfer_max_accepted_size` limits incoming Direct Resource data
in decimal KB and defaults to 1 when omitted. The reusable router library has a separate 1000 KB default. Applications that accept
larger incoming messages should set their own explicit policy.

Common sections and supported keys (see `--exampleconfig` for annotated defaults):

| Section | Keys |
| --- | --- |
| `[lxmf]` | `display_name`, `announce_at_start`, `announce_interval`, `delivery_transfer_max_accepted_size`, `stamp_cost`, `on_inbound` |
| `[propagation]` | `enable_node`, `node_name`, `auth_required`, `announce_at_start`, `announce_interval`, `autopeer`, `autopeer_maxdepth`, `message_storage_limit`, `propagation_message_max_accepted_size`, `propagation_sync_max_accepted_size`, `propagation_stamp_cost_target`, `propagation_stamp_cost_flexibility`, `propagation_stamp_throttle`, `peering_cost`, `remote_peering_cost_max`, `max_peers`, `static_peers`, `prioritise_destinations`, `control_allowed`, `from_static_only`, `sequential_pn_stamp_validation`, `static_peers_bypass_sequential`, `max_inbound_syncs`, `outbound_node`, `propagation_stamp_cost`, `propagation_limit`, `enforce_stamps` |
| `[control]` | `auth_required`, `allowed` |
| `[logging]` | `loglevel` |

Optional hash-list files live next to `<config-dir>/config`:

| File | Meaning |
| --- | --- |
| `ignored` | LXMF destination hashes to ignore. |
| `allowed` | Reticulum **identity hashes** permitted to retrieve messages when propagation `auth_required = yes`. An empty list then admits no clients. |

Each file accepts one raw 32-character hex hash per line. The two files use different hash types. Propagation administration is separate: `control_allowed` contains authorized control identity hashes; the daemon’s own identity is also authorized. Client retrieval authorization does not make the node’s stored messages readable to other clients.

Router state (delivered and processed transient IDs, stamp costs, and tickets)
is kept in `<config-dir>/storage/lxmf/state.db`, the SQLite file LXMF 1.3.1 uses.
Received ratchets are kept
by Reticulum in its own storage. These stores come from the default
`sqlite-store` feature of `lxmf-core`; without it, router state lasts only for
the session.

## Delivery Model

LXMF supports several delivery shapes. rsLXMF exposes them through the router
and, where network-backed, through `lxmd-rs --send-method`.

| Method | Behavior |
| --- | --- |
| Opportunistic | Single-packet delivery when the packed message fits the Reticulum packet path. Delivery completes only after an authenticated Reticulum proof; bounded retries remain in flight until then. The router switches oversized opportunistic messages to Direct. |
| Direct | Link-backed delivery over a Reticulum Link, with resource transfer for larger content. |
| Propagated | Store-and-forward delivery through a propagation node, including deposit, retrieve, peer sync, stamps, and tickets. |
| Paper | Library support for `lxm://` URI generation and ingest. The CLI does not generate QR images. |

Direct and propagation Links use ordinary Reticulum path discovery only for
their initial LINKREQUEST. After a valid LRPROOF, rsLXMF pins the Link to that
proof's ingress interface and all later packets, Resources, proofs, keepalives,
and teardown use the same interface. A lost interface closes the Link instead
of silently rerouting it. Reverse Direct delivery is published only after its
role-correct proof has been admitted to that bound endpoint.

An ordinary direct or opportunistic LXMF message is a signed Reticulum payload:

```text
destination_hash  16 bytes
source_hash       16 bytes
signature         64 bytes
payload           MessagePack([timestamp, title, content, fields, optional_stamp])
```

`title` and `content` are bytes on the wire. `fields` maps integer IDs to
MessagePack values, which can be binary, text, arrays, maps or other supported
values. Standard fields have defined schemas. The library preserves signed
and unsigned integer IDs beyond the CLI’s 0–255 range and rejects duplicate
outer IDs. Encoding a structured field as a binary blob changes its meaning.

Construct `LxMessageDraft` and set `include_ticket` before calling
`LxmRouter::prepare_outbound`; any reply ticket it adds is already in the
router's state store when the call returns. Signing consumes the draft, and
finalization produces an immutable message.


## Feature Status

| Area | Current behavior |
| --- | --- |
| Message format | Signed LXMF envelopes, custom field maps, standard reply/reaction/comment fields, propagation wrappers, `.lxm` containers, and paper URI encode/decode. |
| Delivery | Opportunistic, Direct, Propagated, callbacks, failure callbacks, cancellation, progress state, opportunistic-to-direct fallback, and compression signalling in delivery announces. |
| Propagation | Transactional disk-backed store, deposit, retrieve, peer sync, autopeer/static peers, weighted culling, duplicate checks, size checks, and stamp checks. |
| Stamps and tickets | Soft/hard stamp validation, HKDF-expanded workblocks, fractional and cached destination stamp costs, automatic reply-ticket issue and signed learning, ticket-backed stamps, and restart-safe directional persistence. |
| Control | `--status`, `--peers`, `--sync`, and `--break` over the propagation-control link. |
| Access lists | `ignored` and `allowed` hash-list files in the LXMF config directory. |

## Compatibility Notes

All upstream `lxmd` flags are implemented: `--config`, `--rnsconfig`,
`--propagation-node`, `--on-inbound`, `--verbose`, `--quiet`, `--service`,
`--status`, `--peers`, `--sync`, `--break`, `--remote`, `--identity`,
`--timeout`, `--exampleconfig`, and `--version`.

Additional rsLXMF-only flags: `--send`, `--send-file`, `--send-method`,
`--send-timeout-secs`, and `--send-fields-json`.

rsLXMF 1.5.1 follows Python LXMF 1.3.1 with Reticulum 1.6.1, and
`lxmd-rs --version` names both.

## License

rsLXMF is licensed under the [Reticulum License](LICENSE), the license of the
reference implementation it is ported from. Copyright (c) 2020-2026 Mark Qvist,
unless otherwise noted; additions and modifications Copyright (c) 2026 Ratspeak
LLC.

The license is permissive with two conditions: no use in systems built to
purposefully harm people, and no use in or contribution to AI or language-model
training. The copyright and permission notice must stay in every copy.
[LICENSE](LICENSE) is the binding text.
