# Rust API

Application code that constructs or inspects LXMF messages should use
`lxmf_core::message_api`. It re-exports the existing message, status, and
identifier types without wrapping or replacing them. The original
module-qualified paths remain supported.

The compiled `lxmf-core` `message` example demonstrates message construction,
signing, packing, and unpacking through this path.

## Stability

`lxmf-core` is candidate stable, but that classification does not make every
public implementation detail a permanent API. The message facade is the
recommended application path. Router ownership, delivery orchestration,
propagation clients and nodes, handlers, persistence representations,
admission machinery, Link-delivery state, and raw Reticulum channels remain
provisional module-qualified APIs.

`lxmf-tools` supports the `lxmd-rs` binary and is not a public library
integration target.

The message facade changes no wire fields, signatures, serialization,
delivery methods, proofs, persistence, or runtime behavior. Later reductions
to the broader module tree require a reviewed API diff, downstream migration,
and an explicit version decision.

## Delivery-owner integration

`LinkDeliveryManager::poll_ready` lets one embedding task wait for inbound
delivery packets, local admission acknowledgements, endpoint lifecycle changes,
and staged-transport capacity. On readiness, call `drain_events` and `tick`.
Keep periodic ticks for protocol deadlines, but schedule application maintenance
separately. Drains are bounded and may leave another ready turn. Cancelling the
wait does not discard a packet or publish an unread endpoint binding; existing
periodic consumers remain supported. The API is provisional delivery-owner
integration (LXMF-02/03, RET-05/07), not a new wire protocol or success signal.

`LinkDeliveryManager::set_link_endpoint_dispatch_handle` opts Direct packet
sends into the Reticulum owner's exact local-admission receipts. Supply the
handle from the same runtime that owns the manager's transport channel.
Local FIFO residence and the subsequent measured-RTT proof wait are different
phases; neither is a recipient delivery confirmation.

Applications using responder-owned backchannels should forward the ordered
`LinkManagerAccountingEvent` packet and Resource wait observations through
`observe_backchannel_packet_wait` and `observe_backchannel_resource_wait`,
retaining the exact packet/resource identity and original timestamps.
Forward the optional exact packet-cancellation capability with its original
wait observation as well. A separate application owner can then cancel a
packet still awaiting local admission without closing the shared Link. This
cannot retract driver-admitted bytes. When a command receipt cannot be
published to its message owner, retain its exact identity for bounded cleanup;
close and drain a oneshot receiver before discarding it to fence concurrent
publication.
Adapters implementing that close-and-drain protocol can install their sender
with `set_cancellation_aware_backchannel_sender`, allowing cancellation before
the command receipt arrives to notify the adapter immediately. The existing
`set_backchannel_sender` retains legacy receipt-after-cancellation behavior.
Each pending send captures its adapter policy; replacing a sender does not
retroactively change cancellation semantics for older sends.
`message_timeout_window` exposes the finite current owner window for an outer
orphan watchdog. Externally observed Resource windows include a bounded
180-second notification allowance measured from the original protocol deadline;
this does not alter the Resource engine's timeout or delay explicit terminal
events. It is not renewed by receiving the same observation or by keepalives.
Queued messages without an active protocol owner receive no
blanket timeout exemption. Explicit rejection and cancellation are not evidence
of a failed route.

When an authenticated recipient announcement rules out compression, call
`LinkDeliveryManager::disable_pending_direct_compression` before advancing
ready delivery events. It updates unconstructed Direct Resources and queued
messages, including Link setup waits. Constructed Resources and split plans
remain immutable, and propagation envelopes keep their independent policy.
The call only disables compression; new submissions still carry their policy.
This additive API remains provisional delivery-owner integration.

Applications that reserve inbound attachment memory can opt into
`set_inbound_resource_completion_handler`. It receives one owned completed
payload before the ordinary conclusion callback, so an application can move
its exact Link/Resource reservation into a queued payload and retain it through
processing. This synchronous callback must not block. It replaces the legacy
inbound packet-channel delivery for that Resource, without cloning the data;
applications that do not install it keep the existing completion behavior.

## Compatibility checks

The `api/` directory contains the evidence used by CI:

- `stability.json` records package tiers, source commits, snapshot hashes, and
  the current review decision;
- `snapshots/` records the explicit all-feature Apple ARM64 Rust API and the
  manifest, feature, dependency, target, and MSRV contract; and
- `fixtures/` compiles recommended and retained imports as an external
  consumer.

These checks catch accidental changes, but they do not replace platform builds,
wire and persistence tests, Python interoperability, or manual review. The API
snapshot omits auto-derived, auto-trait, and blanket implementations and is not
by itself a complete SemVer verdict.

Run the checks with:

```sh
python3 tools/check-api-baseline.py
python3 tools/check-api-manifest.py
python3 tools/check-api-compatibility.py
cargo check --manifest-path api/fixtures/Cargo.toml --locked
```

Snapshot updates require a clean source commit and an explicit review recorded
in `api/stability.json`. Additions, removals, deprecations, platform impact, and
version consequences must be reviewed before accepting new evidence.
