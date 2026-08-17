# Changelog

## Unreleased

- Added the exact-reexport `lxmf_core::message_api` facade, a compiled message
  example, and canonical/legacy external-consumer coverage while retaining all
  existing module paths and leaving router, delivery, propagation, wire, and
  persistence behavior unchanged.
- Classified `lxmf-core` as candidate stable and `lxmf-tools` as tool internal,
  with pinned CI-enforced public API snapshots and no visibility or signature
  change.
- Made source releases reproducible from an existing immutable component tag:
  packages are non-publishable by default and expose Rust 1.87 metadata,
  release builds use the committed lockfile and exact dependency commits,
  actions are commit-pinned, and CI verifies the release-source contract.
- Replaced temporary aspect-wide announce handlers in remote-control lookup
  with bounded validated destination recall, and made lxmd's delivery and
  propagation observers exact owned subscriptions with deterministic cleanup.
- Matched current Python LXMF 1.1.0's fresh `lxmd` direct-delivery Resource
  admission default of 1 decimal KB, while keeping the reusable router's
  separate 1000 KB library default and preserving explicit configured limits.
- Bound Direct-delivery, propagation-download, and propagation-sync Link
  initiators to the authenticated LRPROOF ingress interface before LRRTT,
  routed all established-Link traffic through ordered typed endpoints, and
  made reverse delivery proofs durable before plaintext publication.
- Bounded propagation-sync transport staging, scoped Link endpoint failures
  to their owning operation, and prevented Resource responses from becoming
  visible when their delivery proof cannot be retained.
- Made typed Link sends fail closed on rejected transport admission, delayed
  reverse plaintext and propagation responses until their proofs are reliably
  admitted, and made failed graceful closes unbind before deregistration.
- Added automatic pre-sign reply-ticket issue, signature-gated inbound
  learning, directional migration-safe persistence, and proof-gated delivery
  accounting, with live Python restart/reply interoperability.
- Made Opportunistic one-shot delivery wait for an authenticated Reticulum
  proof, with atomic receipt-first dispatch and bounded retries.
- Moved propagation-store persistence off the daemon loop through
  reserve/write/commit transactions so visibility, handled IDs and counters
  advance only after durable writes.
- Added coalescing announce handoff, live allow-list rotation and split
  peer-Resource convergence coverage.
- Made one-shot remote control commands wait for a real online Reticulum
  interface before opening their Link, avoiding stale-path startup loss.

## 1.1.0 - 2026-07-26

- Added bounded propagation-node admission, exact inbound Resource ownership,
  asynchronous validation, and peer-specific throttling.
- Completed live peer offer preparation, encrypted Resource synchronization,
  cancellation, and proof-gated convergence.
- Added public inbound Resource tracking and cancellation plus restart-safe
  persistence and packet/Resource deduplication.
- Unified safe name presentation and authoritative propagation transfer
  status, including restart protection.
- Aligned `lxmd-rs` delivery and stamp defaults with the proven Python LXMF
  compatibility target.
