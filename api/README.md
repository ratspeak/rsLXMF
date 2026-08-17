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
