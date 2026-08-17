# API stability

rsLXMF is currently source-distributed with `publish = false`. The current
Rust module tree is useful to source consumers, but only part of it is an
intentional long-term library boundary.

`api-stability.json` classifies every library package and pins the exact
pre-boundary commit. `api-baseline/*.txt` contains the complete explicit public
surface observed by pinned `cargo-public-api` and rustdoc versions. CI rejects
unreviewed drift. These snapshots are compatibility evidence, not a promise
that every listed state-machine field or helper will remain public forever.

`lxmf-core` is **candidate stable** as a package. Its message, presentation,
ticket, routing, propagation, sync, and public delivery concepts are intended
consumer capabilities. Its current modules also expose handler plumbing,
persistence representations, admission machinery, Link-delivery state, and
other orchestration details that remain provisional until the API-boundary
checkpoint. `lxmf-tools` is **tool internal** and exists to support `lxmd-rs`;
it is not a library compatibility commitment.

No visibility, signature, serialization, wire, persistence, or runtime change
is made by establishing this baseline. Any later boundary reduction must first
show the public API diff, migrate Ratspeak and other first-party users, preserve
the supported facade, and make an explicit version/changelog decision.

The canonical snapshot uses all features on `aarch64-apple-darwin` and omits
auto-derived, auto-trait, and blanket implementations. Other target overlays
remain covered by existing build and interop gates rather than this first
host API snapshot.

```sh
cargo install cargo-public-api --version 0.52.0 --locked
rustup toolchain install nightly-2026-08-01 --profile minimal
python3 tools/check-api-baseline.py
python3 tools/check-api-manifest.py
python3 tools/check-api-compatibility.py
```

The immutable floor and current captured snapshot source are separate
identities in `api-stability.json`. The manifest contract covers features,
targets, MSRV, and non-development dependencies that one Apple/all-feature API
view cannot prove. The compatibility check currently rejects every removal
from the Wave C floor; it complements rather than replaces feature, platform,
wire, persistence, and interoperability evidence.

Run with `--update` only after reviewing and recording the compatibility
impact; refreshing a snapshot is never a substitute for that review.
