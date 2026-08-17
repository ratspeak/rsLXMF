# LXMF message API

`lxmf_core::message_api` is the canonical application path for constructing
and inspecting LXMF message values. It contains exact re-exports of the
existing message, status, and identifier identities; all module-qualified
paths remain supported.

The compiled `lxmf-core` `message` example demonstrates construction, signing,
packing, and unpacking. Its imports are the facade conformance contract.

This first boundary is deliberately narrower than an LXMF router facade.
`LxmRouter`, delivery ownership, propagation clients/nodes, handlers,
persistence, and raw Reticulum transport channels remain provisional,
module-qualified orchestration APIs. The facade does not alter wire fields,
signatures, serialization, delivery methods, proofs, or persistence.

Compatibility is checked by the reviewed API snapshot, the manifest/feature
contract, an additions-only comparison with the immutable Wave C floor, and an
external crate that compiles both canonical and retained imports. Platform,
wire, persistence, and Python interoperability gates remain separate evidence.
