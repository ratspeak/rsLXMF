# Migrating to the next rsLXMF release (draft)

This draft covers source and behaviour changes since the published 1.4.0
release (commit `00f439d`). The crates now follow LXMF 1.3.0 on Reticulum
1.6.0. The release number belongs to the owner. Upstream references are to
LXMF 1.3.0 (`LXMF/...:line`) and Reticulum 1.6.0 (`RNS/...:line`).
`api/stability.json` lists every removed snapshot line under
`approvedBreakingChanges`.

Migrate together with the matching rsReticulum release, whose guide covers
`StampControl`, link request stamps and the runtime changes.

## Stamp costs are fractional

LXMF 1.3.0 takes stamp values from `RNS.Stamps.stamp_value`, which returns a
float (`LXMF/LXStamper.py:12`, `RNS/Stamps.py:104`). Its router costs are
floats too (`PEERING_COST = 18.0`, `PROPAGATION_COST = 16.0`,
`LXMF/LXMRouter.py:63-67`). Every stamp cost, flexibility, peering cost and
stamp value in the API is now `f64`:

- the `constants::{PROPAGATION_COST, PROPAGATION_COST_MIN, PROPAGATION_COST_FLEX,
  PEERING_COST, MAX_PEERING_COST, COST_TICKET}` constants;
- `RouterConfig::{stamp_cost, propagation_stamp_cost, propagation_stamp_flex}`
  and `RouterConfigExt::{peering_cost, max_peering_cost, propagation_cost_min}`;
- `LxmRouter::{set_stamp_cost, get_stamp_cost, set_stamp_requirements,
  get_outbound_lxm_stamp_cost, get_outbound_lxm_propagation_stamp_cost,
  validate_stamp, validate_stamp_with_tickets}`;
- `LxMessageDraft::stamp_cost`, `SignedLxMessage::stamp_cost()`,
  `LxMessage::{validate_stamp_with_tickets, validated_stamp_value}`;
- the `LxmPeer`, `OutboundOfferPolicy`, `AutopeerCandidate`, `PeerStats`,
  `NodeStats`, `PropagationEntry`, `PropagationNodeConfig`,
  `AdvertisedNodePolicy` and `RecoveryPolicy` cost fields;
- `PropagationNode::{min_stamp_cost, set_min_stamp_cost, create_offer,
  accept_stamped_propagated_blob, plan_accept_stamped_propagated_blob}`,
  `ValidatedOpaquePropagationBlob::{validate, stamp_value}`;
- `handlers::{get_announce_app_data, parse_announce_app_data,
  stamp_cost_from_app_data, pn_stamp_cost_from_app_data}`. The announce cost
  slot may be an int or a float (`LXMF/LXMF.py:183-195`).

`StampCostEntry::cost` is `Option<f64>`. A destination that announces no cost
is recorded as `None`, as `outbound_stamp_costs[dest] = [time, stamp_cost]`
stores `None` (`LXMF/LXMRouter.py:1160`).

```rust
// old
router.set_stamp_cost(dest, 8);
// new
router.set_stamp_cost(dest, 8.0);
```

### Stamper

| Old | New |
| --- | --- |
| `stamper::generate_stamp(&[u8], u8, usize) -> Option<([u8; 32], u32)>` | `generate_stamp(&[u8], f64, usize, &StampControl) -> Result<Option<([u8; 32], f64)>, StampError>` |
| `generate_stamp_cancellable(.., &AtomicBool)`, `generate_stamp_limited`, `stamp_iteration_cap` | `generate_stamp` with `StampControl { cancel, deadline, threads }` |
| `stamper::stamp_value`, `stamper::stamp_workblock` | `rns_identity::stamps::{stamp_value, stamp_workblock}` |
| `stamp_valid(&[u8; 32], u8, &[u8])` | `stamp_valid(&[u8], f64, &[u8])` |
| `validate_stamp(&[u8; 32], &[u8; 32], u8, usize)` | `validate_stamp(&[u8; 32], &[u8], f64, usize)` |
| `validate_peering_key(&[u8], &[u8; 32], u8)` | `validate_peering_key(&[u8], &[u8], f64)` (`LXMF/LXStamper.py:26-29`) |
| `validate_pn_stamp(&[u8], u8)`, `PropagationStampParts` with a `u32` value | `f64` value |
| `spawn_deferred_stamp(_on)(.., u8, ..)`, `DeferredStampResult::Success { value: u32 }` | `f64`; new `DeferredStampResult::Failed(StampError)` |
| `PropagationEnvelope::new_cancellable(.., &AtomicBool)`, `pack_for_cancellable(.., &AtomicBool)` | `&StampControl` |
| `LxmPeer::generate_peering_key(&mut self, &[u8; 16], &[u8; 16])` | adds `&StampControl` |
| `LxmfDiscoveryStamper::{generate, valid, value}` | `f64` costs; `generate` takes `&StampControl` |

```rust
let control = rns_identity::stamps::StampControl::default();
let stamp = lxmf_core::stamper::generate_stamp(&material, 8.0, 3000, &control)?;
```

## LXMF delivery (outbound queue)

The router's outbound pass follows `LXMRouter.process_outbound`
(`LXMF/LXMRouter.py:3050`). It returns embedder work instead of per-method
deliveries:

| Old `OutboundAction` | New |
| --- | --- |
| `DeliverOpportunistic { dest_hash, message }` | `SendOpportunistic { message }` |
| `DeliverDirect { dest_hash, message }`, `PlanDirect { dest_hash, message, plan }`, `DeliverPropagated { prop_hash, message }` | `DeliverOverLink { target, message, plan: LinkDeliveryPlan }` (`UseLink` or `StartLink { hops }`), for Direct and Propagated |
| path requests issued inside planning | `RequestPath { destination, drop_existing }` |
| `Expired(message)` | `Failed(message)`: the failure callback has run |

These helpers are removed:

- `DirectDeliveryPlan`, `DirectDeliveryPlanInput`, `DirectRouteSnapshot`,
  `plan_direct_delivery`;
- `LxmRouter::process_outbound_with_direct`, `defer_outbound_for_path_request`.

Call `process_outbound_with_inputs(&OutboundInputs, now)` with a snapshot of
known identities, links and routes (`OutboundInputs::medium: MediumSnapshot`).
Use `await_outbound_path` / `outbound_link_closed` for the path and link
callbacks. `process_outbound()` keeps working with empty inputs.

`MessageMetadata::ratchet_id` is `Option<Vec<u8>>`. It holds the 10-byte
ratchet id or the 16-byte link id the message arrived under, as
`lxmf_delivery(.., ratchet_id=packet.ratchet_id ..)` passes either
(`LXMF/LXMRouter.py:2165-2173`, `RNS/Identity.py:521-522`).
`MessageMetadata` gains upstream's delivery fields (`stamp_checked`,
`stamp_valid`, `sent_on_path`, `awaiting_path`, ...).

**Paper messages.** `LxmRouter::ingest_lxm_uri(&mut self, uri, decrypt)`
becomes `ingest_lxm_uri(uri, allow_duplicate, decrypt) ->
Result<PaperIngest, _>`. `PaperIngest::Delivered(Box<LxMessage>)` or
`Duplicate` replaces upstream's `signal_local_delivery`/`signal_duplicate`
callbacks (`LXMF/LXMRouter.py:2905`).

`DeliveryRatchetState::create_announce` takes a trailing
`Option<&AnnounceStampExt>` for the stamped announce.

## Propagation

- `LxmRouter::sync_peers(&mut self) -> Vec<[u8; 16]>` becomes
  `sync_peers(&mut self, now, store_bytes) -> PeerSyncPass { culled, selected }`.
  This follows the cull-then-select pass in `LXMF/LXMRouter.py:2468-2516`.
  `select_sync_peer` takes the current time.
- `LxmRouter::sync_peer_policies_for_store` is removed.
- `LxmPeer::unhandled_messages` is now a public
  `HashSet<PropagationTransientId>` instead of a count method. Use
  `unhandled_message_count()`.
- `add_unhandled_message(&mut self)` takes the transient id, as
  `add_unhandled_message(transient_id)` does (`LXMF/LXMPeer.py:588-626`).
  `set_unhandled_count` is removed.
- `LxmPeer::peering_key` stores `([u8; 32], f64)`, and `peering_key_value()`
  returns `Option<f64>`.
- Transfer and sync limits keep Python's number kind: lxmd's defaults are ints
  and configured values are floats, and the announce packs whichever it holds
  (`LXMF/LXMRouter.py:394-395`). The following fields are now
  `handlers::PnLimit` (`Int(u64)` or `Float(f64)`, `From<u64>`/`From<f64>`):
  - `PropagationNodeAnnounceData::{transfer_limit, sync_limit}`;
  - `DaemonConfig::{propagation_limit_kb, sync_limit_kb}`;
  - `PythonLxmdConfig::propagation_{transfer,sync}_max_accepted_size`.

  `PropagationNodeAnnounceData::new` takes `impl Into<PnLimit>` for both.
  `RouterConfig::{propagation_limit_kb, sync_limit_kb}`, `NodeStats` limits and
  `LxmRouter::set_propagation_limit` are `f64`.
- `PropagationClientState`, `SyncTaskState` and `PeerSyncTerminalState` gain
  `NoPath`, `PathRequested`, `NoAccess`, `Throttled`, `LinkFailed`,
  `TransferFailed` and `NoIdentityReceived`, where they apply.
  `PropagationAdmission` gains `AlreadyProcessed`. Exhaustive matches need the
  new arms.

## Tools (lxmd library)

- `DaemonConfig::from_config` and `PythonLxmdConfig::from_config` return
  `Result<Self, DaemonConfigError>`. lxmd exits when `as_float`/`as_int`/
  `as_bool` raise on a malformed key (`LXMF/Utilities/lxmd.py:187-240`):

  ```rust
  let config = lxmf_tools::daemon::DaemonConfig::from_config(&cfg)?;
  ```

- The `PythonLxmdConfig` cost fields are `f64` instead of `i64`, read with
  `as_float` (`LXMF/Utilities/lxmd.py:187-215`). `DaemonConfig` cost fields are
  `f64`.
- `lxmd_control::encode_router_control_stats` takes a trailing per-peer lookup
  closure. `encode_nil_response` is removed.
- `lxmd_runtime::delivery_announce_app_data` takes `Option<f64>`.

## New fields and variants

Exhaustive literals and matches over these types need updating:

- `MessageMetadata`, `PropagationNodeAnnounceData`, `LxmPeer`,
  `OutboundOfferPolicy`;
- `RouterConfigExt` (`pn_stamp_throttle`), `PnInboundAdmissionConfig`,
  `DirectLinkSnapshot`;
- `DaemonConfig`, `PythonLxmdConfig` (`propagation_stamp_throttle`);
- `LinkDeliveryStartError::StampFailure`, `SendError::ContentTooLarge`.

## Behaviour and configuration an operator sees

- **Strict lxmd config.** A malformed number or boolean in lxmd's config now
  stops lxmd with a `DaemonConfigError`. 1.4.0 fell back to the default.
  Costs below their floor are raised to it, as `lxmd.py` does
  (`LXMF/Utilities/lxmd.py:187-215`); a cost of 100 or more, which upstream
  accepts but no stamp can meet, is rejected at load.
- **Stored files.**
  - Delivered message ids are journaled in `delivery_claims` in the router's
    storage directory.
  - Admission bodies move from the messages directory to
    `download-admission-bodies` under the router state directory. Bodies still
    in the old place are moved on first start.
  - lxmd keeps one processed-message store.
- **Log levels.** lxmd starts at Notice (3) without a `loglevel` key and always
  applies `-v`/`-q`, as `lxmd.py` does. Control commands log at Notice on
  stdout.
- **Link MTU and stamps.** Delivery, the propagation client and peer sync open
  links that signal the next hop's MTU and carry link request stamps at the
  cost the destination announced. These follow the Reticulum
  `link_mtu_discovery` and `[stamps]` settings.
