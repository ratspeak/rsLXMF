//! Pure admission and lifecycle accounting for inbound propagation-node syncs.
//!
//! Peering-key validation and Resource I/O deliberately live outside this
//! module. Callers first obtain a cheap [`PnOfferCandidate`] with
//! [`PnInboundAdmission::preflight_offer`], then validate the peering key and
//! determine the wanted response before calling
//! [`PnInboundAdmission::commit_validated_offer`]. Failed validation should
//! call [`PnInboundAdmission::discard_candidate`]; merely dropping a candidate
//! is also safe and is pruned on the next preflight.
//!
//! Every caller-supplied [`Duration`] for one coordinator instance must be
//! elapsed time from the same stable monotonic origin. Mixing origins or
//! supplying wall-clock values invalidates throttle-deadline ordering.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

use rns_identity::destination::Destination;

use crate::constants::PN_STAMP_THROTTLE;

const PROPAGATION_DESTINATION_NAME: &str = "lxmf.propagation";

/// Default maximum number of concurrently transferring or validating syncs.
pub const PN_DEFAULT_MAX_INBOUND_SYNCS: usize = 3;
/// Smallest accepted configured inbound-sync limit.
pub const PN_MIN_MAX_INBOUND_SYNCS: usize = 1;
/// Duration applied after a known peer submits an invalid-stamp batch.
pub const PN_INVALID_STAMP_THROTTLE: Duration = Duration::from_secs(PN_STAMP_THROTTLE);

/// Policy applied to inbound propagation-node offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PnInboundAdmissionConfig {
    /// Postpone non-bypassing offers while any stamp validation is active.
    pub sequential_validation: bool,
    /// Make static peers obey sequential validation and the inbound-sync cap.
    ///
    /// The LXMF default is `false`, so a configured static peer bypasses both
    /// admission gates.
    pub static_sequential: bool,
    /// Maximum concurrent Resources in `Transferring` or `Validating` state.
    pub max_inbound_syncs: usize,
    /// Accept propagation offers only from configured static peers.
    pub from_static_only: bool,
}

impl Default for PnInboundAdmissionConfig {
    fn default() -> Self {
        Self {
            sequential_validation: true,
            static_sequential: false,
            max_inbound_syncs: PN_DEFAULT_MAX_INBOUND_SYNCS,
            from_static_only: false,
        }
    }
}

/// The caller's already-computed wire response for an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnOfferResponse {
    HaveAll,
    WantAll,
    WantSome,
}

/// Why an otherwise well-formed offer was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnOfferRejection {
    NoIdentity,
    NoAccess,
    InvalidStampThrottle,
    SequentialValidationActive,
    InboundSyncLimit,
    LinkAlreadyTracked,
    LinkCandidatePending,
    StaleCandidate,
}

/// Result of applying admission policy to an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnOfferAdmission {
    /// The peer offered no messages that are wanted; no record was created.
    HaveAll,
    /// The wanted offer was recorded in [`PnInboundState::Accepted`].
    Accepted,
    Rejected(PnOfferRejection),
}

/// Opaque result of a successful cheap offer preflight.
///
/// The candidate binds the actual link ID to the known peer identity and its
/// derived propagation destination. It is intentionally neither `Clone` nor
/// `Copy`: the validated commit consumes it, and callers cannot substitute a
/// different link or identity at that boundary.
#[must_use = "a preflight candidate must be externally validated or discarded"]
pub struct PnOfferCandidate {
    link_id: [u8; 16],
    peer_identity_hash: [u8; 16],
    peer_destination_hash: [u8; 16],
    lifecycle: Arc<PnOfferLifecycleToken>,
}

struct PnOfferLifecycleToken;

impl PnOfferCandidate {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    /// Raw identity hash used by the caller's external peering-key validator.
    pub fn peer_identity_hash(&self) -> [u8; 16] {
        self.peer_identity_hash
    }

    pub fn peer_destination_hash(&self) -> [u8; 16] {
        self.peer_destination_hash
    }
}

impl fmt::Debug for PnOfferCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PnOfferCandidate")
            .field("link_id", &"<redacted>")
            .field("peer_identity_hash", &"<redacted>")
            .field("peer_destination_hash", &"<redacted>")
            .finish()
    }
}

/// Lifecycle state of a recorded, wanted propagation offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnInboundState {
    Accepted,
    Transferring,
    Validating,
}

/// Result of stamp validation for a transferred batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnValidationResult {
    Valid,
    InvalidStamp,
    Failed,
}

/// Why an invalid-stamp throttle could not be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnThrottleInstallError {
    /// An all-zero destination is an unknown-peer sentinel, not a known
    /// derived `lxmf.propagation` destination.
    UnknownPeerDestination,
}

/// State-machine operation used in typed transition errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnTransitionOperation {
    ResourceStarted,
    ResourceConcluded,
    ValidationConcluded,
}

/// An attempted non-terminal transition was not legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnTransitionError {
    LinkNotTracked,
    IllegalState {
        state: PnInboundState,
        operation: PnTransitionOperation,
    },
}

/// Outcome of an idempotent terminal cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnCleanupResult {
    Removed(PnInboundState),
    CandidateRevoked,
    NotTracked,
}

/// Outcome of explicitly discarding a preflight candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnCandidateDiscardResult {
    Discarded,
    Stale,
}

/// A wanted offer retained until its Resource or link reaches a terminal path.
#[derive(Clone, PartialEq, Eq)]
pub struct PnInboundRecord {
    peer_identity_hash: [u8; 16],
    peer_destination_hash: [u8; 16],
    offer_response: PnOfferResponse,
    state: PnInboundState,
}

impl PnInboundRecord {
    /// Raw identity hash retained for later peering-key or peer bookkeeping.
    pub fn peer_identity_hash(&self) -> &[u8; 16] {
        &self.peer_identity_hash
    }

    /// Derived `lxmf.propagation` SINGLE destination hash for the peer.
    pub fn peer_destination_hash(&self) -> &[u8; 16] {
        &self.peer_destination_hash
    }

    pub fn offer_response(&self) -> PnOfferResponse {
        self.offer_response
    }

    pub fn state(&self) -> PnInboundState {
        self.state
    }
}

impl fmt::Debug for PnInboundRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PnInboundRecord")
            .field("peer_identity_hash", &"<redacted>")
            .field("peer_destination_hash", &"<redacted>")
            .field("offer_response", &self.offer_response)
            .field("state", &self.state)
            .finish()
    }
}

/// Long-lived owner of inbound propagation offer accounting and throttles.
pub struct PnInboundAdmission {
    config: PnInboundAdmissionConfig,
    static_peers: HashSet<[u8; 16]>,
    records: HashMap<[u8; 16], PnInboundRecord>,
    pending_candidates: HashMap<[u8; 16], Weak<PnOfferLifecycleToken>>,
    throttle_deadlines: HashMap<[u8; 16], Duration>,
}

impl PnInboundAdmission {
    pub fn new(mut config: PnInboundAdmissionConfig) -> Self {
        config.max_inbound_syncs = config.max_inbound_syncs.max(PN_MIN_MAX_INBOUND_SYNCS);

        Self {
            config,
            static_peers: HashSet::new(),
            records: HashMap::new(),
            pending_candidates: HashMap::new(),
            throttle_deadlines: HashMap::new(),
        }
    }

    pub fn config(&self) -> PnInboundAdmissionConfig {
        self.config
    }

    /// Replace the configured static propagation destination hashes.
    pub fn set_static_peers<I>(&mut self, peers: I)
    where
        I: IntoIterator<Item = [u8; 16]>,
    {
        self.static_peers = peers.into_iter().collect();
    }

    pub fn add_static_peer(&mut self, peer_destination_hash: [u8; 16]) -> bool {
        self.static_peers.insert(peer_destination_hash)
    }

    pub fn remove_static_peer(&mut self, peer_destination_hash: &[u8; 16]) -> bool {
        self.static_peers.remove(peer_destination_hash)
    }

    pub fn is_static_peer(&self, peer_destination_hash: &[u8; 16]) -> bool {
        self.static_peers.contains(peer_destination_hash)
    }

    /// Derive the remote peer's `lxmf.propagation` destination hash.
    pub fn peer_destination_hash(peer_identity_hash: &[u8; 16]) -> [u8; 16] {
        Destination::hash_from_name_and_identity(
            PROPAGATION_DESTINATION_NAME,
            Some(peer_identity_hash),
        )
    }

    /// Apply all cheap gates before peering-key validation or wanted-ID work.
    ///
    /// A successful preflight creates no admission record. The returned
    /// candidate binds the link and peer values that the caller must use for
    /// external key validation.
    pub fn preflight_offer(
        &mut self,
        link_id: [u8; 16],
        peer_identity_hash: Option<[u8; 16]>,
        now: Duration,
    ) -> Result<PnOfferCandidate, PnOfferRejection> {
        self.prune_abandoned_candidates();

        let Some(peer_identity_hash) = peer_identity_hash else {
            return Err(PnOfferRejection::NoIdentity);
        };
        let peer_destination_hash = Self::peer_destination_hash(&peer_identity_hash);
        if self.pending_candidates.contains_key(&link_id) {
            return Err(PnOfferRejection::LinkCandidatePending);
        }
        self.check_offer_gates(&link_id, &peer_destination_hash, now)?;

        let lifecycle = Arc::new(PnOfferLifecycleToken);
        self.pending_candidates
            .insert(link_id, Arc::downgrade(&lifecycle));

        Ok(PnOfferCandidate {
            link_id,
            peer_identity_hash,
            peer_destination_hash,
            lifecycle,
        })
    }

    /// Commit the externally key-validated candidate and wanted response.
    ///
    /// Calling this method is the caller's assertion that peering-key
    /// validation succeeded for the exact values exposed by `candidate`.
    /// Every mutable admission gate is checked again before any record is
    /// created. The candidate is consumed and no replacement link or identity
    /// can be supplied at commit time.
    pub fn commit_validated_offer(
        &mut self,
        candidate: PnOfferCandidate,
        offer_response: PnOfferResponse,
        now: Duration,
    ) -> PnOfferAdmission {
        if !self.remove_exact_pending_candidate(&candidate) {
            return PnOfferAdmission::Rejected(PnOfferRejection::StaleCandidate);
        }

        if let Err(rejection) =
            self.check_offer_gates(&candidate.link_id, &candidate.peer_destination_hash, now)
        {
            return PnOfferAdmission::Rejected(rejection);
        }

        if offer_response == PnOfferResponse::HaveAll {
            return PnOfferAdmission::HaveAll;
        }

        self.records.insert(
            candidate.link_id,
            PnInboundRecord {
                peer_identity_hash: candidate.peer_identity_hash,
                peer_destination_hash: candidate.peer_destination_hash,
                offer_response,
                state: PnInboundState::Accepted,
            },
        );
        PnOfferAdmission::Accepted
    }

    /// Discard a candidate after external key validation or wanted-ID work
    /// fails.
    ///
    /// Dropping a candidate without calling this method is also safe: the next
    /// preflight prunes its abandoned weak lifecycle entry. Explicit discard
    /// releases the entry immediately.
    pub fn discard_candidate(&mut self, candidate: PnOfferCandidate) -> PnCandidateDiscardResult {
        if self.remove_exact_pending_candidate(&candidate) {
            PnCandidateDiscardResult::Discarded
        } else {
            PnCandidateDiscardResult::Stale
        }
    }

    fn check_offer_gates(
        &mut self,
        link_id: &[u8; 16],
        peer_destination_hash: &[u8; 16],
        now: Duration,
    ) -> Result<(), PnOfferRejection> {
        self.expire_throttles(now);

        let is_static = self.static_peers.contains(peer_destination_hash);
        // Match LXMF's observable policy precedence. Static peers bypass only
        // the sequential-validation and inbound-cap gates when configured to;
        // they never bypass a peer throttle or static-only access policy.
        let bypass_limits = is_static && !self.config.static_sequential;
        if !bypass_limits && self.config.sequential_validation && self.validation_count() != 0 {
            return Err(PnOfferRejection::SequentialValidationActive);
        }

        if !bypass_limits && self.inbound_sync_count() >= self.config.max_inbound_syncs {
            return Err(PnOfferRejection::InboundSyncLimit);
        }

        if self.throttle_deadlines.contains_key(peer_destination_hash) {
            return Err(PnOfferRejection::InvalidStampThrottle);
        }

        if self.config.from_static_only && !is_static {
            return Err(PnOfferRejection::NoAccess);
        }

        // This Rust-specific lifecycle guard follows the upstream policy
        // gates so their rejection precedence remains observable.
        if self.records.contains_key(link_id) {
            return Err(PnOfferRejection::LinkAlreadyTracked);
        }

        Ok(())
    }

    fn prune_abandoned_candidates(&mut self) {
        self.pending_candidates
            .retain(|_, lifecycle| lifecycle.upgrade().is_some());
    }

    fn remove_exact_pending_candidate(&mut self, candidate: &PnOfferCandidate) -> bool {
        let is_exact = self
            .pending_candidates
            .get(&candidate.link_id)
            .and_then(Weak::upgrade)
            .is_some_and(|pending| Arc::ptr_eq(&pending, &candidate.lifecycle));

        if is_exact {
            self.pending_candidates.remove(&candidate.link_id);
        }
        is_exact
    }

    pub fn record(&self, link_id: &[u8; 16]) -> Option<&PnInboundRecord> {
        self.records.get(link_id)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of syncs consuming the configured concurrency allowance.
    ///
    /// An accepted offer does not consume a transfer slot until its Resource
    /// starts. Both transfer and validation work do consume one.
    pub fn inbound_sync_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    PnInboundState::Transferring | PnInboundState::Validating
                )
            })
            .count()
    }

    pub fn validation_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.state == PnInboundState::Validating)
            .count()
    }

    /// Transition an accepted offer when its inbound Resource starts.
    pub fn resource_started(&mut self, link_id: &[u8; 16]) -> Result<(), PnTransitionError> {
        self.transition(
            link_id,
            PnInboundState::Accepted,
            PnInboundState::Transferring,
            PnTransitionOperation::ResourceStarted,
        )
    }

    /// Transition a completed inbound Resource into stamp validation.
    pub fn resource_concluded(&mut self, link_id: &[u8; 16]) -> Result<(), PnTransitionError> {
        self.transition(
            link_id,
            PnInboundState::Transferring,
            PnInboundState::Validating,
            PnTransitionOperation::ResourceConcluded,
        )
    }

    /// Conclude stamp validation and release all active accounting.
    ///
    /// Only [`PnValidationResult::InvalidStamp`] installs a throttle, and a
    /// throttle is possible only for a known peer retained in a valid record.
    /// Repeated conclusion after cleanup is a successful no-op.
    pub fn validation_concluded(
        &mut self,
        link_id: &[u8; 16],
        result: PnValidationResult,
        now: Duration,
    ) -> Result<PnCleanupResult, PnTransitionError> {
        let Some(record) = self.records.get(link_id) else {
            return Ok(PnCleanupResult::NotTracked);
        };
        if record.state != PnInboundState::Validating {
            return Err(PnTransitionError::IllegalState {
                state: record.state,
                operation: PnTransitionOperation::ValidationConcluded,
            });
        }

        let record = self
            .records
            .remove(link_id)
            .expect("record existence checked above");
        if result == PnValidationResult::InvalidStamp {
            // A record's destination was derived from an identified peer at
            // preflight. Ignore only the reserved all-zero unknown sentinel.
            let _ = self.install_invalid_stamp_throttle(record.peer_destination_hash, now);
        }

        Ok(PnCleanupResult::Removed(PnInboundState::Validating))
    }

    /// Install the standard throttle after invalid stamp validation for a
    /// known peer, including an unsolicited Resource with no offer record.
    ///
    /// `peer_destination_hash` must be the peer's already-derived
    /// `lxmf.propagation` SINGLE destination hash. The all-zero value is
    /// rejected so callers cannot accidentally turn an unknown identity into
    /// shared throttle state. `now` must use the same monotonic origin as the
    /// other admission calls.
    pub fn install_invalid_stamp_throttle(
        &mut self,
        peer_destination_hash: [u8; 16],
        now: Duration,
    ) -> Result<Duration, PnThrottleInstallError> {
        if peer_destination_hash == [0; 16] {
            return Err(PnThrottleInstallError::UnknownPeerDestination);
        }

        let requested_deadline = now.saturating_add(PN_INVALID_STAMP_THROTTLE);
        let deadline = self
            .throttle_deadlines
            .entry(peer_destination_hash)
            .and_modify(|deadline| *deadline = (*deadline).max(requested_deadline))
            .or_insert(requested_deadline);
        Ok(*deadline)
    }

    /// Release an accepted offer after its Resource advertisement is rejected.
    pub fn resource_rejected(&mut self, link_id: &[u8; 16]) -> PnCleanupResult {
        self.remove_record(link_id)
    }

    /// Release accounting after Resource cancellation.
    pub fn resource_cancelled(&mut self, link_id: &[u8; 16]) -> PnCleanupResult {
        self.remove_record(link_id)
    }

    /// Release accounting after Resource failure.
    pub fn resource_failed(&mut self, link_id: &[u8; 16]) -> PnCleanupResult {
        self.remove_record(link_id)
    }

    /// Release accounting when the owning Reticulum link closes.
    pub fn link_closed(&mut self, link_id: &[u8; 16]) -> PnCleanupResult {
        let candidate_revoked = self.pending_candidates.remove(link_id).is_some();
        match self.remove_record(link_id) {
            PnCleanupResult::NotTracked if candidate_revoked => PnCleanupResult::CandidateRevoked,
            result => result,
        }
    }

    /// Remove expired invalid-stamp throttles using caller-supplied time.
    pub fn expire_throttles(&mut self, now: Duration) {
        self.throttle_deadlines
            .retain(|_, deadline| *deadline > now);
    }

    pub fn is_peer_throttled(&mut self, peer_destination_hash: &[u8; 16], now: Duration) -> bool {
        self.expire_throttles(now);
        self.throttle_deadlines.contains_key(peer_destination_hash)
    }

    pub fn throttle_deadline(
        &mut self,
        peer_destination_hash: &[u8; 16],
        now: Duration,
    ) -> Option<Duration> {
        self.expire_throttles(now);
        self.throttle_deadlines.get(peer_destination_hash).copied()
    }

    pub fn throttle_count(&self) -> usize {
        self.throttle_deadlines.len()
    }

    fn transition(
        &mut self,
        link_id: &[u8; 16],
        expected: PnInboundState,
        next: PnInboundState,
        operation: PnTransitionOperation,
    ) -> Result<(), PnTransitionError> {
        let record = self
            .records
            .get_mut(link_id)
            .ok_or(PnTransitionError::LinkNotTracked)?;
        if record.state != expected {
            return Err(PnTransitionError::IllegalState {
                state: record.state,
                operation,
            });
        }

        record.state = next;
        Ok(())
    }

    fn remove_record(&mut self, link_id: &[u8; 16]) -> PnCleanupResult {
        self.records
            .remove(link_id)
            .map(|record| PnCleanupResult::Removed(record.state))
            .unwrap_or(PnCleanupResult::NotTracked)
    }
}

impl Default for PnInboundAdmission {
    fn default() -> Self {
        Self::new(PnInboundAdmissionConfig::default())
    }
}

impl fmt::Debug for PnInboundAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PnInboundAdmission")
            .field("config", &self.config)
            .field("static_peer_count", &self.static_peers.len())
            .field("pending_candidate_count", &self.pending_candidates.len())
            .field("record_count", &self.records.len())
            .field("inbound_sync_count", &self.inbound_sync_count())
            .field("validation_count", &self.validation_count())
            .field("throttle_count", &self.throttle_deadlines.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NOW: Duration = Duration::from_secs(1_000);

    fn identity(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn link(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn admit(
        admission: &mut PnInboundAdmission,
        link_id: [u8; 16],
        identity_hash: [u8; 16],
        response: PnOfferResponse,
    ) -> PnOfferAdmission {
        let candidate = admission
            .preflight_offer(link_id, Some(identity_hash), TEST_NOW)
            .expect("test offer passes preflight");
        admission.commit_validated_offer(candidate, response, TEST_NOW)
    }

    fn start_validation(admission: &mut PnInboundAdmission, link_id: &[u8; 16]) {
        admission.resource_started(link_id).unwrap();
        admission.resource_concluded(link_id).unwrap();
    }

    #[test]
    fn defaults_match_lxmf_and_configured_limit_has_a_floor() {
        let defaults = PnInboundAdmission::default();
        assert_eq!(
            defaults.config(),
            PnInboundAdmissionConfig {
                sequential_validation: true,
                static_sequential: false,
                max_inbound_syncs: 3,
                from_static_only: false,
            }
        );
        assert_eq!(PN_INVALID_STAMP_THROTTLE, Duration::from_secs(180));

        let floored = PnInboundAdmission::new(PnInboundAdmissionConfig {
            max_inbound_syncs: 0,
            ..PnInboundAdmissionConfig::default()
        });
        assert_eq!(floored.config().max_inbound_syncs, 1);
    }

    #[test]
    fn unknown_identity_and_static_only_access_create_no_sentinel_state() {
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            from_static_only: true,
            ..PnInboundAdmissionConfig::default()
        });

        assert!(matches!(
            admission.preflight_offer(link(1), None, Duration::from_secs(10)),
            Err(PnOfferRejection::NoIdentity)
        ));
        assert!(admission.is_empty());
        assert_eq!(admission.throttle_count(), 0);

        let peer_identity = identity(0xA1);
        let peer_destination = PnInboundAdmission::peer_destination_hash(&peer_identity);
        assert_eq!(
            peer_destination,
            [
                0x3f, 0x77, 0x7c, 0x3f, 0x69, 0x1a, 0x9f, 0x56, 0x28, 0x01, 0x72, 0x6e, 0xf1, 0x9e,
                0x49, 0x01,
            ]
        );
        assert!(matches!(
            admission.preflight_offer(link(2), Some(peer_identity), TEST_NOW),
            Err(PnOfferRejection::NoAccess)
        ));
        assert!(admission.is_empty());

        admission.add_static_peer(peer_destination);
        assert_eq!(
            admit(
                &mut admission,
                link(2),
                peer_identity,
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );
        let record = admission.record(&link(2)).unwrap();
        assert_eq!(record.peer_identity_hash(), &peer_identity);
        assert_eq!(record.peer_destination_hash(), &peer_destination);
        assert_eq!(record.state(), PnInboundState::Accepted);

        let debug = format!("{record:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("161"));
        assert!(!format!("{admission:?}").contains("161"));
    }

    #[test]
    fn cap_counts_transferring_and_validating_but_not_accepted() {
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            max_inbound_syncs: 2,
            ..PnInboundAdmissionConfig::default()
        });

        assert_eq!(
            admit(
                &mut admission,
                link(1),
                identity(1),
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );
        assert_eq!(
            admit(
                &mut admission,
                link(2),
                identity(2),
                PnOfferResponse::WantSome,
            ),
            PnOfferAdmission::Accepted
        );
        assert_eq!(admission.inbound_sync_count(), 0);

        admission.resource_started(&link(1)).unwrap();
        start_validation(&mut admission, &link(2));
        assert_eq!(admission.inbound_sync_count(), 2);
        assert_eq!(admission.validation_count(), 1);
        assert!(matches!(
            admission.preflight_offer(link(3), Some(identity(3)), TEST_NOW),
            Err(PnOfferRejection::InboundSyncLimit)
        ));
        assert_eq!(admission.len(), 2);
    }

    #[test]
    fn sequential_validation_and_static_bypass_follow_both_static_modes() {
        let normal_identity = identity(1);
        let static_identity = identity(2);
        let static_destination = PnInboundAdmission::peer_destination_hash(&static_identity);
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            max_inbound_syncs: 1,
            ..PnInboundAdmissionConfig::default()
        });
        admission.add_static_peer(static_destination);

        assert_eq!(
            admit(
                &mut admission,
                link(1),
                normal_identity,
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );
        start_validation(&mut admission, &link(1));
        assert!(matches!(
            admission.preflight_offer(link(2), Some(identity(3)), TEST_NOW),
            Err(PnOfferRejection::SequentialValidationActive)
        ));

        // The default static_sequential=false bypasses both the sequential
        // validation gate and the already-full inbound Resource limit.
        assert_eq!(
            admit(
                &mut admission,
                link(3),
                static_identity,
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );

        let mut static_sequential = PnInboundAdmission::new(PnInboundAdmissionConfig {
            static_sequential: true,
            max_inbound_syncs: 1,
            ..PnInboundAdmissionConfig::default()
        });
        static_sequential.add_static_peer(static_destination);
        admit(
            &mut static_sequential,
            link(4),
            normal_identity,
            PnOfferResponse::WantAll,
        );
        start_validation(&mut static_sequential, &link(4));
        assert!(matches!(
            static_sequential.preflight_offer(link(5), Some(static_identity), TEST_NOW),
            Err(PnOfferRejection::SequentialValidationActive)
        ));

        let mut static_capped = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            static_sequential: true,
            max_inbound_syncs: 1,
            ..PnInboundAdmissionConfig::default()
        });
        static_capped.add_static_peer(static_destination);
        admit(
            &mut static_capped,
            link(8),
            normal_identity,
            PnOfferResponse::WantAll,
        );
        static_capped.resource_started(&link(8)).unwrap();
        assert!(matches!(
            static_capped.preflight_offer(link(9), Some(static_identity), TEST_NOW),
            Err(PnOfferRejection::InboundSyncLimit)
        ));

        let mut non_sequential = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            max_inbound_syncs: 2,
            ..PnInboundAdmissionConfig::default()
        });
        admit(
            &mut non_sequential,
            link(6),
            normal_identity,
            PnOfferResponse::WantAll,
        );
        start_validation(&mut non_sequential, &link(6));
        assert_eq!(
            admit(
                &mut non_sequential,
                link(7),
                identity(7),
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );
    }

    #[test]
    fn offer_policy_gates_follow_upstream_precedence() {
        let blocked_identity = identity(9);
        let blocked_destination = PnInboundAdmission::peer_destination_hash(&blocked_identity);

        // Sequential validation wins over a full cap, an invalid-stamp
        // throttle, and static-only access rejection.
        let mut sequential = PnInboundAdmission::new(PnInboundAdmissionConfig {
            max_inbound_syncs: 1,
            from_static_only: true,
            ..PnInboundAdmissionConfig::default()
        });
        let active_identity = identity(1);
        sequential.add_static_peer(PnInboundAdmission::peer_destination_hash(&active_identity));
        admit(
            &mut sequential,
            link(1),
            active_identity,
            PnOfferResponse::WantAll,
        );
        start_validation(&mut sequential, &link(1));
        sequential
            .install_invalid_stamp_throttle(blocked_destination, TEST_NOW)
            .unwrap();
        assert!(matches!(
            sequential.preflight_offer(link(2), Some(blocked_identity), TEST_NOW),
            Err(PnOfferRejection::SequentialValidationActive)
        ));

        // With sequential validation disabled, the full cap wins over the
        // same peer throttle and static-only access rejection.
        let mut capped = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            max_inbound_syncs: 1,
            from_static_only: true,
            ..PnInboundAdmissionConfig::default()
        });
        capped.add_static_peer(PnInboundAdmission::peer_destination_hash(&active_identity));
        admit(
            &mut capped,
            link(3),
            active_identity,
            PnOfferResponse::WantAll,
        );
        capped.resource_started(&link(3)).unwrap();
        capped
            .install_invalid_stamp_throttle(blocked_destination, TEST_NOW)
            .unwrap();
        assert!(matches!(
            capped.preflight_offer(link(4), Some(blocked_identity), TEST_NOW),
            Err(PnOfferRejection::InboundSyncLimit)
        ));

        // With capacity available, an active throttle wins over static-only
        // access rejection. Once it expires, access is the remaining gate.
        let mut throttled = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            from_static_only: true,
            ..PnInboundAdmissionConfig::default()
        });
        let deadline = throttled
            .install_invalid_stamp_throttle(blocked_destination, TEST_NOW)
            .unwrap();
        assert!(matches!(
            throttled.preflight_offer(link(5), Some(blocked_identity), TEST_NOW),
            Err(PnOfferRejection::InvalidStampThrottle)
        ));
        assert!(matches!(
            throttled.preflight_offer(link(5), Some(blocked_identity), deadline),
            Err(PnOfferRejection::NoAccess)
        ));
    }

    #[test]
    fn want_all_and_want_some_are_recorded_while_have_all_is_not() {
        let mut admission = PnInboundAdmission::default();

        assert_eq!(
            admit(
                &mut admission,
                link(1),
                identity(1),
                PnOfferResponse::HaveAll,
            ),
            PnOfferAdmission::HaveAll
        );
        assert!(admission.record(&link(1)).is_none());

        assert_eq!(
            admit(
                &mut admission,
                link(2),
                identity(2),
                PnOfferResponse::WantAll,
            ),
            PnOfferAdmission::Accepted
        );
        assert_eq!(
            admission.record(&link(2)).unwrap().offer_response(),
            PnOfferResponse::WantAll
        );

        assert_eq!(
            admit(
                &mut admission,
                link(3),
                identity(3),
                PnOfferResponse::WantSome,
            ),
            PnOfferAdmission::Accepted
        );
        assert_eq!(
            admission.record(&link(3)).unwrap().offer_response(),
            PnOfferResponse::WantSome
        );
        assert_eq!(admission.len(), 2);
    }

    #[test]
    fn successful_preflight_creates_no_state_and_candidate_cannot_be_rebound() {
        let mut admission = PnInboundAdmission::default();
        let bound_link = link(1);
        let bound_identity = identity(0xA1);
        let bound_destination = PnInboundAdmission::peer_destination_hash(&bound_identity);
        let candidate = admission
            .preflight_offer(bound_link, Some(bound_identity), TEST_NOW)
            .unwrap();

        assert!(admission.is_empty());
        assert_eq!(admission.pending_candidates.len(), 1);
        assert_eq!(candidate.link_id(), bound_link);
        assert_eq!(candidate.peer_identity_hash(), bound_identity);
        assert_eq!(candidate.peer_destination_hash(), bound_destination);

        // Accessors return copies. Mutating caller-owned values cannot change
        // the opaque candidate consumed by the validated commit boundary.
        let mut exposed_link = candidate.link_id();
        let mut exposed_identity = candidate.peer_identity_hash();
        exposed_link.copy_from_slice(&link(2));
        exposed_identity.copy_from_slice(&identity(2));
        assert_eq!(candidate.link_id(), bound_link);
        assert_eq!(candidate.peer_identity_hash(), bound_identity);

        let debug = format!("{candidate:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("161"));

        assert_eq!(
            admission.commit_validated_offer(candidate, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Accepted
        );
        assert!(admission.pending_candidates.is_empty());
        assert!(admission.record(&exposed_link).is_none());
        let record = admission.record(&bound_link).unwrap();
        assert_eq!(record.peer_identity_hash(), &bound_identity);
        assert_ne!(record.peer_identity_hash(), &exposed_identity);
    }

    #[test]
    fn link_close_revokes_preflight_candidate_without_revoking_replacement() {
        let mut admission = PnInboundAdmission::default();
        let link_id = link(1);
        let revoked = admission
            .preflight_offer(link_id, Some(identity(1)), TEST_NOW)
            .unwrap();

        assert_eq!(
            admission.link_closed(&link_id),
            PnCleanupResult::CandidateRevoked
        );
        assert!(admission.pending_candidates.is_empty());
        assert!(admission.is_empty());

        let replacement = admission
            .preflight_offer(link_id, Some(identity(2)), TEST_NOW)
            .unwrap();
        assert_eq!(
            admission.commit_validated_offer(revoked, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::StaleCandidate)
        );
        assert_eq!(admission.pending_candidates.len(), 1);
        assert!(admission.is_empty());

        assert_eq!(
            admission.commit_validated_offer(replacement, PnOfferResponse::WantSome, TEST_NOW),
            PnOfferAdmission::Accepted
        );
        assert_eq!(
            admission.record(&link_id).unwrap().peer_identity_hash(),
            &identity(2)
        );
    }

    #[test]
    fn failed_external_validation_can_explicitly_discard_candidate() {
        let mut admission = PnInboundAdmission::default();
        let link_id = link(1);
        let candidate = admission
            .preflight_offer(link_id, Some(identity(1)), TEST_NOW)
            .unwrap();

        assert_eq!(
            admission.discard_candidate(candidate),
            PnCandidateDiscardResult::Discarded
        );
        assert!(admission.pending_candidates.is_empty());
        assert!(admission.is_empty());

        let retry = admission
            .preflight_offer(link_id, Some(identity(1)), TEST_NOW)
            .unwrap();
        assert_eq!(
            admission.discard_candidate(retry),
            PnCandidateDiscardResult::Discarded
        );
    }

    #[test]
    fn dropped_candidate_is_pruned_by_next_preflight() {
        let mut admission = PnInboundAdmission::default();
        let abandoned = admission
            .preflight_offer(link(1), Some(identity(1)), TEST_NOW)
            .unwrap();
        assert_eq!(admission.pending_candidates.len(), 1);
        drop(abandoned);
        assert_eq!(admission.pending_candidates.len(), 1);

        let next = admission
            .preflight_offer(link(2), Some(identity(2)), TEST_NOW)
            .unwrap();
        assert_eq!(admission.pending_candidates.len(), 1);
        assert!(!admission.pending_candidates.contains_key(&link(1)));
        assert!(admission.pending_candidates.contains_key(&link(2)));
        assert_eq!(
            admission.discard_candidate(next),
            PnCandidateDiscardResult::Discarded
        );
    }

    #[test]
    fn duplicate_live_preflight_for_link_is_rejected_without_recording() {
        let mut admission = PnInboundAdmission::default();
        let candidate = admission
            .preflight_offer(link(1), Some(identity(1)), TEST_NOW)
            .unwrap();

        assert!(matches!(
            admission.preflight_offer(link(1), Some(identity(2)), TEST_NOW),
            Err(PnOfferRejection::LinkCandidatePending)
        ));
        assert!(admission.is_empty());
        assert_eq!(admission.pending_candidates.len(), 1);
        assert_eq!(
            admission.discard_candidate(candidate),
            PnCandidateDiscardResult::Discarded
        );
    }

    #[test]
    fn foreign_candidate_cannot_commit_or_discard_real_pending_token() {
        let mut target = PnInboundAdmission::default();
        let mut foreign_owner = PnInboundAdmission::default();

        let real = target
            .preflight_offer(link(1), Some(identity(1)), TEST_NOW)
            .unwrap();
        let foreign = foreign_owner
            .preflight_offer(link(1), Some(identity(1)), TEST_NOW)
            .unwrap();
        assert_eq!(
            target.commit_validated_offer(foreign, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::StaleCandidate)
        );
        assert_eq!(target.pending_candidates.len(), 1);
        assert!(target.is_empty());
        assert_eq!(
            target.commit_validated_offer(real, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Accepted
        );

        let real = target
            .preflight_offer(link(2), Some(identity(2)), TEST_NOW)
            .unwrap();
        let foreign = foreign_owner
            .preflight_offer(link(2), Some(identity(2)), TEST_NOW)
            .unwrap();
        assert_eq!(
            target.discard_candidate(foreign),
            PnCandidateDiscardResult::Stale
        );
        assert_eq!(target.pending_candidates.len(), 1);
        assert_eq!(
            target.discard_candidate(real),
            PnCandidateDiscardResult::Discarded
        );
        assert!(target.pending_candidates.is_empty());
    }

    #[test]
    fn commit_rechecks_static_access_and_duplicate_link_gates() {
        let peer_identity = identity(1);
        let peer_destination = PnInboundAdmission::peer_destination_hash(&peer_identity);
        let mut static_only = PnInboundAdmission::new(PnInboundAdmissionConfig {
            from_static_only: true,
            ..PnInboundAdmissionConfig::default()
        });
        static_only.add_static_peer(peer_destination);
        let candidate = static_only
            .preflight_offer(link(1), Some(peer_identity), TEST_NOW)
            .unwrap();
        static_only.remove_static_peer(&peer_destination);
        assert_eq!(
            static_only.commit_validated_offer(candidate, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::NoAccess)
        );
        assert!(static_only.is_empty());

        let mut duplicate = PnInboundAdmission::default();
        let stale = duplicate
            .preflight_offer(link(2), Some(identity(2)), TEST_NOW)
            .unwrap();
        // Simulate an independently installed active record between the two
        // phases. Public preflight correctly prevents a second candidate for
        // this link, but commit must still defend its active-record gate.
        duplicate.records.insert(
            link(2),
            PnInboundRecord {
                peer_identity_hash: identity(3),
                peer_destination_hash: PnInboundAdmission::peer_destination_hash(&identity(3)),
                offer_response: PnOfferResponse::WantSome,
                state: PnInboundState::Accepted,
            },
        );
        assert_eq!(
            duplicate.commit_validated_offer(stale, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::LinkAlreadyTracked)
        );
        assert_eq!(duplicate.len(), 1);
        assert_eq!(
            duplicate.record(&link(2)).unwrap().peer_identity_hash(),
            &identity(3)
        );
    }

    #[test]
    fn commit_rechecks_sequential_and_inbound_limit_gates() {
        let mut sequential = PnInboundAdmission::default();
        let stale = sequential
            .preflight_offer(link(2), Some(identity(2)), TEST_NOW)
            .unwrap();
        admit(
            &mut sequential,
            link(1),
            identity(1),
            PnOfferResponse::WantAll,
        );
        start_validation(&mut sequential, &link(1));
        assert_eq!(
            sequential.commit_validated_offer(stale, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::SequentialValidationActive)
        );
        assert_eq!(sequential.len(), 1);

        let mut capped = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            max_inbound_syncs: 1,
            ..PnInboundAdmissionConfig::default()
        });
        let stale = capped
            .preflight_offer(link(4), Some(identity(4)), TEST_NOW)
            .unwrap();
        admit(&mut capped, link(3), identity(3), PnOfferResponse::WantAll);
        capped.resource_started(&link(3)).unwrap();
        assert_eq!(
            capped.commit_validated_offer(stale, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::InboundSyncLimit)
        );
        assert_eq!(capped.len(), 1);
    }

    #[test]
    fn commit_rechecks_invalid_stamp_throttle_gate() {
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            ..PnInboundAdmissionConfig::default()
        });
        let peer_identity = identity(1);
        let stale = admission
            .preflight_offer(link(2), Some(peer_identity), TEST_NOW)
            .unwrap();

        admit(
            &mut admission,
            link(1),
            peer_identity,
            PnOfferResponse::WantSome,
        );
        start_validation(&mut admission, &link(1));
        admission
            .validation_concluded(&link(1), PnValidationResult::InvalidStamp, TEST_NOW)
            .unwrap();

        assert_eq!(
            admission.commit_validated_offer(stale, PnOfferResponse::WantAll, TEST_NOW),
            PnOfferAdmission::Rejected(PnOfferRejection::InvalidStampThrottle)
        );
        assert!(admission.is_empty());
    }

    #[test]
    fn transitions_reject_illegal_or_untracked_operations_without_mutation() {
        let mut admission = PnInboundAdmission::default();
        let link_id = link(1);

        assert_eq!(
            admission.resource_started(&link_id),
            Err(PnTransitionError::LinkNotTracked)
        );
        admit(
            &mut admission,
            link_id,
            identity(1),
            PnOfferResponse::WantAll,
        );
        assert_eq!(
            admission.resource_concluded(&link_id),
            Err(PnTransitionError::IllegalState {
                state: PnInboundState::Accepted,
                operation: PnTransitionOperation::ResourceConcluded,
            })
        );
        assert_eq!(
            admission.record(&link_id).unwrap().state(),
            PnInboundState::Accepted
        );

        admission.resource_started(&link_id).unwrap();
        assert_eq!(
            admission.resource_started(&link_id),
            Err(PnTransitionError::IllegalState {
                state: PnInboundState::Transferring,
                operation: PnTransitionOperation::ResourceStarted,
            })
        );
        assert_eq!(
            admission.validation_concluded(
                &link_id,
                PnValidationResult::Valid,
                Duration::from_secs(20),
            ),
            Err(PnTransitionError::IllegalState {
                state: PnInboundState::Transferring,
                operation: PnTransitionOperation::ValidationConcluded,
            })
        );
        assert!(matches!(
            admission.preflight_offer(link_id, Some(identity(9)), TEST_NOW),
            Err(PnOfferRejection::LinkAlreadyTracked)
        ));
        assert_eq!(
            admission.record(&link_id).unwrap().state(),
            PnInboundState::Transferring
        );
    }

    #[test]
    fn every_terminal_path_is_idempotent() {
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            ..PnInboundAdmissionConfig::default()
        });

        for (link_byte, cleanup) in [
            (
                1,
                PnInboundAdmission::resource_rejected
                    as fn(&mut PnInboundAdmission, &[u8; 16]) -> PnCleanupResult,
            ),
            (2, PnInboundAdmission::resource_cancelled),
            (3, PnInboundAdmission::resource_failed),
            (4, PnInboundAdmission::link_closed),
        ] {
            let link_id = link(link_byte);
            admit(
                &mut admission,
                link_id,
                identity(link_byte),
                PnOfferResponse::WantAll,
            );
            if link_byte != 1 {
                admission.resource_started(&link_id).unwrap();
            }
            if link_byte == 4 {
                admission.resource_concluded(&link_id).unwrap();
            }
            assert!(matches!(
                cleanup(&mut admission, &link_id),
                PnCleanupResult::Removed(_)
            ));
            assert_eq!(
                cleanup(&mut admission, &link_id),
                PnCleanupResult::NotTracked
            );
        }

        let link_id = link(5);
        admit(
            &mut admission,
            link_id,
            identity(5),
            PnOfferResponse::WantSome,
        );
        start_validation(&mut admission, &link_id);
        assert_eq!(
            admission.validation_concluded(
                &link_id,
                PnValidationResult::Valid,
                Duration::from_secs(50),
            ),
            Ok(PnCleanupResult::Removed(PnInboundState::Validating))
        );
        assert_eq!(
            admission.validation_concluded(
                &link_id,
                PnValidationResult::Valid,
                Duration::from_secs(51),
            ),
            Ok(PnCleanupResult::NotTracked)
        );
        assert!(admission.is_empty());
    }

    #[test]
    fn only_invalid_stamp_validation_throttles_known_peer_until_deadline() {
        let mut admission = PnInboundAdmission::new(PnInboundAdmissionConfig {
            sequential_validation: false,
            ..PnInboundAdmissionConfig::default()
        });

        for (link_byte, result) in [
            (1, PnValidationResult::Valid),
            (2, PnValidationResult::Failed),
        ] {
            let link_id = link(link_byte);
            admit(
                &mut admission,
                link_id,
                identity(link_byte),
                PnOfferResponse::WantAll,
            );
            start_validation(&mut admission, &link_id);
            admission
                .validation_concluded(&link_id, result, Duration::from_secs(100))
                .unwrap();
        }
        assert_eq!(admission.throttle_count(), 0);

        assert_eq!(
            admission.validation_concluded(
                &link(99),
                PnValidationResult::InvalidStamp,
                Duration::from_secs(100),
            ),
            Ok(PnCleanupResult::NotTracked)
        );
        assert_eq!(admission.throttle_count(), 0);

        let bad_identity = identity(3);
        let bad_destination = PnInboundAdmission::peer_destination_hash(&bad_identity);
        let bad_link = link(3);
        admit(
            &mut admission,
            bad_link,
            bad_identity,
            PnOfferResponse::WantSome,
        );
        start_validation(&mut admission, &bad_link);
        assert_eq!(
            admission.validation_concluded(
                &bad_link,
                PnValidationResult::InvalidStamp,
                Duration::from_secs(100),
            ),
            Ok(PnCleanupResult::Removed(PnInboundState::Validating))
        );
        assert_eq!(
            admission.throttle_deadline(&bad_destination, Duration::from_secs(100)),
            Some(Duration::from_secs(280))
        );
        assert!(matches!(
            admission.preflight_offer(link(4), Some(bad_identity), Duration::from_millis(279_999),),
            Err(PnOfferRejection::InvalidStampThrottle)
        ));

        // No global or zero-key throttle is created for unrelated peers.
        let unrelated_now = Duration::from_millis(279_999);
        let unrelated = admission
            .preflight_offer(link(5), Some(identity(5)), unrelated_now)
            .unwrap();
        assert_eq!(
            admission.commit_validated_offer(unrelated, PnOfferResponse::HaveAll, unrelated_now,),
            PnOfferAdmission::HaveAll
        );
        assert!(!admission.is_peer_throttled(&[0; 16], unrelated_now));

        let deadline = Duration::from_secs(280);
        let expired = admission
            .preflight_offer(link(6), Some(bad_identity), deadline)
            .unwrap();
        assert_eq!(
            admission.commit_validated_offer(expired, PnOfferResponse::HaveAll, deadline),
            PnOfferAdmission::HaveAll
        );
        assert_eq!(admission.throttle_count(), 0);
    }

    #[test]
    fn unsolicited_invalid_stamp_throttle_is_expiring_and_peer_scoped() {
        let mut admission = PnInboundAdmission::default();
        let bad_identity = identity(0xA1);
        let bad_destination = PnInboundAdmission::peer_destination_hash(&bad_identity);
        let other_identity = identity(0xB2);

        assert_eq!(
            admission.install_invalid_stamp_throttle([0; 16], TEST_NOW),
            Err(PnThrottleInstallError::UnknownPeerDestination)
        );
        assert_eq!(admission.throttle_count(), 0);

        let deadline = admission
            .install_invalid_stamp_throttle(bad_destination, TEST_NOW)
            .unwrap();
        assert_eq!(deadline, TEST_NOW.saturating_add(PN_INVALID_STAMP_THROTTLE));
        assert_eq!(
            admission
                .install_invalid_stamp_throttle(
                    bad_destination,
                    TEST_NOW.saturating_sub(Duration::from_secs(1)),
                )
                .unwrap(),
            deadline,
            "an out-of-order timestamp cannot shorten a live throttle"
        );
        assert_eq!(admission.throttle_count(), 1);
        assert!(matches!(
            admission.preflight_offer(link(1), Some(bad_identity), TEST_NOW),
            Err(PnOfferRejection::InvalidStampThrottle)
        ));

        let other = admission
            .preflight_offer(link(2), Some(other_identity), TEST_NOW)
            .expect("an unsolicited peer throttle is isolated to that peer");
        assert_eq!(
            admission.discard_candidate(other),
            PnCandidateDiscardResult::Discarded
        );

        let expired = admission
            .preflight_offer(link(1), Some(bad_identity), deadline)
            .expect("throttle expires at its monotonic deadline");
        assert_eq!(
            admission.discard_candidate(expired),
            PnCandidateDiscardResult::Discarded
        );
        assert_eq!(admission.throttle_count(), 0);
    }

    #[test]
    fn invalid_stamp_deadline_saturates_at_duration_max() {
        let mut admission = PnInboundAdmission::default();
        let peer_identity = identity(1);
        let peer_destination = PnInboundAdmission::peer_destination_hash(&peer_identity);
        let link_id = link(1);
        admit(
            &mut admission,
            link_id,
            peer_identity,
            PnOfferResponse::WantAll,
        );
        start_validation(&mut admission, &link_id);

        let near_max = Duration::MAX.saturating_sub(Duration::from_secs(1));
        admission
            .validation_concluded(&link_id, PnValidationResult::InvalidStamp, near_max)
            .unwrap();
        assert_eq!(
            admission.throttle_deadline(&peer_destination, near_max),
            Some(Duration::MAX)
        );
        assert!(matches!(
            admission.preflight_offer(link(2), Some(peer_identity), near_max),
            Err(PnOfferRejection::InvalidStampThrottle)
        ));

        // At the greatest representable caller time, the saturated deadline
        // expires deterministically instead of overflowing or becoming NaN.
        let candidate = admission
            .preflight_offer(link(2), Some(peer_identity), Duration::MAX)
            .unwrap();
        assert_eq!(
            admission.commit_validated_offer(candidate, PnOfferResponse::HaveAll, Duration::MAX,),
            PnOfferAdmission::HaveAll
        );
        assert_eq!(admission.throttle_count(), 0);
    }
}
