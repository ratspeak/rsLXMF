//! Crash-safe ratchet ownership for an LXMF delivery destination.
//!
//! A delivery announce is returned only after any candidate private ratchet
//! and the associated announce-ordering state are durably committed. The
//! propagation destination intentionally does not use this type.

use std::path::{Path, PathBuf};

use rns_identity::announce_state::RatchetControlState;
use rns_identity::destination::{AnnounceTime, DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_identity::ratchet::{RatchetRing, RatchetRingFormat};
use thiserror::Error;

/// Reticulum aspect used by an LXMF delivery destination.
pub const DELIVERY_APP_NAME: &str = "lxmf.delivery";

/// Whether a delivery announce is a normal broadcast or a tagged path reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAnnounceKind<'a> {
    Broadcast,
    PathResponse { tag: Option<&'a [u8]> },
}

#[derive(Debug, Error)]
pub enum DeliveryRatchetError {
    #[error("LXMF delivery destination does not match the supplied identity")]
    DestinationMismatch,
    #[error("ratchet control state at {path} is untrusted; refusing to overwrite it")]
    UntrustedControl { path: PathBuf },
    #[error("announce coalesced until wall time advances")]
    Coalesced,
    #[error("failed to plan announce time: {0}")]
    Plan(#[source] std::io::Error),
    #[error("failed to persist announce ordering state at {path}: {source}")]
    PersistControl {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Destination(#[from] rns_identity::destination::DestinationError),
    #[error("internal ratchet invariant failed: {0}")]
    Invariant(&'static str),
}

/// Owns the private-key ring, signed control sidecar, and exact tagged-response
/// cache for one `lxmf.delivery` destination.
pub struct DeliveryRatchetState {
    destination: Destination,
    ring: RatchetRing,
    control: RatchetControlState,
    ring_path: PathBuf,
    control_path: PathBuf,
    ring_file_trusted: bool,
    control_file_trusted: bool,
}

impl DeliveryRatchetState {
    /// Load verified state, preserving any invalid existing files in place.
    ///
    /// A missing ring is generated and persisted before it becomes live. A
    /// ring that cannot be stored leaves delivery available but unratcheted.
    /// An invalid control sidecar defers new announces because their ordering
    /// cannot be proven safely.
    pub fn load_or_initialize(
        identity: &Identity,
        destination_hash: [u8; 16],
        ring_path: PathBuf,
        control_path: PathBuf,
        wall_now: u64,
    ) -> Result<Self, DeliveryRatchetError> {
        let destination = Destination::new(
            Some(identity),
            Direction::In,
            DestType::Single,
            DELIVERY_APP_NAME,
        )?;
        if destination.hash != destination_hash {
            return Err(DeliveryRatchetError::DestinationMismatch);
        }

        let ring_existed = ring_path.exists();
        let (mut ring, ring_file_trusted) = if ring_existed {
            match RatchetRing::load_verified(&ring_path, identity) {
                Ok(loaded) => {
                    let format = loaded.format();
                    let ring = loaded.into_ring();
                    if format == RatchetRingFormat::LegacyRust {
                        match ring.save_verified(&ring_path, identity) {
                            Ok(()) => tracing::info!(
                                path = %ring_path.display(),
                                "migrated legacy Rust ratchet ring to canonical format"
                            ),
                            Err(error) => tracing::warn!(
                                path = %ring_path.display(),
                                %error,
                                "legacy ratchet ring is valid but canonical rewrite failed"
                            ),
                        }
                    }
                    (ring, true)
                }
                Err(error) => {
                    tracing::error!(
                        path = %ring_path.display(),
                        %error,
                        "ratchet ring is untrusted; preserving it and announcing without a ratchet"
                    );
                    (RatchetRing::new(), false)
                }
            }
        } else {
            (RatchetRing::new(), true)
        };

        let control_existed = control_path.exists();
        let (mut control, control_file_trusted) = if control_existed {
            match RatchetControlState::load_verified(&control_path, identity, destination_hash) {
                Ok(state) => (state, true),
                Err(error) => {
                    tracing::error!(
                        path = %control_path.display(),
                        %error,
                        "ratchet control state is untrusted; preserving it and deferring new announces"
                    );
                    (
                        RatchetControlState::new(identity.hash, destination_hash),
                        false,
                    )
                }
            }
        } else {
            (
                RatchetControlState::new(identity.hash, destination_hash),
                true,
            )
        };

        let mut control_changed = false;
        if control_file_trusted && control.last_rotation_wall().is_none() {
            control.anchor_rotation_if_unknown(wall_now);
            control_changed = true;
        }

        if ring.is_empty() && ring_file_trusted && control_file_trusted {
            let prepared = ring.prepare_rotation_at(wall_now as f64);
            match prepared.ring().save_verified(&ring_path, identity) {
                Ok(()) => {
                    ring.commit_prepared_rotation(prepared);
                    control = control.with_rotation_at(wall_now);
                    control_changed = true;
                }
                Err(error) => tracing::error!(
                    path = %ring_path.display(),
                    %error,
                    "could not durably initialise ratchet ring; delivery announces will be unratcheted"
                ),
            }
        }

        if control_file_trusted
            && (!control_existed || control_changed)
            && let Err(error) = control.save_verified(&control_path, identity)
        {
            tracing::warn!(
                path = %control_path.display(),
                %error,
                "could not persist initial ratchet control state; new announces remain deferred until persistence recovers"
            );
        }

        Ok(Self {
            destination,
            ring,
            control,
            ring_path,
            control_path,
            ring_file_trusted,
            control_file_trusted,
        })
    }

    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination.hash
    }

    pub fn ring(&self) -> &RatchetRing {
        &self.ring
    }

    pub fn control(&self) -> &RatchetControlState {
        &self.control
    }

    /// Build an announce after committing all state that its wire bytes claim.
    ///
    /// `wall_now` supplies both rotation age and the 40-bit wire ordering
    /// value. `cache_now` is a separate local elapsed-time domain used only for
    /// tagged path-response expiry.
    pub fn create_announce(
        &mut self,
        identity: &Identity,
        app_data: &[u8],
        wall_now: u64,
        cache_now: f64,
        kind: DeliveryAnnounceKind<'_>,
    ) -> Result<Vec<u8>, DeliveryRatchetError> {
        if identity.hash != self.control.identity_hash() {
            return Err(DeliveryRatchetError::DestinationMismatch);
        }
        let announce_time = AnnounceTime::new(wall_now, cache_now)?;

        if let DeliveryAnnounceKind::PathResponse { tag: Some(tag) } = kind
            && let Some(packet) = self
                .destination
                .cached_path_response_packet(tag, cache_now)?
        {
            return Ok(packet);
        }

        if !self.control_file_trusted {
            return Err(DeliveryRatchetError::UntrustedControl {
                path: self.control_path.clone(),
            });
        }

        let Some(mut candidate_control) = self
            .control
            .prepare_announce(wall_now)
            .map_err(DeliveryRatchetError::Plan)?
        else {
            return Err(DeliveryRatchetError::Coalesced);
        };

        let rotation_due = self.ring.is_empty()
            || self
                .control
                .rotation_due(wall_now, self.ring.ratchet_interval());
        let mut prepared_rotation = None;
        let mut ratchet_public = self.ring.current_public_key();
        if rotation_due && self.ring_file_trusted {
            let prepared = self.ring.prepare_rotation_at(wall_now as f64);
            match prepared.ring().save_verified(&self.ring_path, identity) {
                Ok(()) => {
                    ratchet_public = Some(prepared.public_key());
                    candidate_control = candidate_control.with_rotation_at(wall_now);
                    prepared_rotation = Some(prepared);
                }
                Err(error) => tracing::error!(
                    path = %self.ring_path.display(),
                    %error,
                    "ratchet rotation was not persisted; reusing the last durable ratchet"
                ),
            }
        }

        candidate_control
            .save_verified(&self.control_path, identity)
            .map_err(|source| DeliveryRatchetError::PersistControl {
                path: self.control_path.clone(),
                source,
            })?;

        let wire_now =
            candidate_control
                .last_announce_wire()
                .ok_or(DeliveryRatchetError::Invariant(
                    "prepared announce has no wire-order value",
                ))?;
        if let Some(prepared) = prepared_rotation {
            self.ring.commit_prepared_rotation(prepared);
        }
        self.control = candidate_control;

        let (path_response, tag) = match kind {
            DeliveryAnnounceKind::Broadcast => (false, None),
            DeliveryAnnounceKind::PathResponse { tag } => (true, tag),
        };
        self.destination
            .announce_packet_at(
                identity,
                Some(app_data),
                ratchet_public.as_ref(),
                path_response,
                tag,
                AnnounceTime::new(wire_now, announce_time.cache)?,
            )
            .map_err(DeliveryRatchetError::from)
    }

    /// Best-effort shutdown checkpoint. Invalid files detected during load are
    /// never overwritten by this operation.
    pub fn save(&self, identity: &Identity) {
        if self.ring_file_trusted
            && let Err(error) = self.ring.save_verified(&self.ring_path, identity)
        {
            tracing::warn!(%error, "failed to save ratchet ring");
        }
        if self.control_file_trusted
            && let Err(error) = self.control.save_verified(&self.control_path, identity)
        {
            tracing::warn!(%error, "failed to save ratchet control state");
        }
    }

    pub fn ring_path(&self) -> &Path {
        &self.ring_path
    }

    pub fn control_path(&self) -> &Path {
        &self.control_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_identity::ratchet::ratchet_public_bytes;

    fn unpack_announce(
        raw: &[u8],
    ) -> (
        rns_wire::header::PacketHeader,
        rns_identity::announce::AnnounceData,
    ) {
        let (header, header_len) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
        let announce = rns_identity::announce::AnnounceData::unpack(
            &raw[header_len..],
            header.flags.context_flag,
        )
        .unwrap();
        (header, announce)
    }

    fn state_at(dir: &Path, identity: &Identity, wall_now: u64) -> DeliveryRatchetState {
        let destination_hash =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity.hash));
        DeliveryRatchetState::load_or_initialize(
            identity,
            destination_hash,
            dir.join("ring"),
            dir.join("ring.control"),
            wall_now,
        )
        .unwrap()
    }

    #[test]
    fn survives_restart_rotates_and_retains_the_previous_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let mut state = state_at(dir.path(), &identity, 100);
        let initial_public = state.ring.current_public_key().unwrap();

        let raw = state
            .create_announce(
                &identity,
                b"app",
                101,
                101.0,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        let (header, announce) = unpack_announce(&raw);
        assert!(header.flags.context_flag);
        assert_eq!(announce.ratchet, Some(initial_public));
        let committed_wire_time = state.control.last_announce_wire();
        assert!(matches!(
            state.create_announce(
                &identity,
                b"changed",
                101,
                101.5,
                DeliveryAnnounceKind::Broadcast,
            ),
            Err(DeliveryRatchetError::Coalesced)
        ));
        assert_eq!(state.control.last_announce_wire(), committed_wire_time);

        let mut restarted = state_at(dir.path(), &identity, 102);
        assert_eq!(restarted.ring.current_public_key(), Some(initial_public));
        let raw = restarted
            .create_announce(
                &identity,
                b"app",
                102,
                102.0,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        assert_eq!(unpack_announce(&raw).1.ratchet, Some(initial_public));

        let rotate_at = 100 + restarted.ring.ratchet_interval();
        let raw = restarted
            .create_announce(
                &identity,
                b"app",
                rotate_at,
                rotate_at as f64,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        let rotated_public = unpack_announce(&raw).1.ratchet.unwrap();
        assert_ne!(rotated_public, initial_public);
        assert_eq!(restarted.ring.len(), 2);
        assert!(
            restarted
                .ring
                .private_keys()
                .iter()
                .any(|private| ratchet_public_bytes(private) == initial_public)
        );
    }

    #[test]
    fn unavailable_ring_storage_can_only_emit_an_unratcheted_announce() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let destination =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity.hash));
        let mut state = DeliveryRatchetState::load_or_initialize(
            &identity,
            destination,
            dir.path().join("missing/ring"),
            dir.path().join("ring.control"),
            100,
        )
        .unwrap();
        assert!(state.ring.is_empty());

        let raw = state
            .create_announce(
                &identity,
                b"app",
                101,
                101.0,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        let (header, announce) = unpack_announce(&raw);
        assert!(!header.flags.context_flag);
        assert_eq!(announce.ratchet, None);
        assert!(state.ring.is_empty());
    }

    #[test]
    fn corrupt_ring_is_preserved_and_never_advertised() {
        let dir = tempfile::tempdir().unwrap();
        let ring_path = dir.path().join("ring");
        let corrupt = b"not-a-ratchet-ring";
        std::fs::write(&ring_path, corrupt).unwrap();
        let identity = Identity::new();
        let mut state = state_at(dir.path(), &identity, 100);

        let raw = state
            .create_announce(
                &identity,
                b"app",
                101,
                101.0,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        assert!(!unpack_announce(&raw).0.flags.context_flag);
        assert_eq!(std::fs::read(ring_path).unwrap(), corrupt);
    }

    #[test]
    fn failed_control_commit_cannot_publish_or_commit_a_prepared_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let mut state = state_at(dir.path(), &identity, 100);
        state
            .create_announce(
                &identity,
                b"app",
                101,
                101.0,
                DeliveryAnnounceKind::Broadcast,
            )
            .unwrap();
        let live_public = state.ring.current_public_key();
        let live_wire_time = state.control.last_announce_wire();
        state.control_path = dir.path().join("missing/ring.control");
        let rotate_at = 100 + state.ring.ratchet_interval();

        assert!(matches!(
            state.create_announce(
                &identity,
                b"app",
                rotate_at,
                rotate_at as f64,
                DeliveryAnnounceKind::Broadcast,
            ),
            Err(DeliveryRatchetError::PersistControl { .. })
        ));
        assert_eq!(state.ring.current_public_key(), live_public);
        assert_eq!(state.control.last_announce_wire(), live_wire_time);
    }

    #[test]
    fn same_tag_replays_exact_packet_without_consuming_announce_time() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let mut state = state_at(dir.path(), &identity, 100);
        let tag = b"path-request-tag";
        let first = state
            .create_announce(
                &identity,
                b"first",
                101,
                101.0,
                DeliveryAnnounceKind::PathResponse { tag: Some(tag) },
            )
            .unwrap();
        let committed_wire = state.control.last_announce_wire();

        let replay = state
            .create_announce(
                &identity,
                b"changed",
                101,
                102.0,
                DeliveryAnnounceKind::PathResponse { tag: Some(tag) },
            )
            .unwrap();
        assert_eq!(
            replay, first,
            "removing the cache lookup changes signed bytes"
        );
        assert_eq!(state.control.last_announce_wire(), committed_wire);
        assert_eq!(
            unpack_announce(&replay).0.context,
            rns_wire::context::PacketContext::PathResponse
        );
    }

    #[test]
    fn invalid_cache_clock_cannot_commit_announce_state() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let mut state = state_at(dir.path(), &identity, 100);
        let live_wire = state.control.last_announce_wire();
        let live_public = state.ring.current_public_key();

        assert!(matches!(
            state.create_announce(
                &identity,
                b"app",
                101,
                f64::NAN,
                DeliveryAnnounceKind::Broadcast,
            ),
            Err(DeliveryRatchetError::Destination(_))
        ));
        assert_eq!(state.control.last_announce_wire(), live_wire);
        assert_eq!(state.ring.current_public_key(), live_public);
    }
}
