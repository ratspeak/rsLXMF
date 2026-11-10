//! Shared propagation preparation for daemon and embedding applications.
use crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN;
use crate::message::{LxMessage, MessageError};
use crate::stamper::StampControl;
use bytes::Bytes;

pub const NODE_METADATA_MAX_AGE: f64 = 45.0 * 86400.0;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct AdvertisedNodePolicy {
    /// Announced propagation stamp cost; generation clamps it to `0..=100`.
    pub stamp_cost: f64,
    pub transfer_limit_kb: f64,
    pub recorded_at: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPropagationInput {
    NodeIdentity,
    NodePath,
    NodePolicy,
    RecipientIdentity,
}

#[derive(Debug, Clone, Copy)]
pub struct PreparedNode {
    pub node: [u8; 16],
    pub policy: AdvertisedNodePolicy,
}

/// Check the node identity, node path, advertised policy and recipient key.
/// Policy must be younger than [`NODE_METADATA_MAX_AGE`] and have a finite,
/// nonnegative transfer limit. The recipient may be offline: only its key is
/// needed. This function reports missing inputs; it performs no path discovery.
pub fn propagation_readiness(
    node: [u8; 16],
    node_identity_known: bool,
    node_path_known: bool,
    policy: Option<AdvertisedNodePolicy>,
    recipient_identity_known: bool,
    now: f64,
) -> Result<PreparedNode, MissingPropagationInput> {
    if !node_identity_known {
        return Err(MissingPropagationInput::NodeIdentity);
    }
    if !node_path_known {
        return Err(MissingPropagationInput::NodePath);
    }
    let policy = policy
        .filter(|p| {
            p.recorded_at.is_finite()
                && p.recorded_at <= now
                && now - p.recorded_at < NODE_METADATA_MAX_AGE
                && p.transfer_limit_kb.is_finite()
                && p.transfer_limit_kb >= 0.
        })
        .ok_or(MissingPropagationInput::NodePolicy)?;
    if !recipient_identity_known {
        return Err(MissingPropagationInput::RecipientIdentity);
    }
    Ok(PreparedNode { node, policy })
}

/// One send-owned encryption result. Retrying changes the outer timestamp and,
/// if the saved stamp no longer meets the node's cost, regenerates the PN stamp.
/// Ciphertext and transient ID stay fixed.
#[derive(Debug, Clone)]
pub struct PropagationEnvelope {
    message: LxMessage,
    ciphertext: Bytes,
    transient_id: [u8; 32],
    encryption_binding: [u8; 32],
    stamp: [u8; 32],
    stamp_value: f64,
    required_cost: f64,
}

/// Python `get_outbound_propagation_cost` clamps the node's cost into `0..=100`.
fn outbound_pn_cost(cost: f64) -> f64 {
    cost.clamp(0.0, crate::stamper::STAMP_COST_CAP)
}

fn generate_pn_stamp(
    transient_id: &[u8; 32],
    cost: f64,
    ctl: &StampControl,
) -> Result<([u8; 32], f64), MessageError> {
    crate::stamper::generate_stamp(
        transient_id,
        outbound_pn_cost(cost),
        STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
        ctl,
    )
    .map_err(|e| MessageError::PackFailed(format!("PN stamp generation failed: {e}")))?
    .ok_or_else(|| MessageError::PackFailed("PN stamp generation cancelled".into()))
}

impl PropagationEnvelope {
    pub fn new<F>(
        message: LxMessage,
        encryption_binding: [u8; 32],
        required_cost: f64,
        encrypt: F,
    ) -> Result<Self, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        Self::new_cancellable(
            message,
            encryption_binding,
            required_cost,
            encrypt,
            &StampControl::default(),
        )
    }
    pub fn new_cancellable<F>(
        message: LxMessage,
        encryption_binding: [u8; 32],
        required_cost: f64,
        encrypt: F,
        ctl: &StampControl,
    ) -> Result<Self, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let encrypted = encrypt(&message.wire_bytes()[16..])?;
        let mut ciphertext = Vec::with_capacity(16 + encrypted.len());
        ciphertext.extend_from_slice(&message.destination_hash());
        ciphertext.extend_from_slice(&encrypted);
        let transient_id = rns_crypto::sha::full_hash(&ciphertext);
        let (stamp, stamp_value) = generate_pn_stamp(&transient_id, required_cost, ctl)?;
        Ok(Self {
            message,
            ciphertext: ciphertext.into(),
            transient_id,
            encryption_binding,
            stamp,
            stamp_value,
            required_cost,
        })
    }
    pub fn message(&self) -> &LxMessage {
        &self.message
    }
    pub fn transient_id(&self) -> [u8; 32] {
        self.transient_id
    }
    pub fn ciphertext(&self) -> &Bytes {
        &self.ciphertext
    }
    pub fn stamp(&self) -> &[u8; 32] {
        &self.stamp
    }
    pub fn stamp_value(&self) -> f64 {
        self.stamp_value
    }
    /// Whether the saved stamp already meets a node's announced cost.
    pub fn meets(&self, cost: f64) -> bool {
        crate::stamper::value_meets(self.stamp_value, outbound_pn_cost(cost))
    }
    pub fn matches(&self, message: &LxMessage, encryption_binding: &[u8; 32]) -> bool {
        self.message.wire_bytes() == message.wire_bytes()
            && &self.encryption_binding == encryption_binding
    }
    /// Pack immediately before dispatch using policy checked by
    /// [`propagation_readiness`]. This does not refresh the policy or send data.
    /// It may synchronously regenerate the PN stamp if more work is required.
    pub fn pack_for(
        &mut self,
        node: PreparedNode,
        timestamp: f64,
    ) -> Result<Vec<u8>, MessageError> {
        self.pack_for_cancellable(node, timestamp, &StampControl::default())
    }
    pub fn pack_for_cancellable(
        &mut self,
        node: PreparedNode,
        timestamp: f64,
        ctl: &StampControl,
    ) -> Result<Vec<u8>, MessageError> {
        if !timestamp.is_finite() {
            return Err(MessageError::PackFailed(
                "propagation timestamp must be finite".into(),
            ));
        }
        if !self.meets(node.policy.stamp_cost) {
            (self.stamp, self.stamp_value) =
                generate_pn_stamp(&self.transient_id, node.policy.stamp_cost, ctl)?;
        }
        self.required_cost = node.policy.stamp_cost;
        let blob_len = self
            .ciphertext
            .len()
            .checked_add(32)
            .ok_or_else(|| MessageError::PackFailed("PN envelope size overflow".into()))?;
        let bin_header = if blob_len < 256 {
            2
        } else if blob_len < 65536 {
            3
        } else {
            5
        };
        let packed_len = blob_len
            .checked_add(11 + bin_header)
            .ok_or_else(|| MessageError::PackFailed("PN wrapper size overflow".into()))?;
        let limit = (node.policy.transfer_limit_kb * 1000.).floor();
        let resource_limit = rns_protocol::resource::MAX_EFFICIENT_SIZE
            .checked_mul(rns_protocol::resource::MAX_SEGMENTS)
            .unwrap_or(0);
        if packed_len as f64 > limit || packed_len > resource_limit {
            return Err(MessageError::TooLarge {
                size: packed_len,
                limit: (limit as usize).min(resource_limit),
            });
        }
        let mut out = Vec::with_capacity(packed_len);
        rmp::encode::write_array_len(&mut out, 2).expect("Vec writer");
        rmp::encode::write_f64(&mut out, timestamp).expect("Vec writer");
        rmp::encode::write_array_len(&mut out, 1).expect("Vec writer");
        rmp::encode::write_bin_len(
            &mut out,
            u32::try_from(blob_len)
                .map_err(|_| MessageError::PackFailed("PN blob too large".into()))?,
        )
        .expect("Vec writer");
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.stamp);
        debug_assert_eq!(out.len(), packed_len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DeliveryMethod;
    use crate::message::LxMessageDraft;
    #[test]
    fn offline_recipient_key_is_sufficient_and_zero_cost_is_explicit() {
        let policy = AdvertisedNodePolicy {
            stamp_cost: 0.0,
            transfer_limit_kb: 256.,
            recorded_at: 100.,
        };
        assert!(propagation_readiness([1; 16], true, true, Some(policy), true, 101.).is_ok());
        assert_eq!(
            propagation_readiness([1; 16], true, true, None, true, 101.).unwrap_err(),
            MissingPropagationInput::NodePolicy
        );
        assert_eq!(
            propagation_readiness([1; 16], true, true, Some(policy), false, 101.).unwrap_err(),
            MissingPropagationInput::RecipientIdentity
        );
    }
    #[test]
    fn retry_and_cost_increase_keep_ciphertext_and_transient_id() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&[3; 32]);
        let msg = LxMessageDraft::new([1; 16], [2; 16], "", "test", DeliveryMethod::Propagated)
            .unwrap()
            .sign(&key)
            .unwrap()
            .finalize(None)
            .unwrap();
        let mut envelope = PropagationEnvelope::new(msg, [4; 32], 0.0, |p| Ok(p.to_vec())).unwrap();
        let before = envelope.ciphertext.clone();
        let tid = envelope.transient_id();
        assert_eq!(
            envelope.stamp_value(),
            crate::stamper::stamp_value(
                &crate::stamper::stamp_workblock(&tid, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN),
                envelope.stamp(),
            )
        );
        let mut prepared = PreparedNode {
            node: [5; 16],
            policy: AdvertisedNodePolicy {
                stamp_cost: 0.0,
                transfer_limit_kb: 256.,
                recorded_at: 100.,
            },
        };
        let first = envelope.pack_for(prepared, 101.).unwrap();
        prepared.policy.stamp_cost = 4.5;
        let next = envelope.pack_for(prepared, 102.).unwrap();
        assert_eq!(envelope.ciphertext(), &before);
        assert_eq!(envelope.transient_id(), tid);
        assert!(envelope.stamp_value() >= 4.5);
        assert_ne!(first, next);
        assert!(
            crate::stamper::stamp_value(
                &crate::stamper::stamp_workblock(&tid, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN),
                envelope.stamp()
            ) >= 4.5
        );
    }
}
