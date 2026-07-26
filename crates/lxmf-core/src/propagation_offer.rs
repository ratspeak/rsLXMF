//! Typed evaluation of an inbound propagation-node `/offer` request.
//!
//! Admission policy and lifecycle accounting deliberately live in
//! [`crate::propagation_admission`]. Callers must pass that cheap preflight
//! before performing the peering-key work in this module, then commit the
//! returned wanted outcome to the same admission candidate.

use crate::propagation_admission::PnOfferResponse;
use crate::stamper;
use crate::sync::OfferResponse;
use crate::types::PropagationTransientId;

/// A binary 32-byte transient ID requires at least 34 MessagePack bytes.
const ENCODED_TRANSIENT_ID_MIN_BYTES: usize = 34;

/// A peering-key-validated offer and the subset not present in local storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PnOfferEvaluation {
    HaveAll,
    WantAll,
    WantSome(Vec<PropagationTransientId>),
}

impl PnOfferEvaluation {
    /// Lifecycle outcome recorded by [`crate::propagation_admission`].
    pub fn admission_response(&self) -> PnOfferResponse {
        match self {
            Self::HaveAll => PnOfferResponse::HaveAll,
            Self::WantAll => PnOfferResponse::WantAll,
            Self::WantSome(_) => PnOfferResponse::WantSome,
        }
    }

    /// Python-compatible response value for the `/offer` request.
    pub fn into_wire_response(self) -> OfferResponse {
        match self {
            Self::HaveAll => OfferResponse::HaveAll,
            Self::WantAll => OfferResponse::WantAll,
            Self::WantSome(ids) => {
                OfferResponse::WantSome(ids.into_iter().map(Vec::from).collect())
            }
        }
    }
}

/// Failure before an offer can be committed to admission accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnOfferEvaluationError {
    InvalidData,
    InvalidKey,
}

impl PnOfferEvaluationError {
    pub fn wire_response(self) -> OfferResponse {
        match self {
            Self::InvalidData => OfferResponse::ErrorInvalidData,
            Self::InvalidKey => OfferResponse::ErrorInvalidKey,
        }
    }
}

enum DecodedPeeringKey {
    Empty,
    Key([u8; 32]),
    InvalidLength,
}

pub(crate) struct DecodedOffer {
    peering_key: DecodedPeeringKey,
    transient_ids: Vec<PropagationTransientId>,
}

/// Decode, validate, and determine the wanted subset without mutating
/// admission state.
pub(crate) fn evaluate<F>(
    request_data: &[u8],
    local_identity_hash: &[u8; 16],
    remote_identity_hash: &[u8; 16],
    peering_cost: u8,
    max_offer_size: usize,
    contains: F,
) -> Result<PnOfferEvaluation, PnOfferEvaluationError>
where
    F: FnMut(&PropagationTransientId) -> bool,
{
    let offer = decode(request_data, max_offer_size)?;
    evaluate_decoded(
        offer,
        local_identity_hash,
        remote_identity_hash,
        peering_cost,
        contains,
    )
}

pub(crate) fn evaluate_decoded<F>(
    offer: DecodedOffer,
    local_identity_hash: &[u8; 16],
    remote_identity_hash: &[u8; 16],
    peering_cost: u8,
    mut contains: F,
) -> Result<PnOfferEvaluation, PnOfferEvaluationError>
where
    F: FnMut(&PropagationTransientId) -> bool,
{
    let peering_key_valid = match offer.peering_key {
        DecodedPeeringKey::Empty => peering_cost == 0,
        DecodedPeeringKey::Key(key) => {
            let mut peering_id = [0u8; 32];
            peering_id[..16].copy_from_slice(local_identity_hash);
            peering_id[16..].copy_from_slice(remote_identity_hash);
            stamper::validate_peering_key(&peering_id, &key, peering_cost)
        }
        DecodedPeeringKey::InvalidLength => false,
    };

    if !peering_key_valid {
        return Err(PnOfferEvaluationError::InvalidKey);
    }

    let wanted: Vec<PropagationTransientId> = offer
        .transient_ids
        .iter()
        .filter(|transient_id| !contains(transient_id))
        .copied()
        .collect();

    if wanted.is_empty() {
        Ok(PnOfferEvaluation::HaveAll)
    } else if wanted.len() == offer.transient_ids.len() {
        Ok(PnOfferEvaluation::WantAll)
    } else {
        Ok(PnOfferEvaluation::WantSome(wanted))
    }
}

pub(crate) fn decode(
    data: &[u8],
    max_offer_size: usize,
) -> Result<DecodedOffer, PnOfferEvaluationError> {
    use std::io::Read;

    if data.len() > max_offer_size {
        return Err(PnOfferEvaluationError::InvalidData);
    }

    let mut remaining = data;
    let field_count = rmp::decode::read_array_len(&mut remaining)
        .map_err(|_| PnOfferEvaluationError::InvalidData)?;
    if field_count != 2 {
        return Err(PnOfferEvaluationError::InvalidData);
    }

    let peering_key_len = rmp::decode::read_bin_len(&mut remaining)
        .map_err(|_| PnOfferEvaluationError::InvalidData)? as usize;
    if peering_key_len > remaining.len() {
        return Err(PnOfferEvaluationError::InvalidData);
    }
    let peering_key = match peering_key_len {
        0 => DecodedPeeringKey::Empty,
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remaining[..32]);
            DecodedPeeringKey::Key(key)
        }
        _ => DecodedPeeringKey::InvalidLength,
    };
    remaining = &remaining[peering_key_len..];

    let transient_id_count = rmp::decode::read_array_len(&mut remaining)
        .map_err(|_| PnOfferEvaluationError::InvalidData)? as usize;
    if transient_id_count > remaining.len() / ENCODED_TRANSIENT_ID_MIN_BYTES {
        return Err(PnOfferEvaluationError::InvalidData);
    }

    let mut transient_ids = Vec::with_capacity(transient_id_count);
    for _ in 0..transient_id_count {
        let encoded_len = rmp::decode::read_bin_len(&mut remaining)
            .map_err(|_| PnOfferEvaluationError::InvalidData)? as usize;
        if encoded_len != 32 {
            return Err(PnOfferEvaluationError::InvalidData);
        }
        let mut transient_id = [0u8; 32];
        remaining
            .read_exact(&mut transient_id)
            .map_err(|_| PnOfferEvaluationError::InvalidData)?;
        transient_ids.push(transient_id);
    }

    if !remaining.is_empty() {
        return Err(PnOfferEvaluationError::InvalidData);
    }

    Ok(DecodedOffer {
        peering_key,
        transient_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmpv::Value;

    fn encode_offer(key: Value, ids: Value) -> Vec<u8> {
        crate::encode_value(&Value::Array(vec![key, ids]))
    }

    fn id(value: u8) -> PropagationTransientId {
        [value; 32]
    }

    #[test]
    fn strict_decode_rejects_malformed_fields_and_trailing_bytes() {
        let malformed = [
            vec![0xc1],
            crate::encode_value(&Value::Array(vec![])),
            crate::encode_value(&Value::Array(vec![
                Value::Binary(vec![]),
                Value::Array(vec![]),
                Value::Nil,
            ])),
            encode_offer(Value::Nil, Value::Array(vec![])),
            encode_offer(Value::String("key".into()), Value::Array(vec![])),
            encode_offer(Value::Binary(vec![]), Value::Nil),
            encode_offer(
                Value::Binary(vec![]),
                Value::Array(vec![Value::Binary(vec![1; 31])]),
            ),
            encode_offer(Value::Binary(vec![]), Value::Array(vec![Value::from(1)])),
            encode_offer(
                Value::Binary(vec![]),
                Value::Array(vec![Value::String(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                )]),
            ),
        ];

        for request in malformed {
            assert_eq!(
                evaluate(&request, &[1; 16], &[2; 16], 0, 1024, |_| false),
                Err(PnOfferEvaluationError::InvalidData)
            );
        }

        let mut trailing = encode_offer(Value::Binary(vec![]), Value::Array(vec![]));
        trailing.push(0xc0);
        assert_eq!(
            evaluate(&trailing, &[1; 16], &[2; 16], 0, 1024, |_| false),
            Err(PnOfferEvaluationError::InvalidData)
        );
    }

    #[test]
    fn decode_rejects_requests_over_the_bounded_sync_budget() {
        let request = vec![0xc0; 65];
        assert_eq!(
            evaluate(&request, &[1; 16], &[2; 16], 0, 64, |_| false),
            Err(PnOfferEvaluationError::InvalidData)
        );
    }

    #[test]
    fn decode_rejects_declared_id_count_before_allocating_entries() {
        let mut request = Vec::new();
        rmp::encode::write_array_len(&mut request, 2).unwrap();
        rmp::encode::write_bin_len(&mut request, 0).unwrap();
        rmp::encode::write_array_len(&mut request, u32::MAX).unwrap();

        assert_eq!(
            evaluate(&request, &[1; 16], &[2; 16], 0, usize::MAX, |_| false),
            Err(PnOfferEvaluationError::InvalidData)
        );
    }

    #[test]
    fn empty_key_is_valid_only_when_peering_work_is_disabled() {
        let request = encode_offer(
            Value::Binary(vec![]),
            Value::Array(vec![Value::Binary(id(3).to_vec())]),
        );
        assert_eq!(
            evaluate(&request, &[1; 16], &[2; 16], 0, 1024, |_| false),
            Ok(PnOfferEvaluation::WantAll)
        );
        assert_eq!(
            evaluate(&request, &[1; 16], &[2; 16], 1, 1024, |_| false),
            Err(PnOfferEvaluationError::InvalidKey)
        );
    }

    #[test]
    fn wanted_evaluation_preserves_offer_order_and_duplicates() {
        let request = encode_offer(
            Value::Binary(vec![]),
            Value::Array(vec![
                Value::Binary(id(1).to_vec()),
                Value::Binary(id(2).to_vec()),
                Value::Binary(id(2).to_vec()),
                Value::Binary(id(3).to_vec()),
            ]),
        );

        assert_eq!(
            evaluate(&request, &[1; 16], &[2; 16], 0, 1024, |id| *id == [1; 32]),
            Ok(PnOfferEvaluation::WantSome(vec![id(2), id(2), id(3)]))
        );
    }

    #[test]
    fn outcomes_map_to_admission_and_wire_types() {
        assert_eq!(
            PnOfferEvaluation::HaveAll.admission_response(),
            PnOfferResponse::HaveAll
        );
        assert_eq!(
            PnOfferEvaluation::WantAll.admission_response(),
            PnOfferResponse::WantAll
        );
        let some = PnOfferEvaluation::WantSome(vec![id(7)]);
        assert_eq!(some.admission_response(), PnOfferResponse::WantSome);
        assert_eq!(
            some.into_wire_response(),
            OfferResponse::WantSome(vec![id(7).to_vec()])
        );
    }
}
