//! Actor-owned tracking for inbound LXMF delivery Resources.
//!
//! The Reticulum runtime owns the actual transfers. Embedders project its
//! lifecycle notifications into [`InboundResourceEvent`] and forward bounded
//! [`InboundResourceCancelRequest`] values back to that owner. This keeps the
//! public LXMF API independent of a concrete Reticulum runtime while retaining
//! exact `(link_id, logical_resource_id)` cancellation authority.

use std::collections::HashMap;

use tokio::sync::{mpsc, watch};

/// Exact owner key for one logical inbound Resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InboundResourceKey {
    pub link_id: [u8; 16],
    pub resource_id: [u8; 32],
}

impl InboundResourceKey {
    pub const fn new(link_id: [u8; 16], resource_id: [u8; 32]) -> Self {
        Self {
            link_id,
            resource_id,
        }
    }
}

/// Terminal result of an inbound Resource transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundResourceConclusion {
    Complete,
    Cancelled,
    Rejected,
    Failed,
}

/// Current public state of an inbound Resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundResourceStatus {
    Receiving,
    Complete,
    Cancelled,
    Rejected,
    Failed,
}

impl InboundResourceStatus {
    pub const fn is_closed(self) -> bool {
        !matches!(self, Self::Receiving)
    }
}

impl From<InboundResourceConclusion> for InboundResourceStatus {
    fn from(value: InboundResourceConclusion) -> Self {
        match value {
            InboundResourceConclusion::Complete => Self::Complete,
            InboundResourceConclusion::Cancelled => Self::Cancelled,
            InboundResourceConclusion::Rejected => Self::Rejected,
            InboundResourceConclusion::Failed => Self::Failed,
        }
    }
}

/// Owned, non-sensitive snapshot of one inbound transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResourceSnapshot {
    pub key: InboundResourceKey,
    pub data_size: usize,
    pub transferred: usize,
    pub total_segments: usize,
    pub status: InboundResourceStatus,
}

impl InboundResourceSnapshot {
    pub const fn is_closed(&self) -> bool {
        self.status.is_closed()
    }
}

/// Transport-neutral lifecycle input consumed by [`InboundResourceTracker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundResourceEvent {
    Started {
        key: InboundResourceKey,
        data_size: usize,
        total_segments: usize,
    },
    Progress {
        key: InboundResourceKey,
        transferred: usize,
        total: usize,
    },
    Concluded {
        key: InboundResourceKey,
        conclusion: InboundResourceConclusion,
    },
    LinkClosed {
        link_id: [u8; 16],
    },
}

/// Exact cancellation request for the embedding runtime's Resource owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundResourceCancelRequest {
    key: InboundResourceKey,
}

impl InboundResourceCancelRequest {
    pub const fn new(key: InboundResourceKey) -> Self {
        Self { key }
    }

    pub const fn key(self) -> InboundResourceKey {
        self.key
    }
}

/// Cloneable live handle retained by a caller after the active list changes.
#[derive(Debug, Clone)]
pub struct InboundResourceHandle {
    key: InboundResourceKey,
    snapshot_rx: watch::Receiver<InboundResourceSnapshot>,
    cancel_tx: Option<mpsc::Sender<InboundResourceCancelRequest>>,
}

impl InboundResourceHandle {
    pub const fn key(&self) -> InboundResourceKey {
        self.key
    }

    pub fn snapshot(&self) -> InboundResourceSnapshot {
        self.snapshot_rx.borrow().clone()
    }

    /// Wait for the next lifecycle/progress update.
    ///
    /// Returns `None` after the terminal snapshot has been published and the
    /// actor owner has dropped its sender.
    pub async fn changed(&mut self) -> Option<InboundResourceSnapshot> {
        if self.snapshot_rx.changed().await.is_err() {
            return None;
        }
        Some(self.snapshot())
    }

    /// Queue exact inbound cancellation without blocking the actor owner.
    ///
    /// `false` means the transfer is already closed, cancellation is not
    /// wired by the embedder, or the bounded command channel cannot accept the
    /// request. Authoritative closure arrives through the lifecycle stream.
    pub fn cancel(&self) -> bool {
        if self.snapshot().is_closed() {
            return false;
        }
        self.cancel_tx.as_ref().is_some_and(|tx| {
            tx.try_send(InboundResourceCancelRequest::new(self.key))
                .is_ok()
        })
    }
}

struct ActiveInboundResource {
    snapshot_tx: watch::Sender<InboundResourceSnapshot>,
}

/// Single-owner active Resource registry.
///
/// Terminal records are removed immediately, so the registry is bounded by
/// concurrent transfers. Previously returned handles retain the final owned
/// snapshot without keeping actor state alive.
#[derive(Default)]
pub struct InboundResourceTracker {
    active: HashMap<InboundResourceKey, ActiveInboundResource>,
    cancel_tx: Option<mpsc::Sender<InboundResourceCancelRequest>>,
}

impl InboundResourceTracker {
    pub fn new(cancel_tx: mpsc::Sender<InboundResourceCancelRequest>) -> Self {
        Self {
            active: HashMap::new(),
            cancel_tx: Some(cancel_tx),
        }
    }

    pub fn set_cancel_sender(&mut self, cancel_tx: mpsc::Sender<InboundResourceCancelRequest>) {
        self.cancel_tx = Some(cancel_tx);
    }

    /// Number of currently active inbound Resources.
    pub fn inbound_count(&self) -> usize {
        self.active.len()
    }

    /// Deterministic snapshot of all active Resource handles.
    pub fn inbound_resources(&self) -> Vec<InboundResourceHandle> {
        let mut keys = self.active.keys().copied().collect::<Vec<_>>();
        keys.sort_unstable();
        keys.into_iter()
            .filter_map(|key| self.handle_for(key))
            .collect()
    }

    /// Return the active Resource matching `resource_id`.
    ///
    /// A cryptographic ID collision across two Links fails closed instead of
    /// choosing the wrong cancellation authority.
    pub fn inbound_resource(&self, resource_id: &[u8; 32]) -> Option<InboundResourceHandle> {
        let mut matches = self
            .active
            .keys()
            .filter(|key| &key.resource_id == resource_id)
            .copied();
        let key = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        self.handle_for(key)
    }

    /// Return one exact active Resource.
    pub fn inbound_resource_exact(&self, key: InboundResourceKey) -> Option<InboundResourceHandle> {
        self.handle_for(key)
    }

    /// Queue cancellation for one unique active logical Resource.
    pub fn cancel_inbound(&self, resource_id: &[u8; 32]) -> bool {
        self.inbound_resource(resource_id)
            .is_some_and(|handle| handle.cancel())
    }

    /// Queue cancellation for one exact active Resource.
    pub fn cancel_inbound_exact(&self, key: InboundResourceKey) -> bool {
        self.handle_for(key).is_some_and(|handle| handle.cancel())
    }

    /// Queue cancellation for a stable snapshot of every active Resource.
    ///
    /// The returned count is the number accepted by the bounded command
    /// channel, matching Python's count-oriented `cancel_all_inbound` API.
    pub fn cancel_all_inbound(&self) -> usize {
        self.inbound_resources()
            .into_iter()
            .filter(InboundResourceHandle::cancel)
            .count()
    }

    /// Apply one lifecycle update from the embedding runtime.
    pub fn handle_event(&mut self, event: InboundResourceEvent) {
        match event {
            InboundResourceEvent::Started {
                key,
                data_size,
                total_segments,
            } => self.started(key, data_size, total_segments),
            InboundResourceEvent::Progress {
                key,
                transferred,
                total,
            } => self.progress(key, transferred, total),
            InboundResourceEvent::Concluded { key, conclusion } => self.concluded(key, conclusion),
            InboundResourceEvent::LinkClosed { link_id } => self.link_closed(link_id),
        }
    }

    fn handle_for(&self, key: InboundResourceKey) -> Option<InboundResourceHandle> {
        let active = self.active.get(&key)?;
        Some(InboundResourceHandle {
            key,
            snapshot_rx: active.snapshot_tx.subscribe(),
            cancel_tx: self.cancel_tx.clone(),
        })
    }

    fn started(&mut self, key: InboundResourceKey, data_size: usize, total_segments: usize) {
        if let Some(active) = self.active.get(&key) {
            let mut snapshot = active.snapshot_tx.borrow().clone();
            snapshot.data_size = snapshot.data_size.max(data_size);
            snapshot.total_segments = snapshot.total_segments.max(total_segments.max(1));
            active.snapshot_tx.send_replace(snapshot);
            return;
        }

        let snapshot = InboundResourceSnapshot {
            key,
            data_size,
            transferred: 0,
            total_segments: total_segments.max(1),
            status: InboundResourceStatus::Receiving,
        };
        let (snapshot_tx, _snapshot_rx) = watch::channel(snapshot);
        self.active
            .insert(key, ActiveInboundResource { snapshot_tx });
    }

    fn progress(&mut self, key: InboundResourceKey, transferred: usize, total: usize) {
        let Some(active) = self.active.get(&key) else {
            return;
        };
        let mut snapshot = active.snapshot_tx.borrow().clone();
        snapshot.data_size = snapshot.data_size.max(total);
        snapshot.transferred = transferred.min(snapshot.data_size);
        active.snapshot_tx.send_replace(snapshot);
    }

    fn concluded(&mut self, key: InboundResourceKey, conclusion: InboundResourceConclusion) {
        let Some(active) = self.active.remove(&key) else {
            return;
        };
        let mut snapshot = active.snapshot_tx.borrow().clone();
        snapshot.status = conclusion.into();
        if conclusion == InboundResourceConclusion::Complete {
            snapshot.transferred = snapshot.data_size;
        }
        active.snapshot_tx.send_replace(snapshot);
    }

    fn link_closed(&mut self, link_id: [u8; 16]) {
        let keys = self
            .active
            .keys()
            .filter(|key| key.link_id == link_id)
            .copied()
            .collect::<Vec<_>>();
        for key in keys {
            self.concluded(key, InboundResourceConclusion::Failed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(link: u8, resource: u8) -> InboundResourceKey {
        InboundResourceKey::new([link; 16], [resource; 32])
    }

    fn started(key: InboundResourceKey, size: usize) -> InboundResourceEvent {
        InboundResourceEvent::Started {
            key,
            data_size: size,
            total_segments: 1,
        }
    }

    #[tokio::test]
    async fn active_handle_tracks_progress_and_terminal_snapshot() {
        let (cancel_tx, _cancel_rx) = mpsc::channel(4);
        let mut tracker = InboundResourceTracker::new(cancel_tx);
        let resource = key(1, 2);

        tracker.handle_event(started(resource, 100));
        let mut handle = tracker.inbound_resource(&resource.resource_id).unwrap();
        assert_eq!(tracker.inbound_count(), 1);
        assert_eq!(handle.snapshot().transferred, 0);

        tracker.handle_event(InboundResourceEvent::Progress {
            key: resource,
            transferred: 40,
            total: 100,
        });
        assert_eq!(handle.changed().await.unwrap().transferred, 40);

        tracker.handle_event(InboundResourceEvent::Concluded {
            key: resource,
            conclusion: InboundResourceConclusion::Complete,
        });
        let terminal = handle.changed().await.unwrap();
        assert_eq!(terminal.status, InboundResourceStatus::Complete);
        assert_eq!(terminal.transferred, 100);
        assert!(terminal.is_closed());
        assert_eq!(tracker.inbound_count(), 0);
        assert!(!handle.cancel());
        assert!(handle.changed().await.is_none());
    }

    #[test]
    fn cancellation_is_exact_bounded_and_snapshot_based() {
        let (cancel_tx, mut cancel_rx) = mpsc::channel(2);
        let mut tracker = InboundResourceTracker::new(cancel_tx);
        let first = key(1, 3);
        let second = key(2, 4);
        tracker.handle_event(started(first, 10));
        tracker.handle_event(started(second, 20));

        assert!(tracker.cancel_inbound(&first.resource_id));
        assert_eq!(cancel_rx.try_recv().unwrap().key(), first);
        assert_eq!(tracker.cancel_all_inbound(), 2);
        assert_eq!(cancel_rx.try_recv().unwrap().key(), first);
        assert_eq!(cancel_rx.try_recv().unwrap().key(), second);
        assert!(!tracker.cancel_inbound(&[9; 32]));
    }

    #[test]
    fn full_cancel_channel_fails_without_removing_active_state() {
        let (cancel_tx, _cancel_rx) = mpsc::channel(1);
        let mut tracker = InboundResourceTracker::new(cancel_tx);
        let first = key(1, 5);
        let second = key(1, 6);
        tracker.handle_event(started(first, 10));
        tracker.handle_event(started(second, 10));

        assert!(tracker.cancel_inbound_exact(first));
        assert!(!tracker.cancel_inbound_exact(second));
        assert_eq!(tracker.inbound_count(), 2);
    }

    #[test]
    fn duplicate_start_preserves_one_logical_handle() {
        let (cancel_tx, _cancel_rx) = mpsc::channel(2);
        let mut tracker = InboundResourceTracker::new(cancel_tx);
        let split = key(3, 7);
        tracker.handle_event(InboundResourceEvent::Started {
            key: split,
            data_size: 100,
            total_segments: 3,
        });
        tracker.handle_event(InboundResourceEvent::Started {
            key: split,
            data_size: 100,
            total_segments: 3,
        });

        assert_eq!(tracker.inbound_count(), 1);
        let snapshot = tracker.inbound_resource_exact(split).unwrap().snapshot();
        assert_eq!(snapshot.total_segments, 3);
    }

    #[test]
    fn rejected_or_unknown_resources_never_become_visible() {
        let mut tracker = InboundResourceTracker::default();
        let unknown = key(4, 8);
        tracker.handle_event(InboundResourceEvent::Progress {
            key: unknown,
            transferred: 5,
            total: 10,
        });
        tracker.handle_event(InboundResourceEvent::Concluded {
            key: unknown,
            conclusion: InboundResourceConclusion::Rejected,
        });
        assert_eq!(tracker.inbound_count(), 0);
    }

    #[tokio::test]
    async fn link_close_fails_only_resources_owned_by_that_link() {
        let mut tracker = InboundResourceTracker::default();
        let closed = key(5, 9);
        let retained = key(6, 10);
        tracker.handle_event(started(closed, 10));
        tracker.handle_event(started(retained, 20));
        let mut closed_handle = tracker.inbound_resource_exact(closed).unwrap();

        tracker.handle_event(InboundResourceEvent::LinkClosed {
            link_id: closed.link_id,
        });
        assert_eq!(
            closed_handle.changed().await.unwrap().status,
            InboundResourceStatus::Failed
        );
        assert!(tracker.inbound_resource_exact(closed).is_none());
        assert!(tracker.inbound_resource_exact(retained).is_some());
    }

    #[test]
    fn cancel_then_complete_is_terminal_and_not_requeued() {
        let (cancel_tx, mut cancel_rx) = mpsc::channel(2);
        let mut tracker = InboundResourceTracker::new(cancel_tx);
        let resource = key(7, 11);
        tracker.handle_event(started(resource, 10));
        let handle = tracker.inbound_resource_exact(resource).unwrap();

        assert!(handle.cancel());
        assert_eq!(cancel_rx.try_recv().unwrap().key(), resource);
        tracker.handle_event(InboundResourceEvent::Concluded {
            key: resource,
            conclusion: InboundResourceConclusion::Complete,
        });
        assert_eq!(handle.snapshot().status, InboundResourceStatus::Complete);
        assert!(!handle.cancel());
        assert_eq!(tracker.inbound_count(), 0);
    }
}
