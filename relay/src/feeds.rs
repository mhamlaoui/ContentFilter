//! Signed feed distribution (relay-feeds). The relay *serves* feeds; it
//! never signs them — feeds are produced offline with the release key
//! (docs/KEY_CEREMONY.md) and arrive here as `FeedEnvelope` JSON files in
//! a configured directory, loaded at startup.
//!
//! Deliberate boundaries:
//!
//! - **No relay-side signature verification.** Every client verifies
//!   against its own pinned release key (cf-core `pull_feed`) and must
//!   keep doing so no matter what the relay claims — the relay is not a
//!   trust anchor. A relay-side check would mean pinning a second copy of
//!   the release key that can drift from the clients', for zero security
//!   gain. The right place to validate a feed is at *publish* time,
//!   before the file ever reaches the relay — that's hard-doh-feed-ops'
//!   pipeline.
//! - **A corrupt file fails startup loudly.** Skipping it would mean an
//!   ops mistake silently freezes feed updates at the previous version;
//!   a relay that won't start gets noticed immediately.
//! - **Load-at-startup only.** Rotation cadence, hot reload, and the
//!   staleness alarm belong to hard-doh-feed-ops (#76); this module keeps
//!   one seam (`FeedStore::load_dir`) it can drive however it decides.
//! - **Ingestion is a directory, not an upload endpoint.** An
//!   authenticated admin-upload route would introduce a whole new
//!   authorization class (who may replace the blocklist?) to duplicate
//!   what `scp` + restart already does under existing ops access control.

use cf_core::{FeedEnvelope, FeedKind};
use std::path::Path;

/// The latest known envelope per kind. Empty is a valid state (a relay
/// can start before the first feed is published); serving then 404s.
#[derive(Debug, Default)]
pub struct FeedStore {
    blocklist: Option<FeedEnvelope>,
    doh_endpoints: Option<FeedEnvelope>,
}

impl FeedStore {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads every `*.json` file in `dir` as a `FeedEnvelope`, keeping the
    /// highest `feed_seq` per kind ("version increments" is enforced by
    /// selection here and by every client's own monotonicity floor).
    /// Any unparseable file is a hard error — see the module docs.
    pub fn load_dir(dir: &Path) -> std::io::Result<Self> {
        let mut store = Self::empty();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            let envelope: FeedEnvelope = serde_json::from_str(&text).map_err(|e| {
                std::io::Error::other(format!("corrupt feed file {}: {e}", path.display()))
            })?;
            store.absorb(envelope);
        }
        Ok(store)
    }

    fn absorb(&mut self, envelope: FeedEnvelope) {
        let slot = match envelope.kind {
            FeedKind::Blocklist => &mut self.blocklist,
            FeedKind::DohEndpoints => &mut self.doh_endpoints,
        };
        let newer = slot
            .as_ref()
            .is_none_or(|current| envelope.feed_seq > current.feed_seq);
        if newer {
            *slot = Some(envelope);
        }
    }

    pub fn latest(&self, kind: FeedKind) -> Option<&FeedEnvelope> {
        match kind {
            FeedKind::Blocklist => self.blocklist.as_ref(),
            FeedKind::DohEndpoints => self.doh_endpoints.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_core::relay_client::sign_feed;
    use ed25519_dalek::SigningKey;

    fn release_key() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn envelope(kind: FeedKind, seq: u64) -> FeedEnvelope {
        sign_feed(
            kind,
            seq,
            1_700_000_000,
            format!("payload-{seq}").into_bytes(),
            &release_key(),
        )
    }

    fn write_feed(dir: &Path, name: &str, envelope: &FeedEnvelope) {
        std::fs::write(
            dir.join(name),
            serde_json::to_string_pretty(envelope).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn load_dir_keeps_the_highest_seq_per_kind() {
        let dir = tempfile::tempdir().unwrap();
        write_feed(
            dir.path(),
            "blocklist-7.json",
            &envelope(FeedKind::Blocklist, 7),
        );
        write_feed(
            dir.path(),
            "blocklist-9.json",
            &envelope(FeedKind::Blocklist, 9),
        );
        write_feed(
            dir.path(),
            "blocklist-8.json",
            &envelope(FeedKind::Blocklist, 8),
        );
        write_feed(
            dir.path(),
            "doh-3.json",
            &envelope(FeedKind::DohEndpoints, 3),
        );

        let store = FeedStore::load_dir(dir.path()).unwrap();
        assert_eq!(store.latest(FeedKind::Blocklist).unwrap().feed_seq, 9);
        assert_eq!(store.latest(FeedKind::DohEndpoints).unwrap().feed_seq, 3);
        // Served exactly as loaded, signature included:
        assert_eq!(
            store.latest(FeedKind::Blocklist).unwrap(),
            &envelope(FeedKind::Blocklist, 9)
        );
    }

    #[test]
    fn a_corrupt_feed_file_fails_loudly_at_load() {
        let dir = tempfile::tempdir().unwrap();
        write_feed(dir.path(), "good.json", &envelope(FeedKind::Blocklist, 7));
        std::fs::write(dir.path().join("bad.json"), "{ not json").unwrap();
        let err = FeedStore::load_dir(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("bad.json"),
            "the error must name the offending file: {err}"
        );
    }

    #[test]
    fn non_json_files_are_ignored_and_empty_dirs_are_valid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.txt"), "not a feed").unwrap();
        let store = FeedStore::load_dir(dir.path()).unwrap();
        assert!(store.latest(FeedKind::Blocklist).is_none());
        assert!(store.latest(FeedKind::DohEndpoints).is_none());
    }
}
