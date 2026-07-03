use crate::version::SchemaVersion;
use serde::{Deserialize, Serialize};

/// The current, user-visible filter configuration.
///
/// There is deliberately no `adult` field. Per svc-categories, adult-content
/// blocking is always active and is not a stored preference — if it were a
/// `bool`, "off" would be representable, and representable states get set
/// eventually. Only the genuinely optional categories are toggles here. If
/// you're about to add an `adult: bool`, don't — read THREAT_MODEL.md's
/// traceability row for messaging-wins-ties/category enforcement first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterState {
    pub version: SchemaVersion,
    pub social_enabled: bool,
    pub youtube_enabled: bool,
    /// Seconds since epoch; bookkeeping only, see [`crate::device::Device::registered_at`].
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let s = FilterState {
            version: SchemaVersion::CURRENT,
            social_enabled: true,
            youtube_enabled: false,
            updated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: FilterState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn has_no_adult_field() {
        // Landmine: this test exists purely so that if someone adds
        // `adult: bool` to FilterState, they have to also delete this test
        // and its explanation — not just quietly slip the field in.
        let s = FilterState {
            version: SchemaVersion::CURRENT,
            social_enabled: false,
            youtube_enabled: false,
            updated_at: 0,
        };
        let value = serde_json::to_value(s).unwrap();
        assert!(
            value.get("adult").is_none(),
            "adult-content blocking must not be a stored, disable-able preference"
        );
    }
}
