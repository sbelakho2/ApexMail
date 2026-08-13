//! Resource pressure snapshot, all fixed-point 0..1000.

use serde::{Deserialize, Serialize};

/// Resource pressure snapshot, all fixed-point 0..1000.
///
/// - `argon_capacity`: how much memory-hard PoW the backend can still serve
/// - `issuance_capacity`: remaining challenge issuance headroom
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePressure {
    pub argon_capacity: u16,
    pub issuance_capacity: u16,
}

impl Default for ResourcePressure {
    fn default() -> ResourcePressure {
        ResourcePressure {
            argon_capacity: 1000,
            issuance_capacity: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_healthy() {
        let r = ResourcePressure::default();
        assert_eq!(r.argon_capacity, 1000);
        assert_eq!(r.issuance_capacity, 1000);
    }
}
