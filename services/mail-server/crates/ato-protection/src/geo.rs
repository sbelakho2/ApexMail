//! Geographic analysis — Haversine distance and impossible travel detection

use std::f64::consts::PI;

/// Earth's mean radius in kilometers
const EARTH_RADIUS_KM: f64 = 6371.0;

/// A geographic coordinate
#[derive(Debug, Clone, Copy)]
pub struct GeoPoint {
    /// Latitude in degrees
    pub lat: f64,
    /// Longitude in degrees
    pub lon: f64,
}

/// Calculate Haversine distance between two points in kilometers
pub fn haversine_distance(a: &GeoPoint, b: &GeoPoint) -> f64 {
    let d_lat = (b.lat - a.lat).to_radians();
    let d_lon = (b.lon - a.lon).to_radians();

    let lat1 = a.lat.to_radians();
    let lat2 = b.lat.to_radians();

    // Clamp the haversine to [0, 1] before sqrt/asin:for antipodal or
    // numerically-extreme points the float sum can exceed 1.0, and
    // asin(x > 1) = NaN, which silently poisoned every downstream
    // impossible-travel decision with NaN comparisons.
    let a_val = ((d_lat / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2))
    .clamp(0.0, 1.0);
    let c = 2.0 * a_val.sqrt().asin();

    EARTH_RADIUS_KM * c
}

/// Minimum gap between events before travel is evaluated. Mobile networks
/// routinely bounce a session between points-of-presence within the same
/// minute, and clock skew between collectors produces the same shape;
/// sub-two-minute "travel" is measurement noise, not motion.
const MIN_TRAVEL_GAP_SECS: f64 = 120.0;

/// Minimum distance before travel is evaluated. GeoIP resolves to PoP /
/// city granularity, so two lookups of the same user seconds apart can be
/// tens of km apart; under 100 km is jitter, not travel.
const MIN_TRAVEL_DISTANCE_KM: f64 = 100.0;

/// Check if travel between two points in the given time is physically impossible
/// Returns (is_impossible, required_speed_kmh, distance_km)
///
/// Tolerance rules (all skip, i.e. report not-impossible):
/// - `elapsed <= 0`: clock skew between event collectors, not travel.
/// - `elapsed < MIN_TRAVEL_GAP_SECS`: PoP bounces / same-minute noise.
/// - `distance < MIN_TRAVEL_DISTANCE_KM`: GeoIP resolution jitter.
pub fn check_impossible_travel(
    from: &GeoPoint,
    to: &GeoPoint,
    elapsed_secs: f64,
    max_speed_kmh: f64,
) -> (bool, f64, f64) {
    let distance_km = haversine_distance(from, to);

    if elapsed_secs <= 0.0 {
        // Backwards or identical timestamps are clock skew between
        // collectors. Reporting "infinite speed" here turned skew into
        // account-blocking impossible-travel findings.
        return (false, 0.0, distance_km);
    }
    if elapsed_secs < MIN_TRAVEL_GAP_SECS {
        return (false, 0.0, distance_km);
    }
    if distance_km < MIN_TRAVEL_DISTANCE_KM {
        return (false, 0.0, distance_km);
    }

    let elapsed_hours = elapsed_secs / 3600.0;
    let required_speed = distance_km / elapsed_hours;

    (required_speed > max_speed_kmh, required_speed, distance_km)
}

/// Convert degrees to radians (helper, also available via .to_radians)
#[allow(dead_code)]
fn deg_to_rad(deg: f64) -> f64 {
    deg * PI / 180.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_same_point() {
        let p = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let dist = haversine_distance(&p, &p);
        assert!(dist.abs() < 0.001);
    }

    #[test]
    fn test_haversine_nyc_to_london() {
        let nyc = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let london = GeoPoint {
            lat: 51.5074,
            lon: -0.1278,
        };
        let dist = haversine_distance(&nyc, &london);
        // NYC to London ≈ 5,570 km
        assert!(
            (dist - 5570.0).abs() < 50.0,
            "NYC-London distance: {} km",
            dist
        );
    }

    #[test]
    fn test_haversine_antipodal() {
        let a = GeoPoint { lat: 0.0, lon: 0.0 };
        let b = GeoPoint {
            lat: 0.0,
            lon: 180.0,
        };
        let dist = haversine_distance(&a, &b);
        // Half circumference ≈ 20,015 km
        assert!(
            (dist - 20015.0).abs() < 100.0,
            "Antipodal distance: {} km",
            dist
        );
    }

    #[test]
    fn test_impossible_travel_detected() {
        let nyc = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let tokyo = GeoPoint {
            lat: 35.6762,
            lon: 139.6503,
        };
        // 1 hour between NYC and Tokyo (≈10,800 km) — impossible
        let (impossible, speed, dist) = check_impossible_travel(&nyc, &tokyo, 3600.0, 900.0);
        assert!(
            impossible,
            "Should be impossible: speed={:.0} km/h, dist={:.0} km",
            speed, dist
        );
    }

    #[test]
    fn test_plausible_travel() {
        let nyc = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let london = GeoPoint {
            lat: 51.5074,
            lon: -0.1278,
        };
        // 8 hours between NYC and London (≈5,570 km at ≈696 km/h) — plausible by plane
        let (impossible, speed, _) = check_impossible_travel(&nyc, &london, 8.0 * 3600.0, 900.0);
        assert!(!impossible, "Should be plausible: speed={:.0} km/h", speed);
    }

    #[test]
    fn test_zero_elapsed_different_location_is_skipped() {
        // Same/backwards timestamps are collector clock skew, not travel.
        // Treating them as "infinite speed" blocked accounts on telemetry
        // jitter alone.
        let a = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let b = GeoPoint {
            lat: 35.6762,
            lon: 139.6503,
        };
        let (impossible, _, _) = check_impossible_travel(&a, &b, 0.0, 900.0);
        assert!(
            !impossible,
            "zero/negative elapsed must be skipped as clock skew"
        );
    }

    #[test]
    fn test_zero_elapsed_same_location() {
        let a = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let b = GeoPoint {
            lat: 40.7129,
            lon: -74.006,
        };
        let (impossible, _, _) = check_impossible_travel(&a, &b, 0.0, 900.0);
        assert!(!impossible, "Same timestamp, same location = ok");
    }

    #[test]
    fn test_short_gap_not_impossible() {
        // Fail-first: 30s / 500km was reported as impossible travel.
        // Sub-two-minute gaps are mobile-network PoP bounces and clock
        // skew, not travel — they must not fire.
        let a = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let b = GeoPoint {
            lat: 44.9,
            lon: -70.2,
        }; // ~500 km away
        let dist = haversine_distance(&a, &b);
        assert!((dist - 500.0).abs() < 60.0, "fixture distance: {dist}");
        let (impossible, _, _) = check_impossible_travel(&a, &b, 30.0, 500.0);
        assert!(!impossible, "30s/500km must be skipped as jitter/skew");
    }

    #[test]
    fn test_short_distance_not_impossible() {
        // GeoIP PoP jitter: two resolutions of the same user can be ~50km
        // apart within seconds — under 100 km never counts as travel.
        let a = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        };
        let b = GeoPoint {
            lat: 40.9,
            lon: -74.3,
        }; // ~40 km
        let (impossible, _, _) = check_impossible_travel(&a, &b, 5.0, 500.0);
        assert!(!impossible, "<100km must be skipped as GeoIP jitter");
    }

    #[test]
    fn test_long_haul_impossible_travel_still_fires() {
        // 8000 km in 30 min ≈ 16000 km/h — genuinely impossible.
        let a = GeoPoint {
            lat: 40.7128,
            lon: -74.006,
        }; // NYC
        let b = GeoPoint {
            lat: 48.8566,
            lon: 2.3522,
        }; // Paris ~5837km; use Tokyo for 8000+
        let c = GeoPoint {
            lat: 35.6762,
            lon: 139.6503,
        }; // Tokyo
        let dist = haversine_distance(&a, &c);
        assert!(dist > 8000.0, "NYC-Tokyo fixture: {dist}");
        let (impossible, speed, _) = check_impossible_travel(&a, &c, 1800.0, 500.0);
        assert!(impossible, "8000km/30min must fire (speed {speed:.0} km/h)");
        let _ = b;
    }

    #[test]
    fn test_antipodal_points_no_nan() {
        // Antipodal/extreme points previously produced asin(x > 1) = NaN.
        let a = GeoPoint { lat: 0.0, lon: 0.0 };
        let b = GeoPoint {
            lat: 0.0,
            lon: 180.0,
        };
        let d = haversine_distance(&a, &b);
        assert!(d.is_finite(), "antipodal distance must be finite, got {d}");
        assert!(
            (d - 20015.0).abs() < 100.0,
            "half circumference ~20015km, got {d}"
        );
        // Impossible travel over antipodes must be a decision, not NaN.
        let (impossible, speed, _) = check_impossible_travel(&a, &b, 3600.0, 500.0);
        assert!(impossible);
        assert!(speed.is_finite());
    }
}
