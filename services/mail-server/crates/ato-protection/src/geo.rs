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

    let a_val = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a_val.sqrt().asin();

    EARTH_RADIUS_KM * c
}

/// Check if travel between two points in the given time is physically impossible
/// Returns (is_impossible, required_speed_kmh, distance_km)
pub fn check_impossible_travel(
    from: &GeoPoint,
    to: &GeoPoint,
    elapsed_secs: f64,
    max_speed_kmh: f64,
) -> (bool, f64, f64) {
    if elapsed_secs <= 0.0 {
// Same timestamp or backwards — suspicious if different location
        let dist = haversine_distance(from, to);
        return (dist > 1.0, f64::INFINITY, dist);
    }

    let distance_km = haversine_distance(from, to);
    let elapsed_hours = elapsed_secs / 3600.0;
    let required_speed = distance_km / elapsed_hours;

    (required_speed > max_speed_kmh, required_speed, distance_km)
}

/// Convert degrees to radians (helper, also available via .to_radians)
#[allow(unused)]
fn deg_to_rad(deg: f64) -> f64 {
    deg * PI / 180.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_same_point() {
        let p = GeoPoint { lat: 40.7128, lon: -74.006 };
        let dist = haversine_distance(&p, &p);
        assert!(dist.abs() < 0.001);
    }

    #[test]
    fn test_haversine_nyc_to_london() {
        let nyc = GeoPoint { lat: 40.7128, lon: -74.006 };
        let london = GeoPoint { lat: 51.5074, lon: -0.1278 };
        let dist = haversine_distance(&nyc, &london);
// NYC to London ≈ 5,570 km
        assert!((dist - 5570.0).abs() < 50.0, "NYC-London distance: {} km", dist);
    }

    #[test]
    fn test_haversine_antipodal() {
        let a = GeoPoint { lat: 0.0, lon: 0.0 };
        let b = GeoPoint { lat: 0.0, lon: 180.0 };
        let dist = haversine_distance(&a, &b);
// Half circumference ≈ 20,015 km
        assert!((dist - 20015.0).abs() < 100.0, "Antipodal distance: {} km", dist);
    }

    #[test]
    fn test_impossible_travel_detected() {
        let nyc = GeoPoint { lat: 40.7128, lon: -74.006 };
        let tokyo = GeoPoint { lat: 35.6762, lon: 139.6503 };
// 1 hour between NYC and Tokyo (≈10,800 km) — impossible
        let (impossible, speed, dist) = check_impossible_travel(&nyc, &tokyo, 3600.0, 900.0);
        assert!(impossible, "Should be impossible: speed={:.0} km/h, dist={:.0} km", speed, dist);
    }

    #[test]
    fn test_plausible_travel() {
        let nyc = GeoPoint { lat: 40.7128, lon: -74.006 };
        let london = GeoPoint { lat: 51.5074, lon: -0.1278 };
// 8 hours between NYC and London (≈5,570 km at ≈696 km/h) — plausible by plane
        let (impossible, speed, _) = check_impossible_travel(&nyc, &london, 8.0 * 3600.0, 900.0);
        assert!(!impossible, "Should be plausible: speed={:.0} km/h", speed);
    }

    #[test]
    fn test_zero_elapsed_different_location() {
        let a = GeoPoint { lat: 40.7128, lon: -74.006 };
        let b = GeoPoint { lat: 35.6762, lon: 139.6503 };
        let (impossible, _, _) = check_impossible_travel(&a, &b, 0.0, 900.0);
        assert!(impossible, "Same timestamp, different city = impossible");
    }

    #[test]
    fn test_zero_elapsed_same_location() {
        let a = GeoPoint { lat: 40.7128, lon: -74.006 };
        let b = GeoPoint { lat: 40.7129, lon: -74.006 };
        let (impossible, _, _) = check_impossible_travel(&a, &b, 0.0, 900.0);
        assert!(!impossible, "Same timestamp, same location = ok");
    }
}
