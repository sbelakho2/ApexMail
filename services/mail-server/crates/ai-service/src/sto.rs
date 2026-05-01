//! Send-Time Optimisation (STO) — find the best hour/day to send emails.

use crate::types::SendTimeSlot;

/// Send-time optimisation engine based on engagement histograms.
pub struct SendTimeOptimizer;

impl Default for SendTimeOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SendTimeOptimizer {
    pub fn new() -> Self {
        Self
    }

    /// Find the single best send time from engagement data.
    /// Each entry is `(hour 0-23, day_of_week 0-6, engagement_score)`.
    pub fn find_optimal_time(&self, engagement_data: &[(u8, u8, f64)]) -> Option<SendTimeSlot> {
        if engagement_data.is_empty() {
            return None;
        }

        let heatmap = self.build_heatmap(engagement_data);

        let mut best_hour: u8 = 0;
        let mut best_dow: u8 = 0;
        let mut best_score: f64 = f64::NEG_INFINITY;

        for (h, row) in heatmap.iter().enumerate() {
            for (d, &score) in row.iter().enumerate() {
                if score > best_score {
                    best_score = score;
                    best_hour = h as u8;
                    best_dow = d as u8;
                }
            }
        }

        Some(SendTimeSlot {
            hour: best_hour,
            day_of_week: best_dow,
            score: best_score,
        })
    }

    /// Build a 24×7 engagement heatmap (hours × days).
    /// Each cell is the average engagement score for that (hour, day) slot.
    pub fn build_heatmap(&self, data: &[(u8, u8, f64)]) -> [[f64; 7]; 24] {
        let mut sums = [[0.0f64; 7]; 24];
        let mut counts = [[0u64; 7]; 24];

        for &(hour, dow, score) in data {
            let h = (hour as usize).min(23);
            let d = (dow as usize).min(6);
            sums[h][d] += score;
            counts[h][d] += 1;
        }

        let mut heatmap = [[0.0f64; 7]; 24];
        for h in 0..24 {
            for d in 0..7 {
                if counts[h][d] > 0 {
                    heatmap[h][d] = sums[h][d] / counts[h][d] as f64;
                }
            }
        }
        heatmap
    }

    /// Predict the best 2-hour send window for a given timezone offset.
    /// Returns `(start_hour, end_hour)` in UTC adjusted by `tz_offset` hours.
    pub fn predict_best_window(&self, tz_offset: i32) -> (u8, u8) {
        // Heuristic:business-hours peak in the recipient's local time is 10-12
        let local_start: i32 = 10;
        let local_end: i32 = 12;
        let utc_start = ((local_start - tz_offset).rem_euclid(24)) as u8;
        let utc_end = ((local_end - tz_offset).rem_euclid(24)) as u8;
        (utc_start, utc_end)
    }

    /// Batch-optimise:compute the best send time for each user given their
    /// individual engagement histories.
    /// Each inner slice is the same `(hour, dow, score)` format used by
    /// `find_optimal_time`. Returns one `SendTimeSlot` per user.
    pub fn batch_optimize(&self, user_histories: &[Vec<(u8, u8, f64)>]) -> Vec<SendTimeSlot> {
        user_histories
            .iter()
            .map(|history| {
                self.find_optimal_time(history).unwrap_or(SendTimeSlot {
                    hour: 10,
                    day_of_week: 2,
                    score: 0.0,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_optimal_time() {
        let sto = SendTimeOptimizer::new();
        let data = vec![(9, 1, 0.5), (10, 2, 0.9), (10, 2, 0.8), (15, 4, 0.3)];
        let best = sto.find_optimal_time(&data).unwrap();
        assert_eq!(best.hour, 10);
        assert_eq!(best.day_of_week, 2);
        assert!(best.score > 0.8);
    }

    #[test]
    fn test_build_heatmap_averages() {
        let sto = SendTimeOptimizer::new();
        let data = vec![(5, 0, 0.4), (5, 0, 0.6), (5, 0, 1.0)];
        let hm = sto.build_heatmap(&data);
        let avg = hm[5][0];
        assert!(
            (avg - 2.0 / 3.0 * 1.0).abs() < 0.01 || (avg - (0.4 + 0.6 + 1.0) / 3.0).abs() < 1e-9
        );
    }

    #[test]
    fn test_predict_best_window_timezone() {
        let sto = SendTimeOptimizer::new();
        // UTC+5 → local 10am = UTC 5am
        let (start, end) = sto.predict_best_window(5);
        assert_eq!(start, 5);
        assert_eq!(end, 7);

        // UTC-5 → local 10am = UTC 15 (3pm)
        let (start2, end2) = sto.predict_best_window(-5);
        assert_eq!(start2, 15);
        assert_eq!(end2, 17);
    }
}
