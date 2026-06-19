// FILE: ./src/engine/config.rs                      
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)] // Allows missing keys in TOML to fall back to Default::default()
pub struct Config {
    pub tier1_threshold_rows: u64,
    pub tier2_threshold_rows: u64,
    pub stale_stats_days: u64,
    pub toast_width_threshold_bytes: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tier1_threshold_rows: 100_000,
            tier2_threshold_rows: 10_000,
            stale_stats_days: 7,
            toast_width_threshold_bytes: 2048, // 2KB avg_width is a good baseline for a "wide" column
        }
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Self {
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(config) = toml::from_str(&contents) {
                    return config;
                } else {
                    eprintln!("[WARN] Failed to parse config at {}. Using defaults.", path.display());
                }
            }
        }
        Self::default()
    }
}
