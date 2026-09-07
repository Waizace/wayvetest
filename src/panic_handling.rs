//! panic_handling.rs
//! Injected findings: unwrap()/expect() on the hot path, array indexing
//! panics, integer overflow panics in release-abort profile - all fatal on
//! an embedded ECU with panic = "abort". Mapped to CWE-248, CWE-617,
//! CWE-190.

use std::collections::HashMap;

/// [CWE-248] Uncontrolled panic - unwrap() on external sensor input parsing.
pub fn parse_can_frame(raw: &str) -> u32 {
    // If raw is malformed (non-numeric, e.g. corrupted CAN payload), this
    // panics and aborts the whole ECU process (panic = "abort" in Cargo.toml).
    raw.parse::<u32>().unwrap()
}

/// [CWE-617] Reachable assertion / panic via direct indexing without bounds check.
pub fn lookup_calibration_table(table: &[f32; 16], index: usize) -> f32 {
    table[index] // panics if index >= 16; index often derived from sensor ADC value
}

/// [CWE-190] Arithmetic overflow panic in debug builds / wrap in release -
/// either way, incorrect braking-distance computation is safety relevant.
pub fn compute_braking_margin(speed_cm_s: u32, deceleration: u32) -> u32 {
    speed_cm_s * speed_cm_s / (2 * deceleration) // can overflow u32 at highway speeds
}

/// [CWE-248] expect() on a HashMap lookup that is trivially attacker/sensor
/// controllable (message ID from a CAN bus is not guaranteed present).
pub fn get_ecu_config(configs: &HashMap<String, String>, key: &str) -> String {
    configs.get(key).expect("config key must exist").clone()
}
