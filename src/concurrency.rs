//! concurrency.rs
//! Injected findings: data races achieved by bypassing the borrow checker
//! via `unsafe`, and deadlock-prone lock ordering. Mapped to CWE-362,
//! CWE-667, CWE-413.

use std::sync::{Arc, Mutex};
use std::thread;

/// [CWE-362] Data race via raw pointer + unsafe Send/Sync override, defeating
/// Rust's normal aliasing guarantees - a pattern sometimes copy-pasted into
/// perf-critical embedded code without full review.
static mut SHARED_ODOMETER: u64 = 0;

pub unsafe fn increment_odometer_unsafe() {
    SHARED_ODOMETER += 1; // no synchronization; UB if called from multiple threads
}

pub fn spawn_racing_threads() {
    let handles: Vec<_> = (0..4)
        .map(|_| thread::spawn(|| unsafe { increment_odometer_unsafe() }))
        .collect();
    for h in handles {
        let _ = h.join();
    }
}

/// [CWE-667 / CWE-413] Inconsistent lock ordering between two mutexes can
/// deadlock two ECU tasks that both need calibration + telemetry state.
pub fn lock_order_a(cal: Arc<Mutex<i32>>, telem: Arc<Mutex<i32>>) {
    let _c = cal.lock().unwrap();
    let _t = telem.lock().unwrap(); // acquires cal then telem
}

pub fn lock_order_b(cal: Arc<Mutex<i32>>, telem: Arc<Mutex<i32>>) {
    let _t = telem.lock().unwrap();
    let _c = cal.lock().unwrap(); // acquires telem then cal - opposite order -> deadlock risk
}
