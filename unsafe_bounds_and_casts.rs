//! unsafe_bounds_and_casts.rs
//! Injected findings: bounds-check bypass via get_unchecked, lossy `as`
//! numeric casts, and an unsound `unsafe impl Send`/`Sync`. Mapped to
//! CWE-125, CWE-681/CWE-190, CWE-362/CWE-667.

use std::cell::UnsafeCell;
use std::rc::Rc;

/// [CWE-125] get_unchecked() skips the bounds check entirely - if `index`
/// is ever out of range (e.g. derived from a corrupted CAN frame), this is
/// an out-of-bounds read with no panic, no diagnostic - silent UB.
pub fn read_calibration_unchecked(table: &[f32], index: usize) -> f32 {
    unsafe { *table.get_unchecked(index) }
}

/// [CWE-681 / CWE-190] Lossy `as` cast - unlike `TryFrom`, `as` silently
/// truncates/wraps instead of erroring, turning an out-of-range sensor
/// reading into an incorrect, silently-wrapped value.
pub fn quantize_sensor_reading(raw_mv: i32) -> u8 {
    raw_mv as u8   // values outside 0..=255 wrap silently, no error path
}

/// [CWE-362 / CWE-667] Unsound `unsafe impl Send` on a type wrapping a raw
/// pointer via UnsafeCell with no actual synchronization - asserts a
/// thread-safety guarantee the type does not provide, defeating the
/// compiler's data-race prevention entirely for downstream users.
pub struct SharedSensorState {
    value: UnsafeCell<i32>,
}

unsafe impl Send for SharedSensorState {}
unsafe impl Sync for SharedSensorState {}   // no locking anywhere - false promise

impl SharedSensorState {
    pub fn new(v: i32) -> Self {
        SharedSensorState { value: UnsafeCell::new(v) }
    }
    pub fn set(&self, v: i32) {
        unsafe { *self.value.get() = v; }   // unsynchronized write, now reachable from any thread
    }
}

/// [CWE-401-adjacent] Not itself unsafe, but demonstrates that `Rc` cycles
/// leak in Rust despite the ownership model - paired with memory_leak_cycle.rs.
pub fn wrap_in_rc(v: i32) -> Rc<i32> {
    Rc::new(v)
}
