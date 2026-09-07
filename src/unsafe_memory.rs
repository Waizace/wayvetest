//! unsafe_memory.rs
//! Injected findings: unsound `unsafe` blocks, raw pointer misuse, transmute
//! abuse, uninitialized memory. Mapped to CWE-119, CWE-416, CWE-843,
//! CWE-908, and to CERT-adjacent Rust guidance (unsafe code guidelines).

use std::mem;

/// [CWE-416] Use-after-free via raw pointer outliving its referent.
pub unsafe fn dangling_pointer_demo() -> i32 {
    let boxed = Box::new(42);
    let raw_ptr: *const i32 = &*boxed;
    drop(boxed); // memory freed
    *raw_ptr // use-after-free: undefined behavior
}

/// [CWE-843] Type confusion via std::mem::transmute between incompatible types.
pub fn unsound_transmute(value: u64) -> *const u8 {
    unsafe {
        // Transmuting a u64 directly into a pointer type without validation.
        mem::transmute::<u64, *const u8>(value)
    }
}

/// [CWE-908] Reading uninitialized memory via MaybeUninit misuse.
pub unsafe fn read_uninitialized_buffer() -> [u8; 64] {
    let buf: [u8; 64] = mem::MaybeUninit::uninit().assume_init();
    buf // returns genuinely uninitialized bytes - UB to read as valid u8 array in general case
}

/// [CWE-119] Out-of-bounds write via raw pointer arithmetic on a fixed-size
/// sensor ring buffer without bounds checking (embedded DMA pattern).
pub unsafe fn write_ring_buffer(base: *mut u8, index: isize, value: u8) {
    let target = base.offset(index); // no bounds check against buffer capacity
    *target = value;
}

/// [CWE-704] Unchecked slice-from-raw-parts with attacker/sensor-controlled length.
pub unsafe fn slice_from_sensor(ptr: *const u8, len: usize) -> &'static [u8] {
    std::slice::from_raw_parts(ptr, len) // len not validated against actual allocation
}
