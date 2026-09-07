//! ffi_bindings.rs
//! Injected findings: unsafe FFI boundary issues calling into the C++
//! perception stack (cpp-embedded/). Mapped to CWE-119, CWE-704, CWE-676.

use std::os::raw::{c_char, c_int, c_void};
use std::ffi::CString;

#[link(name = "perception_stack")]
extern "C" {
    // [CWE-704] FFI signature assumes a null-terminated C string but the C++
    // side (string_handling.cpp) does not guarantee bounds - mismatch risk.
    fn copySensorLabel(src: *const c_char);

    // [CWE-119] Raw buffer handed across the FFI boundary with a bare length,
    // no ownership contract documented; Rust caller cannot verify size.
    fn writeSensorFrame(frame: *mut c_void, index: c_int, value: u8);
}

/// [CWE-676] Calls a banned/unsafe C function via FFI with unsanitized input
/// originating from a network-facing diagnostics service.
pub fn forward_label_to_cpp(user_supplied_label: &str) {
    let c_string = CString::new(user_supplied_label).unwrap_or_default();
    unsafe {
        copySensorLabel(c_string.as_ptr()); // triggers strcpy overflow on C++ side
    }
}

/// [CWE-119] No validation of `index` before crossing into unsafe C++ write.
pub fn forward_frame_write(frame_ptr: *mut c_void, index: i32, value: u8) {
    unsafe {
        writeSensorFrame(frame_ptr, index, value); // index unchecked, OOB write downstream
    }
}
