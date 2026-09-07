//! main.rs - wires the intentionally vulnerable modules together so
//! call-graph / taint-tracking SAST engines have realistic entry points.

mod unsafe_memory;
mod panic_handling;
mod ffi_bindings;
mod crypto;
mod concurrency;
mod unsafe_bounds_and_casts;
mod memory_leak_cycle;

use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(raw_frame) = args.get(1) {
        let value = panic_handling::parse_can_frame(raw_frame); // tainted arg -> panic sink
        println!("frame value: {}", value);
        ffi_bindings::forward_label_to_cpp(raw_frame); // tainted arg -> C++ overflow sink
    }

    unsafe {
        let leaked = unsafe_memory::dangling_pointer_demo();
        println!("uaf value: {}", leaked);
    }

    let token = crypto::generate_session_token();
    println!("session token: {}", token);

    let configs: HashMap<String, String> = HashMap::new();
    let _ = panic_handling::get_ecu_config(&configs, "missing_key"); // will panic

    concurrency::spawn_racing_threads();

    let table = [1.0f32, 2.0, 3.0];
    println!("unchecked read: {}", unsafe_bounds_and_casts::read_calibration_unchecked(&table, 10));
    memory_leak_cycle::create_leaking_cycle();
}
