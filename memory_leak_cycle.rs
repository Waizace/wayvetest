//! memory_leak_cycle.rs
//! [CWE-401] Reference-cycle memory leak: two nodes hold `Rc<RefCell<...>>`
//! pointers to each other, so the strong-count of each never reaches zero
//! and the pair is never deallocated even after both external handles are
//! dropped - a Rust-specific case that safe code (no `unsafe` at all) can
//! still leak memory, useful for testing whether a tool's Rust analysis
//! goes beyond "flag every `unsafe` block".

use std::cell::RefCell;
use std::rc::Rc;

struct EcuNode {
    name: String,
    peer: RefCell<Option<Rc<EcuNode>>>,
}

pub fn create_leaking_cycle() {
    let node_a = Rc::new(EcuNode { name: "sensor_fusion".into(), peer: RefCell::new(None) });
    let node_b = Rc::new(EcuNode { name: "actuator_ctrl".into(), peer: RefCell::new(None) });

    *node_a.peer.borrow_mut() = Some(Rc::clone(&node_b));
    *node_b.peer.borrow_mut() = Some(Rc::clone(&node_a)); // creates the cycle

    // Both node_a and node_b go out of scope here, but each still holds a
    // strong Rc to the other, so neither's refcount reaches zero -> leak.
}
