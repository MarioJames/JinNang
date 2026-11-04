//! Jinnang: a local credential vault for AI agents.

pub mod crypto;
pub mod generate;
pub mod input;
pub mod refs;
pub mod run;
pub mod schema;
pub mod seal;
pub mod selector;
pub mod store;

/// Process hardening: no core dumps, not ptrace-able by same-UID processes,
/// private file creation.
pub fn harden_process() {
    use rustix::process::{
        DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit, umask,
    };
    let _ = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    umask(rustix::fs::Mode::from_raw_mode(0o077));
}
