//! The part of angora/fuzzer that a taint scan reaches.
//!
//! Every module below is a byte-for-byte copy from Reusing_mut. What is NOT
//! here is the fuzzing loop -- mut_input, search, fuzz_loop, fuzz_main,
//! fuzz_type, bind_cpu, check_dep, tmpfs -- because the scan never mutates an
//! input or schedules a queue: it runs each seed once under the track binary
//! and serialises what Angora's own pipeline made of it.
//!
//! The chain that matters, all of it Angora's:
//!
//!   Executor::track()          executor/   -- run the track binary on a seed
//!   load_track_data()          track/      -- fparser.rs + filter.rs
//!   Depot::add_entries()       depot/      -- label_pattern_tracker.rs
//!
//! `stats`, `branches`, `command` and `data_cov` are here because Executor
//! holds them, not because a scan uses them for anything.

#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_more;

pub mod branches;
pub mod cond_stmt;
mod data_cov;
pub mod depot;
pub mod executor;
pub mod stats;
pub mod track;

pub mod command;

mod check_dep;
mod fuzz_type;
mod mut_input;
mod search;
mod tmpfs;
