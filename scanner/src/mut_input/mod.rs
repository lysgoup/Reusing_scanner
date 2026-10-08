//! What a scan needs out of angora/fuzzer/mut_input.
//!
//! `offsets` for merge_offsets (cond_stmt/cond_state.rs) and `serialize` for
//! the four little-/big-endian readers and writers that
//! magic_value_if_untransformed and fparser use.
//!
//! `MutInput` itself and `rw` (get/set bytes by offsets) are gone with the
//! search methods that were their only callers -- a scan never writes a
//! mutated buffer back.

pub mod offsets;
mod serialize;

pub use self::serialize::*;
