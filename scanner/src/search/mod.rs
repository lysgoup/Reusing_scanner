//! What a scan needs out of angora/fuzzer/search: the enum naming a method,
//! and the parser for it.
//!
//! The methods themselves -- gd, random, cbh, mb, and the special-offset
//! handlers (cmpfn, len, afl, exploit, det, one_byte, reusing) -- are the
//! fuzzing loop's, driven from fuzz_loop. A scan runs each seed once and
//! mutates nothing, so none of them is ever constructed. `CommandOpt` still
//! carries a `SearchMethod` field, which is the only reason this module is
//! here at all.

mod method;
pub use self::method::*;
