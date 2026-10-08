# Reusing scanner

One-shot taint scan over a seed corpus. Writes the cache `afl-fuzz -r` reads:

    <out>/value_pool.dict        value candidates, one entry per line
    <out>/unsolved_condition     (cmpid, context, order) sites seen one way only
    <out>/<seed>.dtaint          per seed: which sites depend on which bytes

Self-contained: the compiler that instruments a target and the scanner that
runs it are both here.

## What this is

The analysis is Angora's, not a reimplementation of it. Each seed runs once
through `Executor::track()`, the track file is parsed by `load_track_data()`
(fparser + filter, including the magic-byte grouping), and values land in the
pool via `Depot::add_entries()`. The Rust under `scanner/` is the subset of
angora/fuzzer those three calls reach, copied unchanged.

What was left behind is the fuzzing loop. `fuzz_loop`, `fuzz_main` and
`bind_cpu` are gone outright; `search/` keeps only the enum `CommandOpt`
carries, `mut_input/` only the byte readers and `merge_offsets`, `check_dep.rs`
only the ASAN probe. Each of those files says at the top what was dropped and
why. `stats`, `branches`, `command` and `data_cov` are whole, because Executor
holds them.

`llvm_mode/`, `runtime/` and `runtime_fast/` are Angora's, unmodified except
for the two changes this fork exists for:

  * `angora-clang` passes `-fno-builtin`, so `-O1`+ stops expanding a short
    `memcmp(..)==0` inline -- a 4-byte ELF magic otherwise becomes an integer
    compare with no call left for the cmpfn rules to hook. A target that pays
    too much for this (cond counts up, borderline seeds past the track
    timeout) opts out with `ANGORA_KEEP_BUILTINS=1`.
  * `rules/exploitation_list.txt` adds `fun:bcmp=cmpfn`, covering the longer
    comparisons that survive as a `bcmp` call. It is inert under
    `-fno-builtin`, and exists for the targets that opt out.

## Building

    docker build -t reusing-scanner .

or, with LLVM 4.0 and the toolchain in `rust-toolchain` already on PATH:

    ./build/build.sh          # -> bin/{taint_scan,angora-clang,pass,rules,lib}

## Running

Two binaries per target, both built by `bin/angora-clang`:

    export ANGORA_TAINT_RULE_LIST=$PWD/bin/rules/exploitation_list.txt
    bin/angora-clang -o target_fast  target.c          # coverage instrumented
    USE_TRACK=1 bin/angora-clang -o target_track target.c   # DFSan taint

Then:

    bin/taint_scan -i <seed_dir> -o <out_dir> -t <track> -- <fast> [args]

`-t` is the track binary: running it writes a bincode `LogData` to
`$ANGORA_TRACK_OUTPUT`, which is what the scan reads. The binary after `--` is
the fast one -- it is what the forkserver drives, and `@@` marks the input file
in its argv.

    bin/taint_scan -i ./seeds -o ./cache -t ./nm_track -- ./nm_fast -a @@

A seed whose track run crashes or times out is skipped: it gets no `.dtaint`,
which `afl-fuzz -r` reads as "no reusing stage for this seed".

## Output is unordered

Two runs over the same corpus produce the same entries in a different order --
the pool and the per-seed records are built in `HashMap`s, and Rust seeds those
per process. Angora behaves the same way. Compare sorted, not byte-for-byte.
