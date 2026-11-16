//! One-shot taint scan over a seed corpus, driving Angora's own taint
//! pipeline and writing what AFLplusplus_reusing's `afl-fuzz -r` expects.
//!
//! Everything that decides *what* a taint record means is Angora's, called
//! here unmodified: the track binary runs through `Executor::track()` (same
//! env, same memory/time limits, same input delivery), the track file is
//! parsed by `track::load_track_data()` (fparser.rs, including the magic-byte
//! grouping and `filter::filter_cond_list`), and values land in the pool via
//! `add_magic_byte_records()` / `add_cond_to_pattern_map()`. This file only
//! iterates the corpus and serialises the result.
//!
//! That is the point of it: the C scanner it replaces (afl-taint-scan) is a
//! re-implementation of those rules and can drift from them. Here the only
//! thing that can drift is the output encoding below.
//!
//! Usage:
//!   taint_scan -i <seed_dir> -o <out_dir> -t <track_target> -- <target> [args]

extern crate angora;
extern crate angora_common;
extern crate runtime;

use angora::{
    branches, command,
    cond_stmt::CondStmt,
    depot::{self, LABEL_PATTERN_MAP},
    executor, stats,
};
use angora_common::{config, log_data::LogData, tag::TagSeg};
use runtime::get_log_data;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    env, fs,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

/* ---------------------------------------------------------------------- */
/* Output encodings, matching src/afl-taint-scan.c byte for byte so this    */
/* tool is a drop-in replacement for it.                                    */
/* ---------------------------------------------------------------------- */

const DTAINT_MAGIC: u32 = 0x444e_5454;
const DTAINT_VERSION_GROUPED: u32 = 3;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// `<out_dir>/<seed>.dtaint`, the v3 format include/dtaint.h describes: the
/// raw cond list and tag table as the runtime logged them, plus the merged
/// span Angora's grouping assigned to each one-byte magic-byte cond.
fn write_dtaint(path: &Path, log: &LogData, groups: &HashMap<(u32, u32, u32), TagSeg>) {
    let mut out = Vec::with_capacity(20 + log.cond_list.len() * 64);

    put_u32(&mut out, DTAINT_MAGIC);
    put_u32(&mut out, DTAINT_VERSION_GROUPED);
    put_u32(&mut out, log.cond_list.len() as u32);
    put_u32(&mut out, log.tags.len() as u32);
    put_u32(&mut out, 0); // magic_bytes section: unused by the fuzzer side

    for c in &log.cond_list {
        put_u32(&mut out, c.cmpid);
        put_u32(&mut out, c.context);
        put_u32(&mut out, c.order);
        put_u32(&mut out, c.belong);
        put_u32(&mut out, c.condition);
        put_u32(&mut out, c.level);
        put_u32(&mut out, c.op);
        put_u32(&mut out, c.size);
        put_u32(&mut out, c.lb1);
        put_u32(&mut out, c.lb2);
        put_u64(&mut out, c.arg1);
        put_u64(&mut out, c.arg2);

        // 0/0 unless this cond was glued to contiguous same-context siblings.
        match groups.get(&(c.cmpid, c.context, c.order)) {
            Some(g) => {
                put_u32(&mut out, g.begin);
                put_u32(&mut out, g.end);
            },
            None => {
                put_u32(&mut out, 0);
                put_u32(&mut out, 0);
            },
        }
    }

    for (label, segs) in &log.tags {
        put_u32(&mut out, *label);
        put_u32(&mut out, segs.len() as u32);
        for s in segs {
            put_u32(&mut out, s.sign as u32);
            put_u32(&mut out, s.begin);
            put_u32(&mut out, s.end);
        }
    }

    if let Err(e) = fs::write(path, &out) {
        eprintln!("[!] could not write {}: {}", path.display(), e);
    }
}

/// Same escaping as the C side's dict_write_escaped(): printable ASCII as
/// itself, `\\` and `\"` escaped, everything else as \xNN.
fn write_escaped(w: &mut impl Write, seg: &[u8]) -> io::Result<()> {
    write!(w, "\"")?;
    for &b in seg {
        match b {
            b'\\' | b'"' => write!(w, "\\{}", b as char)?,
            0x20..=0x7e => write!(w, "{}", b as char)?,
            _ => write!(w, "\\x{:02x}", b)?,
        }
    }
    write!(w, "\"")
}

/// `value_pool.dict`: one entry per line, its segments in order. Read straight
/// out of Angora's LABEL_PATTERN_MAP, so an entry here is exactly a record its
/// own reusing mutation would have used.
///
/// Alongside it, `value_pool.origin`: one line per entry, in the same order,
/// saying where the value came from -- the input and comparison site it was
/// first seen at (the pool keeps only that first sighting) and, for a value
/// cut from the input, the bytes it was cut from. A separate file, so the
/// fuzzers' pool reader stays as it is.
fn write_value_pool(path: &Path, origin_path: &Path) -> io::Result<(usize, usize)> {
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let mut patterns: Vec<_> = map.iter().collect();
    patterns.sort_by(|a, b| a.0.cmp(b.0));

    let f = fs::File::create(path)?;
    let mut w = BufWriter::new(f);
    let mut o = BufWriter::new(fs::File::create(origin_path)?);
    let (mut entries, mut segments) = (0usize, 0usize);

    writeln!(o, "# where each value_pool.dict entry came from: line N here is entry N there")?;
    writeln!(o, "# (entries counted from 0, comment lines skipped). Each value is kept from")?;
    writeln!(o, "# its first sighting only, and this is that sighting.")?;
    writeln!(o, "#   entry       the entry's index in value_pool.dict")?;
    writeln!(o, "#   pattern     its segment lengths (its bucket in the fuzzer's pool)")?;
    writeln!(o, "#   bucket_idx  its index within that bucket, which the fuzzer's")?;
    writeln!(o, "#               ReusingWrite.entry_idx refers to")?;
    writeln!(o, "#   seed        the input it was seen in (its .dtaint has the same name)")?;
    writeln!(o, "#   kind        input = cut from that input at offsets; magic = the")?;
    writeln!(o, "#               comparison's constant side, compared with the input there")?;
    writeln!(o, "#   cmpid context order  the comparison site")?;
    writeln!(o, "#   operand     input: 0 single-label, 1/2 first/second of a dual-label site")?;
    writeln!(o, "#   offsets     the input's byte ranges, begin-end, one per segment, ';' between")?;
    writeln!(o, "entry\tpattern\tbucket_idx\tseed\tkind\tcmpid\tcontext\torder\toperand\toffsets")?;

    writeln!(w, "# extracted by taint_scan -- one value candidate per line,")?;
    writeln!(w, "# segments in taint-pattern order, sorted by pattern.")?;

    for (pattern, pool) in patterns {
        writeln!(w, "# pattern {:?}: {} record(s)", pattern, pool.records.len())?;
        let mut bucket_idx = 0usize;
        for rec in &pool.records {
            if rec.critical_values.is_empty() {
                continue;
            }
            let g = &rec.origin;
            // The labels' ranges come one per tag; adjoining ones make up one
            // segment, so join them and there is one range per segment.
            let mut ranges: Vec<(u32, u32)> = vec![];
            for t in &rec.offsets {
                match ranges.last_mut() {
                    Some(r) if r.1 == t.begin => r.1 = t.end,
                    _ => ranges.push((t.begin, t.end)),
                }
            }
            writeln!(
                o,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                entries,
                pattern.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","),
                bucket_idx,
                g.seed,
                g.kind,
                rec.cmpid,
                g.context,
                g.order,
                g.operand,
                ranges
                    .iter()
                    .map(|(b, e)| format!("{}-{}", b, e))
                    .collect::<Vec<_>>()
                    .join(";"),
            )?;
            bucket_idx += 1;
            write!(w, "[")?;
            for (i, seg) in rec.critical_values.iter().enumerate() {
                if i > 0 {
                    write!(w, ",")?;
                }
                write_escaped(&mut w, seg)?;
            }
            writeln!(w, "]")?;
            entries += 1;
            segments += rec.critical_values.len();
        }
    }

    Ok((entries, segments))
}

/// `unsolved_condition`: the sites Angora's own queue still considers open.
/// A cond is marked done there the moment it is seen going a second way, so
/// "not done" is exactly "never seen both ways" -- no separate bookkeeping,
/// and no second definition of solved to drift from Angora's.
fn write_unsolved(depot: &depot::Depot, path: &Path) -> io::Result<(usize, usize)> {
    let q = depot.queue.lock().unwrap();
    let total = q.len();

    // Angora keys its queue on (cmpid, context, order), so keep that key
    // rather than collapsing orders here -- two reaches of the same site can
    // genuinely be open and closed independently.
    let mut rows: Vec<(u32, u32, u32, i32)> = q
        .iter()
        .filter(|(_, p)| !p.is_done())
        .map(|(c, _)| {
            (
                c.base.cmpid,
                c.base.context,
                c.base.order,
                c.base.condition as i32,
            )
        })
        .collect();
    rows.sort();
    {

        let f = fs::File::create(path)?;
        let mut w = BufWriter::new(f);
        writeln!(
            w,
            "# unsolved conditions -- {} of {} tracked site(s) never seen both ways (cmpid, context, order)",
            rows.len(),
            total
        )?;
        writeln!(
            w,
            "# seen = the one condition value ever produced here (0 false, 1 true, 2 done)"
        )?;
        for (cmpid, context, order, seen) in &rows {
            writeln!(
                w,
                "cmpid={} context={} order={} seen={}",
                cmpid, context, order, seen
            )?;
        }

        Ok((rows.len(), total))
    }
}

/// `cmpid_map.tsv`: where in the source each cmpid of the track binary is,
/// from the map the pass wrote while building it (`cmpid_track.map`). The
/// ids are computed per build, so a scan's ids only mean something next to
/// the map of the very binary it ran.
///
/// The pass appends one line per instrumented comparison of every module it
/// compiled -- configure's test programs included, and a source compiled
/// twice twice -- so the configure modules are dropped, repeats are folded,
/// and an id that two different places were given (the pass only keeps ids
/// unique within a module) is listed once per place with `n_locations` > 1.
fn write_cmpid_map(src: &Path, path: &Path, tracked: &HashSet<u32>) -> io::Result<(usize, usize)> {
    let text = fs::read_to_string(src)?;
    // cmpid -> its distinct (path, line, col, function, kind, module)
    let mut map: BTreeMap<u32, BTreeSet<(String, u32, u32, String, String, String)>> =
        BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 8 {
            continue;
        }
        let (cmpid, module, dir, file) = match f[0].parse::<u32>() {
            Ok(c) => (c, f[1], f[2], f[3]),
            Err(_) => continue,
        };
        let base = module.rsplit('/').next().unwrap_or(module);
        if base.starts_with("conftest") || module.contains("CMakeTmp") || module.contains("CMakeScratch") {
            continue;
        }
        let full = if file.is_empty() || file.starts_with('/') || dir.is_empty() {
            file.to_string()
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), file)
        };
        map.entry(cmpid).or_default().insert((
            full,
            f[4].parse().unwrap_or(0),
            f[5].parse().unwrap_or(0),
            f[6].to_string(),
            f[7].to_string(),
            module.to_string(),
        ));
    }

    let mut w = BufWriter::new(fs::File::create(path)?);
    let clashes = map.values().filter(|v| v.len() > 1).count();
    writeln!(w, "# cmpid -> source location, for the track binary this scan ran ({})", src.display())?;
    writeln!(
        w,
        "# {} cmpid(s), {} of them tracked by this scan, {} given to more than one place",
        map.len(),
        map.keys().filter(|c| tracked.contains(c)).count(),
        clashes
    )?;
    writeln!(w, "# tracked: 1 if a track run of this scan reported the site")?;
    writeln!(w, "# path: the source file, absolute when the compiler recorded its directory; empty without debug info")?;
    writeln!(w, "cmpid\ttracked\tn_locations\tpath\tline\tcol\tfunction\tkind\tmodule")?;
    for (cmpid, locs) in &map {
        for (full, line, col, func, kind, module) in locs {
            writeln!(
                w,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                cmpid,
                tracked.contains(cmpid) as u8,
                locs.len(),
                full,
                line,
                col,
                func,
                kind,
                module
            )?;
        }
    }
    w.flush()?;
    Ok((map.len(), clashes))
}

/* ---------------------------------------------------------------------- */

fn usage() -> ! {
    eprintln!(
        "Usage: taint_scan -i <seed_dir> -o <out_dir> -t <track_target> -- <target> [args]"
    );
    std::process::exit(1);
}

fn main() {
    pretty_env_logger::init();

    let argv: Vec<String> = env::args().collect();
    let (mut in_dir, mut out_dir, mut track_target) = (None, None, None);
    let mut pargs: Vec<String> = vec![];
    let mut i = 1;

    while i < argv.len() {
        match argv[i].as_str() {
            "-i" => {
                i += 1;
                in_dir = argv.get(i).cloned();
            },
            "-o" => {
                i += 1;
                out_dir = argv.get(i).cloned();
            },
            "-t" => {
                i += 1;
                track_target = argv.get(i).cloned();
            },
            "--" => {
                pargs = argv[i + 1..].to_vec();
                break;
            },
            _ => usage(),
        }
        i += 1;
    }

    let (in_dir, out_dir, track_target) = match (in_dir, out_dir, track_target) {
        (Some(a), Some(b), Some(c)) if !pargs.is_empty() => (a, b, c),
        _ => usage(),
    };

    let cache_dir = PathBuf::from(&out_dir);
    fs::create_dir_all(&cache_dir).expect("could not create the output directory");

    // Angora keeps its scratch (forkserver socket, input file) under a work
    // dir of its own; give it one next to the cache rather than in it, so the
    // cache holds nothing but the scan's results.
    // Depot::new() insists on creating its own subdirectories, so hand it a
    // clean one -- a rescan into the same output directory is normal.
    let work_dir = cache_dir.join(".taint_scan");
    let _ = fs::remove_dir_all(&work_dir);
    fs::create_dir_all(&work_dir).expect("could not create the work directory");

    let command_option = command::CommandOpt::new(
        "llvm",
        &track_target,
        pargs,
        &work_dir,
        "gd",
        config::MEM_LIMIT,
        config::TIME_LIMIT,
        false, // enable_afl
        true,  // enable_exploitation
        false, // analysis_mode
        true,  // enable_reusing -- this is what fills LABEL_PATTERN_MAP
        false, // enable_storfuzz
    );

    // specify() is what turns "@@" into the real input path (and gives this
    // job its own cur_input/track file). fuzz_main does the same before it
    // builds its executor; without it the target is handed a literal "@@".
    let command_option = command_option.specify(0);

    // Where Executor::track() points the track binary; CommandOpt derives it,
    // so take it from there rather than rebuilding the path here.
    let track_path = PathBuf::from(&command_option.track_path);

    let depot = Arc::new(depot::Depot::new(
        PathBuf::from(&in_dir),
        &work_dir,
        true,
    ));
    let global_stats = Arc::new(RwLock::new(stats::ChartStats::new()));
    let global_branches = Arc::new(branches::GlobalBranches::new());
    let mut executor = executor::Executor::new(
        command_option,
        global_branches,
        depot.clone(),
        global_stats,
    );

    // Name order, so a rescan of the same corpus produces the same pool.
    let mut seeds: Vec<PathBuf> = fs::read_dir(&in_dir)
        .expect("could not read the seed directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    seeds.sort();

    println!("[*] scanning {} seed(s) from {}", seeds.len(), in_dir);

    let (mut scanned, mut skipped) = (0usize, 0usize);
    // Every cmpid a track run reported, for cmpid_map.tsv's `tracked`.
    let mut tracked: HashSet<u32> = HashSet::new();

    for (id, seed) in seeds.iter().enumerate() {
        let name = match seed.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let buf = match fs::read(seed) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[!] {}: {}", name, e);
                skipped += 1;
                continue;
            },
        };

        // Angora's own track run: same env, limits and input delivery.
        let conds: Vec<CondStmt> = executor.track(id, &buf, 0);
        tracked.extend(conds.iter().map(|c| c.base.cmpid));

        if conds.is_empty() {
            skipped += 1;
            continue;
        }

        // Angora's own bookkeeping: add_entries() is what decides which conds
        // reach the pattern pool (is_desirable, first sighting, or a sighting
        // that flips a site already in the queue) and marks a site done once
        // it has been seen going both ways. Doing it here rather than calling
        // the pool directly keeps those rules Angora's.
        // What comes back is the span each adjacent-run member was actually
        // filed under -- NOT cond.magic_byte_group, which is the pre-verification
        // tag. A member whose comparison turned out to be transformed splits its
        // group, and the surviving parts are shorter than that tag; a leftover
        // part under two bytes is not filed at all and is absent here. Writing
        // the tag instead would send a reader to a pool length nothing was ever
        // stored under.
        depot::set_current_seed(&name);
        let groups = depot.add_entries(conds.clone(), &buf);

        // The same track file the conds came from, re-read for the parts the
        // fuzzer's own parser wants (the tag table). Cheap next to the run.
        if let Ok(log) = get_log_data(&track_path) {
            write_dtaint(&cache_dir.join(format!("{}.dtaint", name)), &log, &groups);
        }

        scanned += 1;
        if scanned % 500 == 0 {
            println!("[*] {}/{} scanned", scanned, seeds.len());
        }
    }

    match write_value_pool(&cache_dir.join("value_pool.dict"), &cache_dir.join("value_pool.origin")) {
        Ok((e, s)) => println!("[+] wrote {} value pool entr{} ({} segments)", e, if e == 1 { "y" } else { "ies" }, s),
        Err(e) => eprintln!("[!] value_pool.dict: {}", e),
    }
    match write_unsolved(&depot, &cache_dir.join("unsolved_condition")) {
        Ok((u, t)) => println!("[+] wrote {} unsolved condition(s) of {} tracked", u, t),
        Err(e) => eprintln!("[!] unsolved_condition: {}", e),
    }

    // The pass's map of the track binary: ANGORA_CMPID_MAP, else next to the
    // binary as <track_target>.cmpid.map.
    let map_src = env::var("ANGORA_CMPID_MAP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("{}.cmpid.map", track_target)));
    if map_src.is_file() {
        match write_cmpid_map(&map_src, &cache_dir.join("cmpid_map.tsv"), &tracked) {
            Ok((n, c)) => println!("[+] wrote the source locations of {} cmpid(s), {} given to more than one place", n, c),
            Err(e) => eprintln!("[!] cmpid_map.tsv: {}", e),
        }
    } else {
        eprintln!("[!] no cmpid map at {}; cmpid_map.tsv not written", map_src.display());
    }

    println!("[+] scan done: {} scanned, {} without usable taint", scanned, skipped);
}
