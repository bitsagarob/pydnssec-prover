// difftest-oracle: the Rust reference side of the pydnssec-prover differential harness.
//
// Adapted from testdata/proofcheck.rs in the dnssec-verify test corpus, which does the same job
// for one file at a time and only reports TXT records. This version:
//   * speaks a batch line protocol on stdin so one process handles the whole corpus,
//   * dumps EVERY verified record canonically (name, type, and the full RFC 1035 wire encoding
//     produced by dnssec_prover::ser::write_rr with ttl forced to 0), not just TXT,
//   * dumps resolve_name() output the same way.
//
// It links the same dnssec-prover 0.6.10 the corpus oracle used. It performs NO wall-clock check
// and NO BIP 353 check, exactly like verify_rr_stream itself. Clock pinning is the harness's job.
//
// Batch protocol, one request per stdin line:
//     <id> \t <proof-hex> \t <name-to-resolve or ->
// One JSON object per line on stdout, in the same order.
//
// One-shot mode for minimal reproductions:
//     difftest-oracle <proof.bin> [name]

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};

use dnssec_prover::rr::{Name, Record, RR};
use dnssec_prover::ser::{parse_rr_stream, write_rr};
use dnssec_prover::validation::{verify_rr_stream, ValidationError};

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or(())?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or(())?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

// Canonical, comparable encoding of one record: its name as the implementation stores it, its
// numeric type, and its full wire form with the TTL zeroed (TTL is not part of what is signed in
// any meaningful sense here and the two implementations get it from different places).
fn rr_json(rr: &RR) -> String {
    let mut wire = Vec::new();
    write_rr(rr, 0, &mut wire);
    format!(
        "{{\"n\":\"{}\",\"t\":{},\"w\":\"{}\"}}",
        esc(rr.name().as_str()),
        rr.ty(),
        hex(&wire)
    )
}

fn err_name(e: &ValidationError) -> &'static str {
    match e {
        ValidationError::UnsupportedAlgorithm => "unsupported_algorithm",
        ValidationError::Invalid => "invalid",
        ValidationError::ValidationCountLimited => "validation_count_limited",
    }
}

fn run_one(id: &str, proof: &[u8], name: Option<&str>) -> String {
    let rrs = match parse_rr_stream(proof) {
        Ok(r) => r,
        Err(()) => {
            return format!(
                "{{\"id\":\"{}\",\"parsed\":false,\"result\":\"parse_error\",\"error\":\"parse_error\"}}",
                esc(id)
            )
        }
    };
    let n_rrs = rrs.len();
    match verify_rr_stream(&rrs) {
        Err(e) => format!(
            "{{\"id\":\"{}\",\"parsed\":true,\"rr_count\":{},\"result\":\"error\",\"error\":\"{}\"}}",
            esc(id),
            n_rrs,
            err_name(&e)
        ),
        Ok(v) => {
            let verified: Vec<String> = v.verified_rrs.iter().map(|rr| rr_json(rr)).collect();
            let resolved = match name {
                None => "null".to_string(),
                Some(n) => {
                    let dotted = if n.ends_with('.') {
                        n.to_string()
                    } else {
                        format!("{}.", n)
                    };
                    match TryInto::<Name>::try_into(dotted) {
                        Err(_) => "null".to_string(),
                        Ok(name) => {
                            let recs: Vec<String> =
                                v.resolve_name(&name).into_iter().map(|rr| rr_json(rr)).collect();
                            format!("[{}]", recs.join(","))
                        }
                    }
                }
            };
            format!(
                "{{\"id\":\"{}\",\"parsed\":true,\"rr_count\":{},\"result\":\"valid\",\"valid_from\":{},\"expires\":{},\"max_cache_ttl\":{},\"verified_rrs\":[{}],\"resolved\":{}}}",
                esc(id),
                n_rrs,
                v.valid_from,
                v.expires,
                v.max_cache_ttl,
                verified.join(","),
                resolved
            )
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        // One-shot mode: a file path, optionally a name to resolve.
        let bytes = match fs::read(&args[1]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("difftest-oracle: cannot read {}: {}", args[1], e);
                std::process::exit(2);
            }
        };
        let name = args.get(2).map(|s| s.as_str());
        println!("{}", run_one(&args[1], &bytes, name));
        return;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            let _ = writeln!(
                out,
                "{{\"id\":\"?\",\"parsed\":false,\"result\":\"bad_request\",\"error\":\"bad_request\"}}"
            );
            continue;
        }
        let id = parts[0];
        let proof = match unhex(parts[1]) {
            Ok(b) => b,
            Err(()) => {
                let _ = writeln!(
                    out,
                    "{{\"id\":\"{}\",\"parsed\":false,\"result\":\"bad_request\",\"error\":\"bad_hex\"}}",
                    esc(id)
                );
                continue;
            }
        };
        let name = match parts.get(2) {
            None | Some(&"-") | Some(&"") => None,
            Some(n) => Some(*n),
        };
        let _ = writeln!(out, "{}", run_one(id, &proof, name));
        let _ = out.flush();
    }
}
