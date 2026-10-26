//! Command line front-end for the Warden engine (used for testing on any OS).

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use warden_core::engine::{Engine, EngineOptions, HeuristicsLevel};
use warden_core::scan::{run_scan, FileFilter};
use warden_core::signatures::SignatureDb;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    match cmd {
        "scan" => {
            let roots: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
            if roots.is_empty() {
                eprintln!("usage: warden-cli scan <path>...");
                std::process::exit(2);
            }
            let engine = Engine::new(
                SignatureDb::builtin()?,
                EngineOptions {
                    heuristics: HeuristicsLevel::Balanced,
                    ..Default::default()
                },
            );
            let cancel = AtomicBool::new(false);
            let report = run_scan(&engine, &roots, &FileFilter::default(), &cancel, &|_| {});
            println!(
                "scanned {} files in {} ms, {} detections\n",
                report.files_scanned,
                report.duration_ms,
                report.detections.len()
            );
            for d in &report.detections {
                println!(
                    "[{}] {} - {}\n    {}\n    {}",
                    d.severity.as_str().to_uppercase(),
                    d.name,
                    d.location,
                    d.description,
                    d.reasons.join("\n    ")
                );
            }
            for e in &report.errors {
                eprintln!("error: {e}");
            }
        }
        "samples" => {
            let dir = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "warden-test-samples".into());
            for s in warden_core::samples::generate(&dir)? {
                println!("{:<32} {}", s.file_name, s.expected);
            }
            println!("\nwritten to {dir}");
        }
        "stats" => {
            let db = SignatureDb::builtin()?;
            println!("{:#?}", db.stats());
        }
        _ => {
            println!("warden-cli <scan PATH... | samples [DIR] | stats>");
        }
    }
    Ok(())
}
