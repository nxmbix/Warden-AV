//! Structural heuristics: PE inspection, entropy, name tricks and script obfuscation.
//!
//! Each indicator adds to a score; the total decides whether a file is reported
//! as suspicious and how severe it looks.

use crate::filetype::{ext_of_name, FileType, DOC_EXTS, EXECUTABLE_EXTS};
use crate::types::{Detection, DetectionKind, Severity};
use goblin::pe::PE;

pub struct Indicator {
    pub weight: u32,
    pub reason: String,
}

fn ind(weight: u32, reason: impl Into<String>) -> Indicator {
    Indicator {
        weight,
        reason: reason.into(),
    }
}

/// Shannon entropy in bits/byte (0..8). Packed or encrypted data sits above ~7.2.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = data.len() as f64;
    -counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

const INJECTION_APIS: &[&str] = &[
    "WriteProcessMemory",
    "CreateRemoteThread",
    "VirtualAllocEx",
    "NtUnmapViewOfSection",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "QueueUserAPC",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
];
const EVASION_APIS: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "GetTickCount64",
];
const RECON_APIS: &[&str] = &[
    "GetClipboardData",
    "GetAsyncKeyState",
    "GetKeyboardState",
    "BitBlt",
];
const DOWNLOAD_APIS: &[&str] = &[
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenUrlA",
    "InternetReadFile",
    "WinHttpSendRequest",
];
const PERSIST_APIS: &[&str] = &[
    "RegSetValueExA",
    "RegSetValueExW",
    "CreateServiceA",
    "CreateServiceW",
];
const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".packed", "MPRESS1", "MPRESS2",
    ".themida", ".vmp0", ".vmp1", "pebundle", ".petite", "nsp0", "nsp1", ".enigma1",
];

fn api_hits(pe: &PE, list: &[&str]) -> Vec<String> {
    let mut hits: Vec<String> = pe
        .imports
        .iter()
        .filter(|i| list.iter().any(|a| i.name.eq_ignore_ascii_case(a)))
        .map(|i| i.name.to_string())
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

fn analyze_pe(bytes: &[u8], out: &mut Vec<Indicator>) {
    let pe = match PE::parse(bytes) {
        Ok(pe) => pe,
        Err(_) => {
            out.push(ind(
                20,
                "executable header is malformed (possibly corrupted or hand-crafted)",
            ));
            return;
        }
    };

    for s in &pe.sections {
        let name = s
            .name()
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string();
        if PACKER_SECTIONS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&name))
        {
            out.push(ind(
                25,
                format!("packer section \"{name}\" (code is hidden/compressed)"),
            ));
        }
        let start = s.pointer_to_raw_data as usize;
        let end = start
            .saturating_add(s.size_of_raw_data as usize)
            .min(bytes.len());
        if end > start && end - start >= 2048 {
            let e = entropy(&bytes[start..end]);
            if e > 7.2 {
                out.push(ind(
                    20,
                    format!(
                        "section \"{name}\" has very high entropy ({e:.2}/8 - packed or encrypted)"
                    ),
                ));
            }
        }
        let writable_exec =
            s.characteristics & 0x8000_0000 != 0 && s.characteristics & 0x2000_0000 != 0;
        if writable_exec {
            out.push(ind(
                15,
                format!("section \"{name}\" is both writable and executable"),
            ));
        }
        if s.size_of_raw_data == 0 && s.virtual_size > 0x1000 {
            out.push(ind(
                10,
                format!("section \"{name}\" has no file data but large virtual size"),
            ));
        }
    }

    let inj = api_hits(&pe, INJECTION_APIS);
    if inj.len() >= 2 {
        out.push(ind(
            30,
            format!("process-injection APIs: {}", inj.join(", ")),
        ));
    } else if inj.len() == 1 {
        out.push(ind(12, format!("process-injection API: {}", inj[0])));
    }
    let eva = api_hits(&pe, EVASION_APIS);
    if !eva.is_empty() {
        out.push(ind(
            10,
            format!("anti-debug / evasion APIs: {}", eva.join(", ")),
        ));
    }
    let rec = api_hits(&pe, RECON_APIS);
    if !rec.is_empty() {
        out.push(ind(
            15,
            format!("keylogging / screen-capture APIs: {}", rec.join(", ")),
        ));
    }
    let dl = api_hits(&pe, DOWNLOAD_APIS);
    if !dl.is_empty() {
        out.push(ind(12, format!("downloader APIs: {}", dl.join(", "))));
    }
    let per = api_hits(&pe, PERSIST_APIS);
    if !per.is_empty() && (!inj.is_empty() || !dl.is_empty()) {
        out.push(ind(10, format!("persistence APIs: {}", per.join(", "))));
    }
    if pe.imports.is_empty() && pe.libraries.is_empty() {
        out.push(ind(
            18,
            "no imports at all (imports are resolved at runtime - typical of packers)",
        ));
    }
}

fn analyze_name(name: &str, out: &mut Vec<Indicator>) {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        let inner = parts[parts.len() - 2];
        if EXECUTABLE_EXTS.contains(&last) && DOC_EXTS.contains(&inner) {
            out.push(ind(
                50,
                format!("double extension \".{inner}.{last}\" - pretends to be a document but is a program"),
            ));
        }
    }
    if name.contains('\u{202E}') || name.contains('\u{202B}') || name.contains('\u{200F}') {
        out.push(ind(
            40,
            "filename contains a right-to-left override character (extension spoofing)",
        ));
    }
    if name.chars().filter(|c| *c == ' ').count() > 6
        && EXECUTABLE_EXTS.contains(&ext_of_name(name).as_str())
    {
        out.push(ind(
            15,
            "long run of spaces in the filename (hides the real extension)",
        ));
    }
}

fn analyze_script(bytes: &[u8], out: &mut Vec<Indicator>) {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(512 * 1024)]).to_lowercase();
    let mut long_b64 = 0usize;
    for token in
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
    {
        if token.len() > 200 {
            long_b64 += 1;
        }
    }
    if long_b64 > 0 {
        out.push(ind(
            15,
            format!("{long_b64} very long base64-like blob(s) embedded in the script"),
        ));
    }
    let obfuscation = [
        ("frombase64string", 15, "decodes base64 at runtime"),
        ("-enc ", 25, "PowerShell -EncodedCommand"),
        ("-encodedcommand", 25, "PowerShell -EncodedCommand"),
        (
            "invoke-expression",
            20,
            "executes generated code (Invoke-Expression)",
        ),
        ("iex(", 20, "executes generated code (IEX)"),
        ("iex (", 20, "executes generated code (IEX)"),
        ("downloadstring", 20, "downloads code from the internet"),
        ("downloadfile", 15, "downloads a file from the internet"),
        ("webclient", 10, "creates a web client"),
        ("-windowstyle hidden", 15, "runs hidden with no window"),
        ("-nop -w hidden", 20, "runs hidden with profile disabled"),
        ("bypass", 10, "bypasses the script execution policy"),
        (
            "wscript.shell",
            10,
            "spawns other programs through WScript.Shell",
        ),
        ("powershell -", 10, "launches PowerShell"),
        (
            "certutil -decode",
            20,
            "uses certutil to decode a hidden payload",
        ),
        ("bitsadmin /transfer", 20, "downloads with bitsadmin"),
        (
            "vssadmin delete shadows",
            40,
            "deletes shadow copies (ransomware behaviour)",
        ),
        ("bcdedit /set", 20, "changes boot configuration"),
        (
            "schtasks /create",
            12,
            "creates a scheduled task (persistence)",
        ),
        ("reg add", 8, "writes to the registry"),
        (
            "currentversion\\run",
            20,
            "adds itself to the Run key (persistence)",
        ),
        ("attrib +h +s", 12, "hides itself"),
        ("taskkill /f /im", 8, "force-kills processes"),
        ("net stop", 10, "stops Windows services"),
        (
            "add-mppreference -exclusionpath",
            35,
            "adds a Microsoft Defender exclusion",
        ),
        (
            "set-mppreference -disablerealtimemonitoring",
            45,
            "disables Defender real-time protection",
        ),
        ("char]", 12, "builds strings from char codes (obfuscation)"),
        ("-join", 5, "joins obfuscated string pieces"),
    ];
    for (needle, weight, why) in obfuscation {
        if text.contains(needle) {
            out.push(ind(weight, why));
        }
    }
}

fn analyze_office(name: &str, bytes: &[u8], out: &mut Vec<Indicator>) {
    let macro_ext = matches!(
        ext_of_name(name).as_str(),
        "docm" | "xlsm" | "pptm" | "dotm" | "xltm"
    );
    let lower = bytes.to_ascii_lowercase();
    let has = |needle: &str| lower.windows(needle.len()).any(|w| w == needle.as_bytes());
    if has("vbaproject.bin") || has("macros/vba") {
        out.push(ind(
            if macro_ext { 20 } else { 35 },
            if macro_ext {
                "contains VBA macros"
            } else {
                "contains VBA macros although the extension says it should not"
            },
        ));
    }
    for (needle, weight, why) in [
        (
            "autoopen",
            25,
            "macro runs automatically when the document opens (AutoOpen)",
        ),
        (
            "auto_open",
            25,
            "macro runs automatically when the document opens (Auto_Open)",
        ),
        (
            "document_open",
            25,
            "macro runs automatically when the document opens",
        ),
        (
            "workbook_open",
            25,
            "macro runs automatically when the workbook opens",
        ),
        ("shell(", 25, "macro starts another program"),
        ("createobject(\"wscript.shell\"", 30, "macro spawns a shell"),
        ("powershell", 30, "macro launches PowerShell"),
        ("urlmon", 25, "macro downloads from the internet"),
        ("mshta", 25, "macro launches mshta"),
    ] {
        if has(needle) {
            out.push(ind(weight, why));
        }
    }
}

fn analyze_lnk(bytes: &[u8], out: &mut Vec<Indicator>) {
    let text: String = bytes
        .chunks(2)
        .filter(|c| c.len() == 2 && c[1] == 0)
        .map(|c| c[0] as char)
        .collect::<String>()
        .to_lowercase();
    for (needle, weight, why) in [
        ("powershell", 30, "shortcut launches PowerShell"),
        ("cmd.exe", 20, "shortcut launches the command prompt"),
        ("mshta", 30, "shortcut launches mshta"),
        ("-enc", 35, "shortcut runs an encoded command"),
        ("downloadstring", 35, "shortcut downloads and runs code"),
    ] {
        if text.contains(needle) {
            out.push(ind(weight, why));
        }
    }
    if bytes.len() > 150_000 {
        out.push(ind(
            20,
            "unusually large shortcut file (payload embedded in the .lnk)",
        ));
    }
}

fn analyze_pdf(bytes: &[u8], out: &mut Vec<Indicator>) {
    let lower = bytes.to_ascii_lowercase();
    let has = |n: &str| lower.windows(n.len()).any(|w| w == n.as_bytes());
    if has("/openaction") || has("/aa") {
        out.push(ind(15, "PDF runs an action as soon as it is opened"));
    }
    if has("/javascript") || has("/js") {
        out.push(ind(20, "PDF contains JavaScript"));
    }
    if has("/launch") {
        out.push(ind(30, "PDF tries to launch an external program"));
    }
    if has("/embeddedfile") {
        out.push(ind(15, "PDF has an embedded file"));
    }
}

/// Run every heuristic that applies and turn the score into a detection.
pub fn analyze(name: &str, ft: FileType, bytes: &[u8], threshold: u32) -> Option<Detection> {
    let mut indicators = Vec::new();
    analyze_name(name, &mut indicators);
    match ft {
        FileType::Pe => analyze_pe(bytes, &mut indicators),
        FileType::Script | FileType::Text => analyze_script(bytes, &mut indicators),
        FileType::Office => analyze_office(name, bytes, &mut indicators),
        FileType::Lnk => analyze_lnk(bytes, &mut indicators),
        FileType::Pdf => analyze_pdf(bytes, &mut indicators),
        _ => {}
    }
    if indicators.is_empty() {
        return None;
    }
    let score: u32 = indicators.iter().map(|i| i.weight).sum();
    if score < threshold {
        return None;
    }
    let severity = if score >= 90 {
        Severity::Critical
    } else if score >= 60 {
        Severity::High
    } else if score >= 35 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let mut reasons: Vec<String> = indicators.into_iter().map(|i| i.reason).collect();
    reasons.sort();
    reasons.dedup();
    Some(Detection {
        path: String::new(),
        location: name.to_string(),
        name: format!("Heuristic.Suspicious.{}", ft.key().to_uppercase()),
        kind: DetectionKind::Heuristic,
        severity,
        category: "suspicious".into(),
        description: format!(
            "Warden's heuristics scored this file {}/100 based on its structure and contents.",
            score.min(100)
        ),
        reasons,
        sha256: None,
        score: Some(score.min(100)),
    })
}
