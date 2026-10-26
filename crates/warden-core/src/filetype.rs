use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Pe,
    Script,
    Office,
    Lnk,
    Pdf,
    Archive,
    Text,
    Other,
}

impl FileType {
    pub fn key(&self) -> &'static str {
        match self {
            FileType::Pe => "pe",
            FileType::Script => "script",
            FileType::Office => "office",
            FileType::Lnk => "lnk",
            FileType::Pdf => "pdf",
            FileType::Archive => "archive",
            FileType::Text => "text",
            FileType::Other => "other",
        }
    }
}

pub const SCRIPT_EXTS: &[&str] = &[
    "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py",
    "pyw", "sh", "reg", "scr", "au3", "ahk",
];

pub const EXECUTABLE_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "sys", "msi", "msix", "appx", "jar", "lnk", "ocx",
    "drv",
];

pub const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "txt", "rtf",
    "jpg", "jpeg", "png", "gif", "mp3", "mp4", "mov", "avi", "zip", "rar", "csv",
];

/// Extensions worth scanning during a full-disk scan (everything else is skipped unless it starts with `MZ`).
pub const RISKY_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "sys", "msi", "msix", "appx", "jar", "lnk", "ocx",
    "drv", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "py",
    "pyw", "reg", "au3", "ahk", "zip", "docm", "xlsm", "pptm", "doc", "xls", "ppt", "rtf", "iso",
    "img", "vhd", "txt",
];

pub fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn ext_of_name(name: &str) -> String {
    extension(Path::new(name))
}

pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
}

pub fn detect(name: &str, bytes: &[u8]) -> FileType {
    let ext = ext_of_name(name);
    let lname = name.to_ascii_lowercase();
    if lname == "vbaproject.bin" || lname.ends_with("/vbaproject.bin") {
        return FileType::Office;
    }
    if bytes.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if bytes.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) || ext == "lnk" {
        return FileType::Lnk;
    }
    if bytes.starts_with(b"%PDF") {
        return FileType::Pdf;
    }
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileType::Office;
    }
    if is_zip(bytes) {
        return match ext.as_str() {
            "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "dotm" | "xltm" => {
                FileType::Office
            }
            _ => FileType::Archive,
        };
    }
    if SCRIPT_EXTS.contains(&ext.as_str()) {
        return FileType::Script;
    }
    let sample = &bytes[..bytes.len().min(4096)];
    let printable = sample
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if !sample.is_empty() && printable * 100 / sample.len() > 90 {
        return FileType::Text;
    }
    FileType::Other
}
