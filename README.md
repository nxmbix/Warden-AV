# Warden

A Windows antivirus built with Tauri + React and a Rust scan engine.

## Features

- **On-demand scans**: quick, full, folder, or individual files. Scans run in parallel across CPU cores.
- **Real-time protection**: watches Downloads, Desktop and Documents (configurable) and checks new files as they land.
- **Encrypted quarantine**: threats are AES-256-GCM encrypted in a vault so they can't run. You can restore or delete them.
- **Scheduled scans**: daily or weekly. If the PC was off at the scheduled time, the scan runs when Warden next starts.
- **Auto-updating signatures**: downloads public malware hash lists (about 130k SHA-256 hashes).
- **Detection layers**
  - Exact SHA-256 / MD5 known-malware hashes
  - Content rules (text / hex / regex) for ransomware notes, downloaders, stealers, reverse shells, Defender tampering and similar
  - Heuristics: PE analysis (packers, entropy, injection/keylogger/persistence imports, W+X sections), script obfuscation, double extensions, RTL-override filenames, Office macros, LNK and PDF tricks
  - Recursive ZIP/Office archive scanning with size and depth limits
- **Test lab**: creates 13 harmless test files so you can watch Warden catch "viruses" without any risk.

## Test samples

None of the test files can harm your PC. In the app, open **Test lab** and click **Create test files**. You can also run `warden-cli samples <dir>`.

| File | Tests | Why it's safe |
| --- | --- | --- |
| `eicar-test-file.txt` | Signature | EICAR is the industry-standard antivirus test string. It is plain text and does nothing. |
| `eicar-inside-archive.zip` | Archive | Same EICAR text, nested inside a ZIP |
| `warden-hash-test.txt` | Signature | A plain sentence whose hash is in Warden's database |
| `READ-ME-TO-RECOVER-FILES.txt` | Rule | A fake ransom note. It's just text. |
| `fake-stager.ps1`, `disable-protection.bat`, `wipe-restore-points.cmd` | Rule | Every dangerous line is commented out, so running them does nothing |
| `keylogger-strings.txt` | Rule | Suspicious API names in a text file |
| `invoice.pdf.exe` | Heuristic | A double-extension trick. The content is text. |
| `packed-sample.exe` | Heuristic | A fake PE with an invalid machine type and no code. Windows refuses to run it. |
| `macro-document.docm` | Heuristic | A ZIP containing inert macro text, not a real VBA project |
| `clean-shopping-list.txt` | Clean | Should **not** be detected (false-positive check) |

Windows Defender may delete the EICAR files on its own. That's expected. Add the test folder as a Defender exclusion while testing.

## Development

```bash
npm install
npm run tauri dev           # run the desktop app
cargo test -p warden-core   # engine tests
cargo run -p warden-core --bin warden-cli -- scan <path>
```

GitHub Actions builds the Windows installer (`.exe` + `.msi`) on every push. Push a `v*` tag to publish a release.

## Layout

- `crates/warden-core`: scan engine, signatures, quarantine, samples and CLI
- `src-tauri`: desktop shell (commands, real-time watcher, scheduler, tray)
- `src`: React UI
