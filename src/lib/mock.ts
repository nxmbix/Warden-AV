// Browser-only demo data so the UI can be previewed without the desktop app.
import type { Detection, ProtectionEvent, QuarantineEntry, ScanRecord, Settings, Status } from "./types";

const listeners: Record<string, ((p: unknown) => void)[]> = {};
export function mockListen(event: string, h: (p: unknown) => void) {
  (listeners[event] ||= []).push(h);
  return () => { listeners[event] = listeners[event].filter((x) => x !== h); };
}
const emit = (e: string, p: unknown) => (listeners[e] || []).forEach((h) => h(p));

const det = (name: string, file: string, severity: Detection["severity"], kind: Detection["kind"], category: string, reasons: string[]): Detection => ({
  path: `C:\\Users\\you\\Documents\\Warden Test Samples\\${file}`,
  location: `C:\\Users\\you\\Documents\\Warden Test Samples\\${file}`,
  name, kind, severity, category, description: "Demo detection.", reasons, sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", score: kind === "heuristic" ? 88 : null,
});
const demoDetections: Detection[] = [
  det("Ransom.Note.Generic", "READ-ME-TO-RECOVER-FILES.txt", "critical", "rule", "ransomware", ['contains "your files have been encrypted"', 'contains "bitcoin"']),
  det("Trojan.PowerShell.Downloader", "fake-stager.ps1", "high", "rule", "trojan-downloader", ["matches /downloadstring/"]),
  det("Heuristic.Suspicious.PE", "packed-sample.exe", "critical", "heuristic", "suspicious", ['packer section "UPX0"', "very high entropy (7.96/8)"]),
  det("EICAR-Test-File", "eicar-test-file.txt", "medium", "signature", "test", ["SHA-256 matches a known-bad hash"]),
];

let settings: Settings = {
  realtime_enabled: true, watched_folders: ["C:\\Users\\you\\Downloads", "C:\\Users\\you\\Desktop", "C:\\Users\\you\\Documents"],
  auto_quarantine: true, heuristics: "balanced", scan_archives: true, max_file_size_mb: 256, exclusions: [], allowed_hashes: [],
  notifications: true, start_with_windows: true, minimize_to_tray: true,
  schedule: { enabled: true, frequency: "daily", weekday: 0, time: "12:00", scan_type: "quick", last_run: null },
  updates: { auto_update: true, interval_hours: 6, last_update: new Date().toISOString(), last_result: "Aggregated malware SHA-256 list: 131,402 entries",
    feeds: [{ id: "marcoux-sha256", name: "Aggregated malware SHA-256 list (romainmarcoux/malicious-hash)", url: "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt", format: "sha256", enabled: true }] },
};
const history: ScanRecord[] = [{ id: "1", kind: "quick", scheduled: false, auto_quarantined: 0, report: { started_at: new Date(Date.now() - 3600e3).toISOString(), finished_at: new Date(Date.now() - 3590e3).toISOString(), duration_ms: 9400, files_scanned: 4821, files_total: 4821, bytes_scanned: 3.2e9, skipped: 0, errors: [], detections: demoDetections, cancelled: false } }];
const quarantine: QuarantineEntry[] = [{ id: "q1", original_path: "C:\\Users\\you\\Downloads\\free-robux-generator.exe", file_name: "free-robux-generator.exe", threat_name: "Stealer.Discord.Token", severity: "critical", category: "infostealer", description: "Reads Discord credential stores.", reasons: ["discord webhook"], sha256: "ab12", size: 482133, quarantined_at: new Date(Date.now() - 86400e3).toISOString() }];
const events: ProtectionEvent[] = [{ id: "e1", time: new Date(Date.now() - 86400e3).toISOString(), path: quarantine[0].original_path, threat: "Stealer.Discord.Token", severity: "critical", action: "quarantined", detail: "Moved to quarantine automatically.", detection: demoDetections[0] }];

export async function mockCall<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  await new Promise((r) => setTimeout(r, 120));
  const r = (v: unknown) => v as T;
  switch (cmd) {
    case "get_status": {
      const s: Status = { realtime_enabled: settings.realtime_enabled, watched_folders: settings.watched_folders, signatures: { version: "2026.10.26", named_hashes: 2, feed_hashes: 131402, rules: 14 }, last_update: settings.updates.last_update, updating: false, last_scan: history[0], quarantine_count: quarantine.length, scan: null, next_scheduled_scan: new Date(Date.now() + 5 * 3600e3).toISOString(), recent_events: events };
      return r(s);
    }
    case "start_scan": {
      let n = 0; const total = 1200;
      emit("scan-started", args?.kind);
      const t = setInterval(() => {
        n = Math.min(total, n + 90);
        emit("scan-progress", { files_total: total, files_scanned: n, bytes_scanned: n * 2e5, current_file: `C:\\Users\\you\\Downloads\\file-${n}.bin`, detections: Math.floor(n / 400) });
        if (n >= total) { clearInterval(t); const rec = { ...history[0], id: String(Date.now()), kind: String(args?.kind) }; history.unshift(rec); emit("scan-finished", rec); }
      }, 150);
      return r("demo");
    }
    case "get_history": return r(history);
    case "get_settings": return r(settings);
    case "save_settings": settings = args!.settings as Settings; return r(settings);
    case "set_realtime": settings.realtime_enabled = Boolean(args!.enabled); return r(null);
    case "list_quarantine": return r(quarantine);
    case "get_events": return r(events);
    case "update_signatures": return r({ ok: true, feeds: [{ id: "marcoux-sha256", name: "Aggregated malware SHA-256 list", entries: 131402, error: null }], stats: { version: "2026.10.26", named_hashes: 2, feed_hashes: 131402, rules: 14 }, at: new Date().toISOString() });
    case "default_samples_dir": return r("C:\\Users\\you\\Documents\\Warden Test Samples");
    case "generate_samples": return r({ dir: "C:\\Users\\you\\Documents\\Warden Test Samples", samples: [] });
    case "quarantine_detections": return r((args!.detections as Detection[]).map((d) => ({ path: d.path, ok: true, message: "Quarantined" })));
    default: return r(null);
  }
}
