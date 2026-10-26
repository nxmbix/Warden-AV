export type Severity = "low" | "medium" | "high" | "critical";

export interface Detection {
  path: string;
  location: string;
  name: string;
  kind: "signature" | "rule" | "heuristic";
  severity: Severity;
  category: string;
  description: string;
  reasons: string[];
  sha256: string | null;
  score: number | null;
}

export interface ScanProgress {
  files_total: number;
  files_scanned: number;
  bytes_scanned: number;
  current_file: string;
  detections: number;
}

export interface ScanReport {
  started_at: string;
  finished_at: string;
  duration_ms: number;
  files_scanned: number;
  files_total: number;
  bytes_scanned: number;
  skipped: number;
  errors: string[];
  detections: Detection[];
  cancelled: boolean;
}

export interface ScanRecord {
  id: string;
  kind: string;
  scheduled: boolean;
  auto_quarantined: number;
  report: ScanReport;
}

export interface ScanStatus {
  kind: string;
  started_at: string;
  progress: ScanProgress | null;
}

export interface ProtectionEvent {
  id: string;
  time: string;
  path: string;
  threat: string;
  severity: Severity;
  action: "quarantined" | "detected" | "failed";
  detail: string;
  detection: Detection;
}

export interface DbStats {
  version: string;
  named_hashes: number;
  feed_hashes: number;
  rules: number;
}

export interface Status {
  realtime_enabled: boolean;
  watched_folders: string[];
  signatures: DbStats;
  last_update: string | null;
  updating: boolean;
  last_scan: ScanRecord | null;
  quarantine_count: number;
  scan: ScanStatus | null;
  next_scheduled_scan: string | null;
  recent_events: ProtectionEvent[];
}

export interface QuarantineEntry {
  id: string;
  original_path: string;
  file_name: string;
  threat_name: string;
  severity: Severity;
  category: string;
  description: string;
  reasons: string[];
  sha256: string;
  size: number;
  quarantined_at: string;
}

export interface Feed {
  id: string;
  name: string;
  url: string;
  format: string;
  enabled: boolean;
}

export interface Settings {
  realtime_enabled: boolean;
  watched_folders: string[];
  auto_quarantine: boolean;
  heuristics: "off" | "balanced" | "aggressive";
  scan_archives: boolean;
  max_file_size_mb: number;
  exclusions: string[];
  allowed_hashes: string[];
  notifications: boolean;
  start_with_windows: boolean;
  minimize_to_tray: boolean;
  schedule: {
    enabled: boolean;
    frequency: "daily" | "weekly";
    weekday: number;
    time: string;
    scan_type: "quick" | "full";
    last_run: string | null;
  };
  updates: {
    auto_update: boolean;
    interval_hours: number;
    feeds: Feed[];
    last_update: string | null;
    last_result: string | null;
  };
}

export interface FeedOutcome { id: string; name: string; entries: number; error: string | null }
export interface UpdateResult { ok: boolean; feeds: FeedOutcome[]; stats: DbStats; at: string }

export interface Sample {
  file_name: string;
  path: string;
  expected: string;
  tests: "signature" | "rule" | "heuristic" | "archive" | "clean";
  explanation: string;
  safe_because: string;
}
