import type {
  Detection, ProtectionEvent, QuarantineEntry, Sample, ScanRecord, Settings, Status, UpdateResult,
} from "./types";
import { mockCall, mockListen } from "./mock";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) return mockCall<T>(cmd, args);
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export async function on<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
  if (!isTauri) return mockListen(event, handler as (p: unknown) => void);
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(event, (e) => handler(e.payload));
}

export async function pickFolders(multiple = true): Promise<string[]> {
  if (!isTauri) return ["C:\\Users\\you\\Downloads"];
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ directory: true, multiple });
  if (!r) return [];
  return Array.isArray(r) ? r : [r];
}

export async function pickFiles(): Promise<string[]> {
  if (!isTauri) return ["C:\\Users\\you\\Downloads\\setup.exe"];
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ directory: false, multiple: true });
  if (!r) return [];
  return Array.isArray(r) ? r : [r];
}

export const api = {
  status: () => call<Status>("get_status"),
  startScan: (kind: "quick" | "full" | "custom", paths?: string[]) => call<string>("start_scan", { kind, paths }),
  cancelScan: () => call<void>("cancel_scan"),
  history: () => call<ScanRecord[]>("get_history"),
  clearHistory: () => call<void>("clear_history"),
  quarantine: (detections: Detection[]) =>
    call<{ path: string; ok: boolean; message: string }[]>("quarantine_detections", { detections }),
  allow: (sha256: string) => call<void>("allow_hash", { sha256 }),
  listQuarantine: () => call<QuarantineEntry[]>("list_quarantine"),
  restore: (id: string) => call<string>("restore_quarantine", { id }),
  deleteQuarantined: (id: string) => call<void>("delete_quarantine", { id }),
  clearQuarantine: () => call<number>("clear_quarantine"),
  settings: () => call<Settings>("get_settings"),
  saveSettings: (settings: Settings) => call<Settings>("save_settings", { settings }),
  setRealtime: (enabled: boolean) => call<void>("set_realtime", { enabled }),
  updateSignatures: () => call<UpdateResult>("update_signatures"),
  events: () => call<ProtectionEvent[]>("get_events"),
  clearEvents: () => call<void>("clear_events"),
  generateSamples: (dir?: string) => call<{ dir: string; samples: Sample[] }>("generate_samples", { dir }),
  defaultSamplesDir: () => call<string>("default_samples_dir"),
  reveal: (path: string) => call<void>("reveal_path", { path }),
};
