import { useEffect, useState } from "react";
import {
  Activity, FlaskConical, History as HistoryIcon, LayoutDashboard, Lock, RefreshCw, ScanSearch, Settings as Cog, ShieldCheck, CalendarClock,
} from "lucide-react";
import { api, on } from "./lib/api";
import type { ProtectionEvent, ScanProgress, ScanRecord } from "./lib/types";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import Protection from "./pages/Protection";
import QuarantinePage from "./pages/Quarantine";
import Schedule from "./pages/Schedule";
import Updates from "./pages/Updates";
import TestLab from "./pages/TestLab";
import HistoryPage from "./pages/History";
import SettingsPage from "./pages/Settings";

export type Page = "dashboard" | "scan" | "protection" | "quarantine" | "schedule" | "updates" | "testlab" | "history" | "settings";

export interface ScanLive { running: boolean; kind: string | null; progress: ScanProgress | null; result: ScanRecord | null }

const nav: { id: Page; label: string; icon: typeof ShieldCheck; group: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, group: "Overview" },
  { id: "scan", label: "Scan", icon: ScanSearch, group: "Overview" },
  { id: "protection", label: "Real-time protection", icon: Activity, group: "Protection" },
  { id: "quarantine", label: "Quarantine", icon: Lock, group: "Protection" },
  { id: "schedule", label: "Scheduled scans", icon: CalendarClock, group: "Protection" },
  { id: "updates", label: "Signature updates", icon: RefreshCw, group: "Protection" },
  { id: "testlab", label: "Test lab", icon: FlaskConical, group: "Tools" },
  { id: "history", label: "History", icon: HistoryIcon, group: "Tools" },
  { id: "settings", label: "Settings", icon: Cog, group: "Tools" },
];

export default function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [scan, setScan] = useState<ScanLive>({ running: false, kind: null, progress: null, result: null });
  const [toast, setToast] = useState<ProtectionEvent | null>(null);

  useEffect(() => {
    api.status().then((s) => s.scan && setScan({ running: true, kind: s.scan.kind, progress: s.scan.progress, result: null }));
    const offs = [
      on<string>("scan-started", (kind) => setScan({ running: true, kind, progress: null, result: null })),
      on<ScanProgress>("scan-progress", (p) => setScan((s) => ({ ...s, running: true, progress: p }))),
      on<ScanRecord>("scan-finished", (r) => setScan({ running: false, kind: r.kind, progress: null, result: r })),
      on<ProtectionEvent>("protection-event", (e) => { setToast(e); setTimeout(() => setToast(null), 7000); }),
    ];
    return () => { offs.forEach((p) => p.then((f) => f())); };
  }, []);

  const groups = [...new Set(nav.map((n) => n.group))];
  const props = { go: setPage, scan, setScan };

  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-[#090c0d] px-3 py-5">
        <div className="mb-6 flex items-center gap-2.5 px-2">
          <img src="/favicon.svg" className="h-8 w-8" alt="" />
          <div>
            <div className="text-[15px] font-semibold leading-tight">Warden</div>
            <div className="text-[11px] text-muted">Antivirus</div>
          </div>
        </div>
        <nav className="flex-1 space-y-5 overflow-y-auto">
          {groups.map((g) => (
            <div key={g}>
              <div className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted/70">{g}</div>
              {nav.filter((n) => n.group === g).map((n) => (
                <button key={n.id} onClick={() => setPage(n.id)}
                  className={`mb-0.5 flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-[13px] transition ${page === n.id ? "bg-panel2 text-white" : "text-muted hover:bg-panel hover:text-white"}`}>
                  <n.icon size={16} className={page === n.id ? "text-accent" : ""} />
                  {n.label}
                  {n.id === "scan" && scan.running && <span className="ml-auto h-2 w-2 rounded-full bg-accent" />}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="px-2 text-[11px] text-muted/60">v0.1.0</div>
      </aside>
      <main className="flex-1 overflow-y-auto px-9 py-8">
        {page === "dashboard" && <Dashboard {...props} />}
        {page === "scan" && <Scan {...props} />}
        {page === "protection" && <Protection />}
        {page === "quarantine" && <QuarantinePage />}
        {page === "schedule" && <Schedule />}
        {page === "updates" && <Updates />}
        {page === "testlab" && <TestLab {...props} />}
        {page === "history" && <HistoryPage />}
        {page === "settings" && <SettingsPage />}
      </main>
      {toast && (
        <div className="fixed bottom-5 right-5 w-96 rounded-2xl border border-danger/30 bg-panel p-4 shadow-2xl">
          <div className="text-sm font-semibold text-danger">{toast.action === "quarantined" ? "Threat blocked" : "Suspicious file detected"}</div>
          <div className="mt-1 text-sm">{toast.threat}</div>
          <div className="mt-1 truncate text-xs text-muted">{toast.path}</div>
        </div>
      )}
    </div>
  );
}
