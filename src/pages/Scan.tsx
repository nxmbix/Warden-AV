import { CheckCircle2, File, FolderSearch, HardDrive, Square, Zap } from "lucide-react";
import type { Page, ScanLive } from "../App";
import { api, pickFiles, pickFolders } from "../lib/api";
import { Button, Card, PageHeader } from "../components/ui";
import { fmtBytes } from "../lib/format";
import Detections from "../components/Detections";

export default function Scan({ scan }: { go: (p: Page) => void; scan: ScanLive }) {
  const start = (kind: "quick" | "full" | "custom", paths?: string[]) => api.startScan(kind, paths).catch((e) => alert(e));
  const custom = async (files: boolean) => {
    const p = files ? await pickFiles() : await pickFolders();
    if (p.length) start("custom", p);
  };
  const p = scan.progress;
  const pct = p && p.files_total ? Math.round((p.files_scanned / p.files_total) * 100) : 0;
  const r = scan.result?.report;

  const options = [
    { icon: Zap, title: "Quick scan", desc: "Downloads, Desktop, Documents, Temp and startup folders.", run: () => start("quick") },
    { icon: HardDrive, title: "Full scan", desc: "Every drive on this PC. Can take a while.", run: () => start("full") },
    { icon: FolderSearch, title: "Scan a folder", desc: "Pick one or more folders to check.", run: () => custom(false) },
    { icon: File, title: "Scan files", desc: "Check specific files, e.g. something you just downloaded.", run: () => custom(true) },
  ];

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader title="Scan" subtitle="Check your files for viruses, trojans, ransomware and other threats." />
      {scan.running ? (
        <Card className="p-7">
          <div className="flex items-center gap-5">
            <div className="relative h-14 w-14">
              <div className="absolute inset-0 rounded-full border-4 border-line" />
              <div className="sweep absolute inset-0 rounded-full border-4 border-transparent border-t-accent" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-lg font-semibold">{scan.kind === "full" ? "Full" : scan.kind === "quick" ? "Quick" : "Custom"} scan in progress</div>
              <div className="truncate text-xs text-muted">{p?.current_file || "Collecting files…"}</div>
            </div>
            <Button variant="ghost" onClick={() => api.cancelScan()}><Square size={14} /> Stop</Button>
          </div>
          <div className="mt-6 h-2 overflow-hidden rounded-full bg-panel2">
            <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pct}%` }} />
          </div>
          <div className="mt-3 flex justify-between text-xs text-muted">
            <span>{p ? `${p.files_scanned.toLocaleString()} / ${p.files_total.toLocaleString()} files · ${fmtBytes(p.bytes_scanned)}` : "Starting…"}</span>
            <span className={p?.detections ? "text-danger" : ""}>{p?.detections ?? 0} threats found</span>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {options.map((o) => (
            <button key={o.title} onClick={o.run} className="group rounded-2xl border border-line bg-panel p-5 text-left transition hover:border-accent/40 hover:bg-panel2">
              <o.icon className="text-accent" size={22} />
              <div className="mt-3 font-semibold">{o.title}</div>
              <div className="mt-1 text-sm text-muted">{o.desc}</div>
            </button>
          ))}
        </div>
      )}

      {r && !scan.running && (
        <Card className="mt-6">
          <div className="mb-4 flex items-center gap-3">
            {r.detections.length ? null : <CheckCircle2 className="text-accent" size={22} />}
            <div>
              <div className="font-semibold">
                {r.cancelled ? "Scan stopped" : r.detections.length ? `${r.detections.length} threat${r.detections.length === 1 ? "" : "s"} found` : "No threats found"}
              </div>
              <div className="text-xs text-muted">
                {r.files_scanned.toLocaleString()} files · {fmtBytes(r.bytes_scanned)} · {(r.duration_ms / 1000).toFixed(1)} s
                {scan.result!.auto_quarantined > 0 && ` · ${scan.result!.auto_quarantined} quarantined automatically`}
                {r.errors.length > 0 && ` · ${r.errors.length} files couldn't be read`}
              </div>
            </div>
          </div>
          <Detections items={r.detections} />
        </Card>
      )}
    </div>
  );
}
