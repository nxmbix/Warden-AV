import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { api } from "../lib/api";
import type { ScanRecord } from "../lib/types";
import { Button, Card, PageHeader } from "../components/ui";
import { fmtBytes, fmtTime } from "../lib/format";
import Detections from "../components/Detections";

export default function History() {
  const [items, setItems] = useState<ScanRecord[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const load = () => api.history().then(setItems);
  useEffect(() => { load(); }, []);

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader title="Scan history" right={items.length > 0 && <Button variant="ghost" onClick={() => api.clearHistory().then(load)}><Trash2 size={14} /> Clear</Button>} />
      {items.length === 0 && <Card className="py-12 text-center text-sm text-muted">No scans yet.</Card>}
      <div className="space-y-2">
        {items.map((h) => {
          const r = h.report;
          return (
            <Card key={h.id} className="p-0">
              <button className="flex w-full items-center gap-4 px-5 py-4 text-left" onClick={() => setOpen(open === h.id ? null : h.id)}>
                <div className="flex-1">
                  <div className="text-sm font-medium capitalize">{h.kind} scan{h.scheduled ? " (scheduled)" : ""}{r.cancelled ? " — stopped" : ""}</div>
                  <div className="text-xs text-muted">{fmtTime(r.started_at)} · {r.files_scanned.toLocaleString()} files · {fmtBytes(r.bytes_scanned)} · {(r.duration_ms / 1000).toFixed(1)} s</div>
                </div>
                <span className={`text-sm font-medium ${r.detections.length ? "text-danger" : "text-accent"}`}>{r.detections.length ? `${r.detections.length} threats` : "Clean"}</span>
              </button>
              {open === h.id && r.detections.length > 0 && <div className="border-t border-line p-5"><Detections items={r.detections} /></div>}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
