import { useEffect, useState } from "react";
import { Lock, RotateCcw, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import type { QuarantineEntry } from "../lib/types";
import { Button, Card, PageHeader, SeverityBadge } from "../components/ui";
import { fmtBytes, fmtTime } from "../lib/format";

export default function Quarantine() {
  const [items, setItems] = useState<QuarantineEntry[]>([]);
  const [msg, setMsg] = useState("");
  const load = () => api.listQuarantine().then(setItems);
  useEffect(() => { load(); }, []);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); setMsg(ok); } catch (e) { setMsg(String(e)); }
    load();
  };

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader title="Quarantine" subtitle="Threats are encrypted and locked away here so they can't run. Restore only if you're sure a file is safe."
        right={items.length > 0 && <Button variant="danger" onClick={() => confirm("Permanently delete every quarantined file?") && act(api.clearQuarantine, "Quarantine emptied")}><Trash2 size={14} /> Delete all</Button>} />
      {msg && <div className="mb-4 rounded-xl border border-line bg-panel2 px-4 py-2.5 text-sm">{msg}</div>}
      {items.length === 0 ? (
        <Card className="py-14 text-center">
          <Lock className="mx-auto text-muted" size={32} />
          <div className="mt-3 font-medium">Quarantine is empty</div>
          <div className="mt-1 text-sm text-muted">Anything Warden blocks will show up here.</div>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((q) => (
            <Card key={q.id} className="p-4">
              <div className="flex items-center gap-4">
                <SeverityBadge s={q.severity} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{q.threat_name}</div>
                  <div className="truncate text-xs text-muted">{q.original_path}</div>
                  <div className="text-xs text-muted/70">{fmtBytes(q.size)} · quarantined {fmtTime(q.quarantined_at)}</div>
                </div>
                <Button variant="ghost" onClick={() => confirm(`Restore ${q.file_name}? Only do this if you're sure it is safe.`) && act(() => api.restore(q.id), `Restored ${q.file_name}`)}><RotateCcw size={14} /> Restore</Button>
                <Button variant="danger" onClick={() => act(() => api.deleteQuarantined(q.id), `Deleted ${q.file_name}`)}><Trash2 size={14} /> Delete</Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
