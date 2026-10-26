import { useState } from "react";
import { ChevronDown, FolderOpen, Lock, ShieldOff } from "lucide-react";
import { api } from "../lib/api";
import type { Detection } from "../lib/types";
import { Button, SeverityBadge } from "./ui";

export default function Detections({ items, onChange }: { items: Detection[]; onChange?: () => void }) {
  const [open, setOpen] = useState<number | null>(null);
  const [handled, setHandled] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const pending = items.filter((d) => !handled[d.path]);

  const quarantine = async (ds: Detection[]) => {
    setBusy(true);
    try {
      const res = await api.quarantine(ds);
      setHandled((h) => ({ ...h, ...Object.fromEntries(res.map((r) => [r.path, r.ok ? "Quarantined" : r.message])) }));
      onChange?.();
    } finally { setBusy(false); }
  };
  const allow = async (d: Detection) => {
    if (!d.sha256) return;
    await api.allow(d.sha256);
    setHandled((h) => ({ ...h, [d.path]: "Allowed" }));
  };

  if (!items.length) return null;
  return (
    <div>
      {pending.length > 1 && (
        <div className="mb-3 flex justify-end">
          <Button variant="danger" disabled={busy} onClick={() => quarantine(pending)}><Lock size={14} /> Quarantine all ({pending.length})</Button>
        </div>
      )}
      <div className="space-y-2">
        {items.map((d, i) => (
          <div key={d.path + d.location + i} className="rounded-xl border border-line bg-panel2">
            <button className="flex w-full items-center gap-3 px-4 py-3 text-left" onClick={() => setOpen(open === i ? null : i)}>
              <SeverityBadge s={d.severity} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{d.name}</div>
                <div className="truncate text-xs text-muted">{d.location}</div>
              </div>
              {handled[d.path] && <span className="text-xs text-accent">{handled[d.path]}</span>}
              <ChevronDown size={16} className={`text-muted transition ${open === i ? "rotate-180" : ""}`} />
            </button>
            {open === i && (
              <div className="border-t border-line px-4 py-3 text-sm">
                <p className="text-muted">{d.description}</p>
                <div className="mt-3 grid grid-cols-[110px_1fr] gap-y-1 text-xs">
                  <span className="text-muted">Detected by</span><span className="capitalize">{d.kind}{d.score != null ? ` (score ${d.score}/100)` : ""}</span>
                  <span className="text-muted">Category</span><span>{d.category}</span>
                  {d.sha256 && (<><span className="text-muted">SHA-256</span><span className="break-all font-mono">{d.sha256}</span></>)}
                </div>
                {d.reasons.length > 0 && (
                  <ul className="mt-3 list-disc space-y-0.5 pl-5 text-xs text-muted">{d.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                )}
                {!handled[d.path] && (
                  <div className="mt-4 flex gap-2">
                    <Button variant="danger" disabled={busy} onClick={() => quarantine([d])}><Lock size={14} /> Quarantine</Button>
                    <Button variant="ghost" onClick={() => api.reveal(d.path)}><FolderOpen size={14} /> Show in folder</Button>
                    {d.sha256 && <Button variant="ghost" onClick={() => allow(d)}><ShieldOff size={14} /> Allow this file</Button>}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
