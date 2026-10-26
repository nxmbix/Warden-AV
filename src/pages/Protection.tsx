import { useEffect, useState } from "react";
import { FolderPlus, Trash2, X } from "lucide-react";
import { api, on, pickFolders } from "../lib/api";
import type { ProtectionEvent, Settings } from "../lib/types";
import { Button, Card, PageHeader, Row, SeverityBadge, Toggle } from "../components/ui";
import { fmtTime } from "../lib/format";

export default function Protection() {
  const [s, setS] = useState<Settings | null>(null);
  const [events, setEvents] = useState<ProtectionEvent[]>([]);
  const load = () => { api.settings().then(setS); api.events().then(setEvents); };
  useEffect(() => {
    load();
    const offs = [on("protection-event", load), on("realtime-changed", load)];
    return () => { offs.forEach((p) => p.then((f) => f())); };
  }, []);
  if (!s) return null;

  const save = async (next: Settings) => setS(await api.saveSettings(next));
  const addFolder = async () => {
    const f = await pickFolders();
    if (f.length) save({ ...s, watched_folders: [...new Set([...s.watched_folders, ...f])] });
  };

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader title="Real-time protection" subtitle="Warden checks new and changed files the moment they land in a watched folder." />
      <Card>
        <Row title="Real-time protection" desc="Scan files automatically as they are created or downloaded.">
          <Toggle checked={s.realtime_enabled} onChange={(v) => api.setRealtime(v).then(load)} />
        </Row>
        <Row title="Quarantine threats automatically" desc="Move confident detections into the encrypted vault without asking.">
          <Toggle checked={s.auto_quarantine} onChange={(v) => save({ ...s, auto_quarantine: v })} />
        </Row>
        <Row title="Desktop notifications" desc="Show a Windows notification when something is blocked.">
          <Toggle checked={s.notifications} onChange={(v) => save({ ...s, notifications: v })} />
        </Row>
      </Card>

      <Card className="mt-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Watched folders</div>
          <Button variant="subtle" onClick={addFolder}><FolderPlus size={14} /> Add folder</Button>
        </div>
        {s.watched_folders.map((f) => (
          <div key={f} className="flex items-center justify-between border-b border-line py-2.5 text-sm last:border-0">
            <span className="truncate">{f}</span>
            <button className="text-muted hover:text-danger" onClick={() => save({ ...s, watched_folders: s.watched_folders.filter((x) => x !== f) })}><X size={15} /></button>
          </div>
        ))}
        {!s.watched_folders.length && <div className="py-4 text-center text-sm text-muted">No folders watched.</div>}
      </Card>

      <Card className="mt-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Protection log</div>
          {events.length > 0 && <Button variant="ghost" onClick={() => api.clearEvents().then(load)}><Trash2 size={14} /> Clear</Button>}
        </div>
        {events.length === 0 ? <div className="py-6 text-center text-sm text-muted">No threats seen by real-time protection yet.</div> : events.map((e) => (
          <div key={e.id} className="flex items-center gap-3 border-b border-line py-3 last:border-0">
            <SeverityBadge s={e.severity} />
            <div className="min-w-0 flex-1">
              <div className="text-sm">{e.threat} <span className={`ml-2 text-xs ${e.action === "quarantined" ? "text-accent" : e.action === "failed" ? "text-danger" : "text-warn"}`}>{e.action}</span></div>
              <div className="truncate text-xs text-muted">{e.path}</div>
              <div className="text-xs text-muted/70">{e.detail}</div>
            </div>
            <div className="shrink-0 text-xs text-muted">{fmtTime(e.time)}</div>
          </div>
        ))}
      </Card>
    </div>
  );
}
