import { useEffect, useState } from "react";
import { Activity, Lock, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import type { Page, ScanLive } from "../App";
import { api, on } from "../lib/api";
import type { Status } from "../lib/types";
import { Button, Card, SeverityBadge, Stat } from "../components/ui";
import { fmtAgo, fmtTime } from "../lib/format";

export default function Dashboard({ go, scan }: { go: (p: Page) => void; scan: ScanLive }) {
  const [s, setS] = useState<Status | null>(null);
  const [now, setNow] = useState(0);
  const load = () => api.status().then((x) => { setS(x); setNow(Date.now()); });
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    const offs = ["protection-event", "realtime-changed", "update-finished", "scan-finished"].map((e) => on(e, load));
    return () => { clearInterval(t); offs.forEach((p) => p.then((f) => f())); };
  }, []);
  if (!s) return null;

  const lastThreats = s.last_scan?.report.detections.length ?? 0;
  const stale = !s.last_update || now - new Date(s.last_update).getTime() > 3 * 86400e3;
  const issues = [!s.realtime_enabled && "Real-time protection is off", stale && "Threat signatures are out of date"].filter(Boolean) as string[];
  const safe = issues.length === 0;

  const quick = async () => { await api.startScan("quick"); go("scan"); };

  return (
    <div className="mx-auto max-w-5xl">
      <Card className="relative overflow-hidden p-8">
        <div className={`pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full blur-3xl ${safe ? "bg-accent/10" : "bg-warn/10"}`} />
        <div className="relative flex items-center gap-8">
          <div className="relative grid h-28 w-28 place-items-center">
            <div className={`pulse-ring absolute inset-0 rounded-full ${safe ? "bg-accent/25" : "bg-warn/25"}`} />
            <div className={`relative grid h-24 w-24 place-items-center rounded-full ${safe ? "bg-accent/15 text-accent" : "bg-warn/15 text-warn"}`}>
              {safe ? <ShieldCheck size={48} /> : <ShieldAlert size={48} />}
            </div>
          </div>
          <div className="flex-1">
            <h1 className="text-3xl font-semibold tracking-tight">{safe ? "You're protected" : "Action recommended"}</h1>
            <p className="mt-1.5 text-sm text-muted">
              {safe ? `Real-time protection is watching ${s.watched_folders.length} folder${s.watched_folders.length === 1 ? "" : "s"}. Last scan ${fmtAgo(s.last_scan?.report.finished_at)}.` : issues.join(" · ")}
            </p>
            <div className="mt-5 flex gap-2">
              <Button onClick={quick} disabled={scan.running}><Zap size={15} /> {scan.running ? "Scan running…" : "Quick scan"}</Button>
              <Button variant="ghost" onClick={() => go("scan")}><ScanSearch size={15} /> More scan options</Button>
              {!s.realtime_enabled && <Button variant="ghost" onClick={() => api.setRealtime(true).then(load)}><Activity size={15} /> Turn on protection</Button>}
              {stale && <Button variant="ghost" onClick={() => go("updates")}><RefreshCw size={15} /> Update signatures</Button>}
            </div>
          </div>
        </div>
      </Card>

      <div className="mt-4 grid grid-cols-4 gap-4">
        <Stat label="Real-time" value={<span className={s.realtime_enabled ? "text-accent" : "text-warn"}>{s.realtime_enabled ? "On" : "Off"}</span>} sub={`${s.watched_folders.length} folders watched`} />
        <Stat label="Last scan" value={fmtAgo(s.last_scan?.report.finished_at)} sub={s.last_scan ? `${lastThreats} threat${lastThreats === 1 ? "" : "s"} · ${s.last_scan.report.files_scanned.toLocaleString()} files` : "Run your first scan"} />
        <Stat label="Signatures" value={(s.signatures.feed_hashes + s.signatures.named_hashes).toLocaleString()} sub={`+ ${s.signatures.rules} rules · updated ${fmtAgo(s.last_update)}`} />
        <Stat label="Quarantine" value={s.quarantine_count} sub="files locked away" />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4">
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <div className="text-sm font-semibold">Recent protection activity</div>
            <button className="text-xs text-muted hover:text-white" onClick={() => go("protection")}>View all</button>
          </div>
          {s.recent_events.length === 0 ? (
            <div className="py-6 text-center text-sm text-muted">Nothing blocked yet. That's a good thing.</div>
          ) : s.recent_events.slice(0, 4).map((e) => (
            <div key={e.id} className="flex items-center gap-3 border-b border-line py-2.5 last:border-0">
              <SeverityBadge s={e.severity} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{e.threat}</div>
                <div className="truncate text-xs text-muted">{e.path}</div>
              </div>
              <div className="text-xs text-muted">{fmtAgo(e.time)}</div>
            </div>
          ))}
        </Card>
        <Card>
          <div className="mb-3 text-sm font-semibold">Coming up</div>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-muted">Next scheduled scan</span><span>{s.next_scheduled_scan ? fmtTime(s.next_scheduled_scan) : "Off"}</span></div>
            <div className="flex justify-between"><span className="text-muted">Signature version</span><span>{s.signatures.version}</span></div>
            <div className="flex justify-between"><span className="text-muted">Quarantined files</span><button className="flex items-center gap-1 hover:text-accent" onClick={() => go("quarantine")}><Lock size={13} />{s.quarantine_count}</button></div>
          </div>
          <div className="mt-5 rounded-xl border border-line bg-panel2 p-3 text-xs text-muted">
            Want to see Warden catch something? Open the <button className="text-accent hover:underline" onClick={() => go("testlab")}>Test lab</button> to create harmless fake viruses.
          </div>
        </Card>
      </div>
    </div>
  );
}
