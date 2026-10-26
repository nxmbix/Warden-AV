import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Settings } from "../lib/types";
import { Card, PageHeader, Row, Toggle } from "../components/ui";
import { fmtTime } from "../lib/format";

const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const sel = "rounded-lg border border-line bg-panel2 px-3 py-1.5 text-sm outline-none focus:border-accent/50";

export default function Schedule() {
  const [s, setS] = useState<Settings | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const refresh = () => api.status().then((st) => setNext(st.next_scheduled_scan));
  useEffect(() => { api.settings().then(setS); refresh(); }, []);
  if (!s) return null;
  const sch = s.schedule;
  const save = async (patch: Partial<Settings["schedule"]>) => { setS(await api.saveSettings({ ...s, schedule: { ...sch, ...patch } })); refresh(); };

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Scheduled scans" subtitle="Warden runs a scan in the background on a schedule. If your PC was off, it catches up next time it starts." />
      <Card>
        <Row title="Enable scheduled scans"><Toggle checked={sch.enabled} onChange={(v) => save({ enabled: v })} /></Row>
        <Row title="Scan type">
          <select className={sel} value={sch.scan_type} disabled={!sch.enabled} onChange={(e) => save({ scan_type: e.target.value as "quick" | "full" })}>
            <option value="quick">Quick scan</option><option value="full">Full scan</option>
          </select>
        </Row>
        <Row title="How often">
          <select className={sel} value={sch.frequency} disabled={!sch.enabled} onChange={(e) => save({ frequency: e.target.value as "daily" | "weekly" })}>
            <option value="daily">Every day</option><option value="weekly">Once a week</option>
          </select>
        </Row>
        {sch.frequency === "weekly" && (
          <Row title="Day">
            <select className={sel} value={sch.weekday} disabled={!sch.enabled} onChange={(e) => save({ weekday: Number(e.target.value) })}>
              {days.map((d, i) => <option key={d} value={i}>{d}</option>)}
            </select>
          </Row>
        )}
        <Row title="Time">
          <input type="time" className={sel} value={sch.time} disabled={!sch.enabled} onChange={(e) => e.target.value && save({ time: e.target.value })} />
        </Row>
      </Card>
      <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
        <Card className="p-4"><div className="text-xs uppercase tracking-wider text-muted">Next run</div><div className="mt-1">{sch.enabled ? fmtTime(next) : "Off"}</div></Card>
        <Card className="p-4"><div className="text-xs uppercase tracking-wider text-muted">Last run</div><div className="mt-1">{fmtTime(sch.last_run)}</div></Card>
      </div>
    </div>
  );
}
