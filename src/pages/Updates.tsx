import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api, on } from "../lib/api";
import type { Settings, Status, UpdateResult } from "../lib/types";
import { Button, Card, PageHeader, Row, Stat, Toggle } from "../components/ui";
import { fmtAgo } from "../lib/format";

export default function Updates() {
  const [s, setS] = useState<Settings | null>(null);
  const [st, setSt] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UpdateResult | null>(null);
  const [err, setErr] = useState("");
  const load = () => { api.settings().then(setS); api.status().then((x) => { setSt(x); setBusy(x.updating); }); };
  useEffect(() => {
    load();
    const offs = [on("update-started", () => setBusy(true)), on<UpdateResult>("update-finished", (r) => { setResult(r); setBusy(false); load(); })];
    return () => { offs.forEach((p) => p.then((f) => f())); };
  }, []);
  if (!s || !st) return null;

  const update = async () => {
    setBusy(true); setErr("");
    try { setResult(await api.updateSignatures()); } catch (e) { setErr(String(e)); }
    setBusy(false); load();
  };
  const save = async (next: Settings) => setS(await api.saveSettings(next));

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader title="Signature updates" subtitle="Warden downloads fresh lists of known malware fingerprints so it recognises new threats."
        right={<Button onClick={update} disabled={busy}><RefreshCw size={15} className={busy ? "sweep" : ""} /> {busy ? "Updating…" : "Check for updates"}</Button>} />
      <div className="grid grid-cols-3 gap-4">
        <Stat label="Malware hashes" value={(st.signatures.feed_hashes + st.signatures.named_hashes).toLocaleString()} />
        <Stat label="Detection rules" value={st.signatures.rules} sub="+ heuristics engine" />
        <Stat label="Last updated" value={fmtAgo(st.last_update)} sub={s.updates.last_result ?? undefined} />
      </div>
      {err && <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 px-4 py-2.5 text-sm text-danger">{err}</div>}
      {result && (
        <Card className="mt-4">
          <div className="mb-2 text-sm font-semibold">{result.ok ? "Update complete" : "Update finished with problems"}</div>
          {result.feeds.map((f) => (
            <div key={f.id} className="flex justify-between py-1 text-sm">
              <span className="text-muted">{f.name}</span>
              <span className={f.error ? "text-danger" : "text-accent"}>{f.error ?? `${f.entries.toLocaleString()} entries`}</span>
            </div>
          ))}
        </Card>
      )}
      <Card className="mt-4">
        <Row title="Update automatically" desc={`Check every ${s.updates.interval_hours} hours in the background.`}>
          <Toggle checked={s.updates.auto_update} onChange={(v) => save({ ...s, updates: { ...s.updates, auto_update: v } })} />
        </Row>
        <div className="pt-4 text-sm font-semibold">Sources</div>
        {s.updates.feeds.map((f, i) => (
          <Row key={f.id} title={f.name} desc={f.url}>
            <Toggle checked={f.enabled} onChange={(v) => save({ ...s, updates: { ...s.updates, feeds: s.updates.feeds.map((x, j) => (j === i ? { ...x, enabled: v } : x)) } })} />
          </Row>
        ))}
      </Card>
    </div>
  );
}
