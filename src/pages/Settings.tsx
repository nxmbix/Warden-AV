import { useEffect, useState } from "react";
import { FolderPlus, X } from "lucide-react";
import { api, pickFolders } from "../lib/api";
import type { Settings as S } from "../lib/types";
import { Button, Card, PageHeader, Row, Toggle } from "../components/ui";

const sel = "rounded-lg border border-line bg-panel2 px-3 py-1.5 text-sm outline-none focus:border-accent/50";

function ListEditor({ title, desc, items, onChange, placeholder, pick }: {
  title: string; desc: string; items: string[]; onChange: (v: string[]) => void; placeholder: string; pick?: boolean;
}) {
  const [v, setV] = useState("");
  const add = (x: string[]) => { const n = x.map((s) => s.trim()).filter(Boolean); if (n.length) onChange([...new Set([...items, ...n])]); setV(""); };
  return (
    <Card className="mt-4">
      <div className="text-sm font-semibold">{title}</div>
      <div className="mt-0.5 text-xs text-muted">{desc}</div>
      <div className="mt-3 flex gap-2">
        <input value={v} placeholder={placeholder} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add([v])}
          className="flex-1 rounded-xl border border-line bg-panel2 px-3 py-2 text-sm outline-none focus:border-accent/50" />
        <Button variant="subtle" onClick={() => add([v])}>Add</Button>
        {pick && <Button variant="subtle" onClick={async () => add(await pickFolders())}><FolderPlus size={14} /></Button>}
      </div>
      {items.map((x) => (
        <div key={x} className="flex items-center justify-between border-b border-line py-2 text-sm last:border-0">
          <span className="truncate font-mono text-xs">{x}</span>
          <button className="text-muted hover:text-danger" onClick={() => onChange(items.filter((i) => i !== x))}><X size={14} /></button>
        </div>
      ))}
    </Card>
  );
}

export default function Settings() {
  const [s, setS] = useState<S | null>(null);
  useEffect(() => { api.settings().then(setS); }, []);
  if (!s) return null;
  const save = async (patch: Partial<S>) => setS(await api.saveSettings({ ...s, ...patch }));

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Settings" />
      <Card>
        <Row title="Heuristic sensitivity" desc="How suspicious unknown files must look before Warden flags them. Aggressive catches more but may flag safe tools.">
          <select className={sel} value={s.heuristics} onChange={(e) => save({ heuristics: e.target.value as S["heuristics"] })}>
            <option value="off">Off</option><option value="balanced">Balanced</option><option value="aggressive">Aggressive</option>
          </select>
        </Row>
        <Row title="Look inside ZIP archives" desc="Unpack .zip, .docx, .jar and similar files in memory to scan what's inside.">
          <Toggle checked={s.scan_archives} onChange={(v) => save({ scan_archives: v })} />
        </Row>
        <Row title="Skip files larger than" desc="Huge files are rarely malware and slow scans down.">
          <select className={sel} value={s.max_file_size_mb} onChange={(e) => save({ max_file_size_mb: Number(e.target.value) })}>
            {[64, 128, 256, 512, 1024].map((n) => <option key={n} value={n}>{n} MB</option>)}
          </select>
        </Row>
        <Row title="Start with Windows" desc="Keep protection running from the moment you log in.">
          <Toggle checked={s.start_with_windows} onChange={(v) => save({ start_with_windows: v })} />
        </Row>
        <Row title="Keep running in the tray when closed" desc="Closing the window hides Warden instead of quitting, so protection stays on.">
          <Toggle checked={s.minimize_to_tray} onChange={(v) => save({ minimize_to_tray: v })} />
        </Row>
      </Card>
      <ListEditor title="Exclusions" desc="Files or folders Warden will never scan. Use carefully." placeholder="C:\Games\MyGame" items={s.exclusions} pick onChange={(v) => save({ exclusions: v })} />
      <ListEditor title="Allowed files" desc="SHA-256 hashes of files you've marked as safe." placeholder="sha256 hash" items={s.allowed_hashes} onChange={(v) => save({ allowed_hashes: v.map((x) => x.toLowerCase()) })} />
    </div>
  );
}
