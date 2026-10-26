import { useEffect, useState } from "react";
import { FlaskConical, FolderOpen, ScanSearch, ShieldCheck } from "lucide-react";
import type { Page, ScanLive } from "../App";
import { api, pickFolders } from "../lib/api";
import type { Sample } from "../lib/types";
import { Button, Card, PageHeader } from "../components/ui";

const tag: Record<Sample["tests"], string> = {
  signature: "bg-sky-400/15 text-sky-300", rule: "bg-violet-400/15 text-violet-300", heuristic: "bg-orange-400/15 text-orange-300",
  archive: "bg-pink-400/15 text-pink-300", clean: "bg-accent/15 text-accent",
};

export default function TestLab({ go }: { go: (p: Page) => void; scan: ScanLive }) {
  const [dir, setDir] = useState("");
  const [samples, setSamples] = useState<Sample[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => { api.defaultSamplesDir().then(setDir); }, []);

  const generate = async () => {
    setErr("");
    try { const r = await api.generateSamples(dir); setDir(r.dir); setSamples(r.samples); } catch (e) { setErr(String(e)); }
  };
  const scan = async () => { await api.startScan("custom", [dir]); go("scan"); };

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader title="Test lab" subtitle="Create harmless fake viruses to see Warden in action. None of these files can run or change anything on your PC." />
      <Card>
        <div className="flex items-start gap-4">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent/15 text-accent"><FlaskConical size={22} /></div>
          <div className="flex-1 text-sm">
            <div className="font-semibold">How it works</div>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-muted">
              <li>Warden writes 13 test files into the folder below (look-alike ransom notes, fake scripts, a broken fake .exe, the EICAR test file, and one clean file).</li>
              <li>Real-time protection should catch most of them within a couple of seconds. Or run a scan on the folder.</li>
              <li>Every file should be detected except <span className="text-white">clean-shopping-list.txt</span>.</li>
            </ol>
            <p className="mt-3 text-xs text-muted/80">Windows Defender may also delete the EICAR files — that's expected, it means Defender works too. You can add the folder as a Defender exclusion while testing.</p>
          </div>
        </div>
        <div className="mt-5 flex items-center gap-2">
          <input value={dir} onChange={(e) => setDir(e.target.value)} className="flex-1 rounded-xl border border-line bg-panel2 px-3 py-2 text-sm outline-none focus:border-accent/50" />
          <Button variant="ghost" onClick={async () => { const f = await pickFolders(false); if (f[0]) setDir(f[0]); }}><FolderOpen size={14} /> Browse</Button>
          <Button onClick={generate}><FlaskConical size={14} /> Create test files</Button>
        </div>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Card>

      {samples.length > 0 && (
        <Card className="mt-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="text-sm font-semibold">{samples.length} test files created</div>
            <div className="flex gap-2">
              <Button variant="ghost" onClick={() => api.reveal(dir)}><FolderOpen size={14} /> Open folder</Button>
              <Button onClick={scan}><ScanSearch size={14} /> Scan this folder</Button>
            </div>
          </div>
          {samples.map((s) => (
            <div key={s.file_name} className="border-b border-line py-3 last:border-0">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm">{s.file_name}</span>
                <span className={`rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${tag[s.tests]}`}>{s.tests}</span>
                <span className="ml-auto text-xs text-muted">expects: <span className="text-white">{s.expected}</span></span>
              </div>
              <div className="mt-1 text-xs text-muted">{s.explanation}</div>
              <div className="mt-0.5 flex items-center gap-1 text-xs text-accent/80"><ShieldCheck size={12} /> {s.safe_because}</div>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}
