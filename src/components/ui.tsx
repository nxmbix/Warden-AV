import type { ReactNode } from "react";
import type { Severity } from "../lib/types";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-2xl border border-line bg-panel p-5 ${className}`}>{children}</div>;
}

export function Button({ children, onClick, variant = "primary", disabled, className = "" }: {
  children: ReactNode; onClick?: () => void; variant?: "primary" | "ghost" | "danger" | "subtle"; disabled?: boolean; className?: string;
}) {
  const styles = {
    primary: "bg-accent text-black hover:bg-[#6ee7a0]",
    ghost: "border border-line text-white hover:bg-panel2",
    subtle: "bg-panel2 text-white hover:bg-[#1b2325]",
    danger: "bg-danger/15 text-danger border border-danger/30 hover:bg-danger/25",
  }[variant];
  return (
    <button disabled={disabled} onClick={onClick}
      className={`inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-40 ${styles} ${className}`}>
      {children}
    </button>
  );
}

export function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)}
      className={`relative h-6 w-11 shrink-0 rounded-full transition ${checked ? "bg-accent" : "bg-[#2a3436]"} disabled:opacity-40`}>
      <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${checked ? "left-[22px]" : "left-0.5"}`} />
    </button>
  );
}

export function Row({ title, desc, children }: { title: string; desc?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-line py-4 last:border-0">
      <div>
        <div className="text-sm font-medium">{title}</div>
        {desc && <div className="mt-0.5 text-xs text-muted">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

const sevStyle: Record<Severity, string> = {
  critical: "bg-danger/15 text-danger border-danger/30",
  high: "bg-orange-400/15 text-orange-300 border-orange-400/30",
  medium: "bg-warn/15 text-warn border-warn/30",
  low: "bg-sky-400/15 text-sky-300 border-sky-400/30",
};
export function SeverityBadge({ s }: { s: Severity }) {
  return <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${sevStyle[s]}`}>{s}</span>;
}

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <Card className="p-4">
      <div className="text-xs uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </Card>
  );
}
