export function Panel({
  kicker,
  title,
  extra,
  children,
}: {
  kicker: string;
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="min-w-0 border border-line bg-panel">
      <header className="flex items-baseline justify-between gap-3 border-b border-line px-3 py-2">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">{kicker}</p>
          <h2 className="text-[13px] font-medium text-ink">{title}</h2>
        </div>
        {extra}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

export function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <article className="border border-line bg-panel px-3 py-2.5">
      <h2 className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">{label}</h2>
      <p className="mt-1 font-mono text-[22px] leading-none tabular-nums text-ink">{value}</p>
      <p className="mt-1.5 text-[12px] leading-4 text-muted">{note}</p>
    </article>
  );
}
