import { formatNumber } from "@/lib/format";

export function Bars({
  items,
}: {
  items: { key: string; label: string; count: number; href?: string; color?: string }[];
}) {
  if (items.length === 0) {
    return <p className="text-[13px] text-muted">No records in this window.</p>;
  }
  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <ul className="space-y-1.5">
      {items.map((item) => {
        const body = (
          <>
            <span className="truncate text-muted">{item.label}</span>
            <span className="block h-1.5 bg-raise">
              <span className="block h-1.5" style={{ width: `${(item.count / max) * 100}%`, background: item.color ?? "#e10600" }} />
            </span>
            <span className="text-right font-mono tabular-nums text-ink">{formatNumber(item.count)}</span>
          </>
        );
        return (
          <li key={item.key}>
            {item.href ? (
              <a href={item.href} className="grid grid-cols-[minmax(0,140px)_1fr_52px] items-center gap-2 text-[12px] hover:text-ink">
                {body}
              </a>
            ) : (
              <div className="grid grid-cols-[minmax(0,140px)_1fr_52px] items-center gap-2 text-[12px]">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
