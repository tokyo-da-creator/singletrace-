"use client";

import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

type Point = {
  day: string;
  count: number | null;
  baseline: number | null;
  spike: number | null;
  status: string;
};

function Tip({
  active,
  label,
  payload,
}: {
  active?: boolean;
  label?: string;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
}) {
  if (!active || !payload?.length) return null;
  const rows = payload.filter((item) => item.name !== "spike" && item.value != null);
  return (
    <div className="border border-line-strong bg-bg px-2 py-1.5">
      <p className="font-mono text-[11px] text-muted">{label} UTC</p>
      {rows.map((item) => (
        <p key={item.name} className="font-mono text-[12px] text-ink">
          {item.name === "count" ? "Records" : "Baseline median"}: {item.value}
        </p>
      ))}
    </div>
  );
}

export function Trends({ series }: { series: Point[] }) {
  if (series.length === 0) {
    return <p className="text-[13px] text-muted">No days in this window.</p>;
  }
  return (
    <div className="h-[230px] w-full min-w-0">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={series} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="#292929" vertical={false} />
          <XAxis dataKey="day" tick={{ fill: "#929292", fontSize: 10 }} tickFormatter={(value: string) => value.slice(5)} minTickGap={28} />
          <YAxis tick={{ fill: "#929292", fontSize: 10 }} width={36} allowDecimals={false} />
          <Tooltip content={<Tip />} />
          <Line type="monotone" dataKey="baseline" stroke="#5c5c5c" strokeWidth={1} dot={false} connectNulls={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="count" stroke="#e10600" strokeWidth={1.5} dot={false} connectNulls={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="spike" stroke="none" dot={{ r: 3, fill: "#c4841d" }} activeDot={false} isAnimationActive={false} legendType="none" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
