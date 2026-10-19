"use client";

import { useState } from "react";
import type { Week } from "@/lib/grid-layout";

export type GridCell = {
  day: string;
  count: number;
  status: "count" | "zero" | "gap" | "none";
  color: string;
  href: string;
  label: string;
  detail: string;
  selected: boolean;
};

const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export function ActivityGrid({
  weeks,
  breaks,
}: {
  weeks: Week<GridCell>[];
  breaks: [number, number, number];
}) {
  const [tip, setTip] = useState<{ x: number; y: number; cell: GridCell } | null>(null);

  return (
    <div>
      <div className="overflow-x-auto">
        <div className="flex gap-3">
          <div className="mt-4 flex flex-col gap-[3px] pt-px font-mono text-[9px] uppercase tracking-wide text-muted">
            {DOW.map((day) => (
              <span key={day} className="flex h-[13px] items-center">
                {day}
              </span>
            ))}
          </div>
          <div>
            <div className="mb-1 flex" style={{ gap: 3 }}>
              {weeks.map((week, index) => (
                <div key={index} className="w-[13px] font-mono text-[9px] uppercase text-muted">
                  {week.label ?? ""}
                </div>
              ))}
            </div>
            <div className="flex" style={{ gap: 3 }}>
              {weeks.map((week, index) => (
                <div key={index} className="flex flex-col" style={{ gap: 3 }}>
                  {week.cells.map((cell, cellIndex) =>
                    cell ? (
                      <a
                        key={cell.day}
                        href={cell.href}
                        aria-label={cell.label}
                        className={`block h-[13px] w-[13px] ${cell.status === "gap" ? "hatch" : ""}`}
                        style={
                          cell.status === "gap"
                            ? cell.selected
                              ? { boxShadow: "inset 0 0 0 1px #eeeeee" }
                              : undefined
                            : {
                                background: cell.color,
                                boxShadow: cell.selected ? "inset 0 0 0 1px #eeeeee" : cell.status === "none" ? "inset 0 0 0 1px #292929" : undefined,
                              }
                        }
                        onMouseEnter={(event) => setTip({ x: event.clientX, y: event.clientY, cell })}
                        onMouseMove={(event) => setTip({ x: event.clientX, y: event.clientY, cell })}
                        onMouseLeave={() => setTip(null)}
                        onFocus={(event) => {
                          const rect = event.currentTarget.getBoundingClientRect();
                          setTip({ x: rect.left, y: rect.bottom, cell });
                        }}
                        onBlur={() => setTip(null)}
                      />
                    ) : (
                      <span key={`pad-${index}-${cellIndex}`} className="block h-[13px] w-[13px]" />
                    ),
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3 font-mono text-[10px] uppercase tracking-[0.12em] text-muted">
        <Legend swatch="#101010" bordered label="No record" />
        <Legend swatch="#161616" label="Zero in a collected day" />
        <span className="hatch inline-block h-[13px] w-[13px]" aria-hidden="true" />
        <span>Collection gap</span>
        <Legend swatch="#3a1512" label={`1–${breaks[0]}`} />
        <Legend swatch="#7a1e16" label={`${breaks[0] + 1}–${breaks[1]}`} />
        <Legend swatch="#b1160e" label={`${breaks[1] + 1}–${breaks[2]}`} />
        <Legend swatch="#e10600" label={`${breaks[2] + 1}+`} />
      </div>
      {tip ? (
        <div className="tip" style={{ left: Math.min(tip.x + 12, 1100), top: tip.y + 14 }} role="tooltip">
          <p className="font-mono text-[11px] text-ink">{tip.cell.label}</p>
          <p className="mt-1 text-[12px] text-muted">{tip.cell.detail}</p>
        </div>
      ) : null}
    </div>
  );
}

function Legend({ swatch, label, bordered = false }: { swatch: string; label: string; bordered?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block h-[13px] w-[13px]" style={{ background: swatch, boxShadow: bordered ? "inset 0 0 0 1px #292929" : undefined }} />
      {label}
    </span>
  );
}
