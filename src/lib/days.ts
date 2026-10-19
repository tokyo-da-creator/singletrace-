export type DayStatus = "count" | "zero" | "gap" | "none";

export function dayStatus(input: {
  day: string;
  count: number;
  ingestDays: Set<string>;
  firstIngestDay: string | null;
  lastIngestDay: string | null;
}): DayStatus {
  if (input.count > 0) return "count";
  if (!input.firstIngestDay || !input.lastIngestDay) return "none";
  if (input.day < input.firstIngestDay || input.day > input.lastIngestDay) return "none";
  if (input.ingestDays.has(input.day)) return "zero";
  return "gap";
}

export function colorForCount(count: number, breaks: [number, number, number]): string {
  if (count <= 0) return "#161616";
  const [q1, q2, q3] = breaks;
  if (count <= q1) return "#3a1512";
  if (count <= q2) return "#7a1e16";
  if (count <= q3) return "#b1160e";
  return "#e10600";
}

export function quantileBreaks(counts: number[]): [number, number, number] {
  const positive = counts.filter((count) => count > 0).sort((a, b) => a - b);
  if (positive.length === 0) return [1, 1, 1];
  const at = (ratio: number) => positive[Math.min(positive.length - 1, Math.max(0, Math.round((positive.length - 1) * ratio)))];
  return [at(0.25), at(0.5), at(0.75)];
}
