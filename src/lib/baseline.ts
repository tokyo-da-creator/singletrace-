import type { DayStatus } from "@/lib/days";

export type BaselinePoint = {
  day: string;
  count: number;
  status: DayStatus;
};

export type Deviation = {
  day: string;
  count: number;
  median: number;
  mad: number;
  modifiedZ: number | null;
  rule: string;
};

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1] + sorted[mid]) / 2;
  return sorted[mid];
}

// A deviation is a jump above a rolling median, using a modified z-score
// when the median absolute deviation is non-zero. It is not attribution.
export function findDeviations(series: BaselinePoint[], window = 14): Deviation[] {
  const flags: Deviation[] = [];
  series.forEach((point, index) => {
    if (point.status !== "count" && point.status !== "zero") return;
    const prior = series
      .slice(Math.max(0, index - window), index)
      .filter((item) => item.status === "count" || item.status === "zero")
      .map((item) => item.count);
    if (prior.length < 7) return;
    const med = median(prior);
    const mad = median(prior.map((value) => Math.abs(value - med)));
    if (point.count <= med) return;
    if (point.count < med * 2 && med > 0) return;
    if (mad === 0) {
      if (point.count >= med + 5 && (med === 0 || point.count >= med * 2)) {
        flags.push({
          day: point.day,
          count: point.count,
          median: med,
          mad,
          modifiedZ: null,
          rule: "The previous baseline did not vary, and this day is at least 5 above it and at least twice the median.",
        });
      }
      return;
    }
    const modifiedZ = (0.6745 * (point.count - med)) / mad;
    if (modifiedZ >= 3.5) {
      flags.push({
        day: point.day,
        count: point.count,
        median: med,
        mad,
        modifiedZ,
        rule: "Modified z-score is at least 3.5 against the median absolute deviation of up to 14 earlier covered days, and the count is above twice the median.",
      });
    }
  });
  return flags;
}

export function baselineFor(series: BaselinePoint[], window = 14): Array<number | null> {
  return series.map((point, index) => {
    const prior = series
      .slice(Math.max(0, index - window), index)
      .filter((item) => item.status === "count" || item.status === "zero")
      .map((item) => item.count);
    if (prior.length < 7) return null;
    if (point.status !== "count" && point.status !== "zero") return null;
    return median(prior);
  });
}
