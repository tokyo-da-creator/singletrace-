export type Week<T> = { label: string | null; cells: Array<T | null> };

function monthName(day: string): string {
  return new Intl.DateTimeFormat("en-US", { month: "short", timeZone: "UTC" }).format(new Date(`${day}T00:00:00Z`));
}

export function layoutWeeks<T extends { day: string }>(days: T[]): Week<T>[] {
  if (days.length === 0) return [];
  const firstDow = new Date(`${days[0].day}T00:00:00Z`).getUTCDay();
  const padded: Array<T | null> = [...Array.from({ length: firstDow }, () => null), ...days];
  const weeks: Week<T>[] = [];
  for (let index = 0; index < padded.length; index += 7) {
    const cells = padded.slice(index, index + 7);
    while (cells.length < 7) cells.push(null);
    const marker = cells.find((cell) => cell?.day.endsWith("-01")) ?? (weeks.length === 0 ? cells.find(Boolean) : null);
    weeks.push({ label: marker ? monthName(marker.day) : null, cells });
  }
  return weeks;
}
