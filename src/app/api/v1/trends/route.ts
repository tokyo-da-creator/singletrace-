import { readApi } from "@/lib/api";
import { baselineFor, findDeviations } from "@/lib/baseline";
import { parseFilters } from "@/lib/filters";
import { getActivity } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(request, async (db, params) => {
    const activity = await getActivity(db, parseFilters(params));
    const points = activity.days.map((day) => ({ day: day.day, count: day.count, status: day.status }));
    const baselines = baselineFor(points);
    const deviations = findDeviations(points);
    const flagged = new Set(deviations.map((item) => item.day));
    return {
      series: activity.days.map((day, index) => ({
        day: day.day,
        count: day.status === "none" || day.status === "gap" ? null : day.count,
        baseline: baselines[index],
        spike: flagged.has(day.day) ? day.count : null,
        status: day.status,
      })),
      deviations,
    };
  });
}
