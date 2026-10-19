import Link from "next/link";
import { FAMILIES } from "@/lib/family";
import { CATEGORIES, type Filters } from "@/lib/filters";
import { categoryLabel } from "@/lib/format";

const RANGES = [
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
  { id: "90d", label: "90 days" },
  { id: "26w", label: "26 weeks" },
  { id: "custom", label: "Custom" },
];

const SOURCES = [
  { id: "threatfox", label: "ThreatFox" },
  { id: "urlhaus", label: "URLhaus" },
  { id: "cisa_kev", label: "CISA KEV" },
  { id: "all", label: "All collected sources" },
];

function dayValue(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function FilterBar({ filters }: { filters: Filters }) {
  const inclusiveTo = new Date(filters.to.getTime() - 1);
  return (
    <form action="/" method="get" className="flex flex-wrap items-end gap-2 border border-line bg-panel px-3 py-2">
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Range
        <select name="range" defaultValue={filters.preset} aria-label="Time range">
          {RANGES.map((range) => (
            <option key={range.id} value={range.id}>
              {range.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        From
        <input name="from" type="date" defaultValue={dayValue(filters.from)} />
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        To
        <input name="to" type="date" defaultValue={dayValue(inclusiveTo)} />
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Source
        <select name="source" defaultValue={filters.source}>
          {SOURCES.map((source) => (
            <option key={source.id} value={source.id}>
              {source.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Category
        <select name="category" defaultValue={filters.category}>
          <option value="all">All categories</option>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {categoryLabel(category)}
            </option>
          ))}
        </select>
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Label
        <select name="family" defaultValue={filters.family}>
          <option value="all">All labels</option>
          {FAMILIES.map((family) => (
            <option key={family.id} value={family.id}>
              {family.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Country
        <input name="country" type="text" maxLength={2} defaultValue={filters.country ?? ""} placeholder="code" className="w-16 font-mono uppercase" />
      </label>
      <label className="flex w-full min-w-0 flex-1 flex-col gap-1 text-[11px] text-muted sm:min-w-[160px]">
        Record search
        <input name="q" type="search" defaultValue={filters.q ?? ""} placeholder="Indicator, family, summary" className="w-full min-w-0" />
      </label>
      <label className="flex w-full min-w-0 flex-col gap-1 text-[11px] text-muted sm:w-auto">
        Sort
        <select name="sort" defaultValue={filters.sort}>
          <option value="time_desc">Newest</option>
          <option value="time_asc">Oldest</option>
          <option value="confidence_desc">Confidence</option>
        </select>
      </label>
      <button type="submit">Apply</button>
      <Link href="/" className="px-2 py-1 text-[12px] text-muted underline decoration-line-strong underline-offset-2">
        Reset
      </Link>
      <p className="basis-full text-[11px] text-muted">From and to are used when the range is Custom. Dates are UTC. Applying filters clears a selected day.</p>
    </form>
  );
}
