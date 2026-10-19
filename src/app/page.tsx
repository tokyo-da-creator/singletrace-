import Link from "next/link";
import { ActivityGrid, type GridCell } from "@/components/activity-grid";
import { Bars } from "@/components/bars";
import { Feed } from "@/components/feed";
import { FilterBar } from "@/components/filter-bar";
import { Metric, Panel } from "@/components/panel";
import { Shell } from "@/components/shell";
import { ThreatMap } from "@/components/threat-map";
import { Trends } from "@/components/trends";
import { withDb } from "@/lib/db/client";
import { colorForCount } from "@/lib/days";
import { familyLabel } from "@/lib/family";
import { filterQuery, parseFilters, toSearchParams } from "@/lib/filters";
import { categoryLabel, formatNumber, sourceLabel } from "@/lib/format";
import { layoutWeeks } from "@/lib/grid-layout";
import { InputError } from "@/lib/indicators";
import type { Dashboard, ProviderHealth } from "@/lib/queries/dashboard";
import { getDashboard } from "@/lib/queries/dashboard";
import { formatDay, formatUtc } from "@/lib/time";

export const dynamic = "force-dynamic";

const CATEGORY_COLOR: Record<string, string> = {
  reported_ioc: "#E10600",
  malware_distribution: "#C4841D",
  vulnerability_disclosure: "#4C7CB8",
  scanner_classification: "#3D9A6A",
  derived: "#929292",
};

function collected(providers: ProviderHealth[]): boolean {
  return providers.some((provider) => ["threatfox", "urlhaus", "cisa_kev"].includes(provider.id) && provider.lastSuccessAt);
}

function freshness(providers: ProviderHealth[]): string {
  return providers
    .filter((provider) => ["threatfox", "urlhaus", "cisa_kev", "geoip"].includes(provider.id))
    .map((provider) => {
      if (provider.status === "never") return `${provider.name} not collected`;
      if (provider.status === "failing") return `${provider.name} failing`;
      if (provider.status === "stale") return `${provider.name} stale · ${provider.age}`;
      return `${provider.name} ${provider.age}`;
    })
    .join("   ·   ");
}

function familyDetail(families: Record<string, number>): string {
  const parts = Object.entries(families)
    .sort((left, right) => right[1] - left[1])
    .map(([id, count]) => `${familyLabel(id)} ${count}`);
  return parts.join(", ");
}

function gridCells(data: Dashboard, filters: Parameters<typeof filterQuery>[0]): GridCell[] {
  return data.activity.days.map((day) => {
    const selected = filters.day === day.day;
    const detail =
      day.status === "none"
        ? "No successful collection covers this day. That is not evidence of zero activity."
        : day.status === "gap"
          ? "Collection succeeded on earlier and later days, but not on this one."
          : day.status === "zero"
            ? "A collection finished on this UTC day and stored no matching records."
            : `${formatNumber(day.count)} stored records. ${familyDetail(day.families)}`;
    const statusText =
      day.status === "count"
        ? `${day.count} records`
        : day.status === "zero"
          ? "zero records on a collected day"
          : day.status === "gap"
            ? "collection gap"
            : "outside collected coverage";
    return {
      day: day.day,
      count: day.count,
      status: day.status,
      color: day.status === "count" ? colorForCount(day.count, data.activity.breaks) : day.status === "zero" ? "#161616" : "#101010",
      href: filterQuery(filters, { day: selected ? null : day.day }),
      selected,
      label: `${formatDay(day.day)}, ${statusText}`,
      detail,
    };
  });
}

function Notice({ children }: { children: React.ReactNode }) {
  return <p className="border border-line bg-panel px-3 py-2 text-[13px] text-muted">{children}</p>;
}

export default async function ObservatoryPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = await searchParams;
  let filters;
  try {
    filters = parseFilters(toSearchParams(raw));
  } catch (error) {
    const message = error instanceof InputError ? error.message : "Those filters could not be read.";
    return (
      <Shell>
        <Notice>
          {message} <Link className="underline" href="/">Reset the observatory.</Link>
        </Notice>
      </Shell>
    );
  }

  let data: Dashboard;
  try {
    data = await withDb((db) => getDashboard(db, filters));
  } catch {
    return (
      <Shell freshness="Database unavailable">
        <Notice>The local database could not be read. From the project directory, run npm run migrate and reload this page.</Notice>
      </Shell>
    );
  }

  const hasCollection = collected(data.providers);
  const weeks = layoutWeeks(gridCells(data, filters));
  const windowLabel = `${formatUtc(filters.from)} to ${formatUtc(new Date(filters.to.getTime() - 1))}`;
  const delta = data.metrics.delta;
  const deltaNote = hasCollection
    ? `${delta > 0 ? "+" : ""}${formatNumber(delta)} records versus the previous window of the same length. This is a change in stored records, not a rate of attacks.`
    : "No successful collection yet.";

  return (
    <Shell freshness={freshness(data.providers)}>
      <div className="space-y-3">
        <FilterBar filters={filters} />
        {!hasCollection ? (
          <Notice>
            No collection has succeeded. Counts stay blank until <span className="font-mono text-ink">npm run ingest</span> stores a real feed.
            A blank chart is not a claim that nothing happened.
          </Notice>
        ) : null}
        {filters.source === "all" ? (
          <Notice>
            All sources are combined in this view. The total mixes reported indicators, malware-distribution URLs, and vulnerability
            disclosures. It is not a global attack count.
          </Notice>
        ) : (
          <p className="text-[12px] text-muted">
            Showing {sourceLabel(filters.source)} records from {windowLabel}. Other sources stay in their own categories.
          </p>
        )}

        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric
            label="Records in window"
            value={hasCollection ? formatNumber(data.metrics.records) : "—"}
            note={hasCollection ? deltaNote : "Run collection before reading this number."}
          />
          <Metric
            label="Distinct indicators"
            value={hasCollection ? formatNumber(data.metrics.distinctIndicators) : "—"}
            note="Unique type and normalized value inside the filter."
          />
          <Metric
            label="Sources collected"
            value={
              hasCollection
                ? formatNumber(data.providers.filter((provider) => provider.lastSuccessAt && provider.mode !== "on_demand").length)
                : "—"
            }
            note={
              hasCollection
                ? data.providers
                    .filter((provider) => provider.lastSuccessAt && provider.mode !== "on_demand")
                    .map((provider) => provider.name)
                    .join(", ")
                : "ThreatFox, URLhaus, and CISA KEV are collected separately."
            }
          />
          <Metric
            label="Latest collection"
            value={
              data.providers
                .filter((provider) => provider.lastSuccessAt)
                .sort((left, right) => Date.parse(right.lastSuccessAt ?? "") - Date.parse(left.lastSuccessAt ?? ""))[0]?.age ?? "—"
            }
            note="Age of the newest successful collection. The feed is stored, not a live stream."
          />
        </section>

        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.6fr)]">
          <Panel
            kicker="Activity"
            title="Records by UTC day"
            extra={<span className="font-mono text-[10px] uppercase tracking-wide text-muted">Select a day to filter</span>}
          >
            <ActivityGrid weeks={weeks} breaks={data.activity.breaks} />
            <p className="mt-3 text-[12px] leading-5 text-muted">
              Color tracks how many stored records share a UTC day. A hollow cell means collection did not cover that day. A dark cell
              means a collection finished and matched nothing. A hatch is a gap between successful collection days. None of those states
              proves an absence of attacks.
            </p>
            {data.activity.hours ? (
              <div className="mt-3">
                <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
                  {filters.day} by hour · <a className="underline" href={filterQuery(filters, { day: null })}>Clear day</a>
                </p>
                <div className="flex h-16 items-end gap-1">
                  {data.activity.hours.map((hour) => {
                    const peak = Math.max(1, ...data.activity.hours!.map((item) => item.count));
                    return (
                      <div key={hour.hour} className="flex h-full flex-1 flex-col justify-end" title={`${hour.hour}:00 UTC · ${hour.count}`}>
                        <span className="block bg-accent" style={{ height: `${(hour.count / peak) * 100}%`, minHeight: hour.count ? 2 : 0 }} />
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </Panel>
          <Panel kicker="Baseline" title="Deviation from recent days">
            <Trends series={data.trends.series} />
            <p className="mt-2 text-[12px] leading-5 text-muted">
              The grey line is a rolling median of up to 14 earlier days that were collected or confirmed empty. An amber point is a
              statistical jump above that baseline. It is not evidence of a coordinated attack. Days without coverage are left blank.
            </p>
            {data.trends.deviations.length > 0 ? (
              <div className="mt-2 text-[12px] text-muted">
                <p>{data.trends.deviations[data.trends.deviations.length - 1].rule}</p>
                <ul className="mt-1 space-y-1">
                  {data.trends.deviations.slice(-4).map((item) => (
                    <li key={item.day}>
                      <span className="font-mono text-ink">{item.day}</span> · {formatNumber(item.count)} records, median {item.median}.
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="mt-2 text-[12px] text-muted">No day in this window clears the deviation rule.</p>
            )}
          </Panel>
        </div>

        <Panel
          kicker="Geography"
          title="Network location of reported IP addresses"
          extra={
            <span className="font-mono text-[10px] uppercase tracking-wide text-muted">
              {hasCollection
                ? `${formatNumber(data.map.points.length)} of ${formatNumber(data.map.totalLocated)} located IPs`
                : "No locations"}
              {data.map.truncated ? " · capped" : ""}
            </span>
          }
        >
          <ThreatMap points={data.map.points} />
          <p className="mt-2 text-[12px] leading-5 text-muted">
            {hasCollection
              ? `${formatNumber(data.metrics.locatedIpRecords)} of ${formatNumber(data.metrics.ipRecords)} IP records in this filter have a cached network location. `
              : ""}
            Positions come from ip-api after collection. They describe the network the address is registered to, not an operator&apos;s
            location. Domains are not resolved. Clusters count records, not distinct attackers.
          </p>
        </Panel>

        <div className="grid gap-3 lg:grid-cols-3">
          <Panel kicker="Category" title="What kind of record">
            <Bars
              items={data.metrics.byCategory.map((item) => ({
                key: item.category,
                label: categoryLabel(item.category),
                count: item.count,
                color: CATEGORY_COLOR[item.category] ?? "#929292",
                href: filterQuery(filters, { category: item.category }),
              }))}
            />
          </Panel>
          <Panel kicker="Label" title="SignalTrace family heuristic">
            <Bars
              items={data.metrics.byFamily.map((item) => ({
                key: item.family,
                label: familyLabel(item.family),
                count: item.count,
                href: item.family === "unspecified" ? undefined : filterQuery(filters, { family: item.family }),
              }))}
            />
            <p className="mt-2 text-[12px] text-muted">Labels are derived by SignalTrace from malware names and tags. The source did not assign them.</p>
          </Panel>
          <Panel kicker="Country" title="IP network countries">
            <Bars
              items={data.countries.map((item) => ({
                key: item.code,
                label: item.name ? `${item.code} ${item.name}` : item.code,
                count: item.count,
                href: filterQuery(filters, { country: filters.country === item.code ? null : item.code }),
              }))}
            />
            <p className="mt-2 text-[12px] text-muted">Country of the IP&apos;s network location. Unlocated addresses are omitted.</p>
          </Panel>
        </div>

        <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_320px]">
          <Panel kicker="Records" title="Stored collection">
            <Feed rows={data.feed.rows} total={data.feed.total} filters={filters} />
          </Panel>
          <div className="space-y-3">
            <Panel kicker="Catalog" title="Recent KEV additions">
              {data.vulnerabilities.length === 0 ? (
                <p className="text-[13px] text-muted">The CISA catalog has not been stored.</p>
              ) : (
                <ul className="space-y-2">
                  {data.vulnerabilities.map((item) => (
                    <li key={item.cveId} className="border-b border-line pb-2 last:border-0">
                      <a className="font-mono text-[12px] underline decoration-line-strong underline-offset-2" href={`/investigate?q=${item.cveId}`}>
                        {item.cveId}
                      </a>
                      <p className="text-[12px] text-muted">
                        {item.dateAdded} · {item.vendor} {item.product}
                      </p>
                      <p className="text-[12px] text-ink">{item.name}</p>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-2 text-[12px] text-muted">Date added to the catalog. Not the date of an intrusion observed here.</p>
            </Panel>
            <Panel kicker="Collection" title="Provider health">
              <ul className="space-y-2">
                {data.providers.map((provider) => (
                  <li key={provider.id} className="grid grid-cols-[1fr_auto] gap-2 text-[12px]">
                    <span>
                      <span className="text-ink">{provider.name}</span>
                      <span className="mt-0.5 block text-muted">
                        {provider.status}
                        {provider.lastError ? ` · ${provider.lastError}` : ""}
                      </span>
                    </span>
                    <span className="font-mono text-[11px] text-muted">{provider.age}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-[12px] text-muted">
                Runs in this window:{" "}
                {data.coverage.map((item) => `${sourceLabel(item.providerId)} ${item.success} ok / ${item.failed} failed`).join(" · ")}
              </p>
            </Panel>
          </div>
        </div>
      </div>
    </Shell>
  );
}
