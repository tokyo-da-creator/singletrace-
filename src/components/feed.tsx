import Link from "next/link";
import { filterQuery, type Filters } from "@/lib/filters";
import { categoryLabel, formatNumber, kindLabel, shortIndicator, sourceLabel } from "@/lib/format";
import type { ObservationRow } from "@/lib/queries/dashboard";
import { safeReference } from "@/lib/security";
import { formatUtc } from "@/lib/time";

function canonicalEvidence(row: ObservationRow): string | null {
  if (row.providerId === "threatfox") return `https://threatfox.abuse.ch/ioc/${row.sourceRecordId}/`;
  if (row.providerId === "urlhaus") return row.referenceUrl ?? `https://urlhaus.abuse.ch/url/${row.sourceRecordId}/`;
  if (row.providerId === "cisa_kev" && row.indicatorNormalized) return `https://nvd.nist.gov/vuln/detail/${row.indicatorNormalized}`;
  return row.referenceUrl;
}

function Evidence({ url }: { url: string | null }) {
  const safe = safeReference(url);
  if (!safe) return <span className="text-muted">—</span>;
  if (safe.kind === "text") return <span className="text-muted">Unlinked reference</span>;
  return (
    <a href={safe.href} title={safe.href} rel="noreferrer noopener" className="underline decoration-line-strong underline-offset-2">
      source page
    </a>
  );
}

export function Feed({ rows, total, filters }: { rows: ObservationRow[]; total: number; filters: Filters }) {
  const pages = Math.max(1, Math.ceil(total / filters.pageSize));
  const start = total === 0 ? 0 : (filters.page - 1) * filters.pageSize + 1;
  const end = Math.min(total, filters.page * filters.pageSize);
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2 text-[12px] text-muted">
        <p>
          {total === 0 ? "No records match this filter." : `Showing ${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(total)} records.`}
        </p>
        <p>Ordered by source time. This is a stored collection, not a live stream.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[920px] table-fixed border-collapse text-left text-[12.5px]">
          <caption className="sr-only">Stored threat records for the current filter</caption>
          <colgroup>
            <col className="w-[148px]" />
            <col className="w-[118px]" />
            <col className="w-[24%]" />
            <col />
            <col className="w-[92px]" />
            <col className="w-[132px]" />
            <col className="w-[118px]" />
          </colgroup>
          <thead>
            <tr className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
              {["Time (UTC)", "Kind", "Indicator", "Context", "Place", "Source", "Evidence"].map((heading) => (
                <th key={heading} className="border-b border-line px-2 py-2 font-medium">
                  {heading}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-2 py-6 text-muted">
                  Nothing stored for this filter. If collection has not run, use <span className="font-mono text-ink">npm run ingest</span>.
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const indicator = row.indicatorNormalized ?? row.indicatorValue;
                return (
                  <tr key={row.id} className="align-top">
                    <td className="border-b border-line px-2 py-2 font-mono text-[11px] whitespace-nowrap">{formatUtc(row.observedAt)}</td>
                    <td className="border-b border-line px-2 py-2">
                      <span className="font-mono text-[10px] uppercase tracking-wide text-muted">{kindLabel(row.recordKind)}</span>
                      <span className="mt-1 block text-muted">{categoryLabel(row.category)}</span>
                    </td>
                    <td className="border-b border-line px-2 py-2">
                      {indicator ? (
                        <Link href={`/investigate?q=${encodeURIComponent(indicator)}`} className="block break-all font-mono text-[12px] underline decoration-line-strong underline-offset-2" title={row.indicatorValue ?? indicator}>
                          {shortIndicator(indicator, 42)}
                        </Link>
                      ) : (
                        "—"
                      )}
                      <span className="mt-1 block text-muted">{row.eventType}</span>
                    </td>
                    <td className="max-w-[280px] border-b border-line px-2 py-2 text-muted">{row.summary}</td>
                    <td className="border-b border-line px-2 py-2 text-muted">
                      {row.countryCode ? (
                        <>
                          <span className="font-mono text-ink">{row.countryCode}</span>
                          <span className="mt-1 block">{row.geoPrecision ? `${row.geoPrecision} estimate` : "country only"}</span>
                        </>
                      ) : (
                        "Not geolocated"
                      )}
                    </td>
                    <td className="border-b border-line px-2 py-2">
                      <span>{sourceLabel(row.providerId)}</span>
                      <span className="mt-1 block font-mono text-[11px] text-muted">{row.sourceRecordId}</span>
                      {row.confidence != null ? (
                        <span className="mt-1 block text-muted">
                          Confidence {row.confidence}
                          {row.confidenceOrigin ? ` from ${row.confidenceOrigin}` : ""}
                        </span>
                      ) : null}
                    </td>
                    <td className="border-b border-line px-2 py-2">
                      <Evidence url={canonicalEvidence(row)} />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {pages > 1 ? (
        <div className="mt-3 flex gap-2 text-[12px]">
          {filters.page > 1 ? <a className="border border-line-strong px-2 py-1" href={filterQuery(filters, { page: String(filters.page - 1) })}>Previous</a> : null}
          {filters.page < pages ? <a className="border border-line-strong px-2 py-1" href={filterQuery(filters, { page: String(filters.page + 1) })}>Next</a> : null}
        </div>
      ) : null}
    </div>
  );
}
