import type { Metadata } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import { Panel } from "@/components/panel";
import { Shell } from "@/components/shell";
import { withDb } from "@/lib/db/client";
import { categoryLabel, kindLabel, sourceLabel } from "@/lib/format";
import { InputError } from "@/lib/indicators";
import type { Investigation } from "@/lib/queries/investigate";
import { investigate } from "@/lib/queries/investigate";
import { investigateLimiter } from "@/lib/rate-limit";
import { clientKey, safeReference } from "@/lib/security";
import { formatUtc } from "@/lib/time";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Investigate" };

function Evidence({ url }: { url: string | null | undefined }) {
  const safe = safeReference(url);
  if (!safe) return <span className="text-muted">—</span>;
  if (safe.kind === "text") return <span className="text-muted">Reference host is not linked</span>;
  return (
    <a href={safe.href} rel="noreferrer noopener" className="underline decoration-line-strong underline-offset-2">
      {safe.href.replace(/^https?:\/\//, "")}
    </a>
  );
}

function Fact({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="border-b border-line py-1.5">
      <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-[13px] text-ink">{value == null || value === "" ? "—" : String(value)}</dd>
    </div>
  );
}

export default async function InvestigatePage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string | string[] }>;
}) {
  const params = await searchParams;
  const q = (Array.isArray(params.q) ? params.q[0] : params.q)?.trim() ?? "";

  let result: Investigation | null = null;
  let message: string | null = null;
  if (q) {
    const headerStore = await headers();
    const decision = investigateLimiter(clientKey(headerStore));
    if (!decision.ok) {
      message = `Too many investigations from this client. Wait ${decision.retryAfter} seconds.`;
    } else {
      try {
        result = await withDb((db) => investigate(db, q));
      } catch (error) {
        message = error instanceof InputError ? error.message : "The investigation could not be completed.";
      }
    }
  }

  return (
    <Shell>
      <form action="/investigate" className="mb-3 flex flex-wrap gap-2 border border-line bg-panel px-3 py-2" role="search">
        <label className="flex w-full min-w-0 flex-1 flex-col gap-1 text-[11px] text-muted sm:min-w-[240px]">
          Indicator
          <input name="q" type="search" defaultValue={q} placeholder="IP, domain, URL, hash, or CVE" className="w-full min-w-0 font-mono" autoComplete="off" spellCheck={false} />
        </label>
        <button type="submit" className="self-end">
          Investigate
        </button>
      </form>

      {!q ? (
        <p className="text-[13px] text-muted">
          Look up an indicator already stored by collection, or a CVE for catalog and NVD context. SignalTrace does not fetch submitted URLs,
          resolve domains, or execute files.
        </p>
      ) : null}
      {message ? <p className="border border-line bg-panel px-3 py-2 text-[13px] text-amber">{message}</p> : null}

      {result ? (
        <div className="space-y-3">
          <Panel kicker={result.indicator.kind} title={result.indicator.normalized}>
            <dl className="grid gap-x-6 sm:grid-cols-2">
              <Fact label="Submitted value" value={result.indicator.value} />
              <Fact label="Normalized" value={result.indicator.normalized} />
              <Fact label="Port" value={result.indicator.port} />
              <Fact label="Publicly routable" value={result.indicator.routable == null ? "Not an IP" : result.indicator.routable ? "Yes" : "No"} />
            </dl>
            <ul className="mt-3 space-y-1 text-[12px] leading-5 text-muted">
              {result.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </Panel>

          <div className="grid gap-3 lg:grid-cols-2">
            <Panel kicker="Source fact" title="CISA KEV">
              {result.vulnerability ? (
                <dl>
                  <Fact label="In current catalog" value={result.vulnerability.inKev ? "Yes" : "No"} />
                  <Fact label="Removed" value={result.vulnerability.removedAt ? formatUtc(result.vulnerability.removedAt) : null} />
                  <Fact label="Vendor / product" value={[result.vulnerability.vendor, result.vulnerability.product].filter(Boolean).join(" · ")} />
                  <Fact label="Name" value={result.vulnerability.name} />
                  <Fact label="Date added" value={result.vulnerability.dateAdded} />
                  <Fact label="Due date" value={result.vulnerability.dueDate} />
                  <Fact label="Known ransomware use" value={result.vulnerability.knownRansomware} />
                  <Fact label="CWEs" value={result.vulnerability.cwes} />
                  <Fact label="Required action" value={result.vulnerability.requiredAction} />
                  <Fact label="Description" value={result.vulnerability.description} />
                </dl>
              ) : (
                <p className="text-[13px] text-muted">
                  {result.indicator.kind === "cve"
                    ? "This CVE is not in the stored KEV catalog. That does not mean it is unused."
                    : "KEV context applies to CVE identifiers."}
                </p>
              )}
            </Panel>
            <Panel kicker="Source fact" title="NIST NVD">
              {result.nvd ? (
                <dl>
                  <Fact label="Status" value={result.nvd.status} />
                  <Fact label="Published" value={result.nvd.published ? formatUtc(result.nvd.published) : null} />
                  <Fact label="Last modified" value={result.nvd.lastModified ? formatUtc(result.nvd.lastModified) : null} />
                  <Fact label="CVSS" value={result.nvd.cvssScore != null ? `${result.nvd.cvssScore} (${result.nvd.cvssSeverity ?? "unspecified"}) v${result.nvd.cvssVersion}` : null} />
                  <Fact label="Description" value={result.nvd.description} />
                </dl>
              ) : (
                <p className="text-[13px] text-muted">{result.nvdError ?? "NVD is queried only for CVE identifiers, and only when this page is opened."}</p>
              )}
              <p className="mt-2 text-[12px] text-muted">
                Timestamps that NVD returns without a timezone are stored as UTC. A CVSS score is NVD&apos;s severity rating, not proof of exploitation here.
                <span className="mt-1 block">
                  <Evidence url={result.indicator.kind === "cve" ? `https://nvd.nist.gov/vuln/detail/${result.indicator.normalized}` : null} />
                </span>
              </p>
            </Panel>
          </div>

          <div className="grid gap-3 lg:grid-cols-2">
            <Panel kicker="Enrichment" title="GreyNoise community">
              {result.greyNoise ? (
                <dl>
                  <Fact label="Classification" value={result.greyNoise.classification} />
                  <Fact label="Noise" value={result.greyNoise.noise == null ? null : result.greyNoise.noise ? "Seen scanning in the community dataset" : "Not flagged as noise"} />
                  <Fact label="RIOT" value={result.greyNoise.riot == null ? null : result.greyNoise.riot ? "Listed as a common business service" : "Not in the RIOT dataset"} />
                  <Fact label="Name" value={result.greyNoise.name} />
                  <Fact label="Last seen" value={result.greyNoise.last_seen} />
                  <Fact label="Message" value={result.greyNoise.message} />
                </dl>
              ) : (
                <p className="text-[13px] text-muted">{result.greyNoiseError ?? "Scanner context is requested only for a public IP, and only when GREYNOISE_API_KEY is set."}</p>
              )}
              <p className="mt-2 text-[12px] text-muted">
                Classification describes internet-scanning context. It is not proof of a successful intrusion.
                {result.greyNoise?.link ? (
                  <span className="mt-1 block">
                    <Evidence url={result.greyNoise.link} />
                  </span>
                ) : null}
              </p>
            </Panel>
            <Panel kicker="Enrichment" title="Cached network location">
              {result.geo ? (
                <dl>
                  <Fact label="Status" value={result.geo.status} />
                  <Fact label="Precision" value={result.geo.precision} />
                  <Fact label="Place" value={[result.geo.city, result.geo.region, result.geo.countryName].filter(Boolean).join(", ")} />
                  <Fact label="Country code" value={result.geo.countryCode} />
                  <Fact label="Coordinates" value={result.geo.latitude != null ? `${result.geo.latitude}, ${result.geo.longitude}` : null} />
                  <Fact label="ASN / org" value={[result.geo.asn, result.geo.org].filter(Boolean).join(" · ")} />
                  <Fact label="Looked up" value={result.geo.lookedUpAt ? formatUtc(result.geo.lookedUpAt) : null} />
                </dl>
              ) : (
                <p className="text-[13px] text-muted">No cached geolocation. Collection looks up public IP literals. This page does not send a new lookup.</p>
              )}
              <p className="mt-2 text-[12px] text-muted">A coordinate is the network location returned by ip-api. It is not a threat actor&apos;s physical location.</p>
            </Panel>
          </div>

          <Panel kicker="Stored records" title="Observations in this collection">
            {result.facts.length === 0 ? (
              <p className="text-[13px] text-muted">No stored row matches this indicator. Absence from the collection is not a clean result.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left text-[12.5px]">
                  <caption className="sr-only">Stored observations for this indicator</caption>
                  <thead>
                    <tr className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
                      {["Time (UTC)", "Kind", "Source", "Context", "Evidence"].map((heading) => (
                        <th key={heading} className="border-b border-line px-2 py-2 font-medium">
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.facts.map((fact) => (
                      <tr key={fact.id} className="align-top">
                        <td className="border-b border-line px-2 py-2 font-mono text-[11px]">{formatUtc(fact.observedAt)}</td>
                        <td className="border-b border-line px-2 py-2 text-muted">
                          {kindLabel(fact.recordKind)}
                          <span className="mt-1 block">{categoryLabel(fact.category)}</span>
                        </td>
                        <td className="border-b border-line px-2 py-2">
                          {sourceLabel(fact.providerId)}
                          <span className="mt-1 block font-mono text-[11px] text-muted">{fact.sourceRecordId}</span>
                        </td>
                        <td className="border-b border-line px-2 py-2 text-muted">{fact.summary}</td>
                        <td className="border-b border-line px-2 py-2">
                          <Evidence url={fact.referenceUrl} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel kicker="Not a relationship claim" title="Same malware label">
            {result.sameLabel.length === 0 ? (
              <p className="text-[13px] text-muted">No other stored row shares a malware name from the source. SignalTrace does not invent related infrastructure.</p>
            ) : (
              <ul className="space-y-2">
                {result.sameLabel.map((row) => (
                  <li key={row.id} className="text-[13px]">
                    <Link href={`/investigate?q=${encodeURIComponent(row.indicatorNormalized ?? row.indicatorValue ?? "")}`} className="font-mono underline decoration-line-strong underline-offset-2">
                      {row.indicatorNormalized ?? row.indicatorValue}
                    </Link>
                    <span className="ml-2 text-muted">
                      {row.malwareFamily} · {formatUtc(row.observedAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      ) : null}
    </Shell>
  );
}
