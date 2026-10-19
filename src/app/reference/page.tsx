import type { Metadata } from "next";
import { Panel } from "@/components/panel";
import { Shell } from "@/components/shell";

export const metadata: Metadata = { title: "API" };

const ENDPOINTS = [
  ["GET /api/v1/health", "Provider status and freshness. No record bodies."],
  ["GET /api/v1/metrics", "Counts for the current filters. Records, not attacks."],
  ["GET /api/v1/activity", "Daily grid cells, hour breakdown, and color breaks."],
  ["GET /api/v1/trends", "Daily series, rolling median, and statistical deviations."],
  ["GET /api/v1/map", "Located public-IP points, capped at 2,500."],
  ["GET /api/v1/observations", "Paginated stored records."],
  ["GET /api/v1/indicators?q=", "Indicator search across stored rows."],
  ["GET /api/v1/investigate?q=", "Local records plus on-demand NVD or GreyNoise when configured."],
  ["GET /api/v1/providers", "Catalog and collection health."],
  ["GET /api/v1/vulnerabilities", "Stored CVE rows. This route does not call NVD."],
  ["GET /api/v1/vulnerabilities/{cve}", "One stored CVE. Unknown identifiers return found: false."],
  ["POST /api/v1/ingest", "Runs collection when INGEST_SECRET is set. Disabled otherwise."],
];

export default function ReferencePage() {
  return (
    <Shell>
      <div className="mx-auto max-w-3xl space-y-3">
        <Panel kicker="v1" title="Internal HTTP API">
          <p className="text-[13px] leading-6 text-muted">
            Responses use <span className="font-mono text-ink">{`{ data, meta: { generatedAt } }`}</span>. Failures use{" "}
            <span className="font-mono text-ink">{`{ error: { code, message } }`}</span>. Messages do not include SQL or credentials.
            Read routes are limited to 120 requests per minute per client address. Investigation is limited to 30. The limiter is in
            memory and applies to one server process.
          </p>
          <ul className="mt-3 space-y-2">
            {ENDPOINTS.map(([path, text]) => (
              <li key={path} className="text-[13px]">
                <p className="font-mono text-[12px] text-ink">{path}</p>
                <p className="text-muted">{text}</p>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel kicker="Filters" title="Query parameters">
          <div className="space-y-2 text-[13px] leading-6 text-muted">
            <p>
              <span className="font-mono text-ink">range</span> is 24h, 7d, 30d, 90d, 26w, or custom. Custom requires{" "}
              <span className="font-mono text-ink">from</span> and <span className="font-mono text-ink">to</span> as UTC dates. The end
              date is inclusive. The span cannot exceed 400 days. The default range is 26 weeks and the default source is threatfox.
            </p>
            <p>
              <span className="font-mono text-ink">source</span> is threatfox, urlhaus, cisa_kev, or all.{" "}
              <span className="font-mono text-ink">category</span> is one of the stored categories.{" "}
              <span className="font-mono text-ink">family</span> is the derived label.{" "}
              <span className="font-mono text-ink">country</span> is a two-letter code.{" "}
              <span className="font-mono text-ink">q</span> is a substring of at most 200 characters.{" "}
              <span className="font-mono text-ink">day</span> must fall inside the range.{" "}
              <span className="font-mono text-ink">page</span> is 1–200 and <span className="font-mono text-ink">pageSize</span> is 1–100.
              Sort is time_desc, time_asc, or confidence_desc.
            </p>
            <p>
              A map box needs north, south, east, and west together. When west is greater than east, the box crosses the antimeridian.
            </p>
          </div>
        </Panel>
        <Panel kicker="Collection" title="POST /api/v1/ingest">
          <div className="space-y-2 text-[13px] leading-6 text-muted">
            <p>
              If INGEST_SECRET is unset, the route responds 404 and does not collect. Send the secret in the{" "}
              <span className="font-mono text-ink">x-ingest-secret</span> header. Optional{" "}
              <span className="font-mono text-ink">provider</span> is threatfox, urlhaus, cisa_kev, or geoip.{" "}
              <span className="font-mono text-ink">force=1</span> bypasses the minimum interval. The command-line collector does not use
              this secret.
            </p>
            <p className="font-mono text-[12px] text-ink">curl -X POST -H &quot;x-ingest-secret: $INGEST_SECRET&quot; http://127.0.0.1:3000/api/v1/ingest</p>
          </div>
        </Panel>
        <Panel kicker="Errors" title="Status codes">
          <ul className="space-y-1 text-[13px] text-muted">
            <li>400 invalid_input — a filter or indicator failed validation.</li>
            <li>401 unauthorized — the collection secret was rejected.</li>
            <li>404 not_found — HTTP collection is disabled, or a route does not exist.</li>
            <li>429 rate_limited — Retry-After is set in seconds.</li>
            <li>500 internal_error — the operation failed. The body has no internals.</li>
          </ul>
        </Panel>
      </div>
    </Shell>
  );
}
