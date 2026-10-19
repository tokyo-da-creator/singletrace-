import { z } from "zod";
import { requestJson, type RequestOptions } from "@/lib/http";
import { normalizeCve } from "@/lib/indicators";
import { ProviderError } from "@/lib/types";

const nvdSchema = z.object({
  vulnerabilities: z
    .array(
      z.object({
        cve: z.object({
          id: z.string(),
          published: z.string().optional(),
          lastModified: z.string().optional(),
          vulnStatus: z.string().optional(),
          descriptions: z.array(z.object({ lang: z.string(), value: z.string() })).optional(),
          metrics: z.record(z.unknown()).optional(),
        }),
      }),
    )
    .optional(),
});

export type NvdEnrichment = {
  cveId: string;
  status: string | null;
  published: string | null;
  lastModified: string | null;
  description: string | null;
  cvssVersion: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  raw: unknown;
};

type CvssPick = { version: string; score: number; severity: string | null };

function pickCvss(metrics: Record<string, unknown> | undefined): CvssPick | null {
  if (!metrics) return null;
  const groups: Array<[string, string]> = [
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV2", "2.0"],
  ];
  for (const [key, version] of groups) {
    const rows = metrics[key];
    if (!Array.isArray(rows) || rows.length === 0) continue;
    const first = rows[0];
    if (!first || typeof first !== "object") continue;
    const data = (first as { cvssData?: { baseScore?: unknown; baseSeverity?: unknown } }).cvssData;
    const score = data?.baseScore;
    if (typeof score !== "number") continue;
    const severity = data?.baseSeverity ?? (first as { baseSeverity?: unknown }).baseSeverity;
    return { version, score, severity: typeof severity === "string" ? severity : null };
  }
  return null;
}

function nvdTime(value: string | undefined): string | null {
  if (!value) return null;
  const withZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  const parsed = Date.parse(withZone);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

export function parseNvdCve(payload: unknown, expected: string): NvdEnrichment {
  const parsed = nvdSchema.safeParse(payload);
  if (!parsed.success) throw new ProviderError("NVD response did not match the expected schema.");
  const row = parsed.data.vulnerabilities?.find((item) => item.cve.id.toUpperCase() === expected) ?? parsed.data.vulnerabilities?.[0];
  if (!row) throw new ProviderError(`NVD has no CVE record for ${expected}.`);
  const description = row.cve.descriptions?.find((item) => item.lang === "en")?.value ?? row.cve.descriptions?.[0]?.value ?? null;
  const cvss = pickCvss(row.cve.metrics);
  return {
    cveId: row.cve.id.toUpperCase(),
    status: row.cve.vulnStatus ?? null,
    published: nvdTime(row.cve.published),
    lastModified: nvdTime(row.cve.lastModified),
    description,
    cvssVersion: cvss?.version ?? null,
    cvssScore: cvss?.score ?? null,
    cvssSeverity: cvss?.severity ?? null,
    raw: row.cve,
  };
}

let nvdQueue: Promise<unknown> = Promise.resolve();
let nvdLastCall = 0;

export function fetchNvdCve(cveId: string, options: RequestOptions = {}): Promise<unknown> {
  const cve = normalizeCve(cveId);
  if (!cve) return Promise.reject(new ProviderError("NVD lookups require a CVE identifier."));
  const run = nvdQueue.then(async () => {
    const spacing = process.env.NVD_API_KEY ? 700 : 6500;
    const wait = Math.max(0, spacing - (Date.now() - nvdLastCall));
    if (wait > 0) {
      await (options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms))))(wait);
    }
    nvdLastCall = Date.now();
    const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : undefined;
    return requestJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, {
      ...options,
      headers,
      timeoutMs: options.timeoutMs ?? 30000,
      retries: options.retries ?? 2,
    });
  });
  nvdQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}
