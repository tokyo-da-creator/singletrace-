import type { Database } from "@/lib/db/client";
import { fetchGreyNoiseCommunity, type GreyNoiseCommunity } from "@/lib/providers/greynoise";
import { fetchNvdCve, parseNvdCve, type NvdEnrichment } from "@/lib/providers/nvd";
import { hostFromUrl, isPublicIp, parseIndicator, type ParsedIndicator } from "@/lib/indicators";
import { asDay, asIso, asNumber } from "@/lib/time";
import { mapObservation, type StoredObservation } from "@/lib/queries/rows";

export type Investigation = {
  indicator: ParsedIndicator;
  facts: StoredObservation[];
  sameLabel: StoredObservation[];
  vulnerability: {
    cveId: string;
    inKev: boolean;
    removedAt: string | null;
    vendor: string | null;
    product: string | null;
    name: string | null;
    description: string | null;
    requiredAction: string | null;
    dateAdded: string | null;
    dueDate: string | null;
    knownRansomware: string | null;
    cwes: string | null;
    notes: string | null;
  } | null;
  nvd: NvdEnrichment | null;
  nvdError: string | null;
  greyNoise: GreyNoiseCommunity | null;
  greyNoiseError: string | null;
  geo: {
    countryCode: string | null;
    countryName: string | null;
    region: string | null;
    city: string | null;
    latitude: number | null;
    longitude: number | null;
    asn: string | null;
    org: string | null;
    precision: string | null;
    lookedUpAt: string | null;
    status: string | null;
  } | null;
  notes: string[];
};

async function cached<T>(
  db: Database,
  providerId: string,
  key: string,
  maxAgeMs: number,
  load: () => Promise<T>,
): Promise<T> {
  const existing = await db.query<{ fetched_at: string; body: unknown; error: string | null }>(
    `SELECT fetched_at, body, error FROM enrichment_cache WHERE provider_id = ? AND cache_key = ?`,
    [providerId, key],
  );
  const row = existing[0];
  if (row && Date.now() - Date.parse(asIso(row.fetched_at) ?? "") < maxAgeMs && row.body) {
    const body = typeof row.body === "string" ? (JSON.parse(row.body) as T) : (row.body as T);
    return body;
  }
  try {
    const value = await load();
    await db.query(
      `INSERT INTO enrichment_cache (provider_id, cache_key, fetched_at, body, error)
       VALUES (?, ?, ?, ?::jsonb, NULL)
       ON CONFLICT (provider_id, cache_key) DO UPDATE SET
         fetched_at = EXCLUDED.fetched_at, body = EXCLUDED.body, error = NULL`,
      [providerId, key, new Date().toISOString(), JSON.stringify(value)],
    );
    await db.query(`UPDATE providers SET last_success_at = ?, last_attempt_at = ?, last_error = NULL WHERE id = ?`, [
      new Date().toISOString(),
      new Date().toISOString(),
      providerId,
    ]);
    return value;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Lookup failed.";
    await db.query(
      `INSERT INTO enrichment_cache (provider_id, cache_key, fetched_at, body, error)
       VALUES (?, ?, ?, NULL, ?)
       ON CONFLICT (provider_id, cache_key) DO UPDATE SET
         fetched_at = EXCLUDED.fetched_at, error = EXCLUDED.error`,
      [providerId, key, new Date().toISOString(), message],
    );
    await db.query(`UPDATE providers SET last_attempt_at = ?, last_error = ? WHERE id = ?`, [
      new Date().toISOString(),
      message,
      providerId,
    ]);
    throw error;
  }
}

async function loadFacts(db: Database, indicator: ParsedIndicator): Promise<StoredObservation[]> {
  const host = indicator.kind === "url" ? hostFromUrl(indicator.normalized) : null;
  const rows = await db.query<Record<string, unknown>>(
    `SELECT * FROM observations
     WHERE is_simulated = false
       AND (
         indicator_normalized = ?
         OR indicator_value = ?
         OR source_record_id = ?
         OR (?::text IS NOT NULL AND indicator_normalized = ?)
       )
     ORDER BY observed_at DESC
     LIMIT 50`,
    [indicator.normalized, indicator.value, indicator.normalized, host?.value ?? null, host?.value ?? null],
  );
  return rows.map((row) => mapObservation(row));
}

export async function investigate(db: Database, raw: string, options?: { fetch?: typeof fetch; sleep?: (ms: number) => Promise<void> }): Promise<Investigation> {
  const indicator = parseIndicator(raw);
  const facts = await loadFacts(db, indicator);
  const notes = [
    "Rows below are limited to what SignalTrace has collected or cached. Absence is not a clean bill of health.",
  ];
  if (indicator.kind === "ip" && indicator.routable === false) {
    notes.push("This IP is not a public routable address. It was not sent to a geolocation or scanner service.");
  }
  if (indicator.kind === "url") {
    notes.push("The URL was parsed and matched locally. SignalTrace did not request it.");
  }

  let sameLabel: StoredObservation[] = [];
  const family = facts.find((fact) => fact.malwareFamily)?.malwareFamily;
  if (family) {
    const related = await db.query<Record<string, unknown>>(
      `SELECT * FROM observations
       WHERE is_simulated = false
         AND malware_family = ?
         AND COALESCE(indicator_normalized, '') <> ?
       ORDER BY observed_at DESC
       LIMIT 8`,
      [family, indicator.normalized],
    );
    sameLabel = related.map((row) => mapObservation(row));
    notes.push("Indicators with the same malware label share a source label only. That is not evidence of one operator.");
  }

  let vulnerability: Investigation["vulnerability"] = null;
  let nvd: NvdEnrichment | null = null;
  let nvdError: string | null = null;
  if (indicator.kind === "cve") {
    const rows = await db.query<Record<string, unknown>>(`SELECT * FROM vulnerabilities WHERE cve_id = ?`, [indicator.normalized]);
    const row = rows[0];
    if (row) {
      vulnerability = {
        cveId: String(row.cve_id),
        inKev: row.catalog_version != null && row.removed_from_catalog_at == null,
        removedAt: asIso(row.removed_from_catalog_at),
        vendor: (row.vendor as string | null) ?? null,
        product: (row.product as string | null) ?? null,
        name: (row.name as string | null) ?? null,
        description: (row.description as string | null) ?? null,
        requiredAction: (row.required_action as string | null) ?? null,
        dateAdded: asDay(row.date_added),
        dueDate: asDay(row.due_date),
        knownRansomware: (row.known_ransomware as string | null) ?? null,
        cwes: (row.cwes as string | null) ?? null,
        notes: (row.notes as string | null) ?? null,
      };
    }
    const cachedNvd = row?.nvd_fetched_at && Date.now() - Date.parse(asIso(row.nvd_fetched_at) ?? "") < 7 * 86400000;
    if (cachedNvd && row?.nvd_description) {
      nvd = {
        cveId: indicator.normalized,
        status: (row.nvd_status as string | null) ?? null,
        published: asIso(row.nvd_published),
        lastModified: asIso(row.nvd_last_modified),
        description: (row.nvd_description as string | null) ?? null,
        cvssVersion: (row.cvss_version as string | null) ?? null,
        cvssScore: asNumber(row.cvss_score),
        cvssSeverity: (row.cvss_severity as string | null) ?? null,
        raw: row.raw_nvd ?? {},
      };
    } else {
      try {
        const payload = await cached(db, "nvd", indicator.normalized, 7 * 86400000, () =>
          fetchNvdCve(indicator.normalized, { fetch: options?.fetch, sleep: options?.sleep }),
        );
        nvd = parseNvdCve(payload, indicator.normalized);
        await db.query(
          `INSERT INTO vulnerabilities (
            cve_id, nvd_status, nvd_published, nvd_last_modified, cvss_version, cvss_score, cvss_severity,
            nvd_description, nvd_fetched_at, collected_at, raw_nvd, reference_url
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
          ON CONFLICT (cve_id) DO UPDATE SET
            nvd_status = EXCLUDED.nvd_status,
            nvd_published = EXCLUDED.nvd_published,
            nvd_last_modified = EXCLUDED.nvd_last_modified,
            cvss_version = EXCLUDED.cvss_version,
            cvss_score = EXCLUDED.cvss_score,
            cvss_severity = EXCLUDED.cvss_severity,
            nvd_description = EXCLUDED.nvd_description,
            nvd_fetched_at = EXCLUDED.nvd_fetched_at,
            raw_nvd = EXCLUDED.raw_nvd`,
          [
            indicator.normalized,
            nvd.status,
            nvd.published,
            nvd.lastModified,
            nvd.cvssVersion,
            nvd.cvssScore,
            nvd.cvssSeverity,
            nvd.description,
            new Date().toISOString(),
            new Date().toISOString(),
            JSON.stringify(nvd.raw ?? {}),
            `https://nvd.nist.gov/vuln/detail/${indicator.normalized}`,
          ],
        );
      } catch (error) {
        nvdError = error instanceof Error ? error.message : "NVD lookup failed.";
      }
    }
  }

  let greyNoise: GreyNoiseCommunity | null = null;
  let greyNoiseError: string | null = null;
  if (indicator.kind === "ip" && indicator.routable && isPublicIp(indicator.normalized)) {
    if (!process.env.GREYNOISE_API_KEY) {
      greyNoiseError = "GREYNOISE_API_KEY is not set, so no scanner classification was requested.";
    } else {
      try {
        greyNoise = await cached(db, "greynoise", indicator.normalized, 86400000, () =>
          fetchGreyNoiseCommunity(indicator.normalized, { fetch: options?.fetch, sleep: options?.sleep }),
        );
      } catch (error) {
        greyNoiseError = error instanceof Error ? error.message : "GreyNoise lookup failed.";
      }
    }
  }

  let geo: Investigation["geo"] = null;
  if (indicator.kind === "ip") {
    const rows = await db.query<Record<string, unknown>>(`SELECT * FROM geo_cache WHERE ip = ?`, [indicator.normalized]);
    const row = rows[0];
    if (row) {
      geo = {
        countryCode: (row.country_code as string | null) ?? null,
        countryName: (row.country_name as string | null) ?? null,
        region: (row.region as string | null) ?? null,
        city: (row.city as string | null) ?? null,
        latitude: asNumber(row.latitude),
        longitude: asNumber(row.longitude),
        asn: (row.asn as string | null) ?? null,
        org: (row.org as string | null) ?? null,
        precision: (row.precision as string | null) ?? null,
        lookedUpAt: asIso(row.looked_up_at),
        status: (row.status as string | null) ?? null,
      };
    }
  }

  return { indicator, facts, sameLabel, vulnerability, nvd, nvdError, greyNoise, greyNoiseError, geo, notes };
}
