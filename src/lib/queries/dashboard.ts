import { baselineFor, findDeviations } from "@/lib/baseline";
import type { Database } from "@/lib/db/client";
import { dayStatus, quantileBreaks, type DayStatus } from "@/lib/days";
import { type Filters, observationWhere, sortSql, windowDays } from "@/lib/filters";
import { InputError, normalizeCve } from "@/lib/indicators";
import { PROVIDER_CATALOG } from "@/lib/providers/catalog";
import { ageLabel, asDay, asInt, asIso, asNumber } from "@/lib/time";

export type ProviderHealth = {
  id: string;
  name: string;
  mode: string;
  measures: string;
  attribution: string;
  homepage: string;
  retentionNote: string;
  requiresKey: boolean;
  configured: boolean;
  status: "ok" | "stale" | "failing" | "never" | "unconfigured" | "on_demand";
  lastSuccessAt: string | null;
  lastAttemptAt: string | null;
  lastError: string | null;
  sourceUpdatedAt: string | null;
  lastFetched: number | null;
  age: string;
};

export type ObservationRow = {
  id: string;
  providerId: string;
  sourceRecordId: string;
  recordKind: string;
  category: string;
  eventType: string;
  observedAt: string;
  indicatorType: string | null;
  indicatorValue: string | null;
  indicatorNormalized: string | null;
  port: number | null;
  countryCode: string | null;
  countryName: string | null;
  city: string | null;
  geoPrecision: string | null;
  classification: string | null;
  confidence: number | null;
  confidenceOrigin: string | null;
  malwareFamily: string | null;
  derivedLabel: string | null;
  tags: string | null;
  referenceUrl: string | null;
  summary: string;
  urlStatus: string | null;
  isCompromised: boolean | null;
};

export type DayCell = {
  day: string;
  count: number;
  status: DayStatus;
  families: Record<string, number>;
};

export type MapPoint = {
  ip: string;
  latitude: number;
  longitude: number;
  countryCode: string | null;
  countryName: string | null;
  city: string | null;
  precision: string | null;
  records: number;
  lastSeen: string;
  providers: string;
};

export type Dashboard = {
  generatedAt: string;
  metrics: {
    records: number;
    distinctIndicators: number;
    byCategory: { category: string; count: number }[];
    byFamily: { family: string; count: number }[];
    bySource: { source: string; count: number }[];
    priorRecords: number;
    delta: number;
    ipRecords: number;
    locatedIpRecords: number;
    locatedIps: number;
  };
  activity: {
    days: DayCell[];
    breaks: [number, number, number];
    hours: { hour: number; count: number }[] | null;
  };
  trends: {
    series: { day: string; count: number | null; baseline: number | null; spike: number | null; status: DayStatus }[];
    deviations: ReturnType<typeof findDeviations>;
  };
  map: { points: MapPoint[]; truncated: boolean; totalLocated: number };
  countries: { code: string; name: string | null; count: number }[];
  feed: { rows: ObservationRow[]; total: number; page: number; pageSize: number };
  providers: ProviderHealth[];
  vulnerabilities: {
    cveId: string;
    name: string;
    vendor: string | null;
    product: string | null;
    dateAdded: string | null;
    knownRansomware: string | null;
  }[];
  coverage: { providerId: string; success: number; failed: number }[];
};

function configured(id: string): boolean {
  if (id === "greynoise") return Boolean(process.env.GREYNOISE_API_KEY);
  if (id === "nvd") return true;
  return true;
}

function providerStatus(row: {
  id: string;
  mode: string;
  last_success_at: string | null;
  last_attempt_at: string | null;
  last_error: string | null;
  expected_interval_seconds: number | string;
}, now: number): ProviderHealth["status"] {
  if (row.mode === "on_demand") return configured(row.id) ? "on_demand" : "unconfigured";
  if (!configured(row.id)) return "unconfigured";
  const success = asIso(row.last_success_at);
  const attempt = asIso(row.last_attempt_at);
  if (row.last_error && (!success || (attempt && Date.parse(attempt) > Date.parse(success)))) return "failing";
  if (!success) return "never";
  const expected = asInt(row.expected_interval_seconds);
  if (expected > 0 && now - Date.parse(success) > expected * 2 * 1000) return "stale";
  return "ok";
}

function mapObservation(row: Record<string, unknown>): ObservationRow {
  return {
    id: String(row.id),
    providerId: String(row.provider_id),
    sourceRecordId: String(row.source_record_id),
    recordKind: String(row.record_kind),
    category: String(row.category),
    eventType: String(row.event_type),
    observedAt: asIso(row.observed_at) ?? "",
    indicatorType: (row.indicator_type as string | null) ?? null,
    indicatorValue: (row.indicator_value as string | null) ?? null,
    indicatorNormalized: (row.indicator_normalized as string | null) ?? null,
    port: row.port == null ? null : asInt(row.port),
    countryCode: (row.country_code as string | null) ?? null,
    countryName: (row.country_name as string | null) ?? null,
    city: (row.city as string | null) ?? null,
    geoPrecision: (row.geo_precision as string | null) ?? null,
    classification: (row.classification as string | null) ?? null,
    confidence: row.confidence == null ? null : asInt(row.confidence),
    confidenceOrigin: (row.confidence_origin as string | null) ?? null,
    malwareFamily: (row.malware_family as string | null) ?? null,
    derivedLabel: (row.derived_label as string | null) ?? null,
    tags: (row.tags as string | null) ?? null,
    referenceUrl: (row.reference_url as string | null) ?? null,
    summary: String(row.summary ?? ""),
    urlStatus: (row.url_status as string | null) ?? null,
    isCompromised: row.is_compromised == null ? null : Boolean(row.is_compromised),
  };
}

export async function getProviders(db: Database, now = Date.now()): Promise<ProviderHealth[]> {
  const rows = await db.query<Record<string, unknown>>(`SELECT * FROM providers ORDER BY id`);
  const byId = new Map(rows.map((row) => [String(row.id), row]));
  return PROVIDER_CATALOG.map((item) => {
    const row = byId.get(item.id);
    const health = {
      id: item.id,
      mode: item.mode,
      last_success_at: (row?.last_success_at as string | null) ?? null,
      last_attempt_at: (row?.last_attempt_at as string | null) ?? null,
      last_error: (row?.last_error as string | null) ?? null,
      expected_interval_seconds: (row?.expected_interval_seconds as number | string) ?? item.expectedIntervalSeconds,
    };
    const success = asIso(health.last_success_at);
    return {
      id: item.id,
      name: item.name,
      mode: item.mode,
      measures: item.measures,
      attribution: item.attribution,
      homepage: item.homepage,
      retentionNote: item.retentionNote,
      requiresKey: item.requiresKey,
      configured: configured(item.id),
      status: providerStatus(health, now),
      lastSuccessAt: success,
      lastAttemptAt: asIso(health.last_attempt_at),
      lastError: health.last_error,
      sourceUpdatedAt: asIso(row?.source_updated_at),
      lastFetched: row?.last_fetched == null ? null : asInt(row.last_fetched),
      age: ageLabel(success, now),
    };
  });
}

async function ingestCoverage(db: Database, filters: Filters): Promise<{ days: Set<string>; first: string | null; last: string | null }> {
  const params: unknown[] = [];
  let providerSql = "";
  if (filters.source !== "all") {
    params.push(filters.source);
    providerSql = `AND provider_id = $${params.length}`;
  } else {
    providerSql = `AND provider_id IN ('threatfox', 'urlhaus', 'cisa_kev')`;
  }
  const rows = await db.query<{ day: string }>(
    `SELECT DISTINCT to_char(finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day
     FROM ingestion_runs
     WHERE status = 'success' AND finished_at IS NOT NULL ${providerSql}`,
    params,
  );
  const days = new Set(rows.map((row) => row.day).filter(Boolean));
  const bounds = await db.query<{ first: string | null; last: string | null }>(
    `SELECT min(to_char(finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')) AS first,
            max(to_char(finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')) AS last
     FROM ingestion_runs
     WHERE status = 'success' AND finished_at IS NOT NULL ${providerSql}`,
    params,
  );
  return { days, first: bounds[0]?.first ?? null, last: bounds[0]?.last ?? null };
}

export async function getActivity(db: Database, filters: Filters): Promise<Dashboard["activity"]> {
  const where = observationWhere(filters, ["day"]);
  const rows = await db.query<{ day: string; label: string | null; count: number | string }>(
    `SELECT to_char(observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
            COALESCE(derived_label, 'unspecified') AS label,
            count(*)::int AS count
     FROM observations
     ${where.text}
     GROUP BY 1, 2`,
    where.params,
  );
  const byDay = new Map<string, { count: number; families: Record<string, number> }>();
  for (const row of rows) {
    const current = byDay.get(row.day) ?? { count: 0, families: {} };
    const count = asInt(row.count);
    current.count += count;
    current.families[row.label ?? "unspecified"] = count;
    byDay.set(row.day, current);
  }
  const coverage = await ingestCoverage(db, filters);
  const days: DayCell[] = windowDays(filters).map((day) => {
    const found = byDay.get(day);
    const count = found?.count ?? 0;
    return {
      day,
      count,
      status: dayStatus({
        day,
        count,
        ingestDays: coverage.days,
        firstIngestDay: coverage.first,
        lastIngestDay: coverage.last,
      }),
      families: found?.families ?? {},
    };
  });
  let hours: Dashboard["activity"]["hours"] = null;
  if (filters.day) {
    const hourWhere = observationWhere(filters);
    const hourRows = await db.query<{ hour: number | string; count: number | string }>(
      `SELECT extract(hour FROM observed_at AT TIME ZONE 'UTC')::int AS hour, count(*)::int AS count
       FROM observations
       ${hourWhere.text}
       GROUP BY 1`,
      hourWhere.params,
    );
    const counts = new Map(hourRows.map((row) => [asInt(row.hour), asInt(row.count)]));
    hours = Array.from({ length: 24 }, (_, hour) => ({ hour, count: counts.get(hour) ?? 0 }));
  }
  return { days, breaks: quantileBreaks(days.map((day) => day.count)), hours };
}

export async function getMetrics(db: Database, filters: Filters): Promise<Dashboard["metrics"]> {
  const where = observationWhere(filters);
  const totals = await db.query<Record<string, unknown>>(
    `SELECT count(*)::int AS records,
            count(*) FILTER (WHERE indicator_type = 'ip')::int AS ip_records,
            count(*) FILTER (WHERE indicator_type = 'ip' AND latitude IS NOT NULL)::int AS located_ip_records
     FROM observations
     ${where.text}`,
    where.params,
  );
  const distinct = await db.query<{ count: number | string }>(
    `SELECT count(*)::int AS count FROM (
       SELECT DISTINCT indicator_type, indicator_normalized
       FROM observations
       ${where.text}
         AND indicator_normalized IS NOT NULL
     ) indicators`,
    where.params,
  );
  const byCategory = await db.query<{ category: string; count: number | string }>(
    `SELECT category, count(*)::int AS count FROM observations ${where.text} GROUP BY category ORDER BY count DESC`,
    where.params,
  );
  const byFamily = await db.query<{ family: string; count: number | string }>(
    `SELECT COALESCE(derived_label, 'unspecified') AS family, count(*)::int AS count
     FROM observations ${where.text} GROUP BY 1 ORDER BY count DESC`,
    where.params,
  );
  const sourceWhere = observationWhere(filters, ["source"]);
  const bySource = await db.query<{ source: string; count: number | string }>(
    `SELECT provider_id AS source, count(*)::int AS count FROM observations ${sourceWhere.text} GROUP BY 1 ORDER BY count DESC`,
    sourceWhere.params,
  );
  const length = filters.to.getTime() - filters.from.getTime();
  const prior = observationWhere({ ...filters, from: new Date(filters.from.getTime() - length), to: filters.from, day: null });
  const priorRows = await db.query<{ count: number | string }>(
    `SELECT count(*)::int AS count FROM observations ${prior.text}`,
    prior.params,
  );
  const located = await db.query<{ count: number | string }>(
    `SELECT count(DISTINCT indicator_normalized)::int AS count
     FROM observations ${where.text} AND indicator_type = 'ip' AND latitude IS NOT NULL`,
    where.params,
  );
  const records = asInt(totals[0]?.records);
  const priorRecords = asInt(priorRows[0]?.count);
  return {
    records,
    distinctIndicators: asInt(distinct[0]?.count),
    byCategory: byCategory.map((row) => ({ category: row.category, count: asInt(row.count) })),
    byFamily: byFamily.map((row) => ({ family: row.family, count: asInt(row.count) })),
    bySource: bySource.map((row) => ({ source: row.source, count: asInt(row.count) })),
    priorRecords,
    delta: records - priorRecords,
    ipRecords: asInt(totals[0]?.ip_records),
    locatedIpRecords: asInt(totals[0]?.located_ip_records),
    locatedIps: asInt(located[0]?.count),
  };
}

export async function getMap(db: Database, filters: Filters): Promise<Dashboard["map"]> {
  const where = observationWhere(filters);
  const total = await db.query<{ count: number | string }>(
    `SELECT count(DISTINCT indicator_normalized)::int AS count
     FROM observations ${where.text} AND indicator_type = 'ip' AND latitude IS NOT NULL`,
    where.params,
  );
  const rows = await db.query<Record<string, unknown>>(
    `SELECT indicator_normalized AS ip,
            max(latitude) AS latitude,
            max(longitude) AS longitude,
            max(country_code) AS country_code,
            max(country_name) AS country_name,
            max(city) AS city,
            max(geo_precision) AS precision,
            count(*)::int AS records,
            max(observed_at) AS last_seen,
            string_agg(DISTINCT provider_id, ',') AS providers
     FROM observations
     ${where.text}
       AND indicator_type = 'ip'
       AND latitude IS NOT NULL
       AND longitude IS NOT NULL
     GROUP BY indicator_normalized
     ORDER BY max(observed_at) DESC
     LIMIT 2500`,
    where.params,
  );
  const totalLocated = asInt(total[0]?.count);
  return {
    totalLocated,
    truncated: totalLocated > rows.length,
    points: rows.map((row) => ({
      ip: String(row.ip),
      latitude: asNumber(row.latitude) ?? 0,
      longitude: asNumber(row.longitude) ?? 0,
      countryCode: (row.country_code as string | null) ?? null,
      countryName: (row.country_name as string | null) ?? null,
      city: (row.city as string | null) ?? null,
      precision: (row.precision as string | null) ?? null,
      records: asInt(row.records),
      lastSeen: asIso(row.last_seen) ?? "",
      providers: String(row.providers ?? ""),
    })),
  };
}

export async function getFeed(db: Database, filters: Filters): Promise<Dashboard["feed"]> {
  const where = observationWhere(filters);
  const total = await db.query<{ count: number | string }>(
    `SELECT count(*)::int AS count FROM observations ${where.text}`,
    where.params,
  );
  const offset = (filters.page - 1) * filters.pageSize;
  const rows = await db.query<Record<string, unknown>>(
    `SELECT * FROM observations ${where.text}
     ORDER BY ${sortSql(filters.sort)}
     LIMIT ${filters.pageSize} OFFSET ${offset}`,
    where.params,
  );
  return {
    rows: rows.map(mapObservation),
    total: asInt(total[0]?.count),
    page: filters.page,
    pageSize: filters.pageSize,
  };
}

export async function getCountries(db: Database, filters: Filters): Promise<Dashboard["countries"]> {
  const where = observationWhere(filters, ["country"]);
  const rows = await db.query<{ code: string; name: string | null; count: number | string }>(
    `SELECT country_code AS code, max(country_name) AS name, count(*)::int AS count
     FROM observations
     ${where.text} AND country_code IS NOT NULL AND country_code <> ''
     GROUP BY country_code
     ORDER BY count DESC
     LIMIT 12`,
    where.params,
  );
  return rows.map((row) => ({ code: row.code, name: row.name, count: asInt(row.count) }));
}

async function getCoverage(db: Database, filters: Filters): Promise<Dashboard["coverage"]> {
  const rows = await db.query<{ provider_id: string; status: string; count: number | string }>(
    `SELECT provider_id, status, count(*)::int AS count
     FROM ingestion_runs
     WHERE started_at >= ? AND started_at < ? AND provider_id IN ('threatfox', 'urlhaus', 'cisa_kev', 'geoip')
     GROUP BY provider_id, status`,
    [filters.from.toISOString(), filters.to.toISOString()],
  );
  const map = new Map<string, { success: number; failed: number }>();
  for (const id of ["threatfox", "urlhaus", "cisa_kev", "geoip"]) map.set(id, { success: 0, failed: 0 });
  for (const row of rows) {
    const current = map.get(row.provider_id) ?? { success: 0, failed: 0 };
    if (row.status === "success") current.success += asInt(row.count);
    if (row.status === "failed") current.failed += asInt(row.count);
    map.set(row.provider_id, current);
  }
  return [...map.entries()].map(([providerId, counts]) => ({ providerId, ...counts }));
}

async function recentKev(db: Database): Promise<Dashboard["vulnerabilities"]> {
  const rows = await db.query<Record<string, unknown>>(
    `SELECT cve_id, name, vendor, product, date_added, known_ransomware
     FROM vulnerabilities
     WHERE catalog_version IS NOT NULL AND removed_from_catalog_at IS NULL
     ORDER BY date_added DESC
     LIMIT 6`,
  );
  return rows.map((row) => ({
    cveId: String(row.cve_id),
    name: String(row.name ?? row.cve_id),
    vendor: (row.vendor as string | null) ?? null,
    product: (row.product as string | null) ?? null,
    dateAdded: asDay(row.date_added),
    knownRansomware: (row.known_ransomware as string | null) ?? null,
  }));
}

export async function getDashboard(db: Database, filters: Filters): Promise<Dashboard> {
  const metrics = await getMetrics(db, filters);
  const activity = await getActivity(db, filters);
  const map = await getMap(db, filters);
  const countries = await getCountries(db, filters);
  const feed = await getFeed(db, filters);
  const providers = await getProviders(db);
  const vulnerabilities = await recentKev(db);
  const coverage = await getCoverage(db, filters);
  const points = activity.days.map((day) => ({ day: day.day, count: day.count, status: day.status }));
  const baselines = baselineFor(points);
  const deviations = findDeviations(points);
  const deviationDays = new Set(deviations.map((item) => item.day));
  return {
    generatedAt: new Date().toISOString(),
    metrics,
    activity,
    trends: {
      series: activity.days.map((day, index) => ({
        day: day.day,
        count: day.status === "none" || day.status === "gap" ? null : day.count,
        baseline: baselines[index],
        spike: deviationDays.has(day.day) ? day.count : null,
        status: day.status,
      })),
      deviations,
    },
    map,
    countries,
    feed,
    providers,
    vulnerabilities,
    coverage,
  };
}

export async function searchIndicators(db: Database, q: string, limit = 25): Promise<
  { type: string; value: string; records: number; lastSeen: string | null; providers: string }[]
> {
  const pattern = `%${q.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
  const rows = await db.query<Record<string, unknown>>(
    `SELECT indicator_type AS type,
            indicator_normalized AS value,
            count(*)::int AS records,
            max(observed_at) AS last_seen,
            string_agg(DISTINCT provider_id, ',') AS providers
     FROM observations
     WHERE is_simulated = false
       AND indicator_normalized IS NOT NULL
       AND (indicator_normalized ILIKE ? ESCAPE '\\' OR COALESCE(indicator_value, '') ILIKE ? ESCAPE '\\')
     GROUP BY indicator_type, indicator_normalized
     ORDER BY max(observed_at) DESC
     LIMIT ?`,
    [pattern, pattern, limit],
  );
  return rows.map((row) => ({
    type: String(row.type),
    value: String(row.value),
    records: asInt(row.records),
    lastSeen: asIso(row.last_seen),
    providers: String(row.providers ?? ""),
  }));
}

export type VulnerabilityRow = {
  cveId: string;
  name: string | null;
  vendor: string | null;
  product: string | null;
  description: string | null;
  requiredAction: string | null;
  dateAdded: string | null;
  dueDate: string | null;
  knownRansomware: string | null;
  cwes: string | null;
  notes: string | null;
  inKev: boolean;
  removedAt: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  nvdDescription: string | null;
  referenceUrl: string | null;
};

function mapVulnerability(row: Record<string, unknown>): VulnerabilityRow {
  return {
    cveId: String(row.cve_id),
    name: (row.name as string | null) ?? null,
    vendor: (row.vendor as string | null) ?? null,
    product: (row.product as string | null) ?? null,
    description: (row.description as string | null) ?? null,
    requiredAction: (row.required_action as string | null) ?? null,
    dateAdded: asDay(row.date_added),
    dueDate: asDay(row.due_date),
    knownRansomware: (row.known_ransomware as string | null) ?? null,
    cwes: (row.cwes as string | null) ?? null,
    notes: (row.notes as string | null) ?? null,
    inKev: row.catalog_version != null && row.removed_from_catalog_at == null,
    removedAt: asIso(row.removed_from_catalog_at),
    cvssScore: asNumber(row.cvss_score),
    cvssSeverity: (row.cvss_severity as string | null) ?? null,
    nvdDescription: (row.nvd_description as string | null) ?? null,
    referenceUrl: (row.reference_url as string | null) ?? null,
  };
}

export async function listVulnerabilities(
  db: Database,
  options: { q: string | null; page: number; pageSize: number },
): Promise<{ rows: VulnerabilityRow[]; total: number; page: number; pageSize: number }> {
  const where = new WhereClause(options.q);
  const total = await db.query<{ count: number | string }>(
    `SELECT count(*)::int AS count FROM vulnerabilities ${where.text}`,
    where.params,
  );
  const offset = (options.page - 1) * options.pageSize;
  const rows = await db.query<Record<string, unknown>>(
    `SELECT * FROM vulnerabilities ${where.text}
     ORDER BY date_added DESC NULLS LAST, cve_id ASC
     LIMIT ${options.pageSize} OFFSET ${offset}`,
    where.params,
  );
  return {
    rows: rows.map(mapVulnerability),
    total: asInt(total[0]?.count),
    page: options.page,
    pageSize: options.pageSize,
  };
}

export async function getVulnerability(db: Database, cveId: string): Promise<VulnerabilityRow | null> {
  const cve = normalizeCve(cveId);
  if (!cve) throw new InputError("A CVE identifier looks like CVE-2021-44228.");
  const rows = await db.query<Record<string, unknown>>(`SELECT * FROM vulnerabilities WHERE cve_id = ?`, [cve]);
  return rows[0] ? mapVulnerability(rows[0]) : null;
}

class WhereClause {
  readonly params: unknown[] = [];
  private readonly parts: string[] = [];

  constructor(q: string | null) {
    if (!q) return;
    const pattern = `%${q.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
    this.params.push(pattern, pattern, pattern, pattern);
    this.parts.push(
      "(cve_id ILIKE $1 ESCAPE '\\' OR COALESCE(name, '') ILIKE $2 ESCAPE '\\' OR COALESCE(vendor, '') ILIKE $3 ESCAPE '\\' OR COALESCE(product, '') ILIKE $4 ESCAPE '\\')",
    );
  }

  get text(): string {
    return this.parts.length ? `WHERE ${this.parts.join(" AND ")}` : "";
  }
}
