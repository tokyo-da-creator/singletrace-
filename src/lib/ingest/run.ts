import type { Database } from "@/lib/db/client";
import { applyGeoCache, upsertObservations, upsertVulnerabilities } from "@/lib/ingest/store";
import { logEvent } from "@/lib/log";
import { isPublicIp } from "@/lib/indicators";
import { fetchCisaKev, parseCisaKev } from "@/lib/providers/cisa";
import { fetchGeoBatch, type GeoResult } from "@/lib/providers/geo";
import { fetchThreatFoxCsv, parseThreatFoxCsv } from "@/lib/providers/threatfox";
import { fetchUrlhausCsv, parseUrlhausCsv } from "@/lib/providers/urlhaus";
import { assertMinimumRows, rejectSimulated, type NormalizedObservation } from "@/lib/types";
import { asInt } from "@/lib/time";

export type IngestOutcome = {
  providerId: string;
  status: "success" | "failed" | "skipped";
  fetched: number;
  inserted: number;
  updated: number;
  skipped: number;
  error?: string;
  detail?: string;
};

type RunOptions = {
  force?: boolean;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  geoLimit?: number;
};

async function recentRunning(db: Database, providerId: string, now: Date): Promise<boolean> {
  const rows = await db.query<{ started_at: string }>(
    `SELECT started_at FROM ingestion_runs
     WHERE provider_id = ? AND status = 'running' AND started_at > ?
     ORDER BY started_at DESC LIMIT 1`,
    [providerId, new Date(now.getTime() - 20 * 60 * 1000).toISOString()],
  );
  return rows.length > 0;
}

async function tooSoon(db: Database, providerId: string, now: Date): Promise<boolean> {
  const rows = await db.query<{ last_success_at: string | null; min_interval_seconds: number | string }>(
    `SELECT last_success_at, min_interval_seconds FROM providers WHERE id = ?`,
    [providerId],
  );
  const row = rows[0];
  if (!row?.last_success_at) return false;
  const elapsed = now.getTime() - Date.parse(row.last_success_at);
  return elapsed < asInt(row.min_interval_seconds) * 1000;
}

async function openRun(db: Database, providerId: string, now: Date): Promise<string> {
  const rows = await db.query<{ id: number | string }>(
    `INSERT INTO ingestion_runs (provider_id, started_at, status) VALUES (?, ?, 'running') RETURNING id`,
    [providerId, now.toISOString()],
  );
  await db.query(`UPDATE providers SET last_attempt_at = ?, last_error = NULL WHERE id = ?`, [now.toISOString(), providerId]);
  return String(rows[0].id);
}

async function closeRun(
  db: Database,
  runId: string,
  providerId: string,
  outcome: Omit<IngestOutcome, "providerId">,
  sourceUpdatedAt: string | null,
  finished: Date,
): Promise<void> {
  await db.query(
    `UPDATE ingestion_runs
     SET finished_at = ?, status = ?, fetched = ?, inserted = ?, updated = ?, skipped = ?, error = ?, detail = ?
     WHERE id = ?`,
    [
      finished.toISOString(),
      outcome.status,
      outcome.fetched,
      outcome.inserted,
      outcome.updated,
      outcome.skipped,
      outcome.error ?? null,
      outcome.detail ?? null,
      runId,
    ],
  );
  if (outcome.status === "success") {
    await db.query(
      `UPDATE providers
       SET last_success_at = ?, last_error = NULL, source_updated_at = COALESCE(?, source_updated_at),
           last_fetched = ?, last_inserted = ?, last_updated = ?
       WHERE id = ?`,
      [finished.toISOString(), sourceUpdatedAt, outcome.fetched, outcome.inserted, outcome.updated, providerId],
    );
  } else if (outcome.status === "failed") {
    await db.query(`UPDATE providers SET last_error = ? WHERE id = ?`, [outcome.error ?? "failed", providerId]);
  }
}

async function storeFeed(
  db: Database,
  providerId: string,
  records: NormalizedObservation[],
  collectedAt: string,
): Promise<{ inserted: number; updated: number; dropped: number }> {
  const { kept, dropped } = rejectSimulated(records);
  const written = await upsertObservations(db, providerId, kept, collectedAt);
  return { ...written, dropped };
}

export async function ingestProvider(db: Database, providerId: string, options: RunOptions = {}): Promise<IngestOutcome> {
  const now = options.now ?? (() => new Date());
  const started = now();
  if (!options.force && (await recentRunning(db, providerId, started))) {
    return { providerId, status: "skipped", fetched: 0, inserted: 0, updated: 0, skipped: 0, detail: "A run is already in progress." };
  }
  if (!options.force && (await tooSoon(db, providerId, started))) {
    return { providerId, status: "skipped", fetched: 0, inserted: 0, updated: 0, skipped: 0, detail: "Minimum collection interval has not elapsed." };
  }

  const runId = await openRun(db, providerId, started);
  const request = { fetch: options.fetch, sleep: options.sleep };
  try {
    if (providerId === "threatfox") {
      const text = await fetchThreatFoxCsv(request);
      const parsed = parseThreatFoxCsv(text, started.getTime());
      assertMinimumRows(parsed.records.length, 10, "ThreatFox");
      const stored = await storeFeed(db, providerId, parsed.records, started.toISOString());
      const outcome: IngestOutcome = {
        providerId,
        status: "success",
        fetched: parsed.records.length + parsed.skipped,
        inserted: stored.inserted,
        updated: stored.updated,
        skipped: parsed.skipped + stored.dropped,
        detail: "Public recent CSV. Counts are reported indicators, not confirmed intrusions.",
      };
      await closeRun(db, runId, providerId, outcome, parsed.sourceUpdatedAt, now());
      logEvent("ingest_success", { providerId, fetched: outcome.fetched, inserted: outcome.inserted });
      return outcome;
    }
    if (providerId === "urlhaus") {
      const text = await fetchUrlhausCsv(request);
      const parsed = parseUrlhausCsv(text, started.getTime());
      assertMinimumRows(parsed.records.length, 10, "URLhaus");
      const stored = await storeFeed(db, providerId, parsed.records, started.toISOString());
      const outcome: IngestOutcome = {
        providerId,
        status: "success",
        fetched: parsed.records.length + parsed.skipped,
        inserted: stored.inserted,
        updated: stored.updated,
        skipped: parsed.skipped + stored.dropped,
        detail: "Public recent CSV. URLs were not downloaded.",
      };
      await closeRun(db, runId, providerId, outcome, parsed.sourceUpdatedAt, now());
      logEvent("ingest_success", { providerId, fetched: outcome.fetched, inserted: outcome.inserted });
      return outcome;
    }
    if (providerId === "cisa_kev") {
      const payload = await fetchCisaKev(request);
      const parsed = parseCisaKev(payload);
      assertMinimumRows(parsed.vulnerabilities.length, 100, "CISA KEV");
      if (parsed.count && Math.abs(parsed.count - parsed.vulnerabilities.length) > 5) {
        throw new Error(`CISA KEV count field is ${parsed.count} but ${parsed.vulnerabilities.length} entries parsed.`);
      }
      await upsertVulnerabilities(db, parsed.vulnerabilities, started.toISOString());
      const stored = await storeFeed(db, providerId, parsed.observations, started.toISOString());
      const outcome: IngestOutcome = {
        providerId,
        status: "success",
        fetched: parsed.vulnerabilities.length,
        inserted: stored.inserted,
        updated: stored.updated,
        skipped: stored.dropped,
        detail: `Catalog ${parsed.catalogVersion}. Plotted on the UTC day CISA added each CVE.`,
      };
      await closeRun(db, runId, providerId, outcome, parsed.dateReleased, now());
      logEvent("ingest_success", { providerId, fetched: outcome.fetched, inserted: outcome.inserted });
      return outcome;
    }
    throw new Error(`No collector is implemented for ${providerId}.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Collection failed.";
    const outcome: IngestOutcome = {
      providerId,
      status: "failed",
      fetched: 0,
      inserted: 0,
      updated: 0,
      skipped: 0,
      error: message,
    };
    await closeRun(db, runId, providerId, outcome, null, now());
    logEvent("ingest_failed", { providerId, message });
    return outcome;
  }
}

async function pendingIps(db: Database, limit: number): Promise<string[]> {
  const rows = await db.query<{ indicator_normalized: string }>(
    `SELECT observations.indicator_normalized
     FROM observations
     WHERE observations.indicator_type = 'ip'
       AND observations.indicator_normalized IS NOT NULL
       AND observations.latitude IS NULL
       AND observations.is_simulated = false
       AND NOT EXISTS (
         SELECT 1 FROM geo_cache
         WHERE geo_cache.ip = observations.indicator_normalized
           AND geo_cache.looked_up_at > now() - interval '7 days'
       )
     GROUP BY observations.indicator_normalized
     ORDER BY max(observations.observed_at) DESC
     LIMIT ?`,
    [limit],
  );
  return rows.map((row) => row.indicator_normalized);
}

async function saveGeo(db: Database, results: GeoResult[], lookedUpAt: string): Promise<void> {
  for (const result of results) {
    if (!result.ip) continue;
    await db.query(
      `INSERT INTO geo_cache (
        ip, status, country_code, country_name, region, city, latitude, longitude, asn, org, precision, message, looked_up_at, raw
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)
      ON CONFLICT (ip) DO UPDATE SET
        status = EXCLUDED.status,
        country_code = EXCLUDED.country_code,
        country_name = EXCLUDED.country_name,
        region = EXCLUDED.region,
        city = EXCLUDED.city,
        latitude = EXCLUDED.latitude,
        longitude = EXCLUDED.longitude,
        asn = EXCLUDED.asn,
        org = EXCLUDED.org,
        precision = EXCLUDED.precision,
        message = EXCLUDED.message,
        looked_up_at = EXCLUDED.looked_up_at,
        raw = EXCLUDED.raw`,
      [
        result.ip,
        result.status,
        result.countryCode,
        result.countryName,
        result.region,
        result.city,
        result.latitude,
        result.longitude,
        result.asn,
        result.org,
        result.precision,
        result.message,
        lookedUpAt,
        JSON.stringify({ precision: result.precision, source: "ip-api" }),
      ],
    );
  }
}

export async function ingestGeo(db: Database, options: RunOptions = {}): Promise<IngestOutcome> {
  const now = options.now ?? (() => new Date());
  const started = now();
  const limit = options.geoLimit ?? Number(process.env.GEO_MAX_PER_RUN ?? 400);
  const runId = await openRun(db, "geoip", started);
  try {
    await applyGeoCache(db);
    const ips = (await pendingIps(db, Number.isFinite(limit) ? limit : 400)).filter((ip) => isPublicIp(ip));
    const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    let fetched = 0;
    for (let index = 0; index < ips.length; index += 100) {
      if (index > 0) await sleep(1600);
      const batch = ips.slice(index, index + 100);
      const results = await fetchGeoBatch(batch, { fetch: options.fetch, sleep });
      await saveGeo(db, results, now().toISOString());
      fetched += results.length;
    }
    const applied = await applyGeoCache(db);
    const outcome: IngestOutcome = {
      providerId: "geoip",
      status: "success",
      fetched,
      inserted: applied,
      updated: 0,
      skipped: Math.max(0, ips.length - fetched),
      detail: "City-level network location from ip-api. Not a threat actor's physical location.",
    };
    await closeRun(db, runId, "geoip", outcome, null, now());
    logEvent("ingest_success", { providerId: "geoip", fetched, applied });
    return outcome;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Geolocation failed.";
    const outcome: IngestOutcome = { providerId: "geoip", status: "failed", fetched: 0, inserted: 0, updated: 0, skipped: 0, error: message };
    await closeRun(db, runId, "geoip", outcome, null, now());
    logEvent("ingest_failed", { providerId: "geoip", message });
    return outcome;
  }
}

export async function ingestAll(
  db: Database,
  options: RunOptions & { only?: string[]; skipGeo?: boolean } = {},
): Promise<IngestOutcome[]> {
  const ids = options.only ?? ["threatfox", "urlhaus", "cisa_kev"];
  const outcomes: IngestOutcome[] = [];
  for (const id of ids) {
    if (id === "geoip") continue;
    outcomes.push(await ingestProvider(db, id, options));
  }
  if (!options.skipGeo && (options.only == null || options.only.includes("geoip") || ids.some((id) => id === "threatfox" || id === "urlhaus"))) {
    outcomes.push(await ingestGeo(db, options));
  }
  return outcomes;
}
