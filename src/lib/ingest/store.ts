import type { Database } from "@/lib/db/client";
import type { NormalizedObservation, NormalizedVuln } from "@/lib/types";

function chunk<T>(items: T[], size: number): T[][] {
  const groups: T[][] = [];
  for (let index = 0; index < items.length; index += size) groups.push(items.slice(index, index + size));
  return groups;
}

type StoredObservation = NormalizedObservation & { id: string };

async function countProvider(db: Database, providerId: string): Promise<number> {
  const rows = await db.query<{ count: number | string }>(
    `SELECT count(*)::int AS count FROM observations WHERE provider_id = ?`,
    [providerId],
  );
  return Number(rows[0]?.count ?? 0);
}

export async function upsertObservations(
  db: Database,
  providerId: string,
  records: NormalizedObservation[],
  collectedAt: string,
): Promise<{ inserted: number; updated: number }> {
  const unique = new Map<string, NormalizedObservation>();
  for (const record of records) unique.set(record.sourceRecordId, record);
  const list = [...unique.values()];
  const before = await countProvider(db, providerId);

  for (const group of chunk(list, 200)) {
    await db.transaction(async (tx) => {
      const stored: StoredObservation[] = [];
      for (const record of group) {
        const rows = await tx.query<{ id: number | string }>(
          `INSERT INTO observations (
            provider_id, source_record_id, record_kind, category, event_type, observed_at, collected_at,
            indicator_type, indicator_value, indicator_normalized, port, classification, confidence,
            confidence_origin, malware_family, derived_label, derived_label_origin, tags, reference_url,
            summary, url_status, is_compromised, is_simulated, raw
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?::jsonb)
          ON CONFLICT (provider_id, source_record_id) DO UPDATE SET
            record_kind = EXCLUDED.record_kind,
            category = EXCLUDED.category,
            event_type = EXCLUDED.event_type,
            collected_at = EXCLUDED.collected_at,
            indicator_type = EXCLUDED.indicator_type,
            indicator_value = EXCLUDED.indicator_value,
            indicator_normalized = EXCLUDED.indicator_normalized,
            port = EXCLUDED.port,
            classification = EXCLUDED.classification,
            confidence = EXCLUDED.confidence,
            confidence_origin = EXCLUDED.confidence_origin,
            malware_family = EXCLUDED.malware_family,
            derived_label = EXCLUDED.derived_label,
            derived_label_origin = EXCLUDED.derived_label_origin,
            tags = EXCLUDED.tags,
            reference_url = EXCLUDED.reference_url,
            summary = EXCLUDED.summary,
            url_status = EXCLUDED.url_status,
            is_compromised = EXCLUDED.is_compromised,
            raw = EXCLUDED.raw
          RETURNING id`,
          [
            providerId,
            record.sourceRecordId,
            record.recordKind,
            record.category,
            record.eventType,
            record.observedAt,
            collectedAt,
            record.indicatorType,
            record.indicatorValue,
            record.indicatorNormalized,
            record.port,
            record.classification,
            record.confidence,
            record.confidenceOrigin,
            record.malwareFamily,
            record.derivedLabel,
            record.derivedLabelOrigin,
            record.tags,
            record.referenceUrl,
            record.summary,
            record.urlStatus,
            record.isCompromised,
            JSON.stringify(record.raw ?? {}),
          ],
        );
        stored.push({ ...record, id: String(rows[0].id) });
      }
      await linkIndicators(tx, providerId, stored);
    });
  }

  const after = await countProvider(db, providerId);
  const inserted = after - before;
  return { inserted, updated: list.length - inserted };
}

async function linkIndicators(db: Database, providerId: string, records: StoredObservation[]): Promise<void> {
  type Item = { type: string; value: string; first: string; last: string; observationId: string; relationship: string };
  const items: Item[] = [];
  for (const record of records) {
    if (record.indicatorType && record.indicatorNormalized) {
      items.push({
        type: record.indicatorType,
        value: record.indicatorNormalized,
        first: record.observedAt,
        last: record.observedAt,
        observationId: record.id,
        relationship: "reported",
      });
    }
    for (const extra of record.extras) {
      items.push({
        type: extra.type,
        value: extra.value,
        first: record.observedAt,
        last: record.observedAt,
        observationId: record.id,
        relationship: extra.relationship,
      });
    }
  }
  const indicators = new Map<string, Item>();
  for (const item of items) {
    const key = `${item.type}\u0000${item.value}`;
    const previous = indicators.get(key);
    if (!previous || item.first < previous.first) indicators.set(key, { ...previous, ...item, first: item.first, last: previous?.last && previous.last > item.last ? previous.last : item.last });
    else if (item.last > previous.last) previous.last = item.last;
  }
  const ids = new Map<string, string>();
  for (const item of indicators.values()) {
    const rows = await db.query<{ id: number | string }>(
      `INSERT INTO indicators (type, value, first_seen, last_seen)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (type, value) DO UPDATE SET
         first_seen = LEAST(indicators.first_seen, EXCLUDED.first_seen),
         last_seen = GREATEST(indicators.last_seen, EXCLUDED.last_seen)
       RETURNING id`,
      [item.type, item.value, item.first, item.last],
    );
    ids.set(`${item.type}\u0000${item.value}`, String(rows[0].id));
  }
  for (const item of items) {
    const indicatorId = ids.get(`${item.type}\u0000${item.value}`);
    if (!indicatorId) continue;
    await db.query(
      `INSERT INTO indicator_links (indicator_id, observation_id, provider_id, relationship)
       VALUES (?, ?, ?, ?)
       ON CONFLICT DO NOTHING`,
      [indicatorId, item.observationId, providerId, item.relationship],
    );
  }
}

export async function upsertVulnerabilities(db: Database, vulns: NormalizedVuln[], collectedAt: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.exec("CREATE TEMP TABLE kev_seen (cve_id text PRIMARY KEY) ON COMMIT DROP");
    for (const group of chunk(vulns, 200)) {
      for (const vuln of group) {
        await tx.query(`INSERT INTO kev_seen (cve_id) VALUES (?) ON CONFLICT DO NOTHING`, [vuln.cveId]);
        await tx.query(
          `INSERT INTO vulnerabilities (
            cve_id, vendor, product, name, description, required_action, date_added, due_date,
            known_ransomware, cwes, notes, catalog_version, removed_from_catalog_at, reference_url,
            collected_at, raw_kev
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?::jsonb)
          ON CONFLICT (cve_id) DO UPDATE SET
            vendor = EXCLUDED.vendor,
            product = EXCLUDED.product,
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            required_action = EXCLUDED.required_action,
            date_added = EXCLUDED.date_added,
            due_date = EXCLUDED.due_date,
            known_ransomware = EXCLUDED.known_ransomware,
            cwes = EXCLUDED.cwes,
            notes = EXCLUDED.notes,
            catalog_version = EXCLUDED.catalog_version,
            removed_from_catalog_at = NULL,
            reference_url = EXCLUDED.reference_url,
            collected_at = EXCLUDED.collected_at,
            raw_kev = EXCLUDED.raw_kev`,
          [
            vuln.cveId,
            vuln.vendor,
            vuln.product,
            vuln.name,
            vuln.description,
            vuln.requiredAction,
            vuln.dateAdded,
            vuln.dueDate,
            vuln.knownRansomware,
            vuln.cwes.join(", "),
            vuln.notes,
            vuln.catalogVersion,
            `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`,
            collectedAt,
            JSON.stringify(vuln.raw ?? {}),
          ],
        );
      }
    }
    await tx.query(
      `UPDATE vulnerabilities
       SET removed_from_catalog_at = ?
       WHERE catalog_version IS NOT NULL
         AND removed_from_catalog_at IS NULL
         AND NOT EXISTS (SELECT 1 FROM kev_seen WHERE kev_seen.cve_id = vulnerabilities.cve_id)`,
      [collectedAt],
    );
  });
}

export async function applyGeoCache(db: Database): Promise<number> {
  const rows = await db.query<{ count: number | string }>(
    `WITH updated AS (
      UPDATE observations
      SET country_code = geo_cache.country_code,
          country_name = geo_cache.country_name,
          region = geo_cache.region,
          city = geo_cache.city,
          latitude = geo_cache.latitude,
          longitude = geo_cache.longitude,
          geo_precision = geo_cache.precision,
          geo_source = 'ip-api',
          geo_looked_up_at = geo_cache.looked_up_at
      FROM geo_cache
      WHERE observations.indicator_type = 'ip'
        AND observations.indicator_normalized = geo_cache.ip
        AND observations.latitude IS NULL
        AND geo_cache.latitude IS NOT NULL
      RETURNING observations.id
    )
    SELECT count(*)::int AS count FROM updated`,
  );
  return Number(rows[0]?.count ?? 0);
}
