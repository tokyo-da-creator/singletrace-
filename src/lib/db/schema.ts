import type { Database } from "@/lib/db/client";
import { PROVIDER_CATALOG } from "@/lib/providers/catalog";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS schema_meta (
  version integer PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS providers (
  id text PRIMARY KEY,
  name text NOT NULL,
  kind text NOT NULL,
  mode text NOT NULL,
  homepage text NOT NULL,
  attribution text NOT NULL,
  description text NOT NULL,
  measures text NOT NULL,
  retention_note text NOT NULL,
  requires_key boolean NOT NULL DEFAULT false,
  min_interval_seconds integer NOT NULL,
  expected_interval_seconds integer NOT NULL,
  last_success_at timestamptz,
  last_attempt_at timestamptz,
  last_error text,
  source_updated_at timestamptz,
  last_fetched integer,
  last_inserted integer,
  last_updated integer
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
  id bigserial PRIMARY KEY,
  provider_id text NOT NULL REFERENCES providers(id),
  started_at timestamptz NOT NULL,
  finished_at timestamptz,
  status text NOT NULL,
  fetched integer NOT NULL DEFAULT 0,
  inserted integer NOT NULL DEFAULT 0,
  updated integer NOT NULL DEFAULT 0,
  skipped integer NOT NULL DEFAULT 0,
  error text,
  detail text
);
CREATE INDEX IF NOT EXISTS ingestion_runs_provider_finished_idx
  ON ingestion_runs (provider_id, finished_at DESC);

CREATE TABLE IF NOT EXISTS observations (
  id bigserial PRIMARY KEY,
  provider_id text NOT NULL REFERENCES providers(id),
  source_record_id text NOT NULL,
  record_kind text NOT NULL,
  category text NOT NULL,
  event_type text NOT NULL,
  observed_at timestamptz NOT NULL,
  collected_at timestamptz NOT NULL,
  indicator_type text,
  indicator_value text,
  indicator_normalized text,
  port integer,
  country_code text,
  country_name text,
  region text,
  city text,
  latitude double precision,
  longitude double precision,
  geo_precision text,
  geo_source text,
  geo_looked_up_at timestamptz,
  classification text,
  confidence integer,
  confidence_origin text,
  malware_family text,
  derived_label text,
  derived_label_origin text,
  tags text,
  reference_url text,
  summary text,
  url_status text,
  is_compromised boolean,
  is_simulated boolean NOT NULL DEFAULT false,
  raw jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT observations_source_uid UNIQUE (provider_id, source_record_id),
  CONSTRAINT observations_category_chk CHECK (category IN (
    'reported_ioc', 'malware_distribution', 'scanner_classification', 'vulnerability_disclosure', 'derived'
  )),
  CONSTRAINT observations_kind_chk CHECK (record_kind IN (
    'observation', 'enrichment', 'disclosure', 'inference', 'simulation'
  ))
);
CREATE INDEX IF NOT EXISTS observations_observed_idx ON observations (observed_at DESC);
CREATE INDEX IF NOT EXISTS observations_provider_observed_idx ON observations (provider_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS observations_category_observed_idx ON observations (category, observed_at DESC);
CREATE INDEX IF NOT EXISTS observations_indicator_idx ON observations (indicator_normalized);
CREATE INDEX IF NOT EXISTS observations_country_idx ON observations (country_code, observed_at DESC);
CREATE INDEX IF NOT EXISTS observations_derived_idx ON observations (derived_label, observed_at DESC);
CREATE INDEX IF NOT EXISTS observations_sim_observed_idx ON observations (is_simulated, observed_at DESC);

CREATE TABLE IF NOT EXISTS indicators (
  id bigserial PRIMARY KEY,
  type text NOT NULL,
  value text NOT NULL,
  first_seen timestamptz,
  last_seen timestamptz,
  CONSTRAINT indicators_type_value_uid UNIQUE (type, value)
);

CREATE TABLE IF NOT EXISTS indicator_links (
  indicator_id bigint NOT NULL REFERENCES indicators(id),
  observation_id bigint NOT NULL REFERENCES observations(id),
  provider_id text NOT NULL,
  relationship text NOT NULL,
  PRIMARY KEY (indicator_id, observation_id, relationship)
);
CREATE INDEX IF NOT EXISTS indicator_links_observation_idx ON indicator_links (observation_id);

CREATE TABLE IF NOT EXISTS geo_cache (
  ip text PRIMARY KEY,
  status text NOT NULL,
  country_code text,
  country_name text,
  region text,
  city text,
  latitude double precision,
  longitude double precision,
  asn text,
  org text,
  precision text,
  message text,
  looked_up_at timestamptz NOT NULL,
  raw jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  cve_id text PRIMARY KEY,
  vendor text,
  product text,
  name text,
  description text,
  required_action text,
  date_added date,
  due_date date,
  known_ransomware text,
  cwes text,
  notes text,
  catalog_version text,
  removed_from_catalog_at timestamptz,
  reference_url text,
  nvd_status text,
  nvd_published timestamptz,
  nvd_last_modified timestamptz,
  cvss_version text,
  cvss_score double precision,
  cvss_severity text,
  nvd_description text,
  nvd_fetched_at timestamptz,
  collected_at timestamptz NOT NULL,
  raw_kev jsonb,
  raw_nvd jsonb
);
CREATE INDEX IF NOT EXISTS vulnerabilities_date_added_idx ON vulnerabilities (date_added DESC);

CREATE TABLE IF NOT EXISTS enrichment_cache (
  provider_id text NOT NULL,
  cache_key text NOT NULL,
  fetched_at timestamptz NOT NULL,
  http_status integer,
  body jsonb,
  error text,
  PRIMARY KEY (provider_id, cache_key)
);
`;

export async function migrate(db: Database): Promise<void> {
  await db.exec(SCHEMA);
  for (const item of PROVIDER_CATALOG) {
    await db.query(
      `INSERT INTO providers (
        id, name, kind, mode, homepage, attribution, description, measures, retention_note,
        requires_key, min_interval_seconds, expected_interval_seconds
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        kind = EXCLUDED.kind,
        mode = EXCLUDED.mode,
        homepage = EXCLUDED.homepage,
        attribution = EXCLUDED.attribution,
        description = EXCLUDED.description,
        measures = EXCLUDED.measures,
        retention_note = EXCLUDED.retention_note,
        requires_key = EXCLUDED.requires_key,
        min_interval_seconds = EXCLUDED.min_interval_seconds,
        expected_interval_seconds = EXCLUDED.expected_interval_seconds`,
      [
        item.id,
        item.name,
        item.kind,
        item.mode,
        item.homepage,
        item.attribution,
        item.description,
        item.measures,
        item.retentionNote,
        item.requiresKey,
        item.minIntervalSeconds,
        item.expectedIntervalSeconds,
      ],
    );
  }
  await db.query(
    `INSERT INTO schema_meta (version) VALUES (1) ON CONFLICT (version) DO NOTHING`,
  );
}
