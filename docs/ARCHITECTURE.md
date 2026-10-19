# Architecture

SignalTrace is one Next.js application. Collection, queries, and the interface share a PostgreSQL schema. There is no separate worker service.

## Request path

Browser pages are server components. They parse the query string, open the database through `withDb()`, and render HTML. MapLibre, the activity-grid tooltip, and the time-series chart are client islands. Filters are ordinary GET forms.

`/api/v1/*` uses the same query functions. Responses are `{ data, meta: { generatedAt } }` or `{ error: { code, message } }`. Handlers validate input with the same filter parser as the pages. Rate limits are in-memory, 120 requests per minute for reads and 30 for investigation, keyed by the forwarding address. That limit applies to a single Node process.

`POST /api/v1/ingest` is off unless `INGEST_SECRET` is set. The header is compared by SHA-256 and `timingSafeEqual`. The CLI does not use that secret.

## Database

`src/lib/db/schema.ts` is the schema. `npm run migrate` and the first `getDb()` apply it.

Embedded mode uses PGlite in `data/pglite` when `DATABASE_URL` is unset. A `postgres://` URL uses the `pg` driver with a pool of four and a 30 second statement timeout. SQL is written once: `?` placeholders are rewritten to `$1` style. PostGIS is not used. Country filters and bounding boxes are ordinary columns.

PGlite serves one query at a time. `withDb()` serializes access in the server process. Do not open the same data directory from `npm run ingest` and `next dev` together.

Simulated rows can exist only if something inserts `is_simulated = true` directly. Ingest drops `record_kind = simulation` before insert and forces `is_simulated` false. Dashboard queries add `is_simulated = false`.

### Tables

| Table | Role |
| --- | --- |
| `providers` | Catalog, last success, last error, source update time |
| `ingestion_runs` | Each attempt, including failures |
| `observations` | Normalized records. Unique on `(provider_id, source_record_id)` |
| `indicators` / `indicator_links` | Normalized values and documented relationships such as `reported` and `embedded_host` |
| `vulnerabilities` | KEV rows plus cached NVD columns. Removal sets `removed_from_catalog_at` |
| `geo_cache` | ip-api results, including failures, for seven days |
| `enrichment_cache` | GreyNoise and NVD response bodies |

Indexes follow the filters: observation time, provider, category, normalized indicator, country, and derived label.

An upsert updates the description and does not change `observed_at` or stored coordinates. Coordinates are filled later from `geo_cache`.

## Providers

Adapters live in `src/lib/providers`. Each one fetches, validates, and returns normalized records. `src/lib/ingest/run.ts` is the only path that writes observations.

| Id | Mode | Input |
| --- | --- | --- |
| `threatfox` | scheduled | Public recent CSV. Optional `Auth-Key` header if `ABUSECH_AUTH_KEY` is set |
| `urlhaus` | scheduled | Public recent CSV, with the same optional header on 401 or 403 |
| `cisa_kev` | scheduled | Public JSON catalog |
| `geoip` | enrichment | ip-api batch, public IPs only, at most `GEO_MAX_PER_RUN` per run |
| `nvd` | on demand | CVE lookup during investigation |
| `greynoise` | on demand | Community IP lookup during investigation when a key is set |

ThreatFox and URLhaus refuse a feed shorter than 10 rows. KEV refuses a catalog shorter than 100 entries, or one whose `count` disagrees with the parsed length by more than five. A rejected run does not move `last_success_at`.

HTTP retries cover 429 and 5xx with exponential backoff, jitter, and `Retry-After` up to 60 seconds. Logs contain the event name, provider id, and counts. Fields whose names look like secrets are dropped. URLs logged from HTTP errors keep host and path only.

The family label (`signaltrace.family_heuristic.v1`) is derived from malware name, tags, and threat type, using token boundaries. It is not a source field. URLhaus tags do not become a malware family name.

## Time and geography

Timestamps from the abuse.ch files are treated as UTC. KEV is plotted at midnight UTC on `dateAdded`. NVD timestamps without a zone are stored as UTC and described that way in the interface.

The grid uses successful `ingestion_runs` to tell a collected zero from a day outside coverage and from a gap between successful days. Historical first-seen dates still count on their own day when the row is stored.

Only public IP literals are geolocated. Documentation ranges, private space, and domains are not sent out. The map clusters cached coordinates and says they are network locations.

Deviations use the median and median absolute deviation of up to 14 earlier covered days, after at least seven such days. The chart leaves uncovered days blank. The rule is printed next to any flagged day.

## Security boundaries

- API keys stay in environment variables. Client components never receive them.
- Evidence links are limited to a host allowlist. Other URLs, including malware URLs, render as text.
- Investigation does not request a submitted URL, resolve a domain, or execute a file.
- Queries are parameterized. Page size, page, and sort are validated before they are interpolated.
- Security headers: `nosniff`, `no-referrer`, `DENY` frames, a locked-down permissions policy. Content-Security-Policy is added when `NODE_ENV` is production. HSTS is left to a reverse proxy.
- There is no scanning, exploitation, or credential collection feature.

## Tests

Vitest runs in Node against an in-memory PGlite database. Fixtures under `fixtures/` are labeled simulated and are not loaded by ingest. They use documentation addresses, `example` domains, and `CVE-2099-0001`.
