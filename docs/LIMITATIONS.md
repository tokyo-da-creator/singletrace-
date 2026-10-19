# Limitations

These are current limits of the software, not a backlog disguised as completed work.

## Coverage

- There is no original telemetry. Every observation is a copy of someone else's report or catalog entry.
- ThreatFox and URLhaus collection use the recent public CSVs. Those files are rolling exports. They are not a complete history, and ThreatFox stops exporting indicators older than six months. Rows already stored remain.
- GreyNoise is not collected in bulk. Without `GREYNOISE_API_KEY`, investigations say so and send nothing.
- NVD is not bulk-downloaded. A CVE that nobody has opened has no NVD description until an investigation fetches it.
- Geolocation is capped per run and cached for seven days. Many IP records will have no coordinates until a later run reaches them. Domains are never located.
- The map shows at most 2,500 located IPs for the current filter.

## Meaning

- Default counts are ThreatFox records. They are not attacks, victims, or distinct operators.
- `source=all` mixes indicators, malware URLs, and vulnerability disclosures. The interface warns. The API does not add a second warning field. Callers have to keep the categories apart.
- The family label is a local keyword heuristic. It will mis-classify names that do not contain the listed tokens, and it will miss families that are not in the list.
- Shared malware names are listed on the investigation page and described as a shared label. They are not infrastructure links.
- A statistical deviation is a jump in stored volume. It is not attribution.
- KEV means CISA has catalogued the CVE as known exploited somewhere. It does not mean the vulnerability was exploited in a network this project can see.
- `is_compromised` is the reporter's flag from ThreatFox. It is not an independent confirmation.

## Operations

- The rate limiter and the optional scheduler live in one Node process. They reset on restart and do not coordinate across processes.
- PGlite is single-writer. The CLI and the dev server must not use `data/pglite` at the same time.
- A failed run can leave a chunk committed if the failure happens after a chunk transaction and the exception is outside that transaction. `last_success_at` still moves only when the provider function returns success. A crash in the middle of a multi-chunk write can leave a partial feed with status `failed`.
- ip-api free geolocation is not appropriate for a commercial service. The endpoint is HTTP.
- URLhaus can be tens of thousands of rows. The writer inserts per row inside chunks of 200, so a full collection takes minutes.
- In-process scheduling is off by default. Nothing collects until `npm run ingest` or a configured scheduler runs.
- Automated tests use simulated fixtures. They do not prove that today's live feed parsed, only that the parser accepts the fixture shape and the storage rules hold.

## Interface

- The map depends on OpenFreeMap. If the style cannot load, the page says so and leaves the country list in place.
- Grid tooltips need JavaScript. The cells are still links.
- There is no account system. Anyone who can reach the server can read the stored feeds and, if `INGEST_SECRET` is set and they know it, start a collection.
- Evidence links are an allowlist. A useful reference on an unlisted host is shown as text on purpose.

## Dependencies

`npm audit` on 2026-10-19 reported 11 advisories: 2 moderate, 6 high, and 3 critical. They were left in place. `npm audit fix --force` was not run.

- `maplibre-gl` 5.15.0 has a reported XSS bypass in `DOM.sanitize()` / `setHTML` (GHSA-jrc7-96c5-q579). Popups in this app are DOM nodes filled with `textContent`. The map was not upgraded to 6.x.
- `vitest` and `tinypool` advisories are in the test runner.
- `postcss` advisories come in through Next.js.
- `eslint`, `fast-glob`, and `braces` are dev tooling.

## Not in this version

- No passive DNS, certificate transparency, or WHOIS.
- No on-demand ThreatFox `search_ioc` call. Bulk collection is the only writer of observations.
- No authenticated multi-user deployment, no PostGIS, and no message queue.
- The Rainmeter skin that inspired the grid is unchanged and is not bundled here.
