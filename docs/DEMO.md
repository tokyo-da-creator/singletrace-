# Demonstration

Walk this path in a portfolio review on a machine that has already collected once. The numbers below are from the local embedded database on 2026-10-19. They will change after the next collection.

## Collection result

One `npm run ingest` completed. No provider was replaced with sample data.

| Provider | Rows fetched | Source timestamp (UTC) | What the 26-week view shows |
| --- | --- | --- | --- |
| ThreatFox recent CSV | 7,320 | 2026-10-19 05:15 | 5,995 reported indicators. Older first-seen dates sit outside this window. |
| URLhaus recent CSV | 33,379 | 2026-10-19 05:07 | 33,379 malware-distribution URLs. |
| CISA KEV | 1,748 | catalog updated 2026-10-16 | 171 vulnerability disclosures. |
| ip-api | 400 lookups | — | 400 distinct located IPs in the default ThreatFox map. 679 of 3,050 IP records in that window have coordinates. |

GreyNoise was not called. `GREYNOISE_API_KEY` is unset. NVD was called once, during an investigation of CVE-2025-61624, and that response was cached. NVD is not a bulk feed.

The default observatory is ThreatFox only. Choosing every collected source returns 39,545 rows in the same window. That total mixes three kinds of records. The page says so. It is not an attack count.

The activity grid for default ThreatFox has 182 UTC days: 163 days with stored rows, 19 days with no coverage, and no confirmed-zero days. Empty days before the first successful collection are "no record," not proof that nothing happened. There was one successful collection day, so the grid has no collection-gap cells yet.

Filtering to 2026-10-19 returns 150 ThreatFox records. The grid itself stays on the 26-week window.

## Walkthrough

1. Open the observatory. The line under the wordmark names ThreatFox, URLhaus, CISA KEV, and ip-api with an age.
2. Leave the source on ThreatFox. The metric says records, and the note says the change versus the previous window is not a rate of attacks. On this run that change was +5,637 records.
3. Read a grid cell. A hollow cell means that day was not covered. A dark cell would mean a collection finished and matched nothing. A hatch would be a gap between successful collection days.
4. Select a day that has a count. The feed and the metric shrink to that UTC day. Clear the day.
5. Switch the source to CISA KEV. The rows are disclosures on the catalog date. The map still draws the basemap and says 0 of 0 located IPs. Disclosures are not plotted as points.
6. Switch to URLhaus. Open a row. The evidence link should be a urlhaus.abuse.ch page. The malware URL itself should not be a link.
7. Open a ThreatFox IP from the feed. The investigation shows the stored report. A coordinate, when present, is labeled as the network location of the address. With no GreyNoise key, the page says no lookup was sent.
8. Open CVE-2025-61624 from the KEV list. On this run CISA date added is 2026-10-16 and the due date is 2026-10-19. NVD returned CVSS 6 MEDIUM v3.1, published 2026-04-14, and the page says that score is not local evidence of exploitation.
9. Narrow the browser to about 390 pixels. The filter fields stack. The page does not scroll sideways. The grid and the feed scroll inside their own panels.

## Screenshots

Taken from the local production server with headless Brave. These are the stored collection, not mock data.

- `docs/screenshots/desktop-observatory.png` — 1440px. Metrics, grid, baseline, and the map. Red clusters are counts of located IP records. Country borders are the OpenFreeMap dark basemap.
- `docs/screenshots/desktop-feed.png` — the stored-record table and provider health. Evidence links read "source page" and point at the provider's record, not at a malware URL.
- `docs/screenshots/desktop-kev.png` — CISA KEV only. 171 disclosures. The map has no indicator dots.
- `docs/screenshots/desktop-investigate.png` — CVE-2025-61624, with KEV facts and the cached NVD response.
- `docs/screenshots/desktop-methodology.png` — the methodology page.
- `docs/screenshots/tablet-observatory.png` — 768px. Filters, metrics, grid, and the baseline chart.
- `docs/screenshots/mobile-observatory.png` — 390px. Navigation, stacked filters, and the first metrics. The grid is below this viewport.

## What this pass did not do

- No click automation. Day filtering was checked through the metrics API (`day=2026-10-19` returned 150 records), not by clicking a cell.
- Map popups and grid tooltips were not opened.
- A Brave `--screenshot` pass with the GPU disabled drew the zoom control and left the WebGL canvas blank. A later compositor capture showed the basemap and the clusters. The map in a normal browser uses that second path.
- The observatory console, after the favicon redirect and the Noto cluster font, produced no captured warnings on load. That is one headless load, not a full console audit of every page.
- `npm test` passed 25 tests. `npm run build` then passed lint and typecheck. `npm audit` still reports 11 advisories. See [LIMITATIONS.md](LIMITATIONS.md).
