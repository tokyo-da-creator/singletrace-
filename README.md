# SignalTrace

SignalTrace is a local cyber threat observatory. It collects reported indicators, malware-distribution URLs, and the CISA Known Exploited Vulnerabilities catalog, stores them with their source identifiers, and lets you filter, map, and investigate what was actually retrieved.

It is a portfolio project. It does not operate a sensor, and it does not claim a global attack count.

The activity grid follows the same idea as a desktop calendar of ThreatFox first-seen days: one cell per UTC day, darker when more records share that day. The desktop skin is separate and is not part of this application.

## What a record means

| Source | What a row is | What it is not |
| --- | --- | --- |
| ThreatFox recent CSV | An indicator reported to abuse.ch | A confirmed intrusion |
| URLhaus recent CSV | A URL reported as distributing malware | A payload this app downloaded |
| CISA KEV | A vulnerability added to the catalog | An intrusion observed by SignalTrace |
| ip-api | Network location of a public IP | A person's physical location |
| GreyNoise Community | Scanner context, only during an investigation, and only with a key | Proof of compromise |
| NIST NVD | CVE metadata loaded when an analyst opens a CVE | Evidence the CVE was exploited here |

The default view is ThreatFox. Combining sources is an explicit filter and is labeled as a mixture.

A hollow day on the grid means collection did not cover that day. A zero means a collection finished and stored nothing that matched the filter. Neither one means attacks stopped.

## Requirements

- Node.js 22 or newer. This workspace was developed on Node.js 24.
- No Docker and no separate PostgreSQL are required. The app uses embedded PostgreSQL (PGlite) in `data/pglite` when `DATABASE_URL` is unset.
- Optional keys are listed in `.env.example`. The public CSV and KEV feeds used for collection do not need a key.

## Setup

```powershell
cd C:\Users\Cyber\signaltrace
copy .env.example .env
npm install
npm run migrate
npm run ingest
npm run dev
```

Open http://127.0.0.1:3000.

Stop the dev server before `npm run ingest` when you are using the embedded database. PGlite allows one process to open `data/pglite`.

`npm run ingest` prints one line per provider and exits non-zero if any provider fails. It does not replace a failed feed with sample data. Fixtures in `fixtures/` are for tests only.

Useful flags:

```powershell
npm run ingest -- --provider threatfox --force
npm run ingest -- --skip-geo
```

`--force` bypasses the minimum interval. The shortest interval the scheduler will use is 10 minutes.

## Using it

- The observatory filters are a GET form, so they work without JavaScript. Charts, the map, and grid tooltips are progressive enhancements.
- Select a day on the grid to limit the feed, metrics, and map to that UTC day. The grid itself stays on the full window.
- Search an IP, domain, URL, hash, or CVE from the header. The investigation page reads stored rows. It requests NVD only for a CVE, and GreyNoise only for a public IP when `GREYNOISE_API_KEY` is set. It does not fetch the indicator URL.
- Methodology, source notes, and the API reference are linked in the header.

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Next.js development server |
| `npm run build` / `npm start` | Production build and server |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint |
| `npm test` | Vitest, using an in-memory database |
| `npm run ingest` | Collect ThreatFox, URLhaus, CISA KEV, then geolocate public IPs |
| `npm run migrate` | Apply the schema |

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API](docs/API.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Limitations](docs/LIMITATIONS.md)
- [Demonstration](docs/DEMO.md)
- Methodology is also a page in the app: `/methodology`

## Verification

Checked in this workspace on 2026-10-19:

- `npm test` — 25 tests passed (parsers, normalization, deduplication, UTC bucketing, gap versus zero days, KEV retirement, provider failure leaving prior rows, investigation without an outbound call for a domain).
- `npm run build` — Next.js 15.5.28 production build completed, including lint and typecheck.
- Live collection and the browser pass are written in [docs/DEMO.md](docs/DEMO.md). Those counts are from that run. They are not a standing global total.
- `npm audit` reports 11 advisories. They are listed in [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The build is not a clean audit.

## License and data

The application code is a student portfolio project. Feed contents remain subject to the terms of abuse.ch, CISA, NIST, GreyNoise, and ip-api.com. Attribute ip-api when its locations are shown. Do not use the free ip-api endpoint for a commercial deployment.
