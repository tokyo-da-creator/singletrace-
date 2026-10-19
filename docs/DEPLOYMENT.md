# Deployment

The supported local deployment is one Node process and the embedded database. A shared deployment should use PostgreSQL and an external scheduler.

## Local

```powershell
copy .env.example .env
npm install
npm run migrate
npm run ingest
npm run dev
```

`npm run build` then `npm start` serves the production build. The production build sends a Content-Security-Policy that allows OpenFreeMap tiles, sprites, and glyphs on `tiles.openfreemap.org`.

Leave `INGEST_INTERVAL_MINUTES` at `0` and `INGEST_ON_START` at `0` unless you want the server process itself to collect. If you enable the scheduler, the interval is raised to at least 10 minutes. A run already marked `running` inside the last 20 minutes is skipped.

## Environment

| Variable | Required | Effect |
| --- | --- | --- |
| `DATABASE_URL` | No | `postgres://` connection. Unset uses `data/pglite` |
| `ABUSECH_AUTH_KEY` | No | Sent as `Auth-Key` when present. Not required for the public CSVs this app collects |
| `GREYNOISE_API_KEY` | No | Enables investigation lookups. Never used in bulk |
| `NVD_API_KEY` | No | Raises the NVD pace from about one request per 6.5 seconds to about one per 0.7 seconds |
| `INGEST_SECRET` | No | Enables `POST /api/v1/ingest`. Unset returns 404 |
| `INGEST_INTERVAL_MINUTES` | No | Scheduler period. `0` disables it |
| `INGEST_ON_START` | No | `1` collects about 15 seconds after process start |
| `GEO_MAX_PER_RUN` | No | Cap on new public-IP lookups. Default 400 |

Do not commit `.env`. `.env.example` contains names only.

Create a database role that can read and write only this schema. The application does not create roles.

## Scheduled collection

On a server with PostgreSQL, call the CLI from cron or Task Scheduler while the web process is running. They can share `DATABASE_URL`. They must not share a PGlite directory.

```text
npm run ingest
```

A failing provider is reported on its own line. Earlier providers in that invocation stay committed. `last_success_at` moves only after a full successful parse and write.

ip-api's free endpoint is HTTP, non-commercial, and about 45 requests per minute. This app pauses 1.6 seconds between batches of 100 and caches results for seven days. Put a link to https://ip-api.com/ where locations are shown. The footer already does.

## Reverse proxy

Terminate TLS at the proxy. Add HSTS there. Forward `X-Forwarded-For` only from proxies you control. The rate limiter trusts the first forwarded address.

Keep the Node process count at one if you depend on the in-memory rate limiter or the in-process scheduler. More than one process needs a shared limiter and an external cron.

## What not to deploy

- Do not point the app at a feed you are not allowed to poll.
- Do not put abuse.ch or GreyNoise keys in a client bundle or a URL.
- Do not raise the collection interval below the provider minimums. The code refuses intervals under 10 minutes for the scheduled feeds.
- Do not serve the embedded `data/` directory as a production database for more than one user. Use PostgreSQL.
