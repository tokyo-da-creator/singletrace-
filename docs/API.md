# API

Base path: `/api/v1`. The same behavior is summarized in the app at `/reference`.

## Envelope

```json
{ "data": {}, "meta": { "generatedAt": "2026-01-15T12:00:00.000Z" } }
```

```json
{ "error": { "code": "invalid_input", "message": "Country must be a two-letter code." } }
```

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_input` | Filter or indicator failed validation |
| 401 | `unauthorized` | Ingest secret rejected |
| 404 | `not_found` | HTTP collection is disabled |
| 429 | `rate_limited` | `Retry-After` is in seconds |
| 500 | `internal_error` | The operation failed. The body has no SQL or secrets |

Read cache: `private, max-age=30`, except health, providers, and ingest, which are `no-store`. Investigation is `private, max-age=15`.

## Shared filters

Used by metrics, activity, trends, map, and observations.

| Parameter | Rule |
| --- | --- |
| `range` | `24h`, `7d`, `30d`, `90d`, `26w`, `custom`. Default `26w` |
| `from`, `to` | `YYYY-MM-DD` UTC, required for `custom`. `to` is inclusive. Maximum span 400 days |
| `source` | `threatfox` (default), `urlhaus`, `cisa_kev`, `all` |
| `category` | `reported_ioc`, `malware_distribution`, `scanner_classification`, `vulnerability_disclosure`, `derived` |
| `family` | `botnet`, `rat`, `c2`, `phish`, `stealer`, `payload`, `other` |
| `country` | Two letters |
| `q` | At most 200 characters. Matched against indicator, family, and summary |
| `day` | `YYYY-MM-DD` inside the range |
| `page` | 1–200. Default 1 |
| `pageSize` | 1–100. Default 25 |
| `sort` | `time_desc` (default), `time_asc`, `confidence_desc` |
| `north`, `south`, `east`, `west` | All four, or none. West greater than east crosses the antimeridian |

`source=all` is allowed. Callers must not present that total as an attack count.

### GET /metrics

Counts for the filter: `records`, `distinctIndicators`, `byCategory`, `byFamily`, `bySource`, `priorRecords`, `delta`, `ipRecords`, `locatedIpRecords`, `locatedIps`.

`delta` is the change in record count versus the previous window of the same length. It is not a percentage of attacks.

### GET /activity

`days[]` with `day`, `count`, `status` (`count`, `zero`, `gap`, `none`), and `families`. `breaks` is the quantile triple used for color. `hours` is 24 entries when `day` is set, otherwise null.

### GET /trends

`series[]` with `count` null on `gap` and `none` days, a rolling `baseline`, and `spike` when the deviation rule matches. `deviations[]` includes the median, MAD, modified z when MAD is non-zero, and the rule text.

### GET /map

`points[]` grouped by IP, at most 2,500 of the most recent located addresses. `truncated` is true when more exist. `totalLocated` is the uncapped distinct count. Each point has latitude, longitude, precision, country, city, record count, and providers.

### GET /observations

`rows`, `total`, `page`, `pageSize`. Rows include source id, record kind, category, indicator, geography, confidence origin, and summary.

### GET /indicators?q=

Up to 25 grouped indicators. `q` is required.

### GET /investigate?q=

Parses one indicator. Returns stored observations, same-malware-label rows (explicitly not an operator link), KEV fields, cached or freshly fetched NVD data for a CVE, GreyNoise when configured, and cached geo. This route can call NVD or GreyNoise. It does not create an observation from that lookup.

### GET /providers and GET /health

Provider id, status (`ok`, `stale`, `failing`, `never`, `unconfigured`, `on_demand`), last success, and age. Health adds an overall `ok` or `degraded` and omits error strings.

### GET /vulnerabilities

Paginated stored CVE rows. `q` matches id, name, vendor, or product. This route does not call NVD.

### GET /vulnerabilities/{cve}

`{ found: false }` or `{ found: true, vulnerability }`. Invalid CVE syntax is 400.

### POST /ingest

Disabled with 404 when `INGEST_SECRET` is unset.

```text
curl -X POST -H "x-ingest-secret: YOUR_SECRET" "http://127.0.0.1:3000/api/v1/ingest?provider=threatfox"
```

`provider` may be `threatfox`, `urlhaus`, `cisa_kev`, or `geoip`. `force=1` skips the minimum interval. `skipGeo=1` skips geolocation on a full run. The body lists each provider outcome. A failed provider is `status: "failed"` inside a 200 response when the process itself stayed up. Exit status is the CLI's concern, not this HTTP status.
