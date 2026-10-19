import { blankToNull, headerFromComments, parseCsv, rowObject, stripHashComments } from "@/lib/csv";
import { DERIVED_LABEL_ORIGIN, classifyFamily } from "@/lib/family";
import { HttpError, requestText, type RequestOptions } from "@/lib/http";
import { indicatorFromSource } from "@/lib/indicators";
import { parseSourceUtc } from "@/lib/time";
import { ProviderError, type NormalizedObservation } from "@/lib/types";

export const URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";

const HEADER = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"];

export type UrlhausParse = {
  records: NormalizedObservation[];
  skipped: number;
  sourceUpdatedAt: string | null;
};

export function parseUrlhausCsv(text: string, now = Date.now()): UrlhausParse {
  const { body, comments } = stripHashComments(text);
  const header = headerFromComments(comments, "dateadded") ?? HEADER;
  if (!header.includes("id") || !header.includes("url")) {
    throw new ProviderError("URLhaus export is missing the expected column header.");
  }
  const updatedLine = comments.find((line) => /Last updated:/i.test(line));
  const updatedMatch = updatedLine?.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
  const sourceUpdatedAt = updatedMatch ? parseSourceUtc(updatedMatch[1]) : null;
  const horizon = now + 48 * 3600 * 1000;
  const records: NormalizedObservation[] = [];
  let skipped = 0;

  for (const row of parseCsv(body)) {
    const record = rowObject(header, row);
    const sourceRecordId = blankToNull(record.id);
    const observedAt = parseSourceUtc(record.dateadded);
    const rawUrl = blankToNull(record.url);
    if (!sourceRecordId || !observedAt || !rawUrl || Date.parse(observedAt) > horizon) {
      skipped += 1;
      continue;
    }
    const indicator = indicatorFromSource("url", rawUrl);
    const tags = blankToNull(record.tags);
    const threat = blankToNull(record.threat) ?? "malware_download";
    const family = classifyFamily(threat, tags, tags);
    const link = blankToNull(record.urlhaus_link);
    records.push({
      sourceRecordId,
      recordKind: "observation",
      category: "malware_distribution",
      eventType: threat,
      observedAt,
      indicatorType: indicator.type,
      indicatorValue: indicator.value,
      indicatorNormalized: indicator.normalized,
      port: indicator.port,
      classification: blankToNull(record.url_status),
      confidence: null,
      confidenceOrigin: null,
      malwareFamily: null,
      derivedLabel: family,
      derivedLabelOrigin: DERIVED_LABEL_ORIGIN,
      tags,
      referenceUrl: link && link.startsWith("https://urlhaus.abuse.ch/") ? link : `https://urlhaus.abuse.ch/url/${sourceRecordId}/`,
      summary: `URLhaus lists this URL as ${threat}. Source status: ${blankToNull(record.url_status) ?? "not provided"}. Reporter: ${blankToNull(record.reporter) ?? "not provided"}.`,
      urlStatus: blankToNull(record.url_status),
      isCompromised: null,
      raw: {
        url_status: blankToNull(record.url_status),
        last_online: blankToNull(record.last_online),
        threat,
        tags,
        reporter: blankToNull(record.reporter),
      },
      extras: indicator.extras,
    });
  }

  return { records, skipped, sourceUpdatedAt };
}

export async function fetchUrlhausCsv(options: RequestOptions = {}): Promise<string> {
  const attempt = (headers?: Record<string, string>) =>
    requestText(URLHAUS_CSV_URL, { ...options, headers, timeoutMs: options.timeoutMs ?? 90000 });
  try {
    return await attempt();
  } catch (error) {
    if (error instanceof HttpError && (error.status === 401 || error.status === 403) && process.env.ABUSECH_AUTH_KEY) {
      try {
        return await attempt({ "Auth-Key": process.env.ABUSECH_AUTH_KEY });
      } catch (retryError) {
        const status = retryError instanceof HttpError ? retryError.status : "network";
        throw new ProviderError(`URLhaus export failed with ${status} after sending ABUSECH_AUTH_KEY.`);
      }
    }
    if (error instanceof HttpError && (error.status === 401 || error.status === 403)) {
      throw new ProviderError("URLhaus refused the public export. Set ABUSECH_AUTH_KEY and try again.");
    }
    throw new ProviderError(error instanceof Error ? error.message : "URLhaus export failed.");
  }
}
