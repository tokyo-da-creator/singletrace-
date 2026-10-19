import { blankToNull, headerFromComments, parseCsv, rowObject, stripHashComments } from "@/lib/csv";
import { DERIVED_LABEL_ORIGIN, classifyFamily } from "@/lib/family";
import { HttpError, requestText, type RequestOptions } from "@/lib/http";
import { indicatorFromSource } from "@/lib/indicators";
import { parseSourceUtc } from "@/lib/time";
import { ProviderError, type NormalizedObservation } from "@/lib/types";

export const THREATFOX_CSV_URL = "https://threatfox.abuse.ch/export/csv/recent/";

const HEADER = [
  "first_seen_utc",
  "ioc_id",
  "ioc_value",
  "ioc_type",
  "threat_type",
  "fk_malware",
  "malware_alias",
  "malware_printable",
  "last_seen_utc",
  "confidence_level",
  "is_compromised",
  "reference",
  "tags",
  "anonymous",
  "reporter",
];

export type ThreatFoxParse = {
  records: NormalizedObservation[];
  skipped: number;
  sourceUpdatedAt: string | null;
};

function httpUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.toString();
  } catch {
    return null;
  }
}

export function parseThreatFoxCsv(text: string, now = Date.now()): ThreatFoxParse {
  const { body, comments } = stripHashComments(text);
  const header = headerFromComments(comments, "first_seen_utc") ?? HEADER;
  if (!header.includes("ioc_id") || !header.includes("ioc_value")) {
    throw new ProviderError("ThreatFox export is missing the expected column header.");
  }
  const updatedLine = comments.find((line) => /Last updated:/i.test(line));
  const updatedMatch = updatedLine?.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
  const sourceUpdatedAt = updatedMatch ? parseSourceUtc(updatedMatch[1]) : null;
  const rows = parseCsv(body);
  const records: NormalizedObservation[] = [];
  let skipped = 0;
  const horizon = now + 48 * 3600 * 1000;

  for (const row of rows) {
    if (row.length < 5) {
      skipped += 1;
      continue;
    }
    const record = rowObject(header, row);
    const sourceRecordId = blankToNull(record.ioc_id);
    const observedAt = parseSourceUtc(record.first_seen_utc);
    const rawValue = blankToNull(record.ioc_value);
    if (!sourceRecordId || !observedAt || !rawValue || Date.parse(observedAt) > horizon) {
      skipped += 1;
      continue;
    }
    const indicator = indicatorFromSource(record.ioc_type || "unknown", rawValue);
    const malware = blankToNull(record.malware_printable) ?? blankToNull(record.fk_malware);
    const tags = blankToNull(record.tags);
    const confidenceRaw = blankToNull(record.confidence_level);
    const confidence = confidenceRaw != null && /^\d{1,3}$/.test(confidenceRaw) ? Number(confidenceRaw) : null;
    const compromised = blankToNull(record.is_compromised);
    const threatType = blankToNull(record.threat_type) ?? "unknown";
    const family = classifyFamily(threatType, malware, tags);
    const reporter = blankToNull(record.reporter);
    records.push({
      sourceRecordId,
      recordKind: "observation",
      category: "reported_ioc",
      eventType: threatType,
      observedAt,
      indicatorType: indicator.type,
      indicatorValue: indicator.value,
      indicatorNormalized: indicator.normalized,
      port: indicator.port,
      classification: threatType,
      confidence: confidence != null && confidence <= 100 ? confidence : null,
      confidenceOrigin: confidence != null && confidence <= 100 ? "threatfox" : null,
      malwareFamily: malware,
      derivedLabel: family,
      derivedLabelOrigin: DERIVED_LABEL_ORIGIN,
      tags,
      referenceUrl: httpUrl(blankToNull(record.reference)) ?? `https://threatfox.abuse.ch/ioc/${sourceRecordId}/`,
      summary: `ThreatFox reports this ${record.ioc_type || "indicator"} as ${threatType}${malware ? ` for ${malware}` : ""}${reporter ? `. Reporter: ${reporter}` : ""}.`,
      urlStatus: null,
      isCompromised: compromised == null ? null : compromised.toLowerCase() === "true",
      raw: {
        ioc_type: record.ioc_type,
        threat_type: threatType,
        malware,
        malware_alias: blankToNull(record.malware_alias),
        confidence_level: confidence,
        is_compromised: compromised,
        reporter,
        tags,
        last_seen_utc: blankToNull(record.last_seen_utc),
      },
      extras: indicator.extras,
    });
  }

  return { records, skipped, sourceUpdatedAt };
}

export async function fetchThreatFoxCsv(options: RequestOptions = {}): Promise<string> {
  try {
    const headers = process.env.ABUSECH_AUTH_KEY ? { "Auth-Key": process.env.ABUSECH_AUTH_KEY } : undefined;
    return await requestText(THREATFOX_CSV_URL, { ...options, headers, timeoutMs: options.timeoutMs ?? 90000 });
  } catch (error) {
    if (error instanceof HttpError) {
      throw new ProviderError(`ThreatFox export failed with HTTP ${error.status}.`);
    }
    throw new ProviderError(error instanceof Error ? error.message : "ThreatFox export failed.");
  }
}
