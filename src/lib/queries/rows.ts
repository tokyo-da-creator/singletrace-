import { asInt, asIso } from "@/lib/time";

export type StoredObservation = {
  id: string;
  providerId: string;
  sourceRecordId: string;
  recordKind: string;
  category: string;
  eventType: string;
  observedAt: string;
  indicatorType: string | null;
  indicatorValue: string | null;
  indicatorNormalized: string | null;
  port: number | null;
  countryCode: string | null;
  countryName: string | null;
  city: string | null;
  geoPrecision: string | null;
  classification: string | null;
  confidence: number | null;
  confidenceOrigin: string | null;
  malwareFamily: string | null;
  derivedLabel: string | null;
  tags: string | null;
  referenceUrl: string | null;
  summary: string;
  urlStatus: string | null;
  isCompromised: boolean | null;
};

export function mapObservation(row: Record<string, unknown>): StoredObservation {
  return {
    id: String(row.id),
    providerId: String(row.provider_id),
    sourceRecordId: String(row.source_record_id),
    recordKind: String(row.record_kind),
    category: String(row.category),
    eventType: String(row.event_type),
    observedAt: asIso(row.observed_at) ?? "",
    indicatorType: (row.indicator_type as string | null) ?? null,
    indicatorValue: (row.indicator_value as string | null) ?? null,
    indicatorNormalized: (row.indicator_normalized as string | null) ?? null,
    port: row.port == null ? null : asInt(row.port),
    countryCode: (row.country_code as string | null) ?? null,
    countryName: (row.country_name as string | null) ?? null,
    city: (row.city as string | null) ?? null,
    geoPrecision: (row.geo_precision as string | null) ?? null,
    classification: (row.classification as string | null) ?? null,
    confidence: row.confidence == null ? null : asInt(row.confidence),
    confidenceOrigin: (row.confidence_origin as string | null) ?? null,
    malwareFamily: (row.malware_family as string | null) ?? null,
    derivedLabel: (row.derived_label as string | null) ?? null,
    tags: (row.tags as string | null) ?? null,
    referenceUrl: (row.reference_url as string | null) ?? null,
    summary: String(row.summary ?? ""),
    urlStatus: (row.url_status as string | null) ?? null,
    isCompromised: row.is_compromised == null ? null : Boolean(row.is_compromised),
  };
}
