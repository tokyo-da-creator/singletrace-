import type { Category } from "@/lib/filters";
import type { FamilyId } from "@/lib/family";

export type RecordKind = "observation" | "enrichment" | "disclosure" | "inference" | "simulation";

export type NormalizedObservation = {
  sourceRecordId: string;
  recordKind: RecordKind;
  category: Category;
  eventType: string;
  observedAt: string;
  indicatorType: string | null;
  indicatorValue: string | null;
  indicatorNormalized: string | null;
  port: number | null;
  classification: string | null;
  confidence: number | null;
  confidenceOrigin: string | null;
  malwareFamily: string | null;
  derivedLabel: FamilyId | null;
  derivedLabelOrigin: string | null;
  tags: string | null;
  referenceUrl: string | null;
  summary: string;
  urlStatus: string | null;
  isCompromised: boolean | null;
  raw: unknown;
  extras: { type: string; value: string; relationship: string }[];
};

export type NormalizedVuln = {
  cveId: string;
  vendor: string;
  product: string;
  name: string;
  description: string;
  requiredAction: string;
  dateAdded: string;
  dueDate: string;
  knownRansomware: string;
  cwes: string[];
  notes: string;
  catalogVersion: string;
  raw: unknown;
};

export class ProviderError extends Error {
  readonly name = "ProviderError";

  constructor(
    message: string,
    readonly code = "provider_error",
  ) {
    super(message);
  }
}

export function rejectSimulated(records: NormalizedObservation[]): {
  kept: NormalizedObservation[];
  dropped: number;
} {
  const kept = records.filter((record) => record.recordKind !== "simulation");
  return { kept, dropped: records.length - kept.length };
}

export function assertMinimumRows(count: number, minimum: number, label: string): void {
  if (count < minimum) {
    throw new ProviderError(`${label} returned ${count} rows, below the safety minimum of ${minimum}. Nothing was replaced.`);
  }
}
