import { readFileSync } from "fs";
import path from "path";
import { createDatabase, type Database } from "@/lib/db/client";
import { migrate } from "@/lib/db/schema";
import type { NormalizedObservation } from "@/lib/types";

export function fixture(name: string): string {
  return readFileSync(path.join(process.cwd(), "fixtures", name), "utf8");
}

export async function memoryDb(): Promise<Database> {
  const db = await createDatabase(":memory:");
  await migrate(db);
  return db;
}

export function sampleRecord(overrides: Partial<NormalizedObservation> = {}): NormalizedObservation {
  return {
    sourceRecordId: "900001",
    recordKind: "observation",
    category: "reported_ioc",
    eventType: "botnet_cc",
    observedAt: "2026-01-15T12:00:00.000Z",
    indicatorType: "ip",
    indicatorValue: "203.0.113.10:443",
    indicatorNormalized: "203.0.113.10",
    port: 443,
    classification: "botnet_cc",
    confidence: 75,
    confidenceOrigin: "threatfox",
    malwareFamily: "Mirai",
    derivedLabel: "botnet",
    derivedLabelOrigin: "signaltrace.family_heuristic.v1",
    tags: "mirai",
    referenceUrl: "https://threatfox.abuse.ch/ioc/900001/",
    summary: "Simulated record for tests.",
    urlStatus: null,
    isCompromised: false,
    raw: { simulated: true },
    extras: [],
    ...overrides,
  };
}
