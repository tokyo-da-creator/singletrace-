import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Database } from "@/lib/db/client";
import { parseFilters } from "@/lib/filters";
import { ingestProvider } from "@/lib/ingest/run";
import { upsertObservations, upsertVulnerabilities } from "@/lib/ingest/store";
import { investigate } from "@/lib/queries/investigate";
import { getActivity, getMetrics } from "@/lib/queries/dashboard";
import type { NormalizedVuln } from "@/lib/types";
import { fixture, memoryDb, sampleRecord } from "./helpers";

let db: Database;

beforeAll(async () => {
  db = await memoryDb();
});

afterAll(async () => {
  await db.close();
});

function vuln(cveId: string): NormalizedVuln {
  return {
    cveId,
    vendor: "Example",
    product: "Widget",
    name: "Simulated flaw",
    description: "Simulated catalog row.",
    requiredAction: "Update.",
    dateAdded: "2099-01-01",
    dueDate: "2099-02-01",
    knownRansomware: "Unknown",
    cwes: ["CWE-79"],
    notes: "",
    catalogVersion: "2099.01.01",
    raw: { simulated: true },
  };
}

function windowFor(from: string, to: string) {
  return parseFilters(new URLSearchParams({ range: "custom", from, to, source: "threatfox" }), new Date("2026-06-01T00:00:00Z"));
}

describe("storage", () => {
  it("deduplicates on the source id and keeps the first observation time", async () => {
    const first = await upsertObservations(db, "threatfox", [sampleRecord()], "2026-02-01T00:00:00.000Z");
    const second = await upsertObservations(
      db,
      "threatfox",
      [sampleRecord({ observedAt: "2026-03-01T00:00:00.000Z", summary: "Updated simulated summary." })],
      "2026-03-02T00:00:00.000Z",
    );
    expect(first.inserted).toBe(1);
    expect(second.inserted).toBe(0);
    expect(second.updated).toBe(1);
    const rows = await db.query<{ observed_at: string; summary: string; count: number | string }>(
      `SELECT min(observed_at)::text AS observed_at, max(summary) AS summary, count(*)::int AS count
       FROM observations WHERE provider_id = 'threatfox' AND source_record_id = '900001'`,
    );
    expect(Number(rows[0].count)).toBe(1);
    expect(rows[0].summary).toBe("Updated simulated summary.");
    expect(String(rows[0].observed_at)).toContain("2026-01-15");
  });

  it("excludes simulated rows and buckets UTC days", async () => {
    await db.query(
      `INSERT INTO observations (
        provider_id, source_record_id, record_kind, category, event_type, observed_at, collected_at, is_simulated, summary
      ) VALUES ('threatfox', 'sim-1', 'simulation', 'reported_ioc', 'test', '2026-01-15T12:00:00Z', '2026-02-01T00:00:00Z', true, 'simulated')`,
    );
    await upsertObservations(
      db,
      "threatfox",
      [
        sampleRecord({ sourceRecordId: "900010", observedAt: "2026-01-15T23:30:00.000Z" }),
        sampleRecord({ sourceRecordId: "900011", observedAt: "2026-01-16T00:30:00.000Z", indicatorNormalized: "203.0.113.11" }),
      ],
      "2026-02-01T00:00:00.000Z",
    );
    const metrics = await getMetrics(db, windowFor("2026-01-15", "2026-01-16"));
    expect(metrics.records).toBe(3);
    const activity = await getActivity(db, windowFor("2026-01-15", "2026-01-16"));
    const byDay = Object.fromEntries(activity.days.map((day) => [day.day, day.count]));
    expect(byDay["2026-01-15"]).toBe(2);
    expect(byDay["2026-01-16"]).toBe(1);
  });

  it("marks collection gaps from successful runs", async () => {
    await db.query(
      `INSERT INTO ingestion_runs (provider_id, started_at, finished_at, status)
       VALUES ('threatfox', '2026-03-01T01:00:00Z', '2026-03-01T01:05:00Z', 'success'),
              ('threatfox', '2026-03-03T01:00:00Z', '2026-03-03T01:05:00Z', 'success')`,
    );
    const activity = await getActivity(db, windowFor("2026-03-01", "2026-03-03"));
    const status = Object.fromEntries(activity.days.map((day) => [day.day, day.status]));
    expect(status["2026-03-01"]).toBe("zero");
    expect(status["2026-03-02"]).toBe("gap");
    expect(status["2026-03-03"]).toBe("zero");
  });

  it("retires a CVE missing from a later catalog snapshot", async () => {
    await upsertVulnerabilities(db, [vuln("CVE-2099-0001"), vuln("CVE-2099-0002")], "2099-01-02T00:00:00.000Z");
    await upsertVulnerabilities(db, [vuln("CVE-2099-0001")], "2099-01-03T00:00:00.000Z");
    const rows = await db.query<{ cve_id: string; removed: string | null }>(
      `SELECT cve_id, removed_from_catalog_at::text AS removed FROM vulnerabilities ORDER BY cve_id`,
    );
    const removed = Object.fromEntries(rows.map((row) => [row.cve_id, row.removed]));
    expect(removed["CVE-2099-0001"]).toBeNull();
    expect(removed["CVE-2099-0002"]).toContain("2099-01-03");
  });

  it("keeps prior rows when a later feed fails", async () => {
    const header = "# Last updated: 2026-01-20 00:00:00 UTC\n# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, malware_alias, malware_printable, last_seen_utc, confidence_level, is_compromised, reference, tags, anonymous, reporter\n";
    const line = (id: number) =>
      `"2026-01-20 00:00:00", "${id}", "198.51.100.${id - 910000}", "ip", "botnet_cc", "win.mirai", "None", "Mirai", "None", "10", "False", "https://threatfox.abuse.ch/ioc/${id}/", "mirai", "0", "fixture"`;
    const good = `${header}${Array.from({ length: 10 }, (_, index) => line(910001 + index)).join("\n")}\n`;
    const ok = await ingestProvider(db, "threatfox", {
      force: true,
      sleep: async () => undefined,
      fetch: async () => new Response(good, { status: 200 }),
      now: () => new Date("2026-04-01T00:00:00Z"),
    });
    expect(ok.status).toBe("success");
    const before = await db.query<{ count: number | string; success: string | null }>(
      `SELECT (SELECT count(*)::int FROM observations WHERE provider_id = 'threatfox') AS count,
              (SELECT last_success_at::text FROM providers WHERE id = 'threatfox') AS success`,
    );
    const failed = await ingestProvider(db, "threatfox", {
      force: true,
      sleep: async () => undefined,
      fetch: async () => new Response("no", { status: 500 }),
      now: () => new Date("2026-04-01T01:00:00Z"),
    });
    expect(failed.status).toBe("failed");
    const after = await db.query<{ count: number | string; success: string | null; error: string | null }>(
      `SELECT (SELECT count(*)::int FROM observations WHERE provider_id = 'threatfox') AS count,
              (SELECT last_success_at::text FROM providers WHERE id = 'threatfox') AS success,
              (SELECT last_error FROM providers WHERE id = 'threatfox') AS error`,
    );
    expect(Number(after[0].count)).toBe(Number(before[0].count));
    expect(after[0].success).toBe(before[0].success);
    expect(after[0].error).toMatch(/500/);
  });

  it("does not call GreyNoise for a domain and does not store an NVD lookup as an observation", async () => {
    delete process.env.GREYNOISE_API_KEY;
    delete process.env.NVD_API_KEY;
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      return new Response(fixture("nvd-sample.json"), { status: 200 });
    };
    const domain = await investigate(db, "malware.example", { fetch: fetchImpl, sleep: async () => undefined });
    expect(calls).toBe(0);
    expect(domain.greyNoise).toBeNull();
    expect(domain.facts.every((fact) => fact.isCompromised !== undefined)).toBe(true);

    const cve = await investigate(db, "CVE-2099-0001", { fetch: fetchImpl, sleep: async () => undefined });
    expect(calls).toBe(1);
    expect(cve.nvd?.cvssScore).toBe(5.3);
    const observations = await db.query<{ count: number | string }>(
      `SELECT count(*)::int AS count FROM observations WHERE indicator_normalized = 'CVE-2099-0001'`,
    );
    expect(Number(observations[0].count)).toBe(0);
  });
});
