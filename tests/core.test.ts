import { describe, expect, it } from "vitest";
import { findDeviations } from "@/lib/baseline";
import { parseCsv } from "@/lib/csv";
import { dayStatus } from "@/lib/days";
import { classifyFamily } from "@/lib/family";
import { observationWhere, parseFilters } from "@/lib/filters";
import { layoutWeeks } from "@/lib/grid-layout";
import { HttpError, requestText } from "@/lib/http";
import { isDocumentationIp, isPublicIp, parseIndicator } from "@/lib/indicators";
import { createLimiter } from "@/lib/rate-limit";
import { safeReference, secretsEqual } from "@/lib/security";
import { asDay, parseSourceUtc } from "@/lib/time";

describe("csv", () => {
  it("keeps commas and quotes inside quoted fields", () => {
    expect(parseCsv('"a,b","c""d"\n')[0]).toEqual(["a,b", 'c"d']);
  });
});

describe("indicators", () => {
  it("accepts the supported kinds and rejects control text", () => {
    expect(parseIndicator("CVE-2099-0001").kind).toBe("cve");
    expect(parseIndicator("203.0.113.10").routable).toBe(false);
    expect(parseIndicator("8.8.8.8").routable).toBe(true);
    expect(parseIndicator("203.0.113.10:443").port).toBe(443);
    expect(parseIndicator("malware.example").kind).toBe("domain");
    expect(parseIndicator("http://malware.example/sample").kind).toBe("url");
    expect(parseIndicator("a".repeat(64)).kind).toBe("sha256");
    expect(() => parseIndicator("203.0.113.10'; DROP TABLE observations;--")).toThrow(/recognize/i);
    expect(() => parseIndicator("bad\nvalue")).toThrow(/control character/i);
  });

  it("keeps documentation and private addresses off the public set", () => {
    expect(isDocumentationIp("203.0.113.10")).toBe(true);
    expect(isPublicIp("203.0.113.10")).toBe(false);
    expect(isPublicIp("192.168.1.1")).toBe(false);
    expect(isPublicIp("10.1.1.1")).toBe(false);
    expect(isPublicIp("100.64.0.1")).toBe(false);
    expect(isPublicIp("2001:db8::1")).toBe(false);
    expect(isPublicIp("1.1.1.1")).toBe(true);
  });
});

describe("family heuristic", () => {
  it("uses token boundaries and the source threat type", () => {
    expect(classifyFamily("botnet_cc", "Mirai", null)).toBe("botnet");
    expect(classifyFamily("payload_delivery", null, null)).toBe("payload");
    expect(classifyFamily(null, "Remcos", null)).toBe("rat");
    expect(classifyFamily(null, "curation", null)).toBe("other");
    expect(classifyFamily(null, "beaconing-unrelated", null)).toBe("other");
    expect(classifyFamily(null, "Cobalt Strike", null)).toBe("c2");
  });
});

describe("time and days", () => {
  it("parses source timestamps as UTC", () => {
    expect(parseSourceUtc("2026-01-15 12:00:00")).toBe("2026-01-15T12:00:00Z");
    expect(parseSourceUtc("2026-01-15")).toBe("2026-01-15T00:00:00Z");
    expect(asDay(new Date("2026-10-15T00:00:00.000Z"))).toBe("2026-10-15");
    expect(asDay("2026-10-15T00:00:00.000Z")).toBe("2026-10-15");
  });

  it("separates counts, zeros, gaps, and uncovered days", () => {
    const ingestDays = new Set(["2026-01-15", "2026-01-17"]);
    const bounds = { ingestDays, firstIngestDay: "2026-01-15", lastIngestDay: "2026-01-17" };
    expect(dayStatus({ day: "2026-01-15", count: 3, ...bounds })).toBe("count");
    expect(dayStatus({ day: "2026-01-15", count: 0, ...bounds })).toBe("zero");
    expect(dayStatus({ day: "2026-01-16", count: 0, ...bounds })).toBe("gap");
    expect(dayStatus({ day: "2026-01-14", count: 0, ...bounds })).toBe("none");
    expect(dayStatus({ day: "2026-01-16", count: 0, ingestDays: new Set(), firstIngestDay: null, lastIngestDay: null })).toBe("none");
  });

  it("pads weeks to Sunday", () => {
    const weeks = layoutWeeks([{ day: "2026-01-01" }]);
    expect(weeks).toHaveLength(1);
    expect(weeks[0].cells[4]?.day).toBe("2026-01-01");
    expect(weeks[0].cells[0]).toBeNull();
  });
});

describe("baseline", () => {
  it("flags a jump above a flat median without calling it an attack", () => {
    const series = Array.from({ length: 8 }, (_, index) => ({
      day: `2026-01-${String(index + 1).padStart(2, "0")}`,
      count: index === 7 ? 20 : 1,
      status: "count" as const,
    }));
    const flags = findDeviations(series);
    expect(flags).toHaveLength(1);
    expect(flags[0].rule.toLowerCase()).not.toContain("attack");
    expect(flags[0].count).toBe(20);
  });
});

describe("filters", () => {
  it("keeps search text in parameters", () => {
    const filters = parseFilters(new URLSearchParams({ q: "%' OR 1=1 --", range: "7d", source: "threatfox" }), new Date("2026-02-01T00:00:00Z"));
    const where = observationWhere(filters);
    expect(where.text).toContain("ILIKE");
    expect(where.text).not.toContain("DROP");
    expect(where.text).toContain("is_simulated = false");
    expect(where.params.some((value) => String(value).includes("OR 1=1"))).toBe(true);
    expect(where.params.filter((value) => typeof value === "string").every((value) => !String(value).includes("DROP"))).toBe(true);
  });

  it("rejects an oversized page", () => {
    expect(() => parseFilters(new URLSearchParams({ page: "201" }))).toThrow(/page/i);
    expect(() => parseFilters(new URLSearchParams({ range: "custom", from: "2020-01-01", to: "2026-01-01" }))).toThrow(/400/);
  });
});

describe("http and limits", () => {
  it("retries a 429 and then returns the body", async () => {
    const sleeps: number[] = [];
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (calls === 1) return new Response("slow", { status: 429, headers: { "retry-after": "1" } });
      return new Response("ok", { status: 200 });
    };
    const text = await requestText("https://example.com/feed", {
      fetch: fetchImpl,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      retries: 2,
    });
    expect(text).toBe("ok");
    expect(sleeps).toEqual([1000]);
  });

  it("does not retry a 404", async () => {
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      return new Response("missing", { status: 404 });
    };
    await expect(requestText("https://example.com/missing", { fetch: fetchImpl, sleep: async () => undefined, retries: 2 })).rejects.toBeInstanceOf(HttpError);
    expect(calls).toBe(1);
  });

  it("limits repeated keys", () => {
    const limit = createLimiter(2, 60_000);
    expect(limit("client", 1_000).ok).toBe(true);
    expect(limit("client", 1_100).ok).toBe(true);
    const blocked = limit("client", 1_200);
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.retryAfter).toBeGreaterThan(0);
  });
});

describe("references", () => {
  it("links known evidence hosts and withholds other URLs", () => {
    expect(safeReference("https://threatfox.abuse.ch/ioc/1/")?.kind).toBe("link");
    expect(safeReference("http://malware.example/sample")?.kind).toBe("text");
    expect(safeReference("https://user:secret@nvd.nist.gov/vuln/detail/CVE-2099-0001#frag")).toMatchObject({
      kind: "link",
      href: "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
    });
  });

  it("compares secrets without requiring equal length", () => {
    expect(secretsEqual("alpha", "alpha")).toBe(true);
    expect(secretsEqual("alpha", "alphabet")).toBe(false);
  });
});
