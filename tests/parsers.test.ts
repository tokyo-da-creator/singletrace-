import { describe, expect, it } from "vitest";
import { parseCisaKev } from "@/lib/providers/cisa";
import { parseGreyNoiseCommunity } from "@/lib/providers/greynoise";
import { parseNvdCve } from "@/lib/providers/nvd";
import { parseThreatFoxCsv } from "@/lib/providers/threatfox";
import { parseUrlhausCsv } from "@/lib/providers/urlhaus";
import { ProviderError } from "@/lib/types";
import { fixture } from "./helpers";

describe("provider parsers", () => {
  it("normalizes the ThreatFox fixture", () => {
    const parsed = parseThreatFoxCsv(fixture("threatfox-sample.csv"), Date.parse("2026-02-01T00:00:00Z"));
    expect(parsed.records).toHaveLength(3);
    expect(parsed.sourceUpdatedAt).toBe("2026-01-15T12:00:00Z");
    const ip = parsed.records[0];
    expect(ip.indicatorNormalized).toBe("203.0.113.10");
    expect(ip.port).toBe(443);
    expect(ip.category).toBe("reported_ioc");
    expect(ip.confidenceOrigin).toBe("threatfox");
    expect(ip.derivedLabel).toBe("botnet");
    expect(ip.derivedLabelOrigin).toBe("signaltrace.family_heuristic.v1");
    expect(parsed.records[1].indicatorNormalized).toBe("malware.example");
    expect(parsed.records[2].indicatorType).toBe("sha256");
  });

  it("keeps URLhaus payloads unlinkable and records the embedded host", () => {
    const parsed = parseUrlhausCsv(fixture("urlhaus-sample.csv"), Date.parse("2026-02-01T00:00:00Z"));
    expect(parsed.records).toHaveLength(1);
    const row = parsed.records[0];
    expect(row.category).toBe("malware_distribution");
    expect(row.malwareFamily).toBeNull();
    expect(row.referenceUrl).toBe("https://urlhaus.abuse.ch/url/800001/");
    expect(row.extras).toEqual([{ type: "domain", value: "malware.example", relationship: "embedded_host" }]);
    expect(row.summary).not.toContain("http://malware.example");
  });

  it("plots KEV on the catalog date as a disclosure", () => {
    const parsed = parseCisaKev(JSON.parse(fixture("cisa-sample.json")));
    expect(parsed.observations[0]).toMatchObject({
      recordKind: "disclosure",
      category: "vulnerability_disclosure",
      observedAt: "2099-01-01T00:00:00.000Z",
      indicatorNormalized: "CVE-2099-0001",
    });
    expect(() => parseCisaKev({ catalogVersion: "x", dateReleased: "y", count: 1, vulnerabilities: [] })).not.toThrow();
    expect(() => parseCisaKev({ count: 1 })).toThrow(ProviderError);
  });

  it("reads GreyNoise and NVD fixtures", () => {
    const noise = parseGreyNoiseCommunity(JSON.parse(fixture("greynoise-sample.json")));
    expect(noise.classification).toBe("unknown");
    const nvd = parseNvdCve(JSON.parse(fixture("nvd-sample.json")), "CVE-2099-0001");
    expect(nvd.cvssScore).toBe(5.3);
    expect(nvd.cvssVersion).toBe("3.1");
    expect(nvd.published).toBe("2099-01-02T00:00:00.000Z");
    expect(nvd.description).toMatch(/Simulated/);
  });
});
