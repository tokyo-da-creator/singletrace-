import { z } from "zod";
import { requestJson, type RequestOptions } from "@/lib/http";
import { ProviderError, type NormalizedObservation, type NormalizedVuln } from "@/lib/types";

export const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const vulnerabilitySchema = z.object({
  cveID: z.string().regex(/^CVE-\d{4}-\d{4,7}$/),
  vendorProject: z.string(),
  product: z.string(),
  vulnerabilityName: z.string(),
  dateAdded: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  shortDescription: z.string(),
  requiredAction: z.string(),
  dueDate: z.string(),
  knownRansomwareCampaignUse: z.string(),
  notes: z.string().optional().default(""),
  cwes: z.array(z.string()).optional().default([]),
});

const catalogSchema = z.object({
  title: z.string().optional(),
  catalogVersion: z.string(),
  dateReleased: z.string(),
  count: z.number().int().nonnegative(),
  vulnerabilities: z.array(vulnerabilitySchema).max(20000),
});

export type CisaParse = {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: NormalizedVuln[];
  observations: NormalizedObservation[];
};

export function parseCisaKev(payload: unknown): CisaParse {
  const parsed = catalogSchema.safeParse(payload);
  if (!parsed.success) {
    throw new ProviderError("CISA KEV catalog did not match the expected schema.");
  }
  const vulnerabilities: NormalizedVuln[] = [];
  const observations: NormalizedObservation[] = [];
  for (const item of parsed.data.vulnerabilities) {
    vulnerabilities.push({
      cveId: item.cveID,
      vendor: item.vendorProject,
      product: item.product,
      name: item.vulnerabilityName,
      description: item.shortDescription,
      requiredAction: item.requiredAction,
      dateAdded: item.dateAdded,
      dueDate: item.dueDate,
      knownRansomware: item.knownRansomwareCampaignUse,
      cwes: item.cwes,
      notes: item.notes,
      catalogVersion: parsed.data.catalogVersion,
      raw: item,
    });
    observations.push({
      sourceRecordId: item.cveID,
      recordKind: "disclosure",
      category: "vulnerability_disclosure",
      eventType: "known_exploited",
      observedAt: `${item.dateAdded}T00:00:00.000Z`,
      indicatorType: "cve",
      indicatorValue: item.cveID,
      indicatorNormalized: item.cveID,
      port: null,
      classification: item.knownRansomwareCampaignUse,
      confidence: null,
      confidenceOrigin: null,
      malwareFamily: null,
      derivedLabel: null,
      derivedLabelOrigin: null,
      tags: item.cwes.join(", ") || null,
      referenceUrl: `https://nvd.nist.gov/vuln/detail/${item.cveID}`,
      summary: `CISA added ${item.cveID} (${item.vendorProject} ${item.product}) to the Known Exploited Vulnerabilities catalog on ${item.dateAdded}.`,
      urlStatus: null,
      isCompromised: null,
      raw: { catalogVersion: parsed.data.catalogVersion, cve: item.cveID },
      extras: [],
    });
  }
  return {
    catalogVersion: parsed.data.catalogVersion,
    dateReleased: parsed.data.dateReleased,
    count: parsed.data.count,
    vulnerabilities,
    observations,
  };
}

export async function fetchCisaKev(options: RequestOptions = {}): Promise<unknown> {
  try {
    return await requestJson(CISA_KEV_URL, { ...options, timeoutMs: options.timeoutMs ?? 60000 });
  } catch (error) {
    throw new ProviderError(error instanceof Error ? error.message : "CISA KEV request failed.");
  }
}
