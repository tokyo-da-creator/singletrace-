export type ProviderMode = "scheduled" | "on_demand" | "enrichment";

export type ProviderCatalogItem = {
  id: string;
  name: string;
  kind: string;
  mode: ProviderMode;
  homepage: string;
  attribution: string;
  description: string;
  measures: string;
  retentionNote: string;
  requiresKey: boolean;
  minIntervalSeconds: number;
  expectedIntervalSeconds: number;
};

export const PROVIDER_CATALOG: ProviderCatalogItem[] = [
  {
    id: "threatfox",
    name: "ThreatFox",
    kind: "reported_ioc",
    mode: "scheduled",
    homepage: "https://threatfox.abuse.ch/",
    attribution: "abuse.ch ThreatFox",
    description: "Recent malware indicators from the public ThreatFox CSV export.",
    measures:
      "Indicators of compromise submitted to abuse.ch. A row is a report about an indicator. It is not a confirmed intrusion on a network operated by the reader.",
    retentionNote:
      "ThreatFox stops exposing indicators older than six months through its export. SignalTrace keeps ingested rows and marks that limit on the record.",
    requiresKey: false,
    minIntervalSeconds: 600,
    expectedIntervalSeconds: 1800,
  },
  {
    id: "urlhaus",
    name: "URLhaus",
    kind: "malware_distribution",
    mode: "scheduled",
    homepage: "https://urlhaus.abuse.ch/",
    attribution: "abuse.ch URLhaus",
    description: "Recently reported malware-distribution URLs from the public URLhaus CSV.",
    measures:
      "URLs reported to URLhaus as distributing malware. Presence on the list is a report. SignalTrace does not download the URL or the payload.",
    retentionNote: "The recent CSV is a rolling export. SignalTrace upserts by URLhaus id and does not delete rows that later leave the file.",
    requiresKey: false,
    minIntervalSeconds: 600,
    expectedIntervalSeconds: 1800,
  },
  {
    id: "cisa_kev",
    name: "CISA KEV",
    kind: "vulnerability_disclosure",
    mode: "scheduled",
    homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    attribution: "CISA Known Exploited Vulnerabilities catalog",
    description: "The full CISA Known Exploited Vulnerabilities catalog.",
    measures:
      "Vulnerabilities CISA has listed as known exploited. The date used here is the catalog addition date. It is not the date of an intrusion observed by SignalTrace.",
    retentionNote: "The catalog is a snapshot. Entries missing from a later complete snapshot are marked removed. They are not deleted.",
    requiresKey: false,
    minIntervalSeconds: 3600,
    expectedIntervalSeconds: 12 * 3600,
  },
  {
    id: "geoip",
    name: "ip-api",
    kind: "enrichment",
    mode: "enrichment",
    homepage: "https://ip-api.com/",
    attribution: "ip-api.com",
    description: "City-level network geolocation for public IP indicators.",
    measures:
      "Approximate network location of a public IP address. This is not the physical location of a threat actor, and it is not applied to domain names.",
    retentionNote: "Lookups are cached for seven days. The free endpoint is non-commercial and limited to 45 requests per minute.",
    requiresKey: false,
    minIntervalSeconds: 600,
    expectedIntervalSeconds: 1800,
  },
  {
    id: "nvd",
    name: "NIST NVD",
    kind: "vulnerability_disclosure",
    mode: "on_demand",
    homepage: "https://nvd.nist.gov/developers/vulnerabilities",
    attribution: "NIST National Vulnerability Database",
    description: "CVE metadata retrieved when an analyst opens a CVE.",
    measures:
      "Published vulnerability metadata, including CVSS when NVD provides it. A score is NVD's severity rating, not evidence that the vulnerability was exploited here.",
    retentionNote: "Responses are cached for seven days. Without an API key, requests stay at or below 5 per 30 seconds.",
    requiresKey: false,
    minIntervalSeconds: 0,
    expectedIntervalSeconds: 0,
  },
  {
    id: "greynoise",
    name: "GreyNoise Community",
    kind: "scanner_classification",
    mode: "on_demand",
    homepage: "https://docs.greynoise.io/docs/using-the-greynoise-community-api",
    attribution: "GreyNoise",
    description: "Community IP classification, used only during an investigation when a key is set.",
    measures:
      "Whether GreyNoise has seen an IP scanning the internet, or lists it as a common business service. Scanner classification is not proof of a successful intrusion.",
    retentionNote: "Lookups are cached for 24 hours and are never run in bulk.",
    requiresKey: true,
    minIntervalSeconds: 0,
    expectedIntervalSeconds: 0,
  },
];

export function catalogItem(id: string): ProviderCatalogItem | undefined {
  return PROVIDER_CATALOG.find((item) => item.id === id);
}
