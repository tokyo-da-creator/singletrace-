export function formatNumber(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat("en-US").format(value);
}

export function shortIndicator(value: string | null | undefined, max = 72): string {
  if (!value) return "—";
  if (value.length <= max) return value;
  return `${value.slice(0, Math.max(12, max - 16))}…${value.slice(-12)}`;
}

export function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    reported_ioc: "Reported indicator",
    malware_distribution: "Malware distribution",
    scanner_classification: "Scanner classification",
    vulnerability_disclosure: "Vulnerability disclosure",
    derived: "Derived",
  };
  return labels[category] ?? category;
}

export function kindLabel(kind: string): string {
  const labels: Record<string, string> = {
    observation: "Observation",
    enrichment: "Enrichment",
    disclosure: "Disclosure",
    inference: "Inference",
    simulation: "Simulation",
  };
  return labels[kind] ?? kind;
}

export function sourceLabel(id: string): string {
  const labels: Record<string, string> = {
    threatfox: "ThreatFox",
    urlhaus: "URLhaus",
    cisa_kev: "CISA KEV",
    nvd: "NVD",
    greynoise: "GreyNoise",
    geoip: "ip-api",
    all: "All sources",
  };
  return labels[id] ?? id;
}
