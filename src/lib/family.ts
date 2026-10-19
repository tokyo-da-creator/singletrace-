// Heuristic carried forward from the CyberAttacks Rainmeter calendar.
// It is a SignalTrace label, not a field returned by the source. Keyword
// checks use token boundaries so short names do not match inside longer words.
export const FAMILIES = [
  { id: "botnet", label: "Botnet" },
  { id: "rat", label: "RAT" },
  { id: "c2", label: "C2" },
  { id: "phish", label: "Phish" },
  { id: "stealer", label: "Stealer" },
  { id: "payload", label: "Payload" },
  { id: "other", label: "Other" },
] as const;

export type FamilyId = (typeof FAMILIES)[number]["id"];

export const DERIVED_LABEL_ORIGIN = "signaltrace.family_heuristic.v1";

const STEALER = ["vidar", "lumma", "redline", "stealc", "raccoon", "amos", "meta stealer"];
const RAT = ["asyncrat", "purerat", "remcos", "quasar", "njrat", "warzone", "dcrat", "nanocore", "remus", "resolverrat"];
const PHISH = ["iclickfix", "clickfix", "clearfake"];
const C2 = ["cobalt strike", "adaptix", "vshell", "sliver", "brute ratel", "mythic", "havoc", "beacon"];
const BOT = ["mirai", "mozi", "qakbot", "emotet", "trickbot", "danabot", "gafgyt", "hajime"];

function hasTerm(blob: string, term: string): boolean {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, "i").test(blob);
}

function anyTerm(blob: string, terms: string[]): boolean {
  return terms.some((term) => hasTerm(blob, term));
}

export function classifyFamily(threatType: string | null, malware: string | null, tags: string | null): FamilyId {
  const blob = `${malware ?? ""} ${tags ?? ""}`.toLowerCase();
  if (anyTerm(blob, PHISH)) return "phish";
  if (anyTerm(blob, STEALER)) return "stealer";
  if (anyTerm(blob, RAT)) return "rat";
  if (anyTerm(blob, C2)) return "c2";
  if (anyTerm(blob, BOT)) return "botnet";
  if (threatType === "botnet_cc") return "botnet";
  if (threatType === "payload" || threatType === "payload_delivery") return "payload";
  return "other";
}

export function familyLabel(id: string | null): string {
  return FAMILIES.find((family) => family.id === id)?.label ?? "Other";
}
