export type IndicatorKind = "ip" | "domain" | "url" | "md5" | "sha1" | "sha256" | "cve";

export type ParsedIndicator = {
  kind: IndicatorKind;
  value: string;
  normalized: string;
  port: number | null;
  routable: boolean | null;
};

export class InputError extends Error {
  readonly status = 400;
  readonly code = "invalid_input";

  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

function ipv4Parts(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const numbers: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const number = Number(part);
    if (number > 255) return null;
    numbers.push(number);
  }
  return numbers;
}

export function isDocumentationIp(ip: string): boolean {
  const parts = ipv4Parts(ip);
  if (!parts) {
    return ip.toLowerCase().startsWith("2001:db8:");
  }
  const [a, b, c] = parts;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  return false;
}

export function isPublicIp(ip: string): boolean {
  const parts = ipv4Parts(ip);
  if (parts) {
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (isDocumentationIp(ip)) return false;
    return true;
  }
  const nums = parseIpv6(ip);
  if (!nums) return false;
  const [first] = nums;
  if (nums.every((part) => part === 0)) return false;
  if (first === 0 && nums.slice(1, 7).every((part) => part === 0) && nums[7] === 1) return false;
  if ((first & 0xffc0) === 0xfe80) return false;
  if ((first & 0xfe00) === 0xfc00) return false;
  if ((first & 0xff00) === 0xff00) return false;
  if (first === 0x2001 && nums[1] === 0x0db8) return false;
  return true;
}

function parseIpv6(input: string): number[] | null {
  const value = input.toLowerCase().replace(/%.+$/, "");
  if (value.includes(".") || value.split("::").length > 2) return null;
  const halves = value.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 2 && missing < 1) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
  if (groups.length !== 8) return null;
  const nums: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    nums.push(Number.parseInt(group, 16));
  }
  return nums;
}

export function compressIpv6(input: string): string | null {
  const nums = parseIpv6(input);
  if (!nums) return null;
  let bestStart = -1;
  let bestLength = 0;
  let index = 0;
  while (index < nums.length) {
    if (nums[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < nums.length && nums[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const hex = nums.map((part) => part.toString(16));
  if (bestLength < 2) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

export function normalizeIp(input: string): string | null {
  const value = input.trim().toLowerCase().replace(/%.+$/, "");
  const parts = ipv4Parts(value);
  if (parts) return parts.join(".");
  return compressIpv6(value);
}

export function splitHostPort(input: string): { ip: string; port: number } | null {
  const match = input.trim().match(/^(.+):(\d{1,5})$/);
  if (!match) return null;
  const ip = normalizeIp(match[1]);
  const port = Number(match[2]);
  if (!ip || port < 1 || port > 65535) return null;
  return { ip, port };
}

export function normalizeDomain(input: string): string | null {
  const value = input.trim().toLowerCase().replace(/\.$/, "");
  if (!value || value.length > 253 || value.includes(" ") || value.includes("/") || value.includes("*")) return null;
  const labels = value.split(".");
  if (labels.length < 2) return null;
  const valid = labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9-]+$/.test(label) &&
      !label.startsWith("-") &&
      !label.endsWith("-"),
  );
  return valid ? value : null;
}

export function normalizeHash(input: string): { kind: "md5" | "sha1" | "sha256"; value: string } | null {
  const value = input.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(value)) return null;
  if (value.length === 32) return { kind: "md5", value };
  if (value.length === 40) return { kind: "sha1", value };
  if (value.length === 64) return { kind: "sha256", value };
  return null;
}

export function normalizeCve(input: string): string | null {
  const match = input.trim().toUpperCase().match(/^CVE-\d{4}-\d{4,7}$/);
  return match ? match[0] : null;
}

export function normalizeUrl(input: string): string | null {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  url.hash = "";
  url.username = "";
  url.password = "";
  url.hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  return url.toString();
}

export function hostFromUrl(input: string): { kind: "ip" | "domain"; value: string; port: number | null } | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  const ip = normalizeIp(url.hostname);
  if (ip) {
    return { kind: "ip", value: ip, port: url.port ? Number(url.port) : null };
  }
  const domain = normalizeDomain(url.hostname);
  if (!domain) return null;
  return { kind: "domain", value: domain, port: url.port ? Number(url.port) : null };
}

export function parseIndicator(raw: string): ParsedIndicator {
  const input = raw.trim();
  if (!input) throw new InputError("Enter an IP address, domain, URL, file hash, or CVE.");
  if (input.length > 2048) throw new InputError("That indicator is longer than 2048 characters.");
  if (/[\u0000-\u001f]/.test(input)) throw new InputError("The indicator contains a control character.");

  const cve = normalizeCve(input);
  if (cve) return { kind: "cve", value: cve, normalized: cve, port: null, routable: null };

  const hash = normalizeHash(input);
  if (hash) return { kind: hash.kind, value: hash.value, normalized: hash.value, port: null, routable: null };

  if (/^[a-z][a-z0-9+.-]*:/i.test(input)) {
    const url = normalizeUrl(input);
    if (!url) throw new InputError("Only http and https URLs can be investigated. The URL is not fetched.");
    return { kind: "url", value: url, normalized: url, port: null, routable: null };
  }

  const hostPort = splitHostPort(input);
  if (hostPort && ipv4Parts(hostPort.ip)) {
    return {
      kind: "ip",
      value: hostPort.ip,
      normalized: hostPort.ip,
      port: hostPort.port,
      routable: isPublicIp(hostPort.ip),
    };
  }

  const ip = normalizeIp(input);
  if (ip && (ipv4Parts(ip) || parseIpv6(ip))) {
    return { kind: "ip", value: ip, normalized: ip, port: null, routable: isPublicIp(ip) };
  }

  const domain = normalizeDomain(input);
  if (domain) return { kind: "domain", value: domain, normalized: domain, port: null, routable: null };

  const shown = input.length > 80 ? `${input.slice(0, 80)}…` : input;
  throw new InputError(`Could not recognize "${shown}" as an IP address, domain, URL, file hash, or CVE.`);
}

export function indicatorFromSource(
  iocType: string,
  rawValue: string,
): { type: string; value: string; normalized: string | null; port: number | null; extras: { type: string; value: string; relationship: string }[] } {
  const value = rawValue.trim();
  const extras: { type: string; value: string; relationship: string }[] = [];
  if (iocType === "ip:port" || iocType === "ip") {
    const split = splitHostPort(value);
    const ip = split?.ip ?? normalizeIp(value);
    return { type: "ip", value, normalized: ip, port: split?.port ?? null, extras };
  }
  if (iocType === "domain" || iocType === "hostname") {
    return { type: "domain", value, normalized: normalizeDomain(value), port: null, extras };
  }
  if (iocType === "url") {
    const normalized = normalizeUrl(value);
    const host = normalized ? hostFromUrl(normalized) : null;
    if (host) extras.push({ type: host.kind, value: host.value, relationship: "embedded_host" });
    return { type: "url", value, normalized, port: host?.port ?? null, extras };
  }
  if (iocType.includes("md5")) {
    const hash = normalizeHash(value);
    return { type: "md5", value: hash?.value ?? value.toLowerCase(), normalized: hash?.kind === "md5" ? hash.value : null, port: null, extras };
  }
  if (iocType.includes("sha1")) {
    const hash = normalizeHash(value);
    return { type: "sha1", value: hash?.value ?? value.toLowerCase(), normalized: hash?.kind === "sha1" ? hash.value : null, port: null, extras };
  }
  if (iocType.includes("sha256")) {
    const hash = normalizeHash(value);
    return { type: "sha256", value: hash?.value ?? value.toLowerCase(), normalized: hash?.kind === "sha256" ? hash.value : null, port: null, extras };
  }
  const hash = normalizeHash(value);
  if (hash) return { type: hash.kind, value: hash.value, normalized: hash.value, port: null, extras };
  const cve = normalizeCve(value);
  if (cve) return { type: "cve", value: cve, normalized: cve, port: null, extras };
  return { type: iocType || "unknown", value, normalized: null, port: null, extras };
}
