import { createHash, timingSafeEqual } from "crypto";

const BASE_HEADERS: { key: string; value: string }[] = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

// Map tiles and workers are allowed. Inline scripts stay because Next.js
// emits them. Frame embedding is denied. HSTS belongs on the reverse proxy.
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://tiles.openfreemap.org https://*.openfreemap.org",
  "font-src 'self' data:",
  "connect-src 'self' https://tiles.openfreemap.org https://*.openfreemap.org",
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

export function securityHeaders(): { key: string; value: string }[] {
  const headers = [...BASE_HEADERS];
  if (process.env.NODE_ENV === "production") {
    headers.push({ key: "Content-Security-Policy", value: CONTENT_SECURITY_POLICY });
  }
  return headers;
}

export function secretsEqual(left: string, right: string): boolean {
  const a = createHash("sha256").update(left).digest();
  const b = createHash("sha256").update(right).digest();
  return timingSafeEqual(a, b);
}

const REFERENCE_HOSTS = new Set([
  "threatfox.abuse.ch",
  "urlhaus.abuse.ch",
  "bazaar.abuse.ch",
  "nvd.nist.gov",
  "cisa.gov",
  "www.cisa.gov",
  "viz.greynoise.io",
  "www.greynoise.io",
  "malpedia.caad.fkie.fraunhofer.de",
  "www.virustotal.com",
  "virustotal.com",
  "github.com",
  "gist.github.com",
]);

export type SafeLink = { kind: "link"; href: string } | { kind: "text"; text: string };

// Malware URLs and unknown hosts are shown as text. Only known reference
// sites become links, so the interface never fetches or navigates to a payload.
export function safeReference(raw: string | null | undefined): SafeLink | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { kind: "text", text: trimmed };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { kind: "text", text: trimmed };
  }
  url.username = "";
  url.password = "";
  url.hash = "";
  if (!REFERENCE_HOSTS.has(url.hostname.toLowerCase())) {
    return { kind: "text", text: trimmed };
  }
  return { kind: "link", href: url.toString() };
}

export function clientKey(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim();
  const value = first || headers.get("x-real-ip") || "local";
  return value.slice(0, 80);
}
