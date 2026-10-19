import { z } from "zod";
import { HttpError, requestJson, type RequestOptions } from "@/lib/http";
import { isPublicIp } from "@/lib/indicators";
import { ProviderError } from "@/lib/types";

const geoItemSchema = z.object({
  status: z.string(),
  message: z.string().optional(),
  country: z.string().optional(),
  countryCode: z.string().optional(),
  regionName: z.string().optional(),
  city: z.string().optional(),
  lat: z.number().optional(),
  lon: z.number().optional(),
  isp: z.string().optional(),
  org: z.string().optional(),
  as: z.string().optional(),
  query: z.string(),
});

export type GeoResult = {
  ip: string;
  status: "ok" | "fail";
  countryCode: string | null;
  countryName: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  org: string | null;
  precision: "city" | "country" | null;
  message: string | null;
};

const GEO_URL = "http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query";

export function parseGeoBatch(payload: unknown): GeoResult[] {
  if (!Array.isArray(payload)) {
    const message = payload && typeof payload === "object" && "message" in payload ? String(payload.message) : "unexpected response";
    throw new ProviderError(`ip-api batch failed: ${message}`);
  }
  return payload.map((item) => {
    const parsed = geoItemSchema.safeParse(item);
    if (!parsed.success) {
      return {
        ip: "",
        status: "fail" as const,
        countryCode: null,
        countryName: null,
        region: null,
        city: null,
        latitude: null,
        longitude: null,
        asn: null,
        org: null,
        precision: null,
        message: "malformed item",
      };
    }
    const ok = parsed.data.status === "success" && parsed.data.countryCode && parsed.data.lat != null && parsed.data.lon != null;
    return {
      ip: parsed.data.query,
      status: ok ? "ok" : "fail",
      countryCode: ok ? parsed.data.countryCode!.toUpperCase() : null,
      countryName: ok ? parsed.data.country ?? null : null,
      region: ok ? parsed.data.regionName ?? null : null,
      city: ok ? parsed.data.city ?? null : null,
      latitude: ok ? parsed.data.lat! : null,
      longitude: ok ? parsed.data.lon! : null,
      asn: ok ? parsed.data.as ?? null : null,
      org: ok ? parsed.data.org ?? parsed.data.isp ?? null : null,
      precision: ok ? (parsed.data.city ? "city" : "country") : null,
      message: parsed.data.message ?? null,
    };
  });
}

export async function fetchGeoBatch(ips: string[], options: RequestOptions = {}): Promise<GeoResult[]> {
  const publicIps = ips.filter((ip) => isPublicIp(ip)).slice(0, 100);
  if (publicIps.length === 0) return [];
  try {
    const payload = await requestJson(GEO_URL, {
      ...options,
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(publicIps),
      timeoutMs: options.timeoutMs ?? 30000,
      retries: 2,
    });
    return parseGeoBatch(payload).filter((item) => item.ip);
  } catch (error) {
    if (error instanceof HttpError) throw new ProviderError(`ip-api responded HTTP ${error.status}.`);
    throw new ProviderError(error instanceof Error ? error.message : "ip-api request failed.");
  }
}
