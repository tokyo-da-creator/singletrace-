import { z } from "zod";
import { HttpError, requestJson, type RequestOptions } from "@/lib/http";
import { isPublicIp, normalizeIp } from "@/lib/indicators";
import { ProviderError } from "@/lib/types";

export const greyNoiseCommunitySchema = z.object({
  ip: z.string(),
  noise: z.boolean().optional(),
  riot: z.boolean().optional(),
  classification: z.string().optional(),
  name: z.string().optional(),
  link: z.string().optional(),
  last_seen: z.string().optional(),
  message: z.string().optional(),
});

export type GreyNoiseCommunity = z.infer<typeof greyNoiseCommunitySchema>;

export function parseGreyNoiseCommunity(payload: unknown): GreyNoiseCommunity {
  const parsed = greyNoiseCommunitySchema.safeParse(payload);
  if (!parsed.success) throw new ProviderError("GreyNoise response did not match the community schema.");
  return parsed.data;
}

export async function fetchGreyNoiseCommunity(ip: string, options: RequestOptions = {}): Promise<GreyNoiseCommunity> {
  const key = process.env.GREYNOISE_API_KEY;
  if (!key) throw new ProviderError("GREYNOISE_API_KEY is not set. No GreyNoise lookup was sent.");
  const normalized = normalizeIp(ip);
  if (!normalized || !isPublicIp(normalized)) {
    throw new ProviderError("GreyNoise community lookup accepts a public IP address.");
  }
  try {
    const payload = await requestJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(normalized)}`, {
      ...options,
      headers: { key, Accept: "application/json" },
      timeoutMs: options.timeoutMs ?? 20000,
      retries: 1,
    });
    return parseGreyNoiseCommunity(payload);
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      return {
        ip: normalized,
        noise: false,
        riot: false,
        message: "GreyNoise has no community record for this IP.",
      };
    }
    if (error instanceof HttpError) {
      throw new ProviderError(`GreyNoise responded HTTP ${error.status}.`);
    }
    throw new ProviderError(error instanceof Error ? error.message : "GreyNoise lookup failed.");
  }
}
