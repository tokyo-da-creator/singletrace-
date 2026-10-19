import { errorJson, json } from "@/lib/api";
import { withDb } from "@/lib/db/client";
import { ingestAll } from "@/lib/ingest/run";
import { apiLimiter } from "@/lib/rate-limit";
import { clientKey, secretsEqual } from "@/lib/security";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const PROVIDERS = new Set(["threatfox", "urlhaus", "cisa_kev", "geoip"]);

export async function POST(request: Request) {
  const secret = process.env.INGEST_SECRET;
  if (!secret) return errorJson(404, "not_found", "HTTP collection is disabled.");
  const given = request.headers.get("x-ingest-secret") ?? "";
  if (!secretsEqual(given, secret)) return errorJson(401, "unauthorized", "Collection secret was rejected.");

  const decision = apiLimiter(clientKey(request.headers));
  if (!decision.ok) {
    return errorJson(429, "rate_limited", "Too many requests. Wait and try again.", { "Retry-After": String(decision.retryAfter) });
  }

  const params = new URL(request.url).searchParams;
  const provider = params.get("provider");
  if (provider && !PROVIDERS.has(provider)) {
    return errorJson(400, "invalid_input", "Provider must be threatfox, urlhaus, cisa_kev, or geoip.");
  }

  try {
    const outcomes = await withDb((db) =>
      ingestAll(db, {
        only: provider ? [provider] : undefined,
        force: params.get("force") === "1",
        skipGeo: params.get("skipGeo") === "1",
      }),
    );
    return json({ outcomes }, "no-store");
  } catch {
    return errorJson(500, "internal_error", "Collection could not be completed.");
  }
}
