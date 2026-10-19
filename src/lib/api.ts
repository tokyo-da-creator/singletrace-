import { NextResponse } from "next/server";
import type { Database } from "@/lib/db/client";
import { withDb } from "@/lib/db/client";
import { InputError } from "@/lib/indicators";
import { apiLimiter, type LimitDecision } from "@/lib/rate-limit";
import { clientKey } from "@/lib/security";

export function json(data: unknown, cache = "private, max-age=30"): NextResponse {
  return NextResponse.json(
    { data, meta: { generatedAt: new Date().toISOString() } },
    { headers: { "Cache-Control": cache } },
  );
}

export function errorJson(status: number, code: string, message: string, headers?: Record<string, string>): NextResponse {
  return NextResponse.json({ error: { code, message } }, { status, headers: { "Cache-Control": "no-store", ...headers } });
}

export function parsePage(params: URLSearchParams): { page: number; pageSize: number; q: string | null } {
  const page = Number(params.get("page") || "1");
  const pageSize = Number(params.get("pageSize") || "25");
  if (!Number.isInteger(page) || page < 1 || page > 200) throw new InputError("Page must be between 1 and 200.");
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new InputError("Page size must be between 1 and 100.");
  }
  const q = params.get("q")?.trim() || null;
  if (q && q.length > 200) throw new InputError("Search text cannot exceed 200 characters.");
  return { page, pageSize, q };
}

export async function readApi(
  request: Request,
  handler: (db: Database, params: URLSearchParams) => Promise<unknown>,
  options?: { limit?: (key: string) => LimitDecision; cache?: string },
): Promise<NextResponse> {
  const decision = (options?.limit ?? apiLimiter)(clientKey(request.headers));
  if (!decision.ok) {
    return errorJson(429, "rate_limited", "Too many requests. Wait and try again.", {
      "Retry-After": String(decision.retryAfter),
    });
  }
  try {
    const params = new URL(request.url).searchParams;
    const data = await withDb((db) => handler(db, params));
    return json(data, options?.cache ?? "private, max-age=30");
  } catch (error) {
    if (error instanceof InputError) return errorJson(400, error.code, error.message);
    console.error(JSON.stringify({ event: "api_error", name: error instanceof Error ? error.name : "Error" }));
    return errorJson(500, "internal_error", "The request could not be completed.");
  }
}
