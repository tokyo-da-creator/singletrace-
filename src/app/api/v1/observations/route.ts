import { readApi } from "@/lib/api";
import { parseFilters } from "@/lib/filters";
import { getFeed } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(request, (db, params) => getFeed(db, parseFilters(params)));
}
