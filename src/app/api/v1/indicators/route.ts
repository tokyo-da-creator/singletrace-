import { readApi } from "@/lib/api";
import { InputError } from "@/lib/indicators";
import { searchIndicators } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(request, (db, params) => {
    const q = params.get("q")?.trim() ?? "";
    if (!q) throw new InputError("Provide q to search stored indicators.");
    if (q.length > 200) throw new InputError("Search text cannot exceed 200 characters.");
    return searchIndicators(db, q, 25);
  });
}
