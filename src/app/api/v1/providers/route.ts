import { readApi } from "@/lib/api";
import { getProviders } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(request, (db) => getProviders(db), { cache: "no-store" });
}
