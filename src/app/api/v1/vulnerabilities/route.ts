import { parsePage, readApi } from "@/lib/api";
import { listVulnerabilities } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(request, (db, params) => listVulnerabilities(db, parsePage(params)));
}
