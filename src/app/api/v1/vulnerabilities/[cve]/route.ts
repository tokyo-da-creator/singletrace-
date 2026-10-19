import { readApi } from "@/lib/api";
import { getVulnerability } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request, context: { params: Promise<{ cve: string }> }) {
  return readApi(request, async (db) => {
    const { cve } = await context.params;
    const row = await getVulnerability(db, decodeURIComponent(cve));
    if (!row) return { found: false };
    return { found: true, vulnerability: row };
  });
}
