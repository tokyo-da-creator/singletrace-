import { readApi } from "@/lib/api";
import { InputError } from "@/lib/indicators";
import { investigate } from "@/lib/queries/investigate";
import { investigateLimiter } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(
    request,
    (db, params) => {
      const q = params.get("q")?.trim() ?? "";
      if (!q) throw new InputError("Provide q with an IP, domain, URL, hash, or CVE.");
      return investigate(db, q);
    },
    { limit: investigateLimiter, cache: "private, max-age=15" },
  );
}
