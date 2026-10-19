import { readApi } from "@/lib/api";
import { getProviders } from "@/lib/queries/dashboard";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request) {
  return readApi(
    request,
    async (db) => {
      const providers = await getProviders(db);
      const failing = providers.some((provider) => provider.status === "failing");
      return {
        status: failing ? "degraded" : "ok",
        providers: providers.map((provider) => ({
          id: provider.id,
          status: provider.status,
          lastSuccessAt: provider.lastSuccessAt,
          age: provider.age,
          configured: provider.configured,
        })),
      };
    },
    { cache: "no-store" },
  );
}
