import type { Metadata } from "next";
import { Panel } from "@/components/panel";
import { Shell } from "@/components/shell";
import { withDb } from "@/lib/db/client";
import { PROVIDER_CATALOG } from "@/lib/providers/catalog";
import { getProviders } from "@/lib/queries/dashboard";
import { formatUtc } from "@/lib/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Sources" };

export default async function SourcesPage() {
  let providers = PROVIDER_CATALOG.map((item) => ({
    ...item,
    status: item.mode === "on_demand" ? "on_demand" : "unknown",
    lastSuccessAt: null as string | null,
    lastError: null as string | null,
    age: "unavailable",
  }));
  try {
    const health = await withDb((db) => getProviders(db));
    providers = PROVIDER_CATALOG.map((item) => {
      const row = health.find((provider) => provider.id === item.id);
      return {
        ...item,
        status: row?.status ?? "unknown",
        lastSuccessAt: row?.lastSuccessAt ?? null,
        lastError: row?.lastError ?? null,
        age: row?.age ?? "unavailable",
      };
    });
  } catch {
    providers = providers.map((item) => ({ ...item, lastError: "Database unavailable." }));
  }

  return (
    <Shell freshness="Provider status is read from the local collection database">
      <div className="space-y-3">
        <p className="max-w-3xl text-[13px] leading-6 text-muted">
          Each adapter is independent. A failure in one feed does not get replaced with sample data. These sources do not form one attack
          stream, so their records stay in separate categories.
        </p>
        {providers.map((provider) => (
          <Panel key={provider.id} kicker={provider.mode.replace("_", " ")} title={provider.name} extra={<span className="font-mono text-[10px] uppercase text-muted">{provider.status}</span>}>
            <p className="text-[13px] leading-6 text-ink">{provider.measures}</p>
            <dl className="mt-3 grid gap-2 text-[12px] sm:grid-cols-2">
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Attribution</dt>
                <dd>
                  <a className="underline decoration-line-strong underline-offset-2" href={provider.homepage} rel="noreferrer noopener">
                    {provider.attribution}
                  </a>
                </dd>
              </div>
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Last success</dt>
                <dd>{provider.lastSuccessAt ? `${formatUtc(provider.lastSuccessAt)} · ${provider.age}` : "No successful collection"}</dd>
              </div>
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Expected interval</dt>
                <dd>{provider.expectedIntervalSeconds ? `${Math.round(provider.expectedIntervalSeconds / 60)} minutes` : "On demand"}</dd>
              </div>
              <div>
                <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Credential</dt>
                <dd>{provider.requiresKey ? "Requires a server environment variable" : "Public feed, or optional key"}</dd>
              </div>
            </dl>
            <p className="mt-3 text-[12px] leading-5 text-muted">{provider.retentionNote}</p>
            {provider.lastError ? <p className="mt-2 text-[12px] text-amber">{provider.lastError}</p> : null}
          </Panel>
        ))}
      </div>
    </Shell>
  );
}
