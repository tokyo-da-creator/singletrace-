import { ingestAll } from "@/lib/ingest/run";
import { logEvent } from "@/lib/log";
import { withDb } from "@/lib/db/client";

let started = false;
let running = false;

export function startScheduler(): void {
  if (started) return;
  if (process.env.NEXT_PHASE === "phase-production-build") return;
  const minutes = Number(process.env.INGEST_INTERVAL_MINUTES ?? "0");
  const onStart = process.env.INGEST_ON_START === "1";
  if ((!Number.isFinite(minutes) || minutes <= 0) && !onStart) return;
  started = true;
  const intervalMs = Math.max(10, minutes) * 60 * 1000;

  const tick = () => {
    if (running) return;
    running = true;
    void withDb((db) => ingestAll(db))
      .catch((error: unknown) => {
        logEvent("ingest_scheduler_failed", { message: error instanceof Error ? error.message : "failed" });
      })
      .finally(() => {
        running = false;
      });
  };

  if (onStart) setTimeout(tick, 15000);
  if (minutes > 0) setInterval(tick, intervalMs);
  logEvent("ingest_scheduler_started", { minutes, onStart });
}
