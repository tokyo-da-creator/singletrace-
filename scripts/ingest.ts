import { withDb } from "../src/lib/db/client";
import { ingestAll } from "../src/lib/ingest/run";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

async function main(): Promise<void> {
  const provider = option("provider");
  const outcomes = await withDb((db) =>
    ingestAll(db, {
      only: provider ? provider.split(",").map((item) => item.trim()).filter(Boolean) : undefined,
      force: process.argv.includes("--force"),
      skipGeo: process.argv.includes("--skip-geo"),
    }),
  );

  for (const outcome of outcomes) {
    const error = outcome.error ? `\terror=${outcome.error}` : "";
    const detail = outcome.detail ? `\t${outcome.detail}` : "";
    console.log(
      `${outcome.providerId}\t${outcome.status}\tfetched=${outcome.fetched}\tinserted=${outcome.inserted}\tupdated=${outcome.updated}\tskipped=${outcome.skipped}${error}${detail}`,
    );
  }

  if (outcomes.some((outcome) => outcome.status === "failed")) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Collection failed.";
  console.error(message);
  process.exitCode = 1;
});
