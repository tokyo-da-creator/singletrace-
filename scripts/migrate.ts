import { withDb } from "../src/lib/db/client";

async function main(): Promise<void> {
  await withDb(async () => undefined);
  console.log("Schema is current.");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Migration failed.";
  console.error(message);
  process.exitCode = 1;
});
