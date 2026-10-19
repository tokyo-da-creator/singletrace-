"use client";

import { Shell } from "@/components/shell";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <Shell>
      <div className="border border-line bg-panel px-3 py-3">
        <h1 className="text-[13px] font-medium">This view could not be rendered.</h1>
        <p className="mt-2 text-[13px] text-muted">The details stay in the server log. Reload, or try the observatory again.</p>
        <button type="button" className="mt-3" onClick={() => reset()}>
          Try again
        </button>
      </div>
    </Shell>
  );
}
