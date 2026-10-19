import Link from "next/link";
import { Shell } from "@/components/shell";

export default function NotFound() {
  return (
    <Shell>
      <p className="text-[13px] text-muted">
        That page is not part of SignalTrace. Return to the <Link className="underline" href="/">observatory</Link>.
      </p>
    </Shell>
  );
}
