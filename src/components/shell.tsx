import Link from "next/link";

const LINKS = [
  { href: "/", label: "Observatory" },
  { href: "/investigate", label: "Investigate" },
  { href: "/sources", label: "Sources" },
  { href: "/methodology", label: "Methodology" },
  { href: "/reference", label: "API" },
];

export function Shell({
  children,
  freshness,
}: {
  children: React.ReactNode;
  freshness?: string;
}) {
  return (
    <div className="min-h-screen">
      <a className="skip" href="#content">
        Skip to content
      </a>
      <div className="h-0.5 bg-accent" />
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
          <Link href="/" className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 bg-accent" aria-hidden="true" />
            <span className="font-mono text-[13px] tracking-[0.18em]">SIGNALTRACE</span>
          </Link>
          <nav className="flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-muted" aria-label="Primary">
            {LINKS.map((link) => (
              <Link key={link.href} href={link.href} className="hover:text-ink">
                {link.label}
              </Link>
            ))}
          </nav>
          <form action="/investigate" className="flex w-full min-w-0 gap-2 sm:ml-auto sm:w-auto sm:min-w-[220px] sm:max-w-sm sm:flex-1" role="search">
            <label className="sr-only" htmlFor="global-q">
              Investigate an indicator
            </label>
            <input
              id="global-q"
              name="q"
              type="search"
              placeholder="IP, domain, hash, CVE"
              className="w-full font-mono"
              autoComplete="off"
              spellCheck={false}
            />
            <button type="submit">Open</button>
          </form>
        </div>
        {freshness ? (
          <p className="mx-auto max-w-[1440px] px-4 pb-2 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
            {freshness}
          </p>
        ) : null}
      </header>
      <main id="content" className="mx-auto max-w-[1440px] px-4 py-4">
        {children}
      </main>
      <footer className="mx-auto max-w-[1440px] px-4 pb-8 text-[11px] leading-5 text-muted">
        Indicator reports from abuse.ch ThreatFox and URLhaus, vulnerability status from the CISA KEV catalog, and CVE
        metadata from NIST NVD. IP network locations from{" "}
        <a className="underline decoration-line-strong underline-offset-2" href="https://ip-api.com/">
          ip-api.com
        </a>
        . A marker is not a threat actor&apos;s location. A report is not a confirmed intrusion.
      </footer>
    </div>
  );
}
