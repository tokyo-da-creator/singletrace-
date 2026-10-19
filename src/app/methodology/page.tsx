import type { Metadata } from "next";
import { Panel } from "@/components/panel";
import { Shell } from "@/components/shell";

export const metadata: Metadata = { title: "Methodology" };

function Section({ kicker, title, children }: { kicker: string; title: string; children: React.ReactNode }) {
  return (
    <Panel kicker={kicker} title={title}>
      <div className="space-y-3 text-[13px] leading-6 text-muted">{children}</div>
    </Panel>
  );
}

export default function MethodologyPage() {
  return (
    <Shell>
      <div className="mx-auto max-w-3xl space-y-3">
        <Section kicker="Scope" title="What SignalTrace counts">
          <p>
            SignalTrace stores records from specific feeds. A record is a reported indicator, a malware-distribution URL, a catalogued
            vulnerability, or a later enrichment of one of those. It is not a confirmed intrusion, and the sum of those records is not a
            global attack count.
          </p>
          <p>
            The default observatory shows ThreatFox only. URLhaus and the CISA Known Exploited Vulnerabilities catalog are separate
            sources. Choosing every source adds a warning because the mixture is not one kind of event.
          </p>
        </Section>
        <Section kicker="ThreatFox" title="Reported indicators">
          <p>
            Collection reads the public recent CSV at threatfox.abuse.ch. No Auth-Key is sent for that file. Each row is an indicator
            submitted to abuse.ch, with the source&apos;s first-seen time normalized to UTC. The ThreatFox confidence value is kept only when
            it is an integer from 0 to 100, and it is labeled as originating at ThreatFox.
          </p>
          <p>
            The field is_compromised is stored as the reporter&apos;s flag that a legitimate asset was reported, as opposed to dedicated
            infrastructure. SignalTrace does not treat that flag as its own confirmation of a breach. Indicators older than six months
            leave the export. Rows already stored are kept.
          </p>
        </Section>
        <Section kicker="URLhaus" title="Malware-distribution URLs">
          <p>
            Collection reads the public recent CSV. The URL is stored as text. SignalTrace does not request the URL or its payload. The
            only clickable evidence link is the URLhaus report page. Tags are not treated as a malware family name. A family-style label,
            when shown, is the local heuristic and is marked as derived.
          </p>
        </Section>
        <Section kicker="CISA KEV" title="Vulnerability disclosures">
          <p>
            The catalog is a snapshot of vulnerabilities CISA lists as known exploited. The time plotted on the activity grid is midnight
            UTC on the catalog&apos;s dateAdded. That is the day CISA published the entry, not the day SignalTrace observed exploitation.
            These rows use the disclosure kind. They are not drawn on the map.
          </p>
          <p>
            A later complete snapshot that no longer contains a CVE marks that CVE removed. It is not deleted. A snapshot under 100 entries,
            or one whose count field disagrees with the parsed length by more than five, is rejected so a truncated download cannot retire
            the catalog.
          </p>
        </Section>
        <Section kicker="NVD and GreyNoise" title="Investigation only">
          <p>
            Opening a CVE can request NIST NVD metadata. The result is cached for seven days. NVD timestamps without a timezone are stored
            as UTC. CVSS is NVD&apos;s severity score. Without an API key, requests stay inside the public limit of 5 per 30 seconds. NVD
            lookups do not create observatory records.
          </p>
          <p>
            GreyNoise Community is called only for a public IP, only when GREYNOISE_API_KEY is set, and only from an investigation. The
            result is cached for 24 hours. noise means GreyNoise has seen scanning behavior. riot means the address is in its common-business
            dataset. Neither is proof of intrusion. Unauthenticated bulk lookup is not used.
          </p>
        </Section>
        <Section kicker="Place" title="Geographic meaning">
          <p>
            Only public IP literals are sent to ip-api.com. Private, loopback, link-local, multicast, documentation, and IPv4-mapped
            addresses are skipped. Domains are not resolved. A city is shown when the provider returns one. Otherwise the precision is
            country. Results, including failures, are cached for seven days. The map clusters those cached coordinates. A point is the
            network location of the address, not the physical location of a person.
          </p>
        </Section>
        <Section kicker="Time" title="The activity grid">
          <p>
            Days are UTC. A cell with a count contains that many stored records after filters. A zero cell means a collection finished on
            that UTC day and no matching row was stored. A hollow cell means no successful collection covers the day, including days before
            the first collection and after the last. A hatched cell sits between successful collection days when none finished on it.
            Historical first-seen dates inside a feed still count on their own day. Missing telemetry is not evidence that attacks stopped.
          </p>
          <p>
            The color scale is four quantiles of the positive daily counts in the selected window. The trend line leaves uncovered days
            blank. A deviation uses the median and median absolute deviation of up to 14 earlier covered days, and only after seven such
            days exist. The rule is documented on the chart. It is a statistical comparison of record volume.
          </p>
        </Section>
        <Section kicker="Duplicates" title="Identity and retention">
          <p>
            A record is unique per provider and that provider&apos;s own identifier: ThreatFox ioc id, URLhaus id, or CVE id. A later copy
            updates the mutable description and does not move the original observation time. Sample rows whose kind is simulation are
            dropped on ingest and excluded from queries. The minimum interval between collections is 10 minutes for the abuse.ch feeds and
            one hour for KEV. An empty or tiny feed does not advance the last-success time.
          </p>
        </Section>
        <Section kicker="Limits" title="What this cannot say">
          <p>
            There is no sensor inside other people&apos;s networks. Scanning reports, malware URLs, and known-exploited listings answer
            different questions. Confidence, when present, is copied from the source that published it. SignalTrace does not assign threat
            actors, does not score its own confidence, and does not treat a shared malware name as proof of one operator.
          </p>
        </Section>
      </div>
    </Shell>
  );
}
