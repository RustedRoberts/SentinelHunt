import Layout from '../components/Layout'
import Badge from '../components/Badge'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2 className="font-display text-2xl font-semibold text-zinc-100 mb-4">{title}</h2>
      {children}
    </section>
  )
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-5">{children}</div>
  )
}

function ClassItem({
  badge,
  type,
  title,
  body,
}: {
  badge: string
  type: 'maturity' | 'signal' | 'methodology'
  title: string
  body: string
}) {
  return (
    <div className="flex gap-4 py-4 border-b border-[#2a2a2a] last:border-0">
      <div className="shrink-0 pt-0.5">
        <Badge type={type} value={badge} />
      </div>
      <div>
        <div className="text-sm font-medium text-zinc-200 mb-1">{title}</div>
        <div className="text-sm text-zinc-400 leading-relaxed">{body}</div>
      </div>
    </div>
  )
}

export default function Methodology() {
  return (
    <Layout>
      <div className="max-w-3xl">
        <div className="mb-12">
          <h1 className="font-display text-4xl font-bold text-zinc-100 mb-3">Methodology</h1>
          <p className="text-zinc-400 text-lg leading-relaxed">
            SentinelHunt is a library of threat hunts I've built and curated, written
            in a consistent YAML schema so each one can be picked up, understood, and
            run without having to reverse-engineer the author's intent. The hunts here
            lean heavily on Microsoft Sentinel and Defender for Endpoint telemetry, with
            a focus on Entra ID identity threats, endpoint behaviour, and lateral movement.
            Every classification, signal rating, and tuning note on this page exists for one
            reason: so you can decide whether a hunt fits your environment before you run it.
          </p>
        </div>

        <Section title="What Is a Hunt?">
          <Card>
            <p className="text-zinc-300 leading-relaxed mb-4">
              A hunt in this library is a self-contained artefact: a detection hypothesis,
              one or more runnable queries, investigation guidance, and enough context for
              an analyst to understand what they're looking for and why.
              Each one is written to be picked up cold and put to use in a single triage session.

              Hunts are not alerts. They are analytical starting points.
              The goal is to produce a finding worth investigating further,
              not a high-confidence detection event.
            </p>
            <p className="text-zinc-400 leading-relaxed">
              A good hunt narrows the haystack rather than pointing at a single
              needle - it should leave you with a manageable result set and clear
              guidance on how to confirm or rule out each finding.
              Hunts that consistently produce low-volume, high-fidelity results are
              candidates for promotion to the analytics layer, but until that point,
              expect to apply analyst judgement to every result.
            </p>
          </Card>
        </Section>

        <Section title="Methodology Classification">
          <p className="text-zinc-400 mb-4 leading-relaxed">
            Each hunt is classified by its underlying detection methodology. This classification helps
            analysts understand the nature of the signal and its tuning expectations.
          </p>
          <Card>
            <ClassItem
              badge="Signature"
              type="methodology"
              title="Signature"
              body="Matches known-bad indicators: specific command strings, hashes, IOCs, or rule-based patterns derived from threat intelligence. High precision, low coverage — misses unknown variants."
            />
            <ClassItem
              badge="Behavioural"
              type="methodology"
              title="Behavioural"
              body="Detects patterns of activity characteristic of a technique regardless of specific tooling. More robust to attacker variation. Requires careful baselining to manage false-positive volume."
            />
            <ClassItem
              badge="Anomaly"
              type="methodology"
              title="Anomaly"
              body="Surfaces deviations from established baselines — rare processes, unusual volumes, first-seen relationships. Detection quality is directly proportional to baseline quality."
            />
            <ClassItem
              badge="Statistical"
              type="methodology"
              title="Statistical"
              body="Uses aggregations, ratios, and statistical measures to identify outliers in population data. Effective for discovery-phase techniques like port scanning and credential stuffing."
            />
            <ClassItem
              badge="ThreatIntel"
              type="methodology"
              title="Threat Intelligence"
              body="Driven by structured threat intelligence — actor TTPs, campaign infrastructure, malware family characteristics. Highly targeted; requires an active intel feed to remain current."
            />
          </Card>
        </Section>

        <Section title="Maturity Levels">
          <p className="text-zinc-400 mb-4 leading-relaxed">
            Maturity reflects the operational confidence we have in a hunt based on field validation
            and tuning history.
          </p>
          <Card>
            <ClassItem
              badge="Exploratory"
              type="maturity"
              title="Exploratory"
              body="The hypothesis is sound but the query has not been validated against production telemetry. Treat as a starting point — expect tuning before operational use. False-positive rate is unknown."
            />
            <ClassItem
              badge="Validated"
              type="maturity"
              title="Validated"
              body="The hunt has been run against real data and the query produces expected results with an understood false-positive profile. Suitable for scheduled execution with analyst triage."
            />
            <ClassItem
              badge="Promoted"
              type="maturity"
              title="Promoted"
              body="Sufficiently refined to operate as a detection rule with minimal analyst triage overhead. The hunt has been promoted to the analytics layer in at least one environment."
            />
          </Card>
        </Section>

        <Section title="Signal Strength">
          <p className="text-zinc-400 mb-4 leading-relaxed">
            Signal strength is a qualitative assessment of expected result fidelity in a well-tuned
            environment.
          </p>
          <Card>
            <ClassItem
              badge="Low"
              type="signal"
              title="Low"
              body="High volume of expected results requiring significant analyst time to triage. Useful for proactive hunting sessions with dedicated analyst hours, not for automated alerting."
            />
            <ClassItem
              badge="Medium"
              type="signal"
              title="Medium"
              body="Moderate result volume with a reasonable true-positive rate in a baselining environment. Suitable for scheduled hunts with defined triage SLAs."
            />
            <ClassItem
              badge="High"
              type="signal"
              title="High"
              body="Low result volume with high confidence. Events matching this hunt warrant immediate investigation. In promoted hunts, High signal maps to P2 or P1 alert severity."
            />
          </Card>
        </Section>

        <Section title="Schema Reference">
          <p className="text-zinc-400 mb-4 leading-relaxed">
            Each hunt YAML file conforms to a documented schema. The
            following fields are defined:
          </p>
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2a2a2a]">
                  <th className="text-left px-4 py-2 text-zinc-500 font-medium text-xs uppercase tracking-wider">Field</th>
                  <th className="text-left px-4 py-2 text-zinc-500 font-medium text-xs uppercase tracking-wider">Type</th>
                  <th className="text-left px-4 py-2 text-zinc-500 font-medium text-xs uppercase tracking-wider">Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['id', 'string', 'Unique identifier, format HL-NNN'],
                  ['title', 'string', 'Human-readable hunt title'],
                  ['summary', 'string', 'One-paragraph summary for list views'],
                  ['hypothesis', 'markdown', 'Full detection hypothesis — the "why"'],
                  ['tactics', 'string[]', 'ATT&CK tactic names'],
                  ['techniques', '{id, name}[]', 'ATT&CK technique identifiers and names'],
                  ['methodology', 'enum', 'Signature | Behavioural | Anomaly | Statistical | ThreatIntel'],
                  ['maturity', 'enum', 'Exploratory | Validated | Promoted'],
                  ['signal', 'enum', 'Low | Medium | High'],
                  ['dataSources', '{product, table, required}[]', 'Required and optional telemetry sources'],
                  ['implementations', '{platform, language, query}[]', 'Runnable queries per platform'],
                  ['investigationSteps', 'string[]', 'Numbered markdown steps for analysts'],
                  ['falsePositives', 'string[]', 'Known benign scenarios'],
                  ['whatYoullSee', 'markdown', 'Description of true positive indicators'],
                  ['curatorNotes', 'markdown', 'Tuning and operational guidance'],
                  ['references', '{label, url}[]', 'External references and attribution'],
                  ['relatedHunts', 'string[]', 'Related hunt IDs'],
                ].map(([field, type, desc]) => (
                  <tr key={field} className="border-b border-[#242424] last:border-0">
                    <td className="px-4 py-2 font-mono text-[#d4ff3f] text-xs">{field}</td>
                    <td className="px-4 py-2 font-mono text-zinc-500 text-xs">{type}</td>
                    <td className="px-4 py-2 text-zinc-400 text-xs">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>

        <Section title="Curation Philosophy">
          <div className="space-y-4 text-zinc-400 leading-relaxed">
            <p>
              Every hunt in this library is held to three principles: it has to be runnable, honest, and maintained.
            </p>
            <p>
              Runnable means the queries work as written against the data sources listed.

              No half-finished implementations, no placeholder table names, no dependencies
              hidden in the prose. If a hunt needs an external data source (externaldata() calls
              reaching out over HTTPS, for example) or a specific feature enabled
              (UEBA IdentityInfo, EntraOps classification data, Defender for Endpoint
              advanced hunting tables), that requirement is called out in the curator
              notes - not buried in a comment three-quarters of the way down the query.

              The point is to prevent silent failures the first time someone runs the hunt in their own tenant.
            </p>
            <p>
              Honest means a hunt's limitations are documented as clearly as its strengths. False positives are listed explicitly.
              Maturity and signal ratings reflect what I've actually seen in the field, not what I'd like them to be.
              If a hunt only catches a narrow variant of a technique, the hypothesis says so.
              Where evidence of efficacy is incomplete, the maturity level reflects that - there's no value in a library that overpromises.
            </p>
            <p>
              Maintained means I revisit hunts periodically to update them based on new intelligence, feedback from the field, and changes in the threat landscape.
              If a hunt becomes obsolete due to changes in attacker TTPs or platform telemetry, I'll mark it as such and archive it.
              If a hunt can be improved with new data sources or refined queries, I'll make those updates and bump the maturity level accordingly.
              The goal is to keep this library evergreen and relevant, not a static snapshot of my knowledge at a single point in time.
            </p>
            <p>
              This curation philosophy ensures that every hunt in the library is a reliable tool for analysts, providing them with the confidence to use these queries in their own environments.
            </p>
          </div>
        </Section>
      </div>
    </Layout>
  )
}
