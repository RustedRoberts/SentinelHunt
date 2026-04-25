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
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. SentinelHunt is a curated library
            of threat hunting content designed for practitioners who want structured, hypothesis-driven
            detection development. Every hunt in this library follows a consistent schema and curation
            philosophy described below.
          </p>
        </div>

        <Section title="What Is a Hunt?">
          <Card>
            <p className="text-zinc-300 leading-relaxed mb-4">
              Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt
              ut labore et dolore magna aliqua. A hunt in this library is a self-contained artefact
              combining a detection hypothesis, one or more runnable queries, investigation guidance,
              and enough context for an analyst to understand what they're looking for and why.
            </p>
            <p className="text-zinc-400 leading-relaxed">
              Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
              commodo consequat. Hunts are not alerts — they are analytical starting points. The goal
              is to produce a finding worthy of further investigation, not a high-confidence detection
              event.
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
            Lorem ipsum dolor sit amet. Each hunt YAML file conforms to a documented schema. The
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
              Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
              incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud
              exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
            </p>
            <p>
              Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat
              nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui
              officia deserunt mollit anim id est laborum.
            </p>
            <p>
              Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque
              laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi
              architecto beatae vitae dicta sunt explicabo.
            </p>
          </div>
        </Section>
      </div>
    </Layout>
  )
}
