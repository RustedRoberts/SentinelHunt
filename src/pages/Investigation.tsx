import { Link } from 'react-router-dom'
import Layout from '../components/Layout'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2 className="font-display text-2xl font-semibold text-zinc-100 mb-4">{title}</h2>
      {children}
    </section>
  )
}

interface PlaybookEntry {
  id: string
  title: string
  trigger: string
  relatedHunts: { id: string; label: string }[]
  steps: string[]
}

const playbooks: PlaybookEntry[] = [
  // Add investigation playbooks here. Example structure:
  // {
  //   id: 'INV-001',
  //   title: 'Repeated Service Crashes — Device Log Investigation',
  //   trigger: 'A hunt surfaces a high volume of service termination events across one or more endpoints.',
  //   relatedHunts: [{ id: 'HL-001', label: 'HL-001 RDP Lateral Movement' }],
  //   steps: [
  //     'Identify the affected device(s) and the crashing service from hunt results.',
  //     'Pull System event logs from the device: filter for Event ID 7034 (service crashed) and 7031 (unexpected termination).',
  //     'Check Application logs for .NET or native exception records timestamped within ±5 minutes of each crash.',
  //     'Review crash dump files under %SystemRoot%\\Minidump or %LocalAppData%\\CrashDumps.',
  //     'Correlate with process creation events (Sysmon EID 1 or DeviceProcessEvents) to identify parent processes.',
  //     'If a pattern emerges, pivot to the related hunt to determine whether lateral movement or persistence is involved.',
  //   ],
  // },
]

function PlaybookCard({ playbook }: { playbook: PlaybookEntry }) {
  return (
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-6 mb-4">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <span className="font-mono text-xs text-zinc-500 mr-2">{playbook.id}</span>
          <h3 className="font-display text-lg font-semibold text-zinc-100 inline">{playbook.title}</h3>
        </div>
      </div>
      <p className="text-sm text-zinc-400 leading-relaxed mb-4">{playbook.trigger}</p>
      {playbook.relatedHunts.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          {playbook.relatedHunts.map(({ id, label }) => (
            <Link
              key={id}
              to={`/hunt/${id}`}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-[#111111] border border-[#2a2a2a] text-[#d4ff3f] hover:border-[#d4ff3f] transition-colors"
            >
              {label}
            </Link>
          ))}
        </div>
      )}
      <ol className="list-decimal list-inside space-y-1.5">
        {playbook.steps.map((step, i) => (
          <li key={i} className="text-sm text-zinc-300 leading-relaxed">{step}</li>
        ))}
      </ol>
    </div>
  )
}

export default function Investigation() {
  return (
    <Layout>
      <div className="max-w-3xl">
        <div className="mb-12">
          <h1 className="font-display text-4xl font-bold text-zinc-100 mb-3">Investigation</h1>
          <p className="text-zinc-400 text-lg leading-relaxed">
            Forensic investigation playbooks for scenarios surfaced by hunts in the library.
            Each playbook describes the triggering condition, the device-level or log-level
            evidence to gather, and a structured sequence of steps to reach a finding.
            They are meant to be picked up mid-incident without prior context.
          </p>
        </div>

        <Section title="How to Use These Playbooks">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-5 text-sm text-zinc-400 leading-relaxed space-y-3">
            <p>
              Each playbook is linked to one or more hunt library entries. When a hunt produces
              results that warrant deeper device-level investigation, the relevant playbook
              describes exactly where to look and what to collect.
            </p>
            <p>
              Steps are written assuming direct access to the endpoint (RDP, live response, or
              Defender for Endpoint's live response console) and to the Sentinel workspace that
              ingests telemetry from it. Where a step requires a specific table or feature,
              that dependency is noted inline.
            </p>
          </div>
        </Section>

        <Section title="Playbooks">
          {playbooks.length === 0 ? (
            <div className="bg-[#1a1a1a] border border-dashed border-[#2a2a2a] rounded-lg p-8 text-center">
              <p className="text-zinc-500 text-sm">No investigation playbooks yet.</p>
              <p className="text-zinc-600 text-xs mt-1">
                Add entries to the <span className="font-mono">playbooks</span> array in{' '}
                <span className="font-mono">src/pages/Investigation.tsx</span>.
              </p>
            </div>
          ) : (
            playbooks.map(pb => <PlaybookCard key={pb.id} playbook={pb} />)
          )}
        </Section>
      </div>
    </Layout>
  )
}
