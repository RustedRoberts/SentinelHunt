import { Link } from 'react-router-dom'
import Layout from '../components/Layout'
import { allWorkInstructions } from '../lib/work-instructions'
import type { WorkInstruction } from '../types/work-instruction'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2 className="font-display text-2xl font-semibold text-zinc-100 mb-4">{title}</h2>
      {children}
    </section>
  )
}

function WorkInstructionCard({ wi }: { wi: WorkInstruction }) {
  return (
    <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-6 mb-4">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <span className="font-mono text-xs text-zinc-500 mr-2">{wi.id}</span>
          <h3 className="font-display text-lg font-semibold text-zinc-100 inline">{wi.title}</h3>
        </div>
      </div>
      <p className="text-sm text-zinc-400 leading-relaxed mb-4">{wi.trigger}</p>
      {wi.relatedHunts.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          {wi.relatedHunts.map(({ id, label }) => (
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
        {wi.steps.map((step, i) => (
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
          <h1 className="font-display text-4xl font-bold text-zinc-100 mb-3">Work Instructions</h1>
          <p className="text-zinc-400 text-lg leading-relaxed">
            Structured work instructions for investigative scenarios surfaced by hunts in the library.
            Each instruction describes the triggering condition, the device-level or log-level
            evidence to gather, and a structured sequence of steps to reach a finding.
            They are designed to be picked up mid-investigation without prior context.
          </p>
        </div>

        <Section title="How to Use These Work Instructions">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-5 text-sm text-zinc-400 leading-relaxed space-y-3">
            <p>
              Each work instruction is linked to one or more hunt library entries. When a hunt produces
              results that warrant deeper device-level investigation, the relevant work instruction
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

        <Section title="Work Instructions">
          {allWorkInstructions.length === 0 ? (
            <div className="bg-[#1a1a1a] border border-dashed border-[#2a2a2a] rounded-lg p-8 text-center">
              <p className="text-zinc-500 text-sm">No work instructions yet.</p>
              <p className="text-zinc-600 text-xs mt-1">
                Add <span className="font-mono">WI-XXX</span> YAML files to{' '}
                <span className="font-mono">content/work-instructions/</span>.
              </p>
            </div>
          ) : (
            allWorkInstructions.map(wi => <WorkInstructionCard key={wi.id} wi={wi} />)
          )}
        </Section>
      </div>
    </Layout>
  )
}
