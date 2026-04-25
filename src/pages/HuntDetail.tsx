import { useState } from 'react'
import { Link, useParams, Navigate } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Layout from '../components/Layout'
import Badge from '../components/Badge'
import { getHuntById, allHunts } from '../lib/hunts'

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      onClick={copy}
      className="text-xs font-mono px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-100 transition-colors"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}

function Prose({ children }: { children: string }) {
  return (
    <div className="prose prose-hunt prose-sm max-w-none">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-xs uppercase tracking-widest text-zinc-500 font-medium mb-3 font-sans">
      {children}
    </h2>
  )
}

export default function HuntDetail() {
  const { id } = useParams<{ id: string }>()
  const hunt = id ? getHuntById(id) : undefined
  const [activeImpl, setActiveImpl] = useState(0)

  if (!hunt) return <Navigate to="/" replace />

  const relatedHunts = hunt.relatedHunts
    .map(rid => allHunts.find(h => h.id === rid))
    .filter((h): h is NonNullable<typeof h> => !!h)

  const impl = hunt.implementations[activeImpl]

  return (
    <Layout>
      <div className="mb-1">
        <Link to="/" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
          ← Library
        </Link>
      </div>

      {/* Header */}
      <header className="mb-8 pb-6 border-b border-[#2a2a2a]">
        <div className="flex items-center gap-2 mb-2">
          <span className="font-mono text-[#d4ff3f] text-sm font-medium">{hunt.id}</span>
          <span className="text-zinc-700">·</span>
          <span className="text-zinc-500 text-sm">v{hunt.version}</span>
          <span className="text-zinc-700">·</span>
          <span className="text-zinc-500 text-sm">{hunt.updated}</span>
          <span className="text-zinc-700">·</span>
          <span className="text-zinc-500 text-sm">{hunt.author}</span>
        </div>
        <h1 className="font-display text-3xl font-bold text-zinc-100 mb-4 leading-tight">
          {hunt.title}
        </h1>
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <Badge type="maturity" value={hunt.maturity} />
          <Badge type="signal" value={hunt.signal} />
          <Badge type="methodology" value={hunt.methodology} />
          {hunt.tactics.map(t => (
            <Badge key={t} type="tactic" value={t} />
          ))}
        </div>
        <p className="text-zinc-300 text-base leading-relaxed max-w-3xl">{hunt.summary}</p>
      </header>

      {/* Hypothesis */}
      <section className="mb-8 p-5 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg border-l-2 border-l-[#d4ff3f]">
        <SectionLabel>Hypothesis</SectionLabel>
        <Prose>{hunt.hypothesis}</Prose>
      </section>

      {/* Techniques */}
      <section className="mb-8">
        <SectionLabel>ATT&amp;CK Techniques</SectionLabel>
        <div className="flex flex-wrap gap-2">
          {hunt.techniques.map(t => (
            <a
              key={t.id}
              href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1a1a] border border-[#2a2a2a] hover:border-zinc-500 rounded text-sm transition-colors group"
            >
              <span className="font-mono text-[#d4ff3f] text-xs">{t.id}</span>
              <span className="text-zinc-300 group-hover:text-zinc-100">{t.name}</span>
            </a>
          ))}
        </div>
      </section>

      {/* Query implementations */}
      {hunt.implementations.length > 0 && (
        <section className="mb-8">
          <SectionLabel>Query Implementations</SectionLabel>
          <div className="border border-[#2a2a2a] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-[#1a1a1a] border-b border-[#2a2a2a]">
              <div className="flex gap-0">
                {hunt.implementations.map((imp, i) => (
                  <button
                    key={i}
                    onClick={() => setActiveImpl(i)}
                    className={[
                      'px-4 py-1.5 text-xs font-mono rounded transition-colors',
                      activeImpl === i
                        ? 'text-[#d4ff3f] bg-[#d4ff3f]/10'
                        : 'text-zinc-400 hover:text-zinc-100',
                    ].join(' ')}
                  >
                    {imp.platform} · {imp.language}
                  </button>
                ))}
              </div>
              {impl && <CopyButton text={impl.query} />}
            </div>
            {impl && (
              impl.highlightedQuery ? (
                <div
                  className="overflow-x-auto"
                  dangerouslySetInnerHTML={{ __html: impl.highlightedQuery }}
                />
              ) : (
                <pre className="bg-[#1a1a1a] p-5 text-sm font-mono text-zinc-300 overflow-x-auto">
                  {impl.query}
                </pre>
              )
            )}
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Data requirements */}
        <div className="md:col-span-1">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-4">
            <SectionLabel>Data Requirements</SectionLabel>
            <ul className="space-y-2">
              {hunt.dataSources.map(ds => (
                <li key={ds.table} className="flex items-start gap-2">
                  <span
                    className={[
                      'mt-1.5 w-1.5 h-1.5 rounded-full shrink-0',
                      ds.required ? 'bg-[#d4ff3f]' : 'bg-zinc-600',
                    ].join(' ')}
                  />
                  <div>
                    <div className="font-mono text-xs text-zinc-100">{ds.table}</div>
                    <div className="text-xs text-zinc-500">
                      {ds.product} · {ds.required ? 'Required' : 'Optional'}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
            <div className="mt-3 pt-3 border-t border-[#242424]">
              <SectionLabel>Platforms</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {hunt.platforms.map(p => (
                  <Badge key={p} type="platform" value={p} />
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* What you'll see + False positives */}
        <div className="md:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-4">
            <SectionLabel>What You'll See</SectionLabel>
            <Prose>{hunt.whatYoullSee}</Prose>
          </div>
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-4">
            <SectionLabel>False Positives</SectionLabel>
            <ul className="space-y-2">
              {hunt.falsePositives.map((fp, i) => (
                <li key={i} className="text-sm text-zinc-400 flex gap-2">
                  <span className="text-zinc-700 shrink-0 mt-0.5">–</span>
                  <span>{fp}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Investigation steps */}
      {hunt.investigationSteps.length > 0 && (
        <section className="mb-8">
          <SectionLabel>Investigation Steps</SectionLabel>
          <ol className="space-y-3">
            {hunt.investigationSteps.map((step, i) => (
              <li key={i} className="flex gap-4">
                <span className="font-mono text-[#d4ff3f] text-sm shrink-0 w-6 text-right">
                  {i + 1}.
                </span>
                <div className="prose prose-hunt prose-sm max-w-none">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{step}</ReactMarkdown>
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}

      {/* Curator's notes */}
      {hunt.curatorNotes && (
        <section className="mb-8 p-5 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg">
          <SectionLabel>Curator's Notes</SectionLabel>
          <Prose>{hunt.curatorNotes}</Prose>
        </section>
      )}

      {/* References */}
      {hunt.references.length > 0 && (
        <section className="mb-8">
          <SectionLabel>References</SectionLabel>
          <ul className="space-y-1.5">
            {hunt.references.map((ref, i) => (
              <li key={i}>
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-zinc-400 hover:text-[#d4ff3f] transition-colors underline underline-offset-2 decoration-zinc-700 hover:decoration-[#d4ff3f]"
                >
                  {ref.label}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Related hunts */}
      {relatedHunts.length > 0 && (
        <section className="mb-8">
          <SectionLabel>Related Hunts</SectionLabel>
          <div className="flex flex-col gap-2">
            {relatedHunts.map(rh => (
              <Link
                key={rh.id}
                to={`/hunt/${rh.id}`}
                className="flex items-center gap-3 p-3 bg-[#1a1a1a] border border-[#2a2a2a] hover:border-zinc-600 rounded-lg transition-colors"
              >
                <span className="font-mono text-[#d4ff3f] text-xs">{rh.id}</span>
                <span className="text-zinc-300 text-sm">{rh.title}</span>
              </Link>
            ))}
          </div>
        </section>
      )}
    </Layout>
  )
}
