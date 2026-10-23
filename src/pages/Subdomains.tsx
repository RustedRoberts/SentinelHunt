import { useRef, useState } from 'react'
import Layout from '../components/Layout'
import {
  fetchCrtShSubdomains,
  normaliseDomain,
  requestScreenshot,
  resolveAll,
  toCsv,
  toHtmlReport,
  type ResolutionStatus,
  type Screenshot,
  type SubdomainResult,
} from '../lib/subdomains'

type Phase = 'idle' | 'crtsh' | 'resolving' | 'done' | 'error'

type ShotState = { state: 'loading' } | { state: 'error'; error: string } | ({ state: 'done' } & Screenshot)

const STATUS_STYLES: Record<ResolutionStatus, string> = {
  resolved: 'text-[#d4ff3f]',
  'no-a-record': 'text-zinc-500',
  nxdomain: 'text-zinc-600',
  error: 'text-red-400',
}

function ScreenshotCell({ shot, onRequest }: { shot?: ShotState; onRequest: () => void }) {
  if (!shot) {
    return (
      <button
        onClick={onRequest}
        className="px-2 py-0.5 rounded text-xs bg-[#111111] border border-[#2a2a2a] text-zinc-300 hover:border-[#d4ff3f] whitespace-nowrap"
      >
        Screenshot
      </button>
    )
  }
  if (shot.state === 'loading') return <span className="text-xs text-zinc-500">Capturing…</span>
  if (shot.state === 'error') {
    return (
      <div className="text-xs">
        <p className="text-red-400 mb-1 font-sans">{shot.error}</p>
        <button onClick={onRequest} className="text-zinc-400 hover:text-[#d4ff3f] underline">Retry</button>
      </div>
    )
  }
  return (
    <a href={shot.screenshot} target="_blank" rel="noopener noreferrer" title="Open full size (link expires after 24 hours)" className="block w-48">
      <img src={shot.screenshot} alt={shot.title || 'Page screenshot'} loading="lazy" className="w-48 rounded border border-[#2a2a2a] hover:border-[#d4ff3f]" />
      <span className="block mt-1 text-xs text-zinc-500 font-sans truncate">
        {shot.statusCode ?? '?'} · {shot.title || 'no title'}
      </span>
    </a>
  )
}

function download(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function Subdomains() {
  const [input, setInput] = useState('')
  const [domain, setDomain] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [error, setError] = useState('')
  const [total, setTotal] = useState(0)
  const [results, setResults] = useState<SubdomainResult[]>([])
  const [resolvedOnly, setResolvedOnly] = useState(false)
  const [shots, setShots] = useState<Record<string, ShotState>>({})
  const abortRef = useRef<AbortController | null>(null)

  async function run(e: React.FormEvent) {
    e.preventDefault()
    const target = normaliseDomain(input)
    if (!target) {
      setPhase('error')
      setError('That doesn’t look like a valid domain, e.g. nuclera.com')
      return
    }
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setDomain(target)
    setResults([])
    setShots({})
    setTotal(0)
    setError('')
    setPhase('crtsh')
    try {
      const names = await fetchCrtShSubdomains(target, controller.signal)
      setTotal(names.length)
      setPhase('resolving')
      await resolveAll(
        names,
        result => setResults(prev => [...prev, result].sort((a, b) => a.name.localeCompare(b.name))),
        controller.signal,
      )
      if (!controller.signal.aborted) setPhase('done')
    } catch (err) {
      if (controller.signal.aborted) return
      setPhase('error')
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function screenshot(host: string) {
    setShots(prev => ({ ...prev, [host]: { state: 'loading' } }))
    try {
      const shot = await requestScreenshot(host)
      setShots(prev => ({ ...prev, [host]: { state: 'done', ...shot } }))
    } catch (err) {
      setShots(prev => ({ ...prev, [host]: { state: 'error', error: err instanceof Error ? err.message : String(err) } }))
    }
  }

  function stop() {
    abortRef.current?.abort()
    setPhase('done')
  }

  const busy = phase === 'crtsh' || phase === 'resolving'
  const resolvedCount = results.filter(r => r.status === 'resolved').length
  const visible = resolvedOnly ? results.filter(r => r.status === 'resolved') : results

  return (
    <Layout className="!max-w-[96rem]">
      <div>
        <div className="mb-10">
          <h1 className="font-display text-4xl font-bold text-zinc-100 mb-3">Subdomain Recon</h1>
          <p className="text-zinc-400 text-lg leading-relaxed">
            Enter a domain to pull every name seen in certificate transparency logs via{' '}
            <a href="https://crt.sh" target="_blank" rel="noopener noreferrer" className="text-[#d4ff3f] hover:underline">crt.sh</a>,
            then resolve each one’s CNAME chain and A records to see where it’s actually hosted.
            Lookups run in your browser using Cloudflare DNS-over-HTTPS. Screenshots are captured by{' '}
            <a href="https://www.firecrawl.dev" target="_blank" rel="noopener noreferrer" className="text-[#d4ff3f] hover:underline">Firecrawl</a>,
            so the hostname is sent to them; screenshot links expire after 24 hours.
          </p>
        </div>

        <form onSubmit={run} className="flex flex-wrap gap-3 mb-6">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="nuclera.com"
            spellCheck={false}
            autoCapitalize="off"
            className="flex-1 min-w-[16rem] bg-[#1a1a1a] border border-[#2a2a2a] rounded px-4 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-[#d4ff3f]"
          />
          {busy ? (
            <button type="button" onClick={stop} className="px-5 py-2 rounded text-sm font-medium bg-[#242424] border border-[#2a2a2a] text-zinc-200 hover:border-zinc-500">
              Stop
            </button>
          ) : (
            <button type="submit" className="px-5 py-2 rounded text-sm font-medium bg-[#d4ff3f] text-[#111111] hover:bg-[#c2eb2f]">
              Look up
            </button>
          )}
        </form>

        {phase === 'crtsh' && (
          <p className="text-sm text-zinc-400 mb-6">Querying crt.sh for {domain}… this can take up to a minute for larger domains.</p>
        )}
        {phase === 'error' && <p className="text-sm text-red-400 mb-6">{error}</p>}

        {(phase === 'resolving' || phase === 'done') && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
              <p className="text-sm text-zinc-400">
                <span className="text-zinc-100 font-medium">{total}</span> names found ·{' '}
                <span className="text-zinc-100 font-medium">{results.length}</span> checked ·{' '}
                <span className="text-[#d4ff3f] font-medium">{resolvedCount}</span> with A records
              </p>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm text-zinc-400">
                  <input type="checkbox" checked={resolvedOnly} onChange={e => setResolvedOnly(e.target.checked)} />
                  A records only
                </label>
                <button
                  disabled={!results.length}
                  onClick={() => download(`${domain}-subdomains.csv`, toCsv(results), 'text/csv')}
                  className="px-3 py-1 rounded text-sm bg-[#1a1a1a] border border-[#2a2a2a] text-zinc-300 hover:border-[#d4ff3f] disabled:opacity-40"
                >
                  CSV
                </button>
                <button
                  disabled={!results.length}
                  onClick={() => download(`${domain}-subdomains.html`, toHtmlReport(domain, results, new Date()), 'text/html')}
                  className="px-3 py-1 rounded text-sm bg-[#1a1a1a] border border-[#2a2a2a] text-zinc-300 hover:border-[#d4ff3f] disabled:opacity-40"
                >
                  HTML report
                </button>
              </div>
            </div>

            <div className="overflow-x-auto bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg">
              <table className="w-full text-sm font-mono">
                <thead>
                  <tr className="text-left text-zinc-500 border-b border-[#2a2a2a]">
                    <th className="px-4 py-2 font-medium">Subdomain</th>
                    <th className="px-4 py-2 font-medium">Status</th>
                    <th className="px-4 py-2 font-medium">CNAME chain</th>
                    <th className="px-4 py-2 font-medium">A records</th>
                    <th className="px-4 py-2 font-medium">Screenshot</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(r => (
                    <tr key={r.name} className="border-b border-[#2a2a2a] last:border-0 align-top">
                      <td className={['px-4 py-2 whitespace-nowrap', STATUS_STYLES[r.status]].join(' ')}>{r.name}</td>
                      <td className="px-4 py-2 text-zinc-500 whitespace-nowrap" title={r.error}>{r.status}</td>
                      <td className="px-4 py-2 text-zinc-400 break-all">{r.cnameChain.join(' → ')}</td>
                      <td className="px-4 py-2 text-zinc-200">
                        {r.aRecords.map(ip => <div key={ip}>{ip}</div>)}
                      </td>
                      <td className="px-4 py-2">
                        {r.status === 'resolved' && <ScreenshotCell shot={shots[r.name]} onRequest={() => screenshot(r.name)} />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </Layout>
  )
}
