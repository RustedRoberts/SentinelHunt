import { useEffect, useRef, useState, type FormEvent } from 'react'
import Layout from '../components/Layout'

const WORKER_URL = 'https://cv-chatbot.chrisscott.workers.dev'
const MAX_HISTORY = 10

type ApiMessage = { role: 'user' | 'assistant'; content: string }
type DisplayMessage = { kind: 'user' | 'assistant' | 'system'; text: string }

export default function AskChris() {
  const [history, setHistory] = useState<ApiMessage[]>([])
  const [display, setDisplay] = useState<DisplayMessage[]>([
    { kind: 'system', text: 'Ask about my background, skills, or projects.' },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [display, loading])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const text = input.trim()
    if (!text || loading) return

    const nextHistory: ApiMessage[] = [...history, { role: 'user', content: text }]
    setDisplay((d) => [...d, { kind: 'user', text }])
    setHistory(nextHistory)
    setInput('')
    setLoading(true)

    try {
      const res = await fetch(WORKER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: nextHistory.slice(-MAX_HISTORY) }),
      })
      const data = await res.json().catch(() => null)

      if (res.ok && data?.reply) {
        setDisplay((d) => [...d, { kind: 'assistant', text: data.reply }])
        setHistory((h) => [...h, { role: 'assistant', content: data.reply }])
      } else if (res.status === 429) {
        setDisplay((d) => [
          ...d,
          { kind: 'system', text: 'Too many questions for now - try again in a few minutes.' },
        ])
      } else {
        setDisplay((d) => [...d, { kind: 'system', text: 'Something went wrong - please try again.' }])
      }
    } catch {
      setDisplay((d) => [
        ...d,
        { kind: 'system', text: 'Could not reach the assistant - check your connection and try again.' },
      ])
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="max-w-3xl">
        <div className="mb-8">
          <h1 className="font-display text-4xl font-bold text-zinc-100 mb-3">Ask Chris</h1>
          <p className="text-zinc-400 text-lg leading-relaxed">
            A small assistant that answers questions about my background, skills, and projects
            on my behalf, grounded in my actual CV rather than a generic bio. If it doesn't know
            something, it'll say so.
          </p>
        </div>

        <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg flex flex-col h-[520px] overflow-hidden">
          <div ref={logRef} className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-sm">
            {display.map((m, i) => (
              <div
                key={i}
                className={
                  m.kind === 'system'
                    ? 'text-zinc-500 text-xs'
                    : m.kind === 'user'
                      ? 'text-zinc-300'
                      : 'text-zinc-100'
                }
              >
                {m.kind === 'user' && <span className="text-zinc-600">{'> '}</span>}
                {m.kind === 'assistant' && <span className="text-[#d4ff3f] mr-1">{'#'}</span>}
                <span className="whitespace-pre-wrap break-words">{m.text}</span>
              </div>
            ))}
            {loading && (
              <div>
                <span className="inline-block w-2 h-3.5 bg-[#d4ff3f] animate-pulse align-[-2px]" />
              </div>
            )}
          </div>
          <form onSubmit={handleSubmit} className="flex gap-2 p-3 border-t border-[#2a2a2a]">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={loading}
              placeholder="Ask a question..."
              aria-label="Your question"
              className="flex-1 min-w-0 bg-[#111111] border border-[#2a2a2a] rounded-md px-3 py-2 text-sm font-mono text-zinc-100 focus:outline-none focus:ring-2 focus:ring-[#d4ff3f]/50"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="px-4 rounded-md text-sm font-medium font-mono bg-[#d4ff3f] text-[#111111] hover:bg-[#c2ec2f] disabled:opacity-50 disabled:cursor-default transition-colors"
            >
              send
            </button>
          </form>
        </div>
      </div>
    </Layout>
  )
}
