import { useState, useMemo, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import MiniSearch from 'minisearch'
import Layout from '../components/Layout'
import TacticStrip from '../components/TacticStrip'
import HuntCard from '../components/HuntCard'
import FilterBar from '../components/FilterBar'
import { allHunts } from '../lib/hunts'
import type { Hunt, Maturity, Signal } from '../types/hunt'

const miniSearch = new MiniSearch<{ id: string; title: string; summary: string; tacticNames: string; techniqueIds: string; techniqueNames: string }>({
  fields: ['title', 'summary', 'tacticNames', 'techniqueIds', 'techniqueNames'],
  storeFields: ['id'],
  tokenize: text => text.split(/[\s,;:]+/),
  searchOptions: {
    boost: { title: 3, techniqueIds: 2 },
    fuzzy: 0.15,
    prefix: true,
  },
})

miniSearch.addAll(
  allHunts.map(h => ({
    id: h.id,
    title: h.title,
    summary: h.summary,
    tacticNames: h.tactics.join(' '),
    techniqueIds: h.techniques.map(t => t.id).join(' '),
    techniqueNames: h.techniques.map(t => t.name).join(' '),
  })),
)

const allTables = Array.from(
  new Set(allHunts.flatMap(h => h.dataSources.map(ds => ds.table))),
).sort()

interface Filters {
  maturity: Maturity | undefined
  signal: Signal | undefined
  table: string | undefined
}

export default function Home() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('q') ?? '')
  const [activeTactic, setActiveTactic] = useState<string | undefined>(
    searchParams.get('tactic') ?? undefined,
  )
  const [filters, setFilters] = useState<Filters>({
    maturity: (searchParams.get('maturity') as Maturity) ?? undefined,
    signal: (searchParams.get('signal') as Signal) ?? undefined,
    table: searchParams.get('table') ?? undefined,
  })

  useEffect(() => {
    const p: Record<string, string> = {}
    if (query) p['q'] = query
    if (activeTactic) p['tactic'] = activeTactic
    if (filters.maturity) p['maturity'] = filters.maturity
    if (filters.signal) p['signal'] = filters.signal
    if (filters.table) p['table'] = filters.table
    setSearchParams(p, { replace: true })
  }, [query, activeTactic, filters, setSearchParams])

  const results: Hunt[] = useMemo(() => {
    let base: Hunt[]

    if (query.trim()) {
      const ids = new Set(miniSearch.search(query).map(r => r.id as string))
      base = allHunts.filter(h => ids.has(h.id))
    } else {
      base = allHunts
    }

    if (activeTactic) base = base.filter(h => h.tactics.includes(activeTactic))
    if (filters.maturity) base = base.filter(h => h.maturity === filters.maturity)
    if (filters.signal) base = base.filter(h => h.signal === filters.signal)
    if (filters.table) base = base.filter(h => h.dataSources.some(ds => ds.table === filters.table))

    return base
  }, [query, activeTactic, filters])

  return (
    <Layout>
      <div className="mb-10">
        <h1 className="font-display text-4xl font-bold text-zinc-100 mb-2">
          Threat Hunting Library
        </h1>
        <p className="text-zinc-400 text-lg max-w-2xl">
          Curated detection hypotheses, hunting queries, and investigation playbooks for
          Microsoft Sentinel and endpoint telemetry.
        </p>
      </div>

      <div className="mb-6">
        <TacticStrip
          hunts={allHunts}
          activeTactic={activeTactic}
          onTacticClick={t => setActiveTactic(t)}
        />
      </div>

      <div className="mb-5 flex flex-col gap-4">
        <div className="relative">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 w-4 h-4 pointer-events-none"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="search"
            placeholder="Search hunts, techniques (T1021.001), tactics…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            className="w-full bg-[#1a1a1a] border border-[#2a2a2a] focus:border-zinc-500 rounded-lg pl-9 pr-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 outline-none transition-colors"
          />
        </div>

        <FilterBar
          filters={filters}
          availableTables={allTables}
          onChange={setFilters}
        />
      </div>

      <div className="flex items-center justify-between mb-4">
        <span className="text-sm text-zinc-500">
          {results.length} hunt{results.length !== 1 ? 's' : ''}
          {results.length !== allHunts.length && ` of ${allHunts.length}`}
        </span>
      </div>

      {results.length === 0 ? (
        <div className="text-center py-20 text-zinc-600">
          <p className="text-lg mb-1">No hunts match your filters.</p>
          <button
            onClick={() => {
              setQuery('')
              setActiveTactic(undefined)
              setFilters({ maturity: undefined, signal: undefined, table: undefined })
            }}
            className="text-sm text-zinc-500 hover:text-zinc-300 underline underline-offset-2"
          >
            Clear all
          </button>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {results.map(hunt => (
            <HuntCard key={hunt.id} hunt={hunt} />
          ))}
        </div>
      )}
    </Layout>
  )
}
