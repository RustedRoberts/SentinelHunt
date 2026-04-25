import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Layout from '../components/Layout'
import { allHunts } from '../lib/hunts'
import type { Hunt } from '../types/hunt'

const TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

interface TechniqueCell {
  id: string
  name: string
  hunts: Hunt[]
  tactic: string
}

function cellColor(count: number): string {
  if (count === 0) return 'bg-[#1a1a1a] text-zinc-700'
  if (count === 1) return 'bg-[#d4ff3f]/15 text-[#d4ff3f]/70 border-[#d4ff3f]/20'
  if (count === 2) return 'bg-[#d4ff3f]/25 text-[#d4ff3f]/90 border-[#d4ff3f]/30'
  return 'bg-[#d4ff3f]/40 text-[#d4ff3f] border-[#d4ff3f]/50'
}

export default function Coverage() {
  const navigate = useNavigate()
  const [tooltip, setTooltip] = useState<TechniqueCell | null>(null)

  const tacticMap = useMemo(() => {
    const map = new Map<string, TechniqueCell[]>()
    for (const tactic of TACTICS) map.set(tactic, [])

    for (const hunt of allHunts) {
      for (const tactic of hunt.tactics) {
        for (const technique of hunt.techniques) {
          const col = map.get(tactic)
          if (!col) continue
          const existing = col.find(c => c.id === technique.id)
          if (existing) {
            if (!existing.hunts.includes(hunt)) existing.hunts.push(hunt)
          } else {
            col.push({ id: technique.id, name: technique.name, hunts: [hunt], tactic })
          }
        }
      }
    }

    return map
  }, [])

  const totalHunts = allHunts.length
  const coveredTactics = Array.from(tacticMap.entries()).filter(([, cells]) => cells.length > 0).length
  const totalTechniques = Array.from(tacticMap.values()).reduce((n, cells) => n + cells.length, 0)

  return (
    <Layout className="pb-20">
      <div className="mb-8">
        <h1 className="font-display text-4xl font-bold text-zinc-100 mb-2">Coverage</h1>
        <p className="text-zinc-400 text-lg max-w-2xl">
          ATT&amp;CK technique coverage across the hunt library. Cell brightness indicates hunt density.
        </p>
        <div className="flex gap-6 mt-4 text-sm text-zinc-500">
          <span>
            <span className="text-zinc-100 font-medium">{totalHunts}</span> hunts
          </span>
          <span>
            <span className="text-zinc-100 font-medium">{coveredTactics}</span> of {TACTICS.length} tactics covered
          </span>
          <span>
            <span className="text-zinc-100 font-medium">{totalTechniques}</span> techniques mapped
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mb-6 text-xs text-zinc-500">
        <span>Coverage:</span>
        {[0, 1, 2, 3].map(n => (
          <span key={n} className="flex items-center gap-1.5">
            <span
              className={['w-4 h-4 rounded border', cellColor(n)].join(' ')}
            />
            <span>{n === 0 ? 'None' : n === 3 ? '3+' : `${n}`}</span>
          </span>
        ))}
      </div>

      {/* Heatmap */}
      <div className="overflow-x-auto">
        <div className="flex gap-3 min-w-max">
          {TACTICS.map(tactic => {
            const cells = tacticMap.get(tactic) ?? []
            const tacticCount = cells.reduce((n, c) => n + c.hunts.length, 0)

            return (
              <div key={tactic} className="w-[140px]">
                <div className="mb-2">
                  <div className="text-xs font-medium text-zinc-400 leading-tight mb-0.5">
                    {tactic}
                  </div>
                  <div className="text-xs font-mono text-zinc-600">
                    {tacticCount > 0 ? `${tacticCount} hunt${tacticCount !== 1 ? 's' : ''}` : 'no coverage'}
                  </div>
                </div>

                <div className="flex flex-col gap-1">
                  {cells.length === 0 ? (
                    <div className="h-8 rounded border border-[#2a2a2a] bg-[#1a1a1a] opacity-30" />
                  ) : (
                    cells
                      .sort((a, b) => b.hunts.length - a.hunts.length)
                      .map(cell => (
                        <button
                          key={cell.id}
                          className={[
                            'w-full text-left px-2 py-1.5 rounded border text-xs font-mono transition-all hover:scale-[1.02]',
                            cellColor(cell.hunts.length),
                          ].join(' ')}
                          onMouseEnter={() => setTooltip(cell)}
                          onMouseLeave={() => setTooltip(null)}
                          onClick={() =>
                            navigate({
                              pathname: '/',
                              search: `?tactic=${encodeURIComponent(tactic)}`,
                            })
                          }
                        >
                          <div className="font-semibold">{cell.id}</div>
                          <div
                            className="truncate opacity-70 font-sans"
                            style={{ fontSize: '0.6rem' }}
                          >
                            {cell.name}
                          </div>
                        </button>
                      ))
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Tooltip / detail panel */}
      {tooltip && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-[#242424] border border-[#3a3a3a] rounded-xl px-5 py-4 shadow-2xl max-w-md w-full z-50">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[#d4ff3f] text-sm font-semibold">{tooltip.id}</span>
            <span className="text-zinc-400 text-sm">{tooltip.name}</span>
          </div>
          <div className="text-xs text-zinc-500 mb-2">{tooltip.tactic}</div>
          <div className="flex flex-col gap-1">
            {tooltip.hunts.map(h => (
              <div key={h.id} className="flex items-center gap-2 text-xs">
                <span className="font-mono text-zinc-500">{h.id}</span>
                <span className="text-zinc-300">{h.title}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Layout>
  )
}
