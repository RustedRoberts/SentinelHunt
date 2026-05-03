import type { Hunt } from '../types/hunt'

const ORDERED_TACTICS = [
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

interface TacticStripProps {
  hunts: Hunt[]
  activeTactic?: string
  onTacticClick: (tactic: string | undefined) => void
}

export default function TacticStrip({ hunts, activeTactic, onTacticClick }: TacticStripProps) {
  const counts = new Map<string, number>()
  for (const h of hunts) {
    for (const t of h.tactics) {
      counts.set(t, (counts.get(t) ?? 0) + 1)
    }
  }

  return (
    <div className="flex gap-px overflow-x-auto pb-1 -mx-1 px-1">
      {ORDERED_TACTICS.map(tactic => {
        const count = counts.get(tactic) ?? 0
        const isActive = activeTactic === tactic
        const hasCoverage = count > 0

        return (
          <button
            key={tactic}
            onClick={() => onTacticClick(isActive ? undefined : tactic)}
            disabled={!hasCoverage}
            title={hasCoverage ? `${count} hunt${count !== 1 ? 's' : ''}` : 'No coverage'}
            className={[
              'flex flex-col items-center gap-1 px-3 py-2 rounded text-xs transition-all min-w-[80px]',
              hasCoverage ? 'cursor-pointer' : 'cursor-default opacity-30',
              isActive
                ? 'bg-[#d4ff3f]/15 text-[#d4ff3f]'
                : hasCoverage
                  ? 'bg-[#1a1a1a] text-zinc-400 hover:text-zinc-100 hover:bg-[#242424]'
                  : 'bg-[#1a1a1a] text-zinc-600',
            ].join(' ')}
          >
            <span
              className={[
                'w-2 h-2 rounded-full',
                isActive ? 'bg-[#d4ff3f]' : hasCoverage ? 'bg-zinc-500' : 'bg-zinc-700',
              ].join(' ')}
            />
            <span className="flex-1 text-center leading-tight font-medium" style={{ fontSize: '0.65rem' }}>
              {tactic}
            </span>
            {hasCoverage && (
              <span className={['font-mono', isActive ? 'text-[#d4ff3f]' : 'text-zinc-500'].join(' ')}>
                {count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
