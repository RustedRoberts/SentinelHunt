import { Link } from 'react-router-dom'
import type { Hunt } from '../types/hunt'
import Badge from './Badge'

interface HuntCardProps {
  hunt: Hunt
}

export default function HuntCard({ hunt }: HuntCardProps) {
  return (
    <Link
      to={`/hunt/${hunt.id}`}
      className="block border border-[#2a2a2a] bg-[#1a1a1a] hover:bg-[#1f1f1f] hover:border-zinc-600 rounded-lg p-4 transition-all group"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[#d4ff3f] font-mono text-xs font-medium">{hunt.id}</span>
            <span className="text-zinc-700">·</span>
            <span className="text-zinc-500 font-mono text-xs">{hunt.updated}</span>
          </div>
          <h3 className="font-display font-semibold text-zinc-100 group-hover:text-white leading-snug mb-2">
            {hunt.title}
          </h3>
          <p className="text-zinc-400 text-sm leading-relaxed line-clamp-2">{hunt.summary}</p>

          <div className="flex flex-wrap items-center gap-2 mt-3">
            {hunt.tactics.map(t => (
              <Badge key={t} type="tactic" value={t} />
            ))}
            {hunt.techniques.map(t => (
              <span key={t.id} className="font-mono text-xs text-zinc-500">
                {t.id}
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          <Badge type="maturity" value={hunt.maturity} />
          <Badge type="signal" value={hunt.signal} />
          <Badge type="methodology" value={hunt.methodology} />
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-[#242424] flex flex-wrap gap-2">
        {hunt.dataSources.map(ds => (
          <span key={ds.table} className="text-xs font-mono text-zinc-600 flex items-center gap-1">
            <span
              className={['w-1.5 h-1.5 rounded-full', ds.required ? 'bg-zinc-500' : 'bg-zinc-700'].join(' ')}
            />
            {ds.table}
          </span>
        ))}
      </div>
    </Link>
  )
}
