import type { Maturity, Signal } from '../types/hunt'

const MATURITIES: Maturity[] = ['Exploratory', 'Validated', 'Promoted']
const SIGNALS: Signal[] = ['Low', 'Medium', 'High']

interface Filters {
  maturity: Maturity | undefined
  signal: Signal | undefined
  table: string | undefined
}

interface FilterBarProps {
  filters: Filters
  availableTables: string[]
  onChange: (filters: Filters) => void
}

function Pill({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={[
        'px-2.5 py-1 rounded text-xs font-medium font-mono transition-colors',
        active
          ? 'bg-[#d4ff3f]/15 text-[#d4ff3f] border border-[#d4ff3f]/30'
          : 'bg-[#1a1a1a] text-zinc-400 border border-[#2a2a2a] hover:border-zinc-600 hover:text-zinc-100',
      ].join(' ')}
    >
      {label}
    </button>
  )
}

export default function FilterBar({ filters, availableTables, onChange }: FilterBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
      <div className="flex items-center gap-2">
        <span className="text-xs text-zinc-600 uppercase tracking-wider font-medium w-16">Maturity</span>
        <div className="flex gap-1.5">
          {MATURITIES.map(m => (
            <Pill
              key={m}
              label={m}
              active={filters.maturity === m}
              onClick={() => onChange({ ...filters, maturity: filters.maturity === m ? undefined : m })}
            />
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <span className="text-xs text-zinc-600 uppercase tracking-wider font-medium w-16">Signal</span>
        <div className="flex gap-1.5">
          {SIGNALS.map(s => (
            <Pill
              key={s}
              label={s}
              active={filters.signal === s}
              onClick={() => onChange({ ...filters, signal: filters.signal === s ? undefined : s })}
            />
          ))}
        </div>
      </div>

      {availableTables.length > 0 && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-600 uppercase tracking-wider font-medium w-16">Table</span>
          <div className="flex flex-wrap gap-1.5">
            {availableTables.map(t => (
              <Pill
                key={t}
                label={t}
                active={filters.table === t}
                onClick={() => onChange({ ...filters, table: filters.table === t ? undefined : t })}
              />
            ))}
          </div>
        </div>
      )}

      {(filters.maturity ?? filters.signal ?? filters.table) && (
        <button
          onClick={() => onChange({ maturity: undefined, signal: undefined, table: undefined })}
          className="text-xs text-zinc-500 hover:text-zinc-300 underline underline-offset-2"
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
