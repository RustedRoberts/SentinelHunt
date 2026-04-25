import type { Maturity, Signal, Methodology } from '../types/hunt'

const maturityColors: Record<Maturity, string> = {
  Exploratory: 'bg-zinc-800 text-zinc-300',
  Validated: 'bg-blue-950 text-blue-300',
  Promoted: 'bg-[#d4ff3f]/10 text-[#d4ff3f]',
}

const signalColors: Record<Signal, string> = {
  Low: 'bg-zinc-800 text-zinc-400',
  Medium: 'bg-amber-950 text-amber-300',
  High: 'bg-red-950 text-red-400',
}

const methodologyColors: Record<Methodology, string> = {
  Signature: 'bg-zinc-800 text-zinc-300',
  Behavioural: 'bg-purple-950 text-purple-300',
  Anomaly: 'bg-cyan-950 text-cyan-300',
  Statistical: 'bg-indigo-950 text-indigo-300',
  ThreatIntel: 'bg-orange-950 text-orange-300',
}

interface BadgeProps {
  type: 'maturity' | 'signal' | 'methodology' | 'tactic' | 'platform'
  value: string
}

export default function Badge({ type, value }: BadgeProps) {
  let className = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono '

  if (type === 'maturity') className += maturityColors[value as Maturity] ?? 'bg-zinc-800 text-zinc-300'
  else if (type === 'signal') className += signalColors[value as Signal] ?? 'bg-zinc-800 text-zinc-300'
  else if (type === 'methodology') className += methodologyColors[value as Methodology] ?? 'bg-zinc-800 text-zinc-300'
  else if (type === 'tactic') className += 'bg-zinc-800 text-zinc-300 border border-zinc-700'
  else className += 'bg-zinc-800 text-zinc-400'

  return <span className={className}>{value}</span>
}
