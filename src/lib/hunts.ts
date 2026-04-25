import type { Hunt } from '../types/hunt'
import rawHunts from 'virtual:hunt-data'

export const allHunts: Hunt[] = rawHunts as Hunt[]

export function getHuntById(id: string): Hunt | undefined {
  return allHunts.find(h => h.id === id)
}

export function getAllTactics(): string[] {
  const set = new Set<string>()
  for (const h of allHunts) h.tactics.forEach(t => set.add(t))
  return Array.from(set).sort()
}

export function getTacticCoverage(): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const h of allHunts) {
    for (const t of h.tactics) {
      counts[t] = (counts[t] ?? 0) + 1
    }
  }
  return counts
}

export function getTechniqueCoverage(): Map<string, { name: string; hunts: Hunt[] }> {
  const map = new Map<string, { name: string; hunts: Hunt[] }>()
  for (const h of allHunts) {
    for (const t of h.techniques) {
      const existing = map.get(t.id)
      if (existing) {
        existing.hunts.push(h)
      } else {
        map.set(t.id, { name: t.name, hunts: [h] })
      }
    }
  }
  return map
}
