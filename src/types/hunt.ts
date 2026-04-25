export type Methodology = 'Signature' | 'Behavioural' | 'Anomaly' | 'Statistical' | 'ThreatIntel'
export type Maturity = 'Exploratory' | 'Validated' | 'Promoted'
export type Signal = 'Low' | 'Medium' | 'High'

export interface Technique {
  id: string
  name: string
}

export interface DataSource {
  product: string
  table: string
  required: boolean
}

export interface Implementation {
  platform: string
  language: string
  query: string
  highlightedQuery?: string
}

export interface Reference {
  label: string
  url: string
}

export interface Hunt {
  id: string
  title: string
  summary: string
  hypothesis: string
  author: string
  updated: string
  version: string
  tactics: string[]
  techniques: Technique[]
  platforms: string[]
  methodology: Methodology
  maturity: Maturity
  signal: Signal
  dataSources: DataSource[]
  whatYoullSee: string
  investigationSteps: string[]
  falsePositives: string[]
  curatorNotes: string
  references: Reference[]
  implementations: Implementation[]
  relatedHunts: string[]
}
