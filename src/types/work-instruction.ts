export interface RelatedHunt {
  id: string
  label: string
}

export interface WorkInstruction {
  id: string
  title: string
  trigger: string
  relatedHunts: RelatedHunt[]
  steps: string[]
}
