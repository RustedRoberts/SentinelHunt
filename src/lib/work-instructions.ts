import type { WorkInstruction } from '../types/work-instruction'
import rawWorkInstructions from 'virtual:work-instruction-data'

export const allWorkInstructions: WorkInstruction[] = rawWorkInstructions as WorkInstruction[]

export function getWorkInstructionById(id: string): WorkInstruction | undefined {
  return allWorkInstructions.find(wi => wi.id === id)
}
