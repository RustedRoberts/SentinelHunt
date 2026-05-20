/// <reference types="vite/client" />

declare module 'virtual:hunt-data' {
  const hunts: import('./types/hunt').Hunt[]
  export default hunts
}

declare module 'virtual:work-instruction-data' {
  const workInstructions: import('./types/work-instruction').WorkInstruction[]
  export default workInstructions
}
