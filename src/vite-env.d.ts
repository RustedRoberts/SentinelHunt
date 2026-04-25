/// <reference types="vite/client" />

declare module 'virtual:hunt-data' {
  const hunts: import('./types/hunt').Hunt[]
  export default hunts
}
