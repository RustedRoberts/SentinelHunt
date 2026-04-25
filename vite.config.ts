import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { huntsPlugin } from './hunts-plugin'

export default defineConfig({
  base: '/SentinelHunt/',
  plugins: [react(), huntsPlugin()],
})
