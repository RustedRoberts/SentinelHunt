import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { huntsPlugin } from './hunts-plugin'
import { workInstructionsPlugin } from './work-instructions-plugin'
import { blogPlugin } from './blog-plugin'

export default defineConfig({
  base: '/SentinelHunt/',
  plugins: [react(), huntsPlugin(), workInstructionsPlugin(), blogPlugin()],
})
