import type { Plugin, ViteDevServer } from 'vite'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve, join } from 'node:path'
import yaml from 'js-yaml'

const VIRTUAL_ID = 'virtual:work-instruction-data'
const RESOLVED_ID = '\0' + VIRTUAL_ID

function buildModule(dir: string): string {
  const files = readdirSync(dir)
    .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))
    .sort()

  const items = files.map(file => yaml.load(readFileSync(join(dir, file), 'utf-8')))
  return `export default ${JSON.stringify(items)}`
}

export function workInstructionsPlugin(): Plugin {
  let dir: string

  return {
    name: 'vite-plugin-work-instructions',

    configResolved(config) {
      dir = resolve(config.root, 'content/work-instructions')
    },

    resolveId(id) {
      if (id === VIRTUAL_ID) return RESOLVED_ID
    },

    load(id) {
      if (id !== RESOLVED_ID) return undefined

      const files = readdirSync(dir)
        .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))
        .map(f => join(dir, f))

      for (const f of files) this.addWatchFile(f)

      return buildModule(dir)
    },

    configureServer(server: ViteDevServer) {
      server.watcher.add(join(dir, '*.yaml'))
      server.watcher.on('change', file => {
        if (file.includes('work-instructions') && file.endsWith('.yaml')) {
          const mod = server.moduleGraph.getModuleById(RESOLVED_ID)
          if (mod) server.moduleGraph.invalidateModule(mod)
          server.ws.send({ type: 'full-reload' })
        }
      })
    },
  }
}
