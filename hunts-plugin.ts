import type { Plugin, ViteDevServer } from 'vite'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve, join } from 'node:path'
import yaml from 'js-yaml'

const VIRTUAL_ID = 'virtual:hunt-data'
const RESOLVED_ID = '\0' + VIRTUAL_ID

type RawImpl = { platform: string; language: string; query: string }

function langForShiki(language: string): string {
  if (language === 'KQL') return 'kusto'
  if (language === 'SPL') return 'powershell'
  return 'sql'
}

async function buildModule(huntsDir: string): Promise<string> {
  const { createHighlighter } = await import('shiki')
  const highlighter = await createHighlighter({
    themes: ['github-dark'],
    langs: ['kusto', 'sql', 'powershell'],
  })

  const files = readdirSync(huntsDir)
    .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))
    .sort()

  const hunts = files.map(file => {
    const raw = readFileSync(join(huntsDir, file), 'utf-8')
    const hunt = yaml.load(raw) as Record<string, unknown>

    if (Array.isArray(hunt['implementations'])) {
      hunt['implementations'] = (hunt['implementations'] as RawImpl[]).map(impl => ({
        ...impl,
        highlightedQuery: highlighter.codeToHtml(impl.query.trim(), {
          lang: langForShiki(impl.language),
          theme: 'github-dark',
        }),
      }))
    }

    return hunt
  })

  highlighter.dispose()
  return `export default ${JSON.stringify(hunts)}`
}

export function huntsPlugin(): Plugin {
  let huntsDir: string

  return {
    name: 'vite-plugin-hunts',

    configResolved(config) {
      huntsDir = resolve(config.root, 'content/hunts')
    },

    resolveId(id) {
      if (id === VIRTUAL_ID) return RESOLVED_ID
    },

    async load(id) {
      if (id !== RESOLVED_ID) return undefined

      const files = readdirSync(huntsDir)
        .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))
        .map(f => join(huntsDir, f))

      for (const f of files) this.addWatchFile(f)

      return buildModule(huntsDir)
    },

    configureServer(server: ViteDevServer) {
      server.watcher.add(join(huntsDir, '*.yaml'))
      server.watcher.on('change', file => {
        if (file.includes('content') && file.endsWith('.yaml')) {
          const mod = server.moduleGraph.getModuleById(RESOLVED_ID)
          if (mod) server.moduleGraph.invalidateModule(mod)
          server.ws.send({ type: 'full-reload' })
        }
      })
    },
  }
}
