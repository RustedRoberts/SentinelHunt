import type { Plugin, ViteDevServer } from 'vite'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve, join, basename } from 'node:path'
import yaml from 'js-yaml'

const VIRTUAL_ID = 'virtual:blog-data'
const RESOLVED_ID = '\0' + VIRTUAL_ID

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/

function parsePost(raw: string, slug: string): Record<string, unknown> {
  const match = raw.match(FRONTMATTER_RE)
  if (!match) throw new Error(`Blog post '${slug}.md' is missing YAML frontmatter (--- ... ---)`)

  const frontmatter = yaml.load(match[1]) as Record<string, unknown>
  const content = match[2].trim()
  const wordCount = content.split(/\s+/).filter(Boolean).length
  const readingTime = Math.max(1, Math.round(wordCount / 200))

  return { ...frontmatter, slug, content, readingTime }
}

function buildModule(dir: string): string {
  const files = readdirSync(dir)
    .filter(f => f.endsWith('.md') && !f.startsWith('_'))
    .sort()

  const posts = files
    .map(file => parsePost(readFileSync(join(dir, file), 'utf-8'), basename(file, '.md')))
    .filter(post => post['published'] === true)
    .sort((a, b) => ((a['date'] as string) < (b['date'] as string) ? 1 : -1))

  return `export default ${JSON.stringify(posts)}`
}

export function blogPlugin(): Plugin {
  let dir: string

  return {
    name: 'vite-plugin-blog',

    configResolved(config) {
      dir = resolve(config.root, 'content/blog')
    },

    resolveId(id) {
      if (id === VIRTUAL_ID) return RESOLVED_ID
    },

    load(id) {
      if (id !== RESOLVED_ID) return undefined

      const files = readdirSync(dir)
        .filter(f => f.endsWith('.md') && !f.startsWith('_'))
        .map(f => join(dir, f))

      for (const f of files) this.addWatchFile(f)

      return buildModule(dir)
    },

    configureServer(server: ViteDevServer) {
      server.watcher.add(join(dir, '*.md'))
      server.watcher.on('change', file => {
        if (file.includes('blog') && file.endsWith('.md')) {
          const mod = server.moduleGraph.getModuleById(RESOLVED_ID)
          if (mod) server.moduleGraph.invalidateModule(mod)
          server.ws.send({ type: 'full-reload' })
        }
      })
    },
  }
}
