// Validates work instruction YAML files before build/deploy.
import { readFileSync, readdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import yaml from 'js-yaml'

const __dirname = dirname(fileURLToPath(import.meta.url))
const WI_DIR = join(__dirname, '..', 'content', 'work-instructions')

const REQUIRED_STRINGS = ['id', 'title', 'trigger']
const REQUIRED_ARRAYS = ['relatedHunts', 'steps']

let totalErrors = 0

const files = readdirSync(WI_DIR)
  .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))

for (const file of files) {
  const path = join(WI_DIR, file)
  const errors = []

  let wi
  try {
    wi = yaml.load(readFileSync(path, 'utf8'))
  } catch (e) {
    console.error(`  FAIL  ${file}: YAML parse error — ${e.message}`)
    totalErrors++
    continue
  }

  for (const field of REQUIRED_STRINGS) {
    if (wi[field] == null) {
      errors.push(`'${field}' is null or missing (should be a string)`)
    }
  }

  for (const field of REQUIRED_ARRAYS) {
    if (wi[field] == null) {
      errors.push(`'${field}' is null — use [] for an empty list`)
    } else if (!Array.isArray(wi[field])) {
      errors.push(`'${field}' is not an array (got ${typeof wi[field]})`)
    }
  }

  if (Array.isArray(wi.relatedHunts)) {
    wi.relatedHunts.forEach((rh, i) => {
      if (typeof rh !== 'object' || rh == null || !rh.id || !rh.label) {
        errors.push(`'relatedHunts[${i}]' must have 'id' and 'label' fields`)
      }
    })
  }

  if (errors.length > 0) {
    console.error(`  FAIL  ${file}`)
    for (const e of errors) console.error(`        - ${e}`)
    totalErrors += errors.length
  } else {
    console.log(`    OK  ${file}`)
  }
}

console.log(`\n${files.length} file(s) checked, ${totalErrors} error(s) found.`)
if (totalErrors > 0) process.exit(1)
