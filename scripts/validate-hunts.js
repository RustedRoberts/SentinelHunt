// Validates hunt YAML files before build/deploy.
// Catches null fields that should be empty arrays — the most common authoring mistake.
import { readFileSync, readdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import yaml from 'js-yaml'

const __dirname = dirname(fileURLToPath(import.meta.url))
const HUNTS_DIR = join(__dirname, '..', 'content', 'hunts')

const REQUIRED_STRINGS = [
  'id', 'title', 'summary', 'hypothesis', 'author',
  'updated', 'version', 'whatYoullSee', 'curatorNotes',
  'methodology', 'maturity', 'signal',
]

const REQUIRED_ARRAYS = [
  'tactics', 'techniques', 'platforms', 'dataSources',
  'investigationSteps', 'falsePositives', 'references',
  'implementations', 'relatedHunts',
]

const VALID_METHODOLOGY = ['Signature', 'Behavioural', 'Anomaly', 'Statistical', 'ThreatIntel']
const VALID_MATURITY = ['Exploratory', 'Experimental', 'Validated', 'Promoted']
const VALID_SIGNAL = ['Low', 'Medium', 'High']

let totalErrors = 0

const files = readdirSync(HUNTS_DIR)
  .filter(f => f.endsWith('.yaml') && !f.startsWith('_'))

for (const file of files) {
  const path = join(HUNTS_DIR, file)
  const errors = []

  let hunt
  try {
    hunt = yaml.load(readFileSync(path, 'utf8'))
  } catch (e) {
    console.error(`  FAIL  ${file}: YAML parse error — ${e.message}`)
    totalErrors++
    continue
  }

  for (const field of REQUIRED_STRINGS) {
    if (hunt[field] == null) {
      errors.push(`'${field}' is null or missing (should be a string)`)
    }
  }

  for (const field of REQUIRED_ARRAYS) {
    if (hunt[field] == null) {
      errors.push(`'${field}' is null — use [] for an empty list`)
    } else if (!Array.isArray(hunt[field])) {
      errors.push(`'${field}' is not an array (got ${typeof hunt[field]})`)
    }
  }

  if (hunt.methodology != null && !VALID_METHODOLOGY.includes(hunt.methodology)) {
    errors.push(`'methodology' has invalid value '${hunt.methodology}' — must be one of: ${VALID_METHODOLOGY.join(', ')}`)
  }

  if (hunt.maturity != null && !VALID_MATURITY.includes(hunt.maturity)) {
    errors.push(`'maturity' has invalid value '${hunt.maturity}' — must be one of: ${VALID_MATURITY.join(', ')}`)
  }

  if (hunt.signal != null && !VALID_SIGNAL.includes(hunt.signal)) {
    errors.push(`'signal' has invalid value '${hunt.signal}' — must be one of: ${VALID_SIGNAL.join(', ')}`)
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
