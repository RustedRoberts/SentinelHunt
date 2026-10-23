#!/usr/bin/env node
// Subdomain recon CLI: pulls names for a domain from certificate transparency
// logs (crt.sh), resolves each one's CNAME chain and A records using this
// machine's DNS resolver, then optionally probes HTTPS/HTTP to see whether a
// web server actually answers. No dependencies beyond Node 18+.
//
// Usage:
//   node scripts/subdomain-recon.js contoso.com
//   node scripts/subdomain-recon.js contoso.com --csv out.csv --html out.html
//   node scripts/subdomain-recon.js contoso.com --no-live
//   node scripts/subdomain-recon.js contoso.com --doh
//
// Screenshots: --urls writes the hosts that answered the web check as a URL
// list for gowitness (https://github.com/sensepost/gowitness, v3):
//   node scripts/subdomain-recon.js contoso.com --urls urls.txt
//   gowitness scan file -f urls.txt --write-db
//   gowitness report server

import { promises as dns } from 'dns'
import { writeFileSync } from 'fs'

const DNS_CONCURRENCY = 20
const LIVE_CONCURRENCY = 10
const LIVE_TIMEOUT_MS = 8000
const CRTSH_TIMEOUT_MS = 90000
const MAX_CNAME_HOPS = 10

function usage(code) {
  console.log(`Usage: node scripts/subdomain-recon.js <domain> [--csv <file>] [--html <file>] [--urls <file>] [--no-live] [--doh]

  --csv <file>    write results to a CSV file
  --html <file>   write results to a standalone HTML report
  --urls <file>   write the URLs that answered the web check, one per line,
                  ready for: gowitness scan file -f <file>
  --no-live       skip the HTTPS/HTTP web check
  --doh           resolve via Cloudflare DNS-over-HTTPS instead of the system
                  resolver (use where local DNS is filtered or intercepted)`)
  process.exit(code)
}

function parseArgs(argv) {
  const opts = { domain: null, csv: null, html: null, urls: null, live: true, doh: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--csv' || arg === '--html' || arg === '--urls') {
      if (!argv[i + 1]) usage(1)
      opts[arg.slice(2)] = argv[++i]
    } else if (arg === '--no-live') opts.live = false
    else if (arg === '--doh') opts.doh = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else if (!opts.domain) opts.domain = arg
    else usage(1)
  }
  if (!opts.domain) usage(1)
  if (opts.urls && !opts.live) {
    console.error('--urls needs the web check, so it cannot be combined with --no-live')
    process.exit(1)
  }
  return opts
}

function normaliseDomain(input) {
  const host = input
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, '')
    .split(/[/?#:]/)[0]
    .replace(/^\*\./, '')
    .replace(/\.$/, '')
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) ? host : null
}

// crt.sh is frequently slow or returns 502/503 under load, so retry a few times.
async function fetchCrtShSubdomains(domain) {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`
  let lastError
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(CRTSH_TIMEOUT_MS) })
      if (!res.ok) throw new Error(`crt.sh returned HTTP ${res.status}`)
      const names = new Set()
      for (const entry of await res.json()) {
        // A single certificate can list many SANs, newline separated.
        for (const raw of entry.name_value.split('\n')) {
          const name = raw.trim().toLowerCase().replace(/^\*\./, '')
          if (name === domain || name.endsWith(`.${domain}`)) names.add(name)
        }
      }
      return [...names].sort()
    } catch (err) {
      lastError = err
      console.error(`  crt.sh attempt ${attempt} failed: ${err.message}`)
      await new Promise(r => setTimeout(r, attempt * 2000))
    }
  }
  throw lastError
}

async function resolveSubdomain(name) {
  const result = { name, cnameChain: [], aRecords: [], status: 'resolved', error: '', live: null }
  try {
    let current = name
    for (let hop = 0; hop < MAX_CNAME_HOPS; hop++) {
      try {
        const [target] = await dns.resolveCname(current)
        result.cnameChain.push(target)
        current = target
      } catch {
        break
      }
    }
    result.aRecords = await dns.resolve4(name)
    if (!result.aRecords.length) result.status = 'no-a-record'
  } catch (err) {
    if (err.code === 'ENOTFOUND') result.status = 'nxdomain'
    else if (err.code === 'ENODATA') result.status = 'no-a-record'
    else {
      result.status = 'error'
      result.error = err.code || err.message
    }
  }
  return result
}

// DoH returns the whole CNAME chain and the final A records in one answer.
async function resolveSubdomainDoh(name) {
  const result = { name, cnameChain: [], aRecords: [], status: 'resolved', error: '', live: null }
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(LIVE_TIMEOUT_MS),
    })
    if (!res.ok) throw new Error(`DoH returned HTTP ${res.status}`)
    const body = await res.json()
    const answers = body.Answer ?? []
    result.cnameChain = answers.filter(a => a.type === 5).map(a => a.data.replace(/\.$/, ''))
    result.aRecords = answers.filter(a => a.type === 1).map(a => a.data)
    if (body.Status === 3) result.status = 'nxdomain'
    else if (!result.aRecords.length) result.status = 'no-a-record'
  } catch (err) {
    result.status = 'error'
    result.error = err.message
  }
  return result
}

// Tries HTTPS then HTTP. Records the final status, where redirects ended up,
// the Server header and the page <title>, which together usually identify
// the hosting platform.
async function liveCheck(name) {
  const failures = []
  for (const scheme of ['https', 'http']) {
    try {
      const res = await fetch(`${scheme}://${name}/`, {
        redirect: 'follow',
        signal: AbortSignal.timeout(LIVE_TIMEOUT_MS),
        headers: { 'user-agent': 'Mozilla/5.0 (subdomain-recon)' },
      })
      const body = (await res.text()).slice(0, 65536)
      const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1].trim().replace(/\s+/g, ' ') ?? ''
      return {
        url: `${scheme}://${name}/`,
        status: res.status,
        finalUrl: res.url,
        server: res.headers.get('server') ?? '',
        title,
      }
    } catch (err) {
      failures.push(`${scheme}: ${err.cause?.code || err.name}`)
    }
  }
  return { url: '', status: 0, finalUrl: '', server: '', title: '', error: failures.join('; ') }
}

async function mapConcurrent(items, limit, fn, onProgress) {
  const out = new Array(items.length)
  let next = 0
  let done = 0
  async function worker() {
    while (next < items.length) {
      const i = next++
      out[i] = await fn(items[i])
      onProgress?.(++done, items.length)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

function progress(label) {
  return (done, total) => {
    if (process.stderr.isTTY) process.stderr.write(`\r  ${label} ${done}/${total}`)
    if (done === total && process.stderr.isTTY) process.stderr.write('\n')
  }
}

function liveSummary(live) {
  if (!live) return ''
  if (!live.status) return `no response (${live.error})`
  return [live.status, live.finalUrl !== live.url ? `→ ${live.finalUrl}` : '', live.server && `[${live.server}]`, live.title && `"${live.title}"`]
    .filter(Boolean)
    .join(' ')
}

function csvCell(value) {
  const s = String(value ?? '')
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function toCsv(results) {
  const rows = [['subdomain', 'status', 'cname_chain', 'a_records', 'http_status', 'final_url', 'server', 'title', 'live_error']]
  for (const r of results) {
    rows.push([
      r.name, r.status, r.cnameChain.join(' -> '), r.aRecords.join(' '),
      r.live?.status || '', r.live?.finalUrl ?? '', r.live?.server ?? '', r.live?.title ?? '', r.live?.error ?? '',
    ])
  }
  return rows.map(row => row.map(csvCell).join(',')).join('\n') + '\n'
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`)
}

function toHtmlReport(domain, results, includeLive) {
  const resolved = results.filter(r => r.status === 'resolved').length
  const liveCount = results.filter(r => r.live?.status).length
  const rows = results
    .map(r => {
      const cells = [r.name, r.status, r.cnameChain.join(' → '), r.aRecords.join(', ')]
      if (includeLive) cells.push(liveSummary(r.live))
      return `<tr class="${r.status}">${cells.map(c => `<td>${escapeHtml(c)}</td>`).join('')}</tr>`
    })
    .join('\n')
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Subdomains: ${escapeHtml(domain)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#111;color:#e4e4e7}
h1{font-size:1.5rem}p{color:#a1a1aa}
table{border-collapse:collapse;width:100%;font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #2a2a2a;vertical-align:top}
th{color:#a1a1aa;font-weight:600}
tr.resolved td:first-child{color:#d4ff3f}
tr.nxdomain td,tr.no-a-record td{color:#71717a}
tr.error td{color:#f87171}
</style></head><body>
<h1>Subdomains of ${escapeHtml(domain)}</h1>
<p>${results.length} names from crt.sh, ${resolved} with A records${includeLive ? `, ${liveCount} answering on HTTP(S)` : ''}. Generated ${new Date().toISOString()}.</p>
<table><thead><tr><th>Subdomain</th><th>Status</th><th>CNAME chain</th><th>A records</th>${includeLive ? '<th>Web check</th>' : ''}</tr></thead>
<tbody>
${rows}
</tbody></table>
</body></html>
`
}

async function main() {
  const opts = parseArgs(process.argv.slice(2))
  const domain = normaliseDomain(opts.domain)
  if (!domain) {
    console.error(`"${opts.domain}" doesn't look like a valid domain, e.g. contoso.com`)
    process.exit(1)
  }

  console.error(`Querying crt.sh for ${domain}...`)
  const names = await fetchCrtShSubdomains(domain)
  console.error(`  ${names.length} unique names found`)

  console.error(`Resolving DNS${opts.doh ? ' over HTTPS' : ''}...`)
  const resolve = opts.doh ? resolveSubdomainDoh : resolveSubdomain
  const results = await mapConcurrent(names, DNS_CONCURRENCY, resolve, progress('resolved'))

  if (opts.live) {
    const targets = results.filter(r => r.status === 'resolved')
    console.error(`Checking ${targets.length} hosts for a live web server...`)
    await mapConcurrent(targets, LIVE_CONCURRENCY, async r => { r.live = await liveCheck(r.name) }, progress('checked'))
  }

  console.log()
  for (const r of results.filter(r => r.status === 'resolved')) {
    console.log(r.name)
    if (r.cnameChain.length) console.log(`  CNAME  ${r.cnameChain.join(' -> ')}`)
    console.log(`  A      ${r.aRecords.join(', ')}`)
    if (r.live) console.log(`  WEB    ${liveSummary(r.live)}`)
  }
  const unresolved = results.filter(r => r.status !== 'resolved')
  if (unresolved.length) {
    console.log(`\n${unresolved.length} names without A records:`)
    for (const r of unresolved) console.log(`  ${r.name}  (${r.status}${r.error ? `: ${r.error}` : ''})`)
  }

  if (opts.csv) {
    writeFileSync(opts.csv, toCsv(results))
    console.error(`\nCSV written to ${opts.csv}`)
  }
  if (opts.html) {
    writeFileSync(opts.html, toHtmlReport(domain, results, opts.live))
    console.error(`HTML report written to ${opts.html}`)
  }
  if (opts.urls) {
    // The URL that answered (HTTPS, or HTTP if HTTPS failed), not where it
    // redirected to: gowitness follows redirects itself.
    const urls = results.filter(r => r.live?.status).map(r => r.live.url)
    writeFileSync(opts.urls, urls.join('\n') + (urls.length ? '\n' : ''))
    console.error(`${urls.length} URLs written to ${opts.urls} - next: gowitness scan file -f ${opts.urls} --write-db`)
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`)
  process.exit(1)
})
