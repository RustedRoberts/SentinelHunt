// Subdomain discovery for the Recon page: pulls names from certificate
// transparency logs (crt.sh), then resolves each one over DNS-over-HTTPS.
// Both services send `Access-Control-Allow-Origin: *`, so lookups run
// entirely in the visitor's browser. Screenshots are the exception: they go
// through the screenshot-worker Cloudflare Worker, which holds the Firecrawl
// API key.

const CRTSH_URL = 'https://crt.sh/'
// Firecrawl screenshot proxy - see screenshot-worker/README.md.
const SCREENSHOT_WORKER_URL = 'https://sentinelhunt-screenshot.chrisscott.workers.dev'
const DOH_URL = 'https://cloudflare-dns.com/dns-query'
const DNS_CONCURRENCY = 10

const DNS_TYPE_A = 1
const DNS_TYPE_CNAME = 5
const DNS_STATUS_NXDOMAIN = 3

export type ResolutionStatus = 'resolved' | 'no-a-record' | 'nxdomain' | 'error'

export interface SubdomainResult {
  name: string
  cnameChain: string[]
  aRecords: string[]
  status: ResolutionStatus
  error?: string
}

export interface Screenshot {
  screenshot: string
  title: string
  statusCode: number | null
}

interface CrtShEntry {
  name_value: string
}

interface DohAnswer {
  name: string
  type: number
  data: string
}

interface DohResponse {
  Status: number
  Answer?: DohAnswer[]
}

// Accepts "contoso.com", "https://www.contoso.com/path" etc. and returns the
// bare lower-case domain, or null if it doesn't look like a hostname.
export function normaliseDomain(input: string): string | null {
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
export async function fetchCrtShSubdomains(domain: string, signal?: AbortSignal): Promise<string[]> {
  const url = `${CRTSH_URL}?q=${encodeURIComponent(`%.${domain}`)}&output=json`
  let lastError: unknown
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { signal })
      if (!res.ok) throw new Error(`crt.sh returned HTTP ${res.status}`)
      const entries = (await res.json()) as CrtShEntry[]
      return extractNames(entries, domain)
    } catch (err) {
      if (signal?.aborted) throw err
      lastError = err
      await new Promise(r => setTimeout(r, attempt * 2000))
    }
  }
  throw lastError instanceof Error ? lastError : new Error('crt.sh lookup failed')
}

function extractNames(entries: CrtShEntry[], domain: string): string[] {
  const names = new Set<string>()
  for (const entry of entries) {
    // A single certificate can list many SANs, newline separated.
    for (const raw of entry.name_value.split('\n')) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, '')
      if (name === domain || name.endsWith(`.${domain}`)) names.add(name)
    }
  }
  return [...names].sort()
}

export async function resolveSubdomain(name: string, signal?: AbortSignal): Promise<SubdomainResult> {
  try {
    const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal,
    })
    if (!res.ok) throw new Error(`DNS lookup returned HTTP ${res.status}`)
    const body = (await res.json()) as DohResponse
    if (body.Status === DNS_STATUS_NXDOMAIN) {
      return { name, cnameChain: [], aRecords: [], status: 'nxdomain' }
    }
    const answers = body.Answer ?? []
    const cnameChain = answers
      .filter(a => a.type === DNS_TYPE_CNAME)
      .map(a => a.data.replace(/\.$/, ''))
    const aRecords = answers.filter(a => a.type === DNS_TYPE_A).map(a => a.data)
    return { name, cnameChain, aRecords, status: aRecords.length ? 'resolved' : 'no-a-record' }
  } catch (err) {
    if (signal?.aborted) throw err
    return { name, cnameChain: [], aRecords: [], status: 'error', error: String(err) }
  }
}

export async function resolveAll(
  names: string[],
  onResult: (result: SubdomainResult) => void,
  signal?: AbortSignal,
): Promise<void> {
  let next = 0
  async function worker() {
    while (next < names.length && !signal?.aborted) {
      onResult(await resolveSubdomain(names[next++], signal))
    }
  }
  await Promise.all(Array.from({ length: Math.min(DNS_CONCURRENCY, names.length) }, worker))
}

export async function requestScreenshot(host: string): Promise<Screenshot> {
  const res = await fetch(SCREENSHOT_WORKER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host }),
  })
  const body = await res.json().catch(() => null)
  if (!res.ok || !body?.screenshot) {
    throw new Error(body?.error ?? `Screenshot service returned HTTP ${res.status}`)
  }
  return body as Screenshot
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

export function toCsv(results: SubdomainResult[]): string {
  const rows = [['subdomain', 'status', 'cname_chain', 'a_records']]
  for (const r of results) {
    rows.push([r.name, r.status, r.cnameChain.join(' -> '), r.aRecords.join(' ')])
  }
  return rows.map(row => row.map(csvCell).join(',')).join('\n') + '\n'
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`)
}

export function toHtmlReport(domain: string, results: SubdomainResult[], generatedAt: Date): string {
  const resolved = results.filter(r => r.status === 'resolved').length
  const rows = results
    .map(
      r => `<tr class="${r.status}"><td>${escapeHtml(r.name)}</td><td>${r.status}</td>` +
        `<td>${escapeHtml(r.cnameChain.join(' → '))}</td><td>${escapeHtml(r.aRecords.join(', '))}</td></tr>`,
    )
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
<p>${results.length} names from crt.sh, ${resolved} with A records. Generated ${generatedAt.toISOString()}.</p>
<table><thead><tr><th>Subdomain</th><th>Status</th><th>CNAME chain</th><th>A records</th></tr></thead>
<tbody>
${rows}
</tbody></table>
</body></html>
`
}
