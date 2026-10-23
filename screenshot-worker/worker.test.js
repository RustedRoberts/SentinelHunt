import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import worker from './worker.js'

function memoryKv() {
  const store = new Map()
  return {
    store,
    async get(key) { return store.get(key) ?? null },
    async put(key, value) { store.set(key, value) },
  }
}

let env
let firecrawlCalls

function stubFirecrawl(response, status = 200) {
  globalThis.fetch = async (url, init) => {
    firecrawlCalls.push({ url, body: JSON.parse(init.body), auth: init.headers.Authorization })
    return new Response(JSON.stringify(response), { status })
  }
}

function post(body, ip = '203.0.113.5') {
  return new Request('https://worker.example/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

beforeEach(() => {
  env = { FIRECRAWL_API_KEY: 'fc-test', RATE_LIMIT: memoryKv() }
  firecrawlCalls = []
  stubFirecrawl({
    success: true,
    data: { screenshot: 'https://img.example/shot.png', metadata: { title: 'Contoso Home', statusCode: 200 } },
  })
})

test('returns screenshot, title and status for a valid host', async () => {
  const res = await worker.fetch(post({ host: 'WWW.Contoso.com' }), env)
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { screenshot: 'https://img.example/shot.png', title: 'Contoso Home', statusCode: 200 })
  assert.equal(firecrawlCalls[0].body.url, 'https://www.contoso.com/')
  assert.deepEqual(firecrawlCalls[0].body.formats, ['screenshot'])
  assert.equal(firecrawlCalls[0].auth, 'Bearer fc-test')
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), 'https://rustedroberts.github.io')
})

test('rejects anything that is not a bare hostname', async () => {
  for (const host of ['https://example.com/', '10.0.0.1', 'example.com:8080', 'localhost', 'a/b.com', '', 42]) {
    const res = await worker.fetch(post({ host }), env)
    assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(host)}`)
  }
  assert.equal((await worker.fetch(post('not json'), env)).status, 400)
  assert.equal(firecrawlCalls.length, 0)
})

test('handles CORS preflight and non-POST methods', async () => {
  const pre = await worker.fetch(new Request('https://worker.example/', { method: 'OPTIONS' }), env)
  assert.equal(pre.status, 204)
  const get = await worker.fetch(new Request('https://worker.example/'), env)
  assert.equal(get.status, 405)
})

test('enforces the per-IP hourly limit', async () => {
  for (let i = 0; i < 20; i++) {
    assert.equal((await worker.fetch(post({ host: 'example.com' }), env)).status, 200)
  }
  assert.equal((await worker.fetch(post({ host: 'example.com' }), env)).status, 429)
  assert.equal((await worker.fetch(post({ host: 'example.com' }, '198.51.100.9'), env)).status, 200)
})

test('enforces the global daily limit across IPs', async () => {
  for (let i = 0; i < 30; i++) {
    assert.equal((await worker.fetch(post({ host: 'example.com' }, `192.0.2.${i}`), env)).status, 200)
  }
  const res = await worker.fetch(post({ host: 'example.com' }, '192.0.2.200'), env)
  assert.equal(res.status, 429)
  assert.match((await res.json()).error, /daily/)
  assert.equal(firecrawlCalls.length, 30)
})

test('returns 502 when Firecrawl fails', async () => {
  stubFirecrawl({ success: false, error: 'ERR_NAME_NOT_RESOLVED', code: 'SCRAPE_FAILED' }, 500)
  const res = await worker.fetch(post({ host: 'down.example.com' }), env)
  assert.equal(res.status, 502)
  assert.match((await res.json()).error, /down\.example\.com/)
})
