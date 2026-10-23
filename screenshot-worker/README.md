# sentinelhunt-screenshot worker

Cloudflare Worker that takes page screenshots for the Recon page
(`/#/recon`) on [rustedroberts.github.io/SentinelHunt](https://rustedroberts.github.io/SentinelHunt),
using the [Firecrawl](https://www.firecrawl.dev) scrape API. Deployed
standalone from this folder - it is not part of the Vite build for the main
site, and is separate from the chatbot Worker in `worker/`.

Expected URL once deployed: `https://sentinelhunt-screenshot.chrisscott.workers.dev`
(`SCREENSHOT_WORKER_URL` in `src/pages/Subdomains.tsx` must match).

## Request contract

```
POST /  { "host": "orders.nuclera.com" }
  -> 200 { "screenshot": "<image url>", "title": "...", "statusCode": 200 }
  -> 4xx/5xx { "error": "..." }
```

The Worker only screenshots `https://<host>/`. Callers send a bare hostname,
never a URL, so it can't be pointed at arbitrary paths, ports, IP addresses
or other schemes.

CORS is locked to `ALLOWED_ORIGIN` in `worker.js` (the GitHub Pages origin).

Firecrawl screenshot links expire after 24 hours.

## Limits and cost

Each screenshot costs 1 Firecrawl credit; the free plan gives 1,000 a month.
There is no passphrase, so two caps in `worker.js` protect the credits:

| Constant | Default | Purpose |
|---|---|---|
| `RATE_LIMIT_PER_HOUR` | 20 | Screenshots per visitor IP per hour (`rl:<ip>` in KV) |
| `DAILY_LIMIT` | 30 | Screenshots per day across all visitors (`day:<YYYY-MM-DD>` in KV) - about 900 a month |

Both are counted before calling Firecrawl, so failed captures still count.
KV is eventually consistent, so a burst of parallel requests can overshoot a
cap slightly.

## Bindings and secrets

| Name | Type | Purpose |
|---|---|---|
| `RATE_LIMIT` | KV namespace (titled `SCREENSHOT_RATE_LIMIT`) | Per-IP and daily counters |
| `FIRECRAWL_API_KEY` | Secret | Firecrawl API auth |

## First-time setup

```powershell
cd screenshot-worker
npx wrangler kv namespace create SCREENSHOT_RATE_LIMIT
# paste the id it prints into wrangler.toml as the RATE_LIMIT binding's id
npx wrangler secret put FIRECRAWL_API_KEY
npx wrangler deploy --dry-run
npx wrangler deploy
```

Then smoke-test it from the Recon page: look up a domain and press
**Screenshot** on a resolved row.

## Tests

`node --test screenshot-worker/worker.test.js` runs the Worker's handler
against a stubbed Firecrawl and in-memory KV - no network or credits used.
