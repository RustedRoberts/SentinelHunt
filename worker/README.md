# cv-chatbot worker

Cloudflare Worker that proxies the CV chatbot widget on
[rustedroberts.github.io/SentinelHunt](https://rustedroberts.github.io/SentinelHunt)
to the Claude API. Deployed standalone from this folder - it is not part of
the Vite build for the main site.

Live at: `https://cv-chatbot.chrisscott.workers.dev`

## Request contract

```
POST /  { "messages": [ { "role": "user", "content": "..." }, ... ] }
  -> 200 { "reply": "..." }
  -> 4xx/5xx { "error": "..." }
```

CORS is locked to `ALLOWED_ORIGIN` in `worker.js` (currently the GitHub Pages
origin above).

## What the worker does

1. Rate-limits by visitor IP (`CF-Connecting-IP`) via the `RATE_LIMIT` KV
   namespace - 20 requests/hour, tracked as `rl:<ip>`.
2. Runs a cheap Haiku classification pass on the visitor's latest message to
   screen for jailbreak/prompt-injection attempts, before the message ever
   reaches the main CV-answering call. Flags are tracked as `flag:<ip>` in
   the same KV store; three flags escalate to a 24h hard block. The screen
   fails open on any error, timeout, or bad response.
3. If the message passes, sends the full conversation plus the CV system
   prompt to Claude and returns the reply.

## Bindings and secrets

| Name | Type | Purpose |
|---|---|---|
| `RATE_LIMIT` | KV namespace | Rate limiting and flagged-IP tracking |
| `ANTHROPIC_API_KEY` | Secret | Claude API auth |
| `AXIOM_TOKEN` | Secret | Axiom ingest auth for log/trace export |
| `AXIOM_DATASET` | Var (plain) | Axiom dataset name - `ai_chatbot_logs` |

Secrets are never stored in `wrangler.toml` or committed to the repo. Set or
rotate them with:

```powershell
cd worker
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put AXIOM_TOKEN
```

`wrangler secret list` shows which secrets are registered without revealing
their values.

## Observability

Two independent logging layers are enabled, both configured in
`wrangler.toml`:

**Workers Logs** (`[observability]` / `[observability.logs]`) - Cloudflare's
native invocation logging, viewable via `wrangler tail` or the dashboard.
Always on for this Worker; `invocation_logs = true` keeps the automatic
request/response log entries (this is also the default).

**Axiom tracing** (OpenTelemetry) - `worker.js` wraps the `fetch` handler
with `instrument()` from `@microlabs/otel-cf-workers`, which exports request
traces to Axiom's EU Central 1 (AWS) edge:

```
https://eu-central-1.aws.edge.axiom.co/v1/traces
```

authenticated via `Bearer ${AXIOM_TOKEN}` and routed to the
`ai_chatbot_logs` dataset via the `X-Axiom-Dataset` header. This requires
the `nodejs_compat` compatibility flag (the library uses
`AsyncLocalStorage` for span context propagation) - already set in
`wrangler.toml`.

If `AXIOM_TOKEN` is unset or wrong, trace export fails silently in the
background (`ctx.waitUntil`) and does not affect the chatbot response - it
just means nothing shows up in Axiom.

**Known issue, no fix yet:** `@microlabs/otel-cf-workers` pins an older
`@opentelemetry/core` internally, which carries a moderate advisory
(GHSA-8988-4f7v-96qf, unbounded allocation parsing oversized inbound W3C
baggage headers). No patched release of the library exists yet. Practical
risk here is low - Cloudflare's edge enforces header size limits well below
the threshold that would need to trigger it - but re-run `npm audit` in this
folder after any dependency bump to check whether a fix has landed.

## Deploying

```powershell
cd worker
npx wrangler deploy
```

Run `npx wrangler deploy --dry-run` first after any `wrangler.toml` or
dependency change - it validates config parsing and confirms which bindings
the Worker will actually have (this caught a real bug once: see git history
around the `kv_namespaces` / `[observability]` ordering fix - TOML tables
swallow every bare key that follows them until the next `[header]`, so
table sections belong at the bottom of the file, or immediately followed by
another header).

## Local dev

No local dev server is set up for this Worker - `wrangler dev` would work in
principle but needs its own `.dev.vars` for secrets. Changes are validated
via `--dry-run` and smoke-tested against the live URL after deploy.

## Customising

The CV content the bot answers from lives in `KNOWLEDGE_DOCUMENT` inside
`worker.js`, alongside the system prompt and its disclosure rules. Edit that
string directly - there is no separate content file for this Worker.
