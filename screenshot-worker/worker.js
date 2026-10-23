// Cloudflare Worker: takes page screenshots for the Recon page via Firecrawl.
//
// Bindings this Worker needs:
//   - Secret:       FIRECRAWL_API_KEY  (wrangler secret put FIRECRAWL_API_KEY)
//   - KV namespace: RATE_LIMIT         (per-IP and daily usage counters)
//
// Request contract:
//   POST { "host": "orders.nuclera.com" }
//   -> 200 { "screenshot": "<url>", "title": "...", "statusCode": 200 }
//   -> 4xx/5xx { "error": "..." }
//
// The Worker only ever screenshots https://<host>/ - callers send a bare
// hostname, not a URL, so it can't be pointed at arbitrary paths, ports,
// IP addresses or non-web schemes. HTTPS only is deliberate: every name the
// Recon page lists came from a TLS certificate.
//
// Access is open (no passphrase), so two caps protect the Firecrawl credits:
// a per-IP hourly limit and a global daily limit. The daily cap is what
// keeps a month of use inside the free plan's 1,000 credits. KV is
// eventually consistent, so both caps can overshoot slightly under bursts
// of parallel requests - fine for a budget guard, not a hard quota.
//
// Firecrawl's screenshot links expire after 24 hours.

const FIRECRAWL_SCRAPE_URL = "https://api.firecrawl.dev/v2/scrape";

const ALLOWED_ORIGIN = "https://rustedroberts.github.io"; // update if your site differs
const RATE_LIMIT_PER_HOUR = 20; // screenshots per visitor IP
const DAILY_LIMIT = 30;         // screenshots per day across everyone (~900/month)
const SCRAPE_TIMEOUT_MS = 30000;

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

async function readCount(env, key) {
  const current = await env.RATE_LIMIT.get(key);
  return current ? parseInt(current, 10) : 0;
}

// Checks both caps before spending anything, then counts the request
// against both. Returns an error message, or null if allowed.
async function checkLimits(env, ip) {
  const ipKey = `rl:${ip}`;
  const dayKey = `day:${new Date().toISOString().slice(0, 10)}`;
  const [ipCount, dayCount] = await Promise.all([readCount(env, ipKey), readCount(env, dayKey)]);

  if (dayCount >= DAILY_LIMIT) {
    return "The daily screenshot limit has been reached - please try again tomorrow.";
  }
  if (ipCount >= RATE_LIMIT_PER_HOUR) {
    return "Too many screenshots from this visitor for now - please try again later.";
  }

  await Promise.all([
    env.RATE_LIMIT.put(ipKey, String(ipCount + 1), { expirationTtl: 3600 }),
    env.RATE_LIMIT.put(dayKey, String(dayCount + 1), { expirationTtl: 2 * 86400 }),
  ]);
  return null;
}

async function takeScreenshot(env, host) {
  const res = await fetch(FIRECRAWL_SCRAPE_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.FIRECRAWL_API_KEY}`,
    },
    body: JSON.stringify({
      url: `https://${host}/`,
      formats: ["screenshot"],
      timeout: SCRAPE_TIMEOUT_MS,
    }),
  });

  let body;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok || !body?.success || !body.data?.screenshot) {
    console.error("Firecrawl scrape failed", res.status, body?.code, body?.error);
    return { error: `Couldn't capture https://${host}/ - the site may not respond over HTTPS.`, status: 502 };
  }

  const title = body.data.metadata?.title;
  return {
    screenshot: body.data.screenshot,
    title: Array.isArray(title) ? title[0] ?? "" : title ?? "",
    statusCode: body.data.metadata?.statusCode ?? null,
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "Use POST." }, 405);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON body." }, 400);
    }

    const host = typeof body.host === "string" ? body.host.trim().toLowerCase() : "";
    if (!HOSTNAME_RE.test(host)) {
      return jsonResponse({ error: "Send a bare hostname, e.g. { \"host\": \"www.example.com\" }." }, 400);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const limited = await checkLimits(env, ip);
    if (limited) {
      return jsonResponse({ error: limited }, 429);
    }

    const result = await takeScreenshot(env, host);
    if (result.error) {
      return jsonResponse({ error: result.error }, result.status);
    }
    return jsonResponse(result);
  },
};
