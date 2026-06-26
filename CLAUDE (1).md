# CLAUDE.md — Security Hardening: cookie-aware-cors-proxy

This file contains instructions for Claude Code. This is a fork of
[gcollin/cookie-aware-cors-proxy](https://github.com/gcollin/cookie-aware-cors-proxy)
being patched to address confirmed security vulnerabilities before deployment
in a YunoHost environment at `cmdfoo.com`.

---

## Project Overview

`cookie-aware-cors-proxy` is a Node.js/Express/TypeScript CORS proxy that:
- Accepts a `?url=` query parameter pointing at a target URL
- Fetches that URL server-side using Axios
- Forwards the response to the browser with CORS headers set
- Translates cookies and redirect `Location` headers so the browser keeps
  calling the proxy rather than the target directly

The YunoHost package sits nginx in front of the Node app. The compiled output
runs from `/var/www/cac-proxy/package/` on the host.

**Do not break the core proxy functionality.** Cookie translation, redirect
wrapping, and the `?url=` parameter interface must continue to work after
these changes.

---

## Confirmed Vulnerabilities (from live security audit, 2026-06-26)

### CRIT-1 — Reflected Origin + `credentials: true`

The server reads `req.headers.origin` and reflects it verbatim into
`Access-Control-Allow-Origin` on every response, while simultaneously
setting `Access-Control-Allow-Credentials: true`. This combination
entirely defeats browser same-origin policy.

Evidence:
```
# Request with attacker origin:
curl -sI -H "Origin: https://evil.example.com" https://cmdfoo.com/proxy/

# Response:
Access-Control-Allow-Origin: https://evil.example.com   ← reflected
Access-Control-Allow-Credentials: true                  ← critical combo
```

Additional observed bypasses:
- Subdomain trick: `Origin: https://cmdfoo.com.evil.com` → reflected
- Null origin: `Origin: null` → `Access-Control-Allow-Origin: null` (exploitable
  from sandboxed iframes)
- No origin: returns literal string `"undefined"` (JS bug)

### CRIT-2 — SSRF: Loopback and Internal Services Reachable

The proxy fetches any URL passed via `?url=` without a target blocklist.
Loopback requests connect to nginx running on `localhost` and return a real
`302` response. Cloud metadata endpoints (`169.254.169.254`) are attempted
before timing out — they are not blocked.

Evidence:
```
curl "https://cmdfoo.com/proxy/?url=http://127.0.0.1/"
→ HTTP 302 (nginx on localhost responding)

curl "https://cmdfoo.com/proxy/?url=http://169.254.169.254/latest/meta-data/"
→ hangs (connection attempted, not blocked)
```

Axios is configured with `maxRedirects: 0`, which prevents the proxy from
*following* the 302 — but the 302 body/headers are still returned to the
caller. A browser client using `redirect: 'follow'` would chain into the
redirect target.

### HIGH-1 — Full Stack Trace Disclosure on Errors

Any DNS resolution failure or Axios error returns a full JSON stack trace
including: absolute server paths, npm package names and versions,
`x-forwarded-for` client IP, Cloudflare ray IDs, and full Axios config.

Evidence:
```json
{
  "stack": "Error: getaddrinfo ENOTFOUND metadata.google.internal\n
    at /var/www/cac-proxy/package/node_modules/axios/...",
  "config": {
    "headers": { "x-forwarded-for": "163.182.102.236", ... },
    "url": "http://metadata.google.internal/..."
  }
}
```

### HIGH-2 — Upstream Response Headers Passed Through Unfiltered

All headers returned by the proxied upstream are forwarded to the browser
client without filtering. Tested with `X-Internal-Secret: leaked` and
confirmed the header appeared in the proxy response.

### MED-1 — No Rate Limiting

10 sequential requests all returned `200` with no throttling, no `429`,
no `Retry-After`. The proxy can be used as a free open fetch relay.

### LOW-1 — `access-control-allow-headers: undefined` (string literal)

When no `Access-Control-Request-Headers` is present in the request,
the server sets the response header to the literal string `"undefined"`.
This is a JS coercion bug.

---

## Tasks

Work through these in order. Commit each task separately with a descriptive
message referencing the finding ID (e.g. `fix(cors): lock origin to allowlist
[CRIT-1]`).

### Task 1 — CORS Origin Allowlist [CRIT-1]

Replace the reflected-origin logic with an explicit allowlist loaded from
an environment variable.

**Requirements:**
- Add env var `CORS_ALLOWED_ORIGINS` — comma-separated list of allowed origins
  (e.g. `https://cmdfoo.com,https://app.cmdfoo.com`)
- If the request `Origin` header matches an entry in the allowlist exactly
  (case-insensitive, no partial/substring matching), reflect that origin back
- If the request `Origin` does not match, **omit** `Access-Control-Allow-Origin`
  entirely (do not return a rejection body — just don't set the header, let
  the browser enforce same-origin)
- `Origin: null` must never be reflected — treat it as no match
- If `CORS_ALLOWED_ORIGINS` is empty/unset, default to **no origins allowed**
  (fail closed, not open)
- Keep `Access-Control-Allow-Credentials: true` only when an origin was matched
  and reflected; omit or set to `false` when no match

**Fix the `undefined` bug [LOW-1] in the same change:**
- `Access-Control-Allow-Headers`: if `Access-Control-Request-Headers` is
  absent, omit the response header rather than setting it to `"undefined"`

### Task 2 — SSRF Target Blocklist [CRIT-2]

Before Axios makes any outbound request, validate the target URL and reject
disallowed targets.

**Requirements:**

Block the following and return `HTTP 403` with a generic message
`{"error": "Target URL not allowed"}`:

| Category | Patterns to block |
|---|---|
| Loopback IPv4 | `127.0.0.0/8` |
| Loopback IPv6 | `[::1]`, `[0:0:0:0:0:0:0:1]` |
| Unspecified | `0.0.0.0` |
| Link-local / cloud metadata | `169.254.0.0/16` |
| RFC 1918 private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Localhost hostname | `localhost` (case-insensitive) |
| Disallowed schemes | `file://`, `gopher://`, `ftp://` — allow only `http://` and `https://` |

Implementation notes:
- Parse the URL before making the request; reject malformed URLs with `400`
- Check the scheme first (reject non-http/https immediately)
- Check the hostname/IP against the blocklist
- Do **not** rely solely on regex for IP ranges — use a proper CIDR check or
  the `ipaddr.js` npm package (already likely in the dependency tree, or add it)
- After parsing, also check for DNS rebinding risk: if the resolved IP falls in
  a blocked range, block the request. This is a stretch goal — implement if
  the architecture makes it straightforward, otherwise document it as a known
  remaining gap.

Add an env var `SSRF_ALLOW_PRIVATE` (default `false`) that can be set to `true`
to disable RFC 1918 blocking for local development only. Loopback, link-local,
and disallowed schemes must always be blocked regardless of this flag.

### Task 3 — Error Sanitization [HIGH-1]

Replace all error responses that expose stack traces, internal paths, or
Axios config objects with sanitized generic responses.

**Requirements:**
- Add a global Express error handler as the last middleware registered
- The handler logs the full error internally (to stdout/stderr so systemd/pm2
  captures it) and returns a generic JSON body: `{"error": "Proxy error"}`
  with an appropriate HTTP status code
- Catch Axios errors specifically and map them:
  - DNS resolution failure (`ENOTFOUND`) → `502 Bad Gateway`
  - Connection refused (`ECONNREFUSED`) → `502 Bad Gateway`  
  - Timeout → `504 Gateway Timeout`
  - Blocked by SSRF check → `403 Forbidden`
  - All other Axios errors → `502 Bad Gateway`
- Remove any existing `catch` blocks that `res.json(err)` or `res.send(err.stack)`

### Task 4 — Response Header Filtering [HIGH-2]

Do not blindly forward all upstream response headers to the browser client.

**Requirements:**
- Define an allowlist of headers the proxy will forward from the upstream
  response. Suggested allowlist:
  ```
  content-type, content-length, content-encoding, cache-control,
  last-modified, etag, expires, set-cookie, location, www-authenticate,
  retry-after, x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset
  ```
- Headers related to CORS (`access-control-*`) from the upstream should be
  **dropped** — the proxy sets its own
- Security headers (`strict-transport-security`, `x-frame-options`, etc.) from
  the upstream should be dropped — the YunoHost nginx layer sets these
- Any header not on the allowlist is silently dropped, not forwarded
- Add env var `UPSTREAM_HEADER_PASSTHROUGH_EXTRA` (comma-separated) to allow
  the allowlist to be extended without code changes

### Task 5 — Rate Limiting [MED-1]

Add basic rate limiting using `express-rate-limit`.

**Requirements:**
- Install `express-rate-limit` if not already present
- Default: 60 requests per IP per minute, returning `429 Too Many Requests`
  with `Retry-After` header set
- Configurable via env vars:
  - `RATE_LIMIT_WINDOW_MS` (default: `60000`)
  - `RATE_LIMIT_MAX` (default: `60`)
- Apply to all routes under `/proxy/`
- Trust the `X-Forwarded-For` header for IP extraction (Cloudflare sits in front)
  but set `trustProxy` appropriately to avoid IP spoofing via that header

### Task 6 — Environment Variable Documentation

Update `README.md` with a configuration section documenting all new env vars:

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | *(empty — no origins allowed)* | Comma-separated list of allowed CORS origins |
| `SSRF_ALLOW_PRIVATE` | `false` | Allow RFC 1918 targets (dev only) |
| `UPSTREAM_HEADER_PASSTHROUGH_EXTRA` | *(empty)* | Extra upstream headers to forward |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window in ms |
| `RATE_LIMIT_MAX` | `60` | Max requests per window per IP |

### Task 7 — Tests

Add or extend tests for the new security behavior. The project uses Jest.

At minimum, test:
- `CORS_ALLOWED_ORIGINS` set to a specific origin → that origin reflected, others rejected
- `Origin: null` → no ACAO header returned
- Empty `CORS_ALLOWED_ORIGINS` → no ACAO header on any request
- `?url=http://127.0.0.1/` → 403
- `?url=http://169.254.169.254/` → 403
- `?url=http://10.0.0.1/` → 403 (with `SSRF_ALLOW_PRIVATE=false`)
- `?url=http://10.0.0.1/` → passes through (with `SSRF_ALLOW_PRIVATE=true`)
- `?url=file:///etc/passwd` → 403
- Error from Axios → generic `{"error": "Proxy error"}`, no stack trace in body
- Upstream response with `X-Internal-Secret` header → header not present in proxy response

---

## Project Structure (discover on clone)

The key source is under `src/`. Explore it first before making changes:

```bash
find src/ -type f | sort
```

The main Express app and route handler(s) are where CORS headers are being
set and where Axios calls are made. The compiled output goes to `dist/` or
similar — check `tsconfig.json` for `outDir`.

Build command (verify in `package.json`):
```bash
npm run build
```

Test command:
```bash
npm test
```

---

## Constraints and Non-Goals

- **Do not change the proxy's public API** (`?url=` parameter, response body
  format, cookie/redirect translation behavior)
- **Do not upgrade Axios or other core dependencies** beyond what's needed for
  the security fixes — this is a patch branch, not a modernization
- **Do not add authentication** to the proxy endpoint — that is handled at the
  YunoHost/nginx layer via SSO (`x-sso-wat` header observed in responses)
- CRLF injection was tested and returned a `404` from the upstream (httpbin
  rejected the malformed URL) — this appears incidentally handled but is not
  explicitly in scope unless you find a direct injection path in the source
- Redirect test showed `maxRedirects: 0` in Axios config — **preserve this
  setting**; do not enable redirect following

---

## YunoHost Deployment Notes

After patching and building, the deployer will:

1. Set `CORS_ALLOWED_ORIGINS` in the systemd unit or YNH env config
2. Install from this fork via:
   ```bash
   sudo yunohost app upgrade cac-proxy -u https://github.com/YOUR_FORK/cac-proxy_ynh
   ```
   (A companion YNH packaging fork will point `manifest.toml` at this repo)

The env vars above need to be injectable at install time. If there is an
existing config file mechanism in the project (`.env`, a config module), use
it and document where the YNH packaging fork should write it during install.

---

## Reference: Confirmed Safe Behaviors (do not regress)

From the audit, these things already work correctly and should stay working:

- TLS 1.3 enforced by Cloudflare ✅
- `Strict-Transport-Security` with preload ✅
- `X-Content-Type-Options: nosniff` ✅
- `X-Frame-Options: SAMEORIGIN` ✅
- `Permissions-Policy: interest-cohort=()` ✅
- `maxRedirects: 0` on Axios (prevents redirect-following SSRF chains) ✅
- Alternative protocol schemes (file://, gopher://) returned 404 from upstream
  in testing — add explicit blocking anyway (defense in depth)
