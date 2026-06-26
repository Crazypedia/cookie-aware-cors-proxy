# cookie-aware-cors-proxy

A Cors proxy letting the browser manages cookies and redirects.
Based on the work of several repositories like https://github.com/miguelduarte42/cloudflare-scraper

## Install

```bash
npm install cookie-aware-cors-proxy
```

## Extra Features

- Translates cookies and redirect locations from the target website to have the browser continue to call the proxy and not directly the website
- Extensive and dynamic support for log and debug information
- Two engines: a lightweight and one based on chrome to support websites running javascript

## Quick Example

```shell
node run start
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | *(empty — no origins allowed)* | Comma-separated list of exact-match origins (e.g. `https://app.example.com,https://example.com`) allowed to receive `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials`. Unset or empty means every cross-origin request is denied (fail closed). `Origin: null` is never matched. |
| `SSRF_ALLOW_PRIVATE` | `false` | Allow `?url=` targets in RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — for local development only. Loopback, link-local/cloud-metadata (`169.254.0.0/16`), the `localhost` hostname, and non-`http(s)` schemes are always blocked regardless of this flag. |
| `UPSTREAM_HEADER_PASSTHROUGH_EXTRA` | *(empty)* | Comma-separated list of extra upstream response headers (case-insensitive) to forward to the client, in addition to the built-in allowlist (`content-type`, `content-length`, `content-encoding`, `cache-control`, `last-modified`, `etag`, `expires`, `set-cookie`, `location`, `www-authenticate`, `retry-after`, `x-ratelimit-*`). Headers not on the allowlist (e.g. upstream `access-control-*` or other internal headers) are dropped rather than forwarded. |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window, in milliseconds, applied per client IP to all `/proxy` routes. |
| `RATE_LIMIT_MAX` | `60` | Maximum requests per client IP per `RATE_LIMIT_WINDOW_MS` window before the proxy responds `429 Too Many Requests` with a `Retry-After` header. The proxy trusts one reverse-proxy hop (`X-Forwarded-For`) for IP extraction, matching the nginx/Cloudflare front end it's deployed behind. |

## API

TODO (same api as request package)

## TODO list

- replace request usage with axios
