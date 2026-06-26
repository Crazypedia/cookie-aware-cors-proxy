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

## API

TODO (same api as request package)

## TODO list

- replace request usage with axios
