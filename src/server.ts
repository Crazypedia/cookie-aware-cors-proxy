import express, { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import axios, {
  AxiosError,
  AxiosRequestConfig,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from "axios";
import { Stream } from "stream";
import { chromeEngine } from "./chrome-engine/chromeEngine";
import { argv } from "process";
import * as http from "http";
import * as dns from "dns";
import ipaddr from "ipaddr.js";
import { transformCookie } from "./chrome-engine/fillCookiesJar";

const PORT = process.env.CACP_PORT || 3000;
const REDIRECT_PATH = process.env.CACP_REDIRECT_PATH || "/proxy";
const REDIRECT_HOST = process.env.CACP_REDIRECT_HOST;
const DEBUG_MODE = process.env.CACP_DEBUG === "TRUE";
const LOG_MODE = process.env.CACP_LOG === "TRUE";
const NGINX_PATH = process.env.CACP_NGINX_PATH || "/proxy";
const BYPASS_CHROME_SANDBOX = process.env.CACP_BYPASS_SANDBOX == "TRUE";
const CHROME_EXEC = process.env.CACP_CHROME_EXEC;

// CRIT-1: explicit allowlist, no reflected-origin/credentials-true combo.
// Empty/unset env var means no origins are allowed (fail closed).
const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim().toLowerCase())
  .filter((origin) => origin.length > 0);

function isOriginAllowed(origin: string | undefined): boolean {
  // "null" is the literal Origin header value sent by sandboxed iframes/file://
  // pages, and must never be allowlisted regardless of CORS_ALLOWED_ORIGINS.
  if (origin == null || origin.toLowerCase() === "null") return false;
  return CORS_ALLOWED_ORIGINS.includes(origin.toLowerCase());
}

// HIGH-2: only forward a known-safe set of upstream response headers to the
// browser client. Everything else (including upstream access-control-* and
// security headers, which the proxy/nginx set themselves) is silently
// dropped rather than passed through unfiltered.
const UPSTREAM_HEADER_PASSTHROUGH = new Set([
  "content-type",
  "content-length",
  "content-encoding",
  "cache-control",
  "last-modified",
  "etag",
  "expires",
  "set-cookie",
  "location",
  "www-authenticate",
  "retry-after",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "x-ratelimit-reset",
  ...(process.env.UPSTREAM_HEADER_PASSTHROUGH_EXTRA || "")
    .split(",")
    .map((header) => header.trim().toLowerCase())
    .filter((header) => header.length > 0),
]);

function isUpstreamHeaderAllowed(headerKey: string): boolean {
  return UPSTREAM_HEADER_PASSTHROUGH.has(headerKey.toLowerCase());
}

// Forwarding a header in the response is not enough for browser JS to read
// it cross-origin - only a small CORS-safelisted set (content-type,
// content-length, etc.) is readable by default. Anything else (e.g.
// X-RateLimit-*) needs to be explicitly exposed. set-cookie is excluded:
// browsers never expose it via this header regardless, it's handled through
// the document cookie jar instead.
const EXPOSED_RESPONSE_HEADERS = Array.from(UPSTREAM_HEADER_PASSTHROUGH).filter(
  (header) => header !== "set-cookie"
);

// CRIT-2: SSRF target blocklist. Loopback/link-local/unspecified are always
// blocked; RFC 1918 private ranges can be allowed for local dev only.
// Read dynamically (not cached) so it can be toggled at runtime/in tests.
function isPrivateRangeAllowed(): boolean {
  return process.env.SSRF_ALLOW_PRIVATE === "true";
}

const SSRF_ALWAYS_BLOCKED_RANGES = new Set(["loopback", "linkLocal", "unspecified"]);
const SSRF_PRIVATE_RANGES = new Set(["private", "uniqueLocal", "carrierGradeNat"]);

function isIpBlocked(ip: string): boolean {
  if (!ipaddr.isValid(ip)) return false;
  const range = ipaddr.process(ip).range();
  if (SSRF_ALWAYS_BLOCKED_RANGES.has(range)) return true;
  if (!isPrivateRangeAllowed() && SSRF_PRIVATE_RANGES.has(range)) return true;
  return false;
}

// Checks the scheme, hostname/IP literal, and (stretch goal) the resolved IP
// of the target before Axios is allowed to connect to it.
async function isTargetUrlAllowed(targetUrl: URL): Promise<boolean> {
  const scheme = targetUrl.protocol.toLowerCase();
  if (scheme !== "http:" && scheme !== "https:") return false;

  let hostname = targetUrl.hostname.toLowerCase();
  if (hostname === "localhost") return false;

  // URL keeps brackets around IPv6 literals (e.g. "[::1]"); ipaddr.js wants
  // them stripped.
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }

  if (ipaddr.isValid(hostname)) {
    return !isIpBlocked(hostname);
  }

  // Not a literal IP: resolve it so a hostname that maps to a blocked range
  // (DNS rebinding) is also rejected, not just IP literals.
  try {
    const lookupResult = await dns.promises.lookup(hostname);
    if (isIpBlocked(lookupResult.address)) return false;
  } catch {
    // DNS resolution failure is not an SSRF concern; let Axios attempt the
    // request and fail naturally (handled by the error sanitization layer).
  }
  return true;
}

export const app = express();

// MED-1: trust only the immediate reverse proxy hop (nginx/Cloudflare sit in
// front in the deployed YunoHost setup) so X-Forwarded-For is used for rate
// limiting without letting a client spoof its own IP via that header.
app.set("trust proxy", 1);

app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

// MED-1: basic per-IP rate limiting on the proxy routes.
const RATE_LIMIT_WINDOW_MS = parseInt(
  process.env.RATE_LIMIT_WINDOW_MS || "60000",
  10
);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || "60", 10);

const proxyRateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  limit: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response): void => {
    res.status(429).json({ error: "Too many requests" });
  },
});

app.use(NGINX_PATH, proxyRateLimiter);

export function extractDomain(url: string): string {
  let domain = url.substring(
    url.indexOf("//") + 2,
    url.indexOf("/", url.indexOf("//") + 2)
  );
  if (domain.indexOf(":") != -1)
    domain = domain.substring(0, domain.indexOf(":"));
  return domain;
}

function modifyCookieField(
  cookieText: string,
  fieldKey: string,
  fieldValue?: string
): string {
  if (fieldValue == null) {
    // we remove the field
    const startDomainField = cookieText.indexOf(fieldKey);
    if (startDomainField != -1) {
      let tempCookie = cookieText.substring(0, startDomainField);
      const endField = cookieText.indexOf(
        ";",
        startDomainField + fieldKey.length + 1
      );
      if (endField != -1) {
        tempCookie = tempCookie + cookieText.substring(endField + 1);
      }
      return tempCookie;
    } else {
      return cookieText;
    }
  } else {
    // We replace the value or add the field
    const startDomainField = cookieText.indexOf(fieldKey);
    if (startDomainField != -1) {
      // We replace the value
      let tempCookie = cookieText.substring(
        0,
        startDomainField + fieldKey.length
      );
      if (fieldValue != "") tempCookie = tempCookie + "=" + fieldValue;
      const endField = cookieText.indexOf(
        ";",
        startDomainField + fieldKey.length
      );
      if (endField != -1) {
        tempCookie = tempCookie + cookieText.substring(endField);
      }
      return tempCookie;
    } else {
      // We add the field at the end of the cookie
      cookieText = cookieText + "; " + fieldKey;
      if (fieldValue != "") cookieText = cookieText + "=" + fieldValue;
      return cookieText;
    }
  }
}

/*function toRequestConfig(config: AxiosRequestConfig<any>): CoreOptions {
    const ret:CoreOptions={};
    ret.method=config.method;
    ret.headers=config.headers;
    ret.body=config.data;
    ret.followRedirect=false;
    return ret;
}*/

app.all(NGINX_PATH + "/**", async (req: Request, res: Response, next) => {
  return handleProxyRequest(req, res, next);
});

// HIGH-1: catch-all error handler, registered last. Handles errors passed
// via next(err) (e.g. from the response stream's "error" event after
// headers may already be partially sent) so they never reach Express's
// default error handler, which would otherwise leak stack traces.
app.use(
  (err: unknown, req: Request, res: Response, next: NextFunction): void => {
    if (res.headersSent) {
      // Response already started streaming to the client; nothing more we
      // can safely send. Just log and close out.
      console.error("Error after headers sent", err);
      res.end();
      return;
    }
    if (axios.isAxiosError(err)) {
      handleAxiosError(res, err);
    } else {
      handleUnexpectedError(res, err);
    }
  }
);

function remapUrl(
  url: string | null,
  redirectUrl: string,
  path: string,
  targetUrlOrigin: string,
  pathFromUrl: boolean
): string {
  if (url != null) {
    let urlParam = "";
    if (url.startsWith("http")) {
      // Absolute url
      urlParam = url;
    } else if (url.startsWith("/")) {
      // Url with root path
      urlParam = targetUrlOrigin + url;
    } else {
      // Url with relative path
      urlParam = path + path.endsWith("/") ? "" : "/" + url;
    }
    if (pathFromUrl == false) {
      return redirectUrl + urlParam;
    } else {
      return redirectUrl + "?url=" + encodeURIComponent(urlParam);
    }
  }
  throw new Error("Cannot remap a null url");
}

export async function handleProxyRequest(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  let debugMode = false;
  let logMode = false;
  let redirectUrl = REDIRECT_HOST;
  let pathFromUrl = false;
  if (redirectUrl == null) {
    redirectUrl = req.protocol + "://" + req.get("host");
  }

  redirectUrl = redirectUrl + REDIRECT_PATH;
  if (!redirectUrl.endsWith("/")) redirectUrl = redirectUrl + "/";

  // Makes log for the same request easy to find
  const logId =
    new Date().getTime().toString(36) +
    Math.random().toString(36).slice(2) +
    ": ";

  //console.log(req.path);
  try {
    // Set CORS headers: only reflect the origin if it's on the allowlist
    // (CORS_ALLOWED_ORIGINS); otherwise omit Access-Control-Allow-Origin
    // entirely and let the browser enforce same-origin policy.
    const requestOrigin = req.header("origin");
    if (isOriginAllowed(requestOrigin)) {
      res.header("Access-Control-Allow-Origin", requestOrigin);
      res.header("Access-Control-Allow-Credentials", "true");
      res.header(
        "Access-Control-Expose-Headers",
        EXPOSED_RESPONSE_HEADERS.join(", ")
      );
    }
    res.header("Access-Control-Allow-Methods", "GET, PUT, PATCH, POST, DELETE");
    const requestedHeaders = req.header("access-control-request-headers");
    if (requestedHeaders != null) {
      res.header("Access-Control-Allow-Headers", requestedHeaders);
    }

    let path = req.originalUrl;
    if (path.startsWith(NGINX_PATH)) path = path.substring(NGINX_PATH.length);

    // HIGH-3: debug/log mode is operator-controlled only (CACP_DEBUG /
    // CACP_LOG env vars, set at deploy time). A caller could previously flip
    // either on for their own request via a "/debug" or "/log" path prefix or
    // a CACP_DEBUG/CACP_LOG request header - and since debugMode logs the
    // full forwarded request config (including Authorization/Key/x-apikey
    // headers) to the server's own logs, that let any caller force another
    // in-flight request's credentials into plaintext logs. Removed; toggle
    // via the env vars and restart the service instead.
    debugMode = DEBUG_MODE;
    logMode = LOG_MODE;

    // Immediatly return yes on cors requests
    if (req.method.toLowerCase() == "options") {
      // If it's a CORS request, just answer yes to anything
      if (logMode) {
        console.log(
          logId +
            "CORS request received and allowed for " +
            req.method +
            ":" +
            req.url
        );
      }
      if (debugMode) {
        console.log(
          logId + "Sending CORS request response  ",
          convertForLog(res)
        );
      }
      res.status(200).send();
      return;
    }

    // Generate the Axios config to call the server
    const config: AxiosRequestConfig<any> = {};

    // Is the target path sent as a parameter ?
    if (req.query["url"] != null) {
      path = decodeURIComponent(req.query["url"] as string);
      pathFromUrl = true;
      if (debugMode) {
        console.log("Using path from url parameter: ", path);
      }
    }

    // Find the url of the server to call
    if (path.startsWith("/")) path = path.substring(1);
    if (path == "") {
      res.sendFile("./pages/index.html", { root: __dirname });
      return;
    } else if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(path)) {
      // Any absolute URL (including disallowed schemes like file:// or
      // gopher://) falls through to the SSRF check below, which rejects
      // them with 403. Only truly relative/non-URL paths are 404'd here.
      console.warn("Ignoring relative url path " + path);
      if (debugMode)
        console.debug(
          "Ignoring relative url path " + path + " for request",
          req
        );
      res.sendStatus(404).send();
      return;
    }

    // Sometimes proxy mess up the url
    const protocolIndex = path.indexOf(":/");
    if (path.charAt(protocolIndex + 2) != "/") {
      path =
        path.substring(0, protocolIndex + 1) +
        "/" +
        path.substring(protocolIndex + 1);
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(path);
    } catch {
      res.status(400).json({ error: "Invalid target URL" });
      return;
    }

    if (!(await isTargetUrlAllowed(targetUrl))) {
      res.status(403).json({ error: "Target URL not allowed" });
      return;
    }

    config.url = path;
    config.method = req.method;
    config.headers = {};
    // We send back the redirects to the client
    config.maxRedirects = 0;

    // Any http error from the server will be sent back to the client
    config.validateStatus = function (status) {
      return true;
    };

    config.responseType = "stream";
    config.decompress = false;

    // We copy the headers from the client to the server
    // except for host that needs to be the server's host (and not the proxy's host)
    for (const headerKey in req.headers) {
      if (headerKey.toLowerCase() == "host") {
        //config.headers[headerKey]=targetUrl.host;
        delete config.headers[headerKey];
        if (debugMode) {
          console.log(logId + "Removing Host header");
        }
      } else if (headerKey.toLowerCase() == "origin") {
        if (debugMode) {
          console.log(
            logId +
              "Changing " +
              headerKey +
              " from " +
              req.headers[headerKey] +
              " to " +
              targetUrl.origin
          );
        }
        config.headers[headerKey] = targetUrl.origin;
        // Ignore them
      } else if (headerKey.toLowerCase() == "referer") {
        if (debugMode) {
          console.log(
            logId +
              "Changing " +
              headerKey +
              " from " +
              req.headers[headerKey] +
              " to " +
              targetUrl.origin +
              "/"
          );
        }
        config.headers[headerKey] = targetUrl.origin + "/";
        // Ignore them
      } /*else if( headerKey.toLowerCase()=='sec-fetch-mode') {
                if (debugMode) {
                    console.log(logId+"Changing "+headerKey+' from '+req.headers[headerKey]+' to navigate');
                }
                config.headers[headerKey]='navigate';
            }*/ else if (headerKey.toLowerCase() == "sec-fetch-site") {
        if (debugMode) {
          console.log(
            logId +
              "Changing " +
              headerKey +
              " from " +
              req.headers[headerKey] +
              " to same-site"
          );
        }
        config.headers[headerKey] = "same-site";
      } /*else if( headerKey.toLowerCase()=='sec-fetch-dest') {
                if (debugMode) {
                    console.log(logId+"Changing "+headerKey+' from '+req.headers[headerKey]+' to document');
                }
                config.headers[headerKey]='document';
            }*/ else if (headerKey.toLowerCase() == "connection") {
        if (debugMode) {
          console.log(
            logId +
              "Changing " +
              headerKey +
              " from " +
              req.headers[headerKey] +
              " to keep-alive"
          );
        }
        config.headers[headerKey] = "keep-alive";
      } else {
        config.headers[headerKey] = req.headers[headerKey];
      }

      //            config.headers['Referrer-Policy']='strict-origin-when-cross-origin';
      //console.log("Header:"+headerKey);
    }

    if (req.method.toLowerCase() != "get") config.data = req.body;

    if (debugMode) console.log(logId + "Sending request: ", config);
    if (logMode)
      console.log(
        logId + "Sending request: " + config.method + ":" + config.url
      );

    let response: AxiosResponse | null = null;

    if (
      req.query["engine"] != null &&
      (req.query["engine"] as string).toLowerCase() !== "standard"
    ) {
      const engine = (req.query["engine"] as string).toLowerCase();
      if (engine === "chrome" || engine === "cloudflare") {
        const chromeResult = await chromeEngine.request(
          engine,
          config,
          BYPASS_CHROME_SANDBOX,
          CHROME_EXEC
        );
        if (chromeResult != null) {
          response = chromeResult;
        } else {
          response = {
            status: 500,
            statusText: "Error ",
            data: undefined,
            headers: {},
            config: config as InternalAxiosRequestConfig,
          };
        }
      } else {
        res.status(400).statusMessage =
          (("Engine type " + req.query["engine"]) as string) +
          " is not supported";
        if (debugMode)
          console.log(
            (logId +
              "Unknown engine type received " +
              req.query["engine"]) as string,
            config
          );
        if (logMode)
          console.log(
            (logId +
              "Unknown engine type received " +
              req.query["engine"]) as string
          );
        res.send();
        return;
      }
    } else {
      response = await axios.request<any, AxiosResponse<Stream>>(config);
    }

    if (response == null) {
      res.status(500).statusMessage = "No Response...";
      res.send();
      return;
    }

    const responseStatus = response.status;
    const responseBody = response.data;
    if (debugMode)
      console.log(logId + "Received response: ", convertForLog(response));
    if (logMode) console.log(logId + "Received response: ", responseStatus);
    for (const headerKey in response.headers) {
      if (!isUpstreamHeaderAllowed(headerKey)) continue;
      if (headerKey.toLowerCase() == "set-cookie") {
        // We have special handling for cookies
        const newCookies = new Array<string>();
        // Change some values of the cookies to make it work with the browser across the proxy
        for (let cookieText of response.headers[headerKey]!) {
          const originalText = cookieText;
          cookieText = transformCookie(originalText);
          if (debugMode)
            console.log(
              logId + "Replaced cookie " + originalText + " to " + cookieText
            );
          newCookies.push(cookieText);
        }
        res.header(headerKey, newCookies);
      } else res.header(headerKey, response.headers[headerKey]);
    }

    res.status(responseStatus);
    res.statusMessage = response.statusText;
    // Handle the locations of the redirect
    if (responseStatus >= 300 && responseStatus < 400) {
      const rootLocation = response.headers["location"];
      res.header(
        "location",
        remapUrl(rootLocation, redirectUrl, path, targetUrl.origin, pathFromUrl)
      );
      if (debugMode)
        console.log(
          logId +
            "Replaced Redirect location " +
            rootLocation +
            " to " +
            res.getHeader("location")
        );
    }
    if (debugMode)
      console.log(logId + "Sending response: ", convertForLog(res));
    if (logMode) console.log(logId + "Sending response: ", res.statusCode);

    if (responseBody != null) {
      if (responseBody.pipe != null) {
        // Is it s stream ?
        responseBody
          .pipe(res)
          .on("finish", () => {
            next();
          })
          .on("error", (err: any) => {
            if (debugMode) console.log(logId + "Error sending response: ", err);
            if (logMode)
              console.log(logId + "Error sending response: ", err.toString());
            next(err);
          });
      } else {
        res.send(responseBody);
      }
    } else {
      res.send();
    }
  } catch (error) {
    try {
      if (axios.isAxiosError(error)) {
        handleAxiosError(res, error, logId);
      } else {
        handleUnexpectedError(res, error, logId);
      }
    } catch (errorInError) {
      // Even error handling crashes, just send error 500
      res.sendStatus(500);
    }
  }
}

// HIGH-1: never send the raw Error/AxiosError object back to the client -
// it serializes to JSON including the stack trace, internal paths, and the
// full Axios request config (headers, target URL, etc). Always respond with
// a generic body and a status mapped from the error type.
function axiosErrorStatus(error: AxiosError<any, any>): number {
  switch (error.code) {
    case "ENOTFOUND":
    case "ECONNREFUSED":
    case "EHOSTUNREACH":
    case "ENETUNREACH":
      return 502; // Bad Gateway
    case "ECONNABORTED":
    case "ETIMEDOUT":
      return 504; // Gateway Timeout
    default:
      return 502; // Bad Gateway
  }
}

function handleAxiosError(
  res: Response,
  error: AxiosError<any, any>,
  logId: string = ""
) {
  console.error(logId + "Received Error", convertForLog(error));
  res.status(axiosErrorStatus(error)).json({ error: "Proxy error" });
}

function handleUnexpectedError(
  res: Response,
  error: unknown,
  logId: string = ""
) {
  console.error(logId + "Received Unknown Error", error);
  res.status(500).json({ error: "Proxy error" });
}

function convertForLog(
  item: AxiosError<any, any> | AxiosResponse | Response
): any {
  const ret: any = {};
  if (item instanceof AxiosError) {
    const axiosError = item as AxiosError;
    ret.status = axiosError.status;
    ret.message = axiosError.message;

    if (ret.message == null && ret.response?.message != null) {
      ret.message = ret.response.message;
    }

    if (ret.status == null) {
      ret.status = 500;
    }
    if (axiosError.config != null) {
      ret.url = axiosError.config.url;
      ret.method = axiosError.config.method;
      ret.headers = axiosError.config.headers;
    }
  } else if ((item as any).config == null && (item as any).toJSON == null) {
    // It's an express response
    const expressResponse = item as Response;
    ret.status = expressResponse.statusCode;
    ret.message = expressResponse.statusMessage;

    if (expressResponse.req != null) {
      ret.url = expressResponse.req.url;
      ret.method = expressResponse.req.method;
      ret.headers = expressResponse.req.headers;
    }
  } else {
    const axiosResponse = item as AxiosResponse;
    ret.status = axiosResponse.status;
    ret.message = axiosResponse.statusText;
    if (axiosResponse.config != null) {
      ret.url = axiosResponse.config.url;
      ret.method = axiosResponse.config.method;
      ret.headers = axiosResponse.config.headers;
    }
    if (axiosResponse.data == null) {
      ret.bodyType = "Empty body";
    } else if (axiosResponse.data.pipe != null) {
      ret.bodyType = "Body is a stream";
    } else {
      ret.bodyType = "Body is string data";
      try {
        const bodyText = axiosResponse.data.toString();
        ret.bodyLength = bodyText.length;
      } catch (error) {
        ret.bodyType = "Body is unknown data";
      }
    }
  }
  return ret;
}

let proxyServer: http.Server | null = null;

export function getProxyServer(): http.Server {
  if (proxyServer != null) return proxyServer;
  else throw new Error("No proxy Server created");
}

if (argv[2] === "testChrome") {
  let url = "https://dont-code.net";
  if (argv[3] != null) {
    url = argv[3];
  }
  chromeEngine
    .request("chrome", { url: url, method: "get" }, BYPASS_CHROME_SANDBOX, CHROME_EXEC)
    .then((value) => {
      console.log("Response received with status: " + value.status);
      console.log(value.data);
      if (value.status == 200) {
        console.log("Succesfully called external website.");
        process.exit(0);
      } else {
        console.error("Error " + value.status + " calling external website.");
        process.exit(1);
      }
    })
    .catch((reason) => {
      console.error("Error calling external website:", reason);
      process.exit(-1);
    });
} else {
  proxyServer = app.listen(PORT, () => {
    console.log(
      "Application started on port " +
        PORT +
        ' with redirection "' +
        (REDIRECT_HOST ? REDIRECT_HOST + REDIRECT_PATH : "proxy") +
        '".'
    );
  });
}
