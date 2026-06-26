import axios from "axios";
import request from "supertest";

describe("SSRF target blocklist [CRIT-2]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";

  it("blocks loopback IPv4 (127.0.0.1)", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://127.0.0.1/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
    expect(response.data).toEqual({ error: "Target URL not allowed" });
  });

  it("blocks the localhost hostname", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://localhost/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
  });

  it("blocks link-local / cloud metadata (169.254.169.254)", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://169.254.169.254/latest/meta-data/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
  });

  it("blocks unspecified address (0.0.0.0)", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://0.0.0.0/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
  });

  it("blocks IPv6 loopback ([::1])", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://[::1]/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
  });

  it("blocks file:// scheme", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "file:///etc/passwd" },
      method: "get",
      validateStatus: () => true,
    });
    expect(response.status).toBe(403);
  });

  it("blocks gopher:// and ftp:// schemes", async () => {
    const gopherResponse = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "gopher://127.0.0.1/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(gopherResponse.status).toBe(403);

    const ftpResponse = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "ftp://127.0.0.1/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(ftpResponse.status).toBe(403);
  });

});

// tests/globalSetup.js starts one shared proxy server (used by all the specs
// above) with SSRF_ALLOW_PRIVATE permanently set to "true", so its dummy
// backend - which has to bind to a real, often RFC 1918, interface address -
// passes the SSRF check. That means the shared server's SSRF_ALLOW_PRIVATE
// behavior can't be toggled per-test by mutating process.env from here: this
// test file and the shared server run in different processes once Jest forks
// test files into workers, so such a mutation is invisible to the server
// that actually receives the request. Each test below instead loads its own
// isolated copy of src/server.ts (same pattern as corsAllowlist.spec.ts) with
// the env var set the way that specific test needs.
describe("SSRF private-range flag [CRIT-2]", () => {
  it("blocks RFC 1918 private targets by default (10.0.0.1)", async () => {
    const previousAllowPrivate = process.env.SSRF_ALLOW_PRIVATE;
    const previousPort = process.env.CACP_PORT;
    delete process.env.SSRF_ALLOW_PRIVATE;
    process.env.CACP_PORT = "0";

    let isolatedServer!: typeof import("../src/server");
    jest.resetModules();
    jest.isolateModules(() => {
      isolatedServer = require("../src/server");
    });

    process.env.SSRF_ALLOW_PRIVATE = previousAllowPrivate;
    process.env.CACP_PORT = previousPort;

    try {
      const response = await request(isolatedServer.app).get("/proxy/").query({
        url: "http://10.0.0.1/",
      });
      expect(response.status).toBe(403);
    } finally {
      isolatedServer.getProxyServer().close();
    }
  });

  it("allows RFC 1918 private targets when SSRF_ALLOW_PRIVATE=true, but still blocks loopback", async () => {
    const previousAllowPrivate = process.env.SSRF_ALLOW_PRIVATE;
    const previousPort = process.env.CACP_PORT;
    process.env.SSRF_ALLOW_PRIVATE = "true";
    process.env.CACP_PORT = "0";

    let isolatedServer!: typeof import("../src/server");
    jest.resetModules();
    jest.isolateModules(() => {
      isolatedServer = require("../src/server");
    });

    process.env.SSRF_ALLOW_PRIVATE = previousAllowPrivate;
    process.env.CACP_PORT = previousPort;

    try {
      // The dummy backend (tests/globalSetup.js) binds to a real, non-loopback
      // interface address, which is typically RFC 1918 private in CI/sandbox
      // environments. Routing the proxy at it - rather than an unreachable
      // address like 10.0.0.1, whose connection behavior varies by network
      // environment - deterministically exercises "private range allowed"
      // without depending on how a given host treats a dead connection.
      const privateResponse = await request(isolatedServer.app)
        .get("/proxy/")
        .query({ url: process.env.SERVER_ADDRESS + "/index.html" });
      expect(privateResponse.status).toBe(200);

      // Loopback/link-local must always be blocked regardless of the flag.
      const loopbackResponse = await request(isolatedServer.app)
        .get("/proxy/")
        .query({ url: "http://127.0.0.1/" });
      expect(loopbackResponse.status).toBe(403);
    } finally {
      isolatedServer.getProxyServer().close();
    }
  });
});
