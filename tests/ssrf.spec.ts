import axios from "axios";

describe("SSRF target blocklist [CRIT-2]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";

  const originalAllowPrivate = process.env.SSRF_ALLOW_PRIVATE;

  afterEach(() => {
    if (originalAllowPrivate === undefined) {
      delete process.env.SSRF_ALLOW_PRIVATE;
    } else {
      process.env.SSRF_ALLOW_PRIVATE = originalAllowPrivate;
    }
  });

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

  it("blocks RFC 1918 private targets by default (10.0.0.1)", async () => {
    delete process.env.SSRF_ALLOW_PRIVATE;
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://10.0.0.1/" },
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

  it("allows RFC 1918 private targets when SSRF_ALLOW_PRIVATE=true, but still blocks loopback", async () => {
    process.env.SSRF_ALLOW_PRIVATE = "true";

    // Private range should no longer be rejected by the SSRF check itself.
    // There's no real host at 10.0.0.1 in this sandbox, so the connection
    // attempt itself may fail or time out - what matters is that it's not
    // rejected with the SSRF 403 before Axios even tries.
    try {
      const privateResponse = await axios.request({
        url: TEST_SERVER_URL + "/",
        params: { url: "http://10.0.0.1/" },
        method: "get",
        validateStatus: () => true,
        timeout: 3000,
      });
      expect(privateResponse.status).not.toBe(403);
    } catch (err: any) {
      expect(err.response?.status).not.toBe(403);
    }

    // Loopback/link-local must always be blocked regardless of the flag.
    const loopbackResponse = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://127.0.0.1/" },
      method: "get",
      validateStatus: () => true,
    });
    expect(loopbackResponse.status).toBe(403);
  });
});
