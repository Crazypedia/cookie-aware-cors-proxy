import axios from "axios";

describe("Rate limiting [MED-1]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";
  // Default RATE_LIMIT_MAX (60/window) unless overridden for the test run.
  const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || "60", 10);

  it("returns 429 with Retry-After once a single IP exceeds the limit, without affecting other clients", async () => {
    // Use a dedicated X-Forwarded-For value so this test's burst of requests
    // doesn't share a rate-limit bucket with the other test suites running
    // against the same server (trust proxy is set to 1 hop, so this header
    // is honored as the client IP, exercising the spec's X-Forwarded-For
    // requirement directly).
    const fakeClientIp = "203.0.113.77";

    const requests = Array.from({ length: RATE_LIMIT_MAX + 5 }, () =>
      axios.request({
        url: TEST_SERVER_URL + "/" + process.env.SERVER_ADDRESS + "/index.html",
        method: "get",
        headers: { "X-Forwarded-For": fakeClientIp },
        validateStatus: () => true,
      })
    );

    const responses = await Promise.all(requests);
    const limited = responses.filter((response) => response.status === 429);

    expect(limited.length).toBeGreaterThan(0);
    expect(limited[0].data).toEqual({ error: "Too many requests" });
    expect(limited[0].headers["retry-after"]).toBeDefined();

    // A different client IP must still be served normally.
    const otherClientResponse = await axios.request({
      url: TEST_SERVER_URL + "/" + process.env.SERVER_ADDRESS + "/index.html",
      method: "get",
      headers: { "X-Forwarded-For": "203.0.113.200" },
      validateStatus: () => true,
    });
    expect(otherClientResponse.status).toBe(200);
  });
});
