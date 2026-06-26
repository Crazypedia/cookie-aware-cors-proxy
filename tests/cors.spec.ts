import axios from "axios";

describe("CORS origin allowlist [CRIT-1]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";

  // CORS_ALLOWED_ORIGINS is unset in the test environment, so the allowlist
  // is empty and every origin below must be rejected (fail closed).

  it("omits Access-Control-Allow-Origin for an origin not on the allowlist", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/" + process.env.SERVER_ADDRESS + "/index.html",
      method: "get",
      headers: { Origin: "https://evil.example.com" },
    });
    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("never reflects the literal 'null' origin", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/" + process.env.SERVER_ADDRESS + "/index.html",
      method: "get",
      headers: { Origin: "null" },
    });
    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("omits Access-Control-Allow-Headers instead of sending the literal string 'undefined' [LOW-1]", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/" + process.env.SERVER_ADDRESS + "/index.html",
      method: "options",
      headers: { Origin: "https://evil.example.com" },
    });
    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-headers"]).toBeUndefined();
  });
});
