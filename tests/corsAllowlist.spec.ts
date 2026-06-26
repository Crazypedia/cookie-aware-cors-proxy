import request from "supertest";

// This suite needs a fresh server instance with a different
// CORS_ALLOWED_ORIGINS value than the rest of the test run, so it loads its
// own isolated copy of src/server.ts (on its own port) rather than using the
// shared one started by tests/globalSetup.js.
describe("CORS allowlist reflects a configured origin [CRIT-1]", () => {
  let isolatedServer: typeof import("../src/server");

  beforeAll(() => {
    const previousOrigins = process.env.CORS_ALLOWED_ORIGINS;
    const previousPort = process.env.CACP_PORT;
    process.env.CORS_ALLOWED_ORIGINS = "https://allowed.example.com";
    process.env.CACP_PORT = "0";

    jest.resetModules();
    jest.isolateModules(() => {
      isolatedServer = require("../src/server");
    });

    process.env.CORS_ALLOWED_ORIGINS = previousOrigins;
    process.env.CACP_PORT = previousPort;
  });

  afterAll(() => {
    isolatedServer.getProxyServer().close();
  });

  it("reflects an allowlisted origin with credentials enabled", async () => {
    const response = await request(isolatedServer.app)
      .get("/proxy/" + process.env.SERVER_ADDRESS + "/index.html")
      .set("Origin", "https://allowed.example.com");

    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBe(
      "https://allowed.example.com"
    );
    expect(response.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("still rejects an origin not on this allowlist", async () => {
    const response = await request(isolatedServer.app)
      .get("/proxy/" + process.env.SERVER_ADDRESS + "/index.html")
      .set("Origin", "https://other.example.com");

    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("exposes the forwarded headers Vantage needs (e.g. rate-limit quota) but never set-cookie [HIGH-2]", async () => {
    const response = await request(isolatedServer.app)
      .get("/proxy/" + process.env.SERVER_ADDRESS + "/index.html")
      .set("Origin", "https://allowed.example.com");

    const exposed = response.headers["access-control-expose-headers"];
    expect(exposed).toBeDefined();
    expect(exposed).toMatch(/x-ratelimit-remaining/i);
    expect(exposed).not.toMatch(/set-cookie/i);
  });
});
