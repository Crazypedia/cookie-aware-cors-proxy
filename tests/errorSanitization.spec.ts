import axios from "axios";

describe("Error sanitization [HIGH-1]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";

  it("returns a generic body with no stack trace when the target host can't be resolved", async () => {
    const response = await axios.request({
      url: TEST_SERVER_URL + "/",
      params: { url: "http://this-domain-does-not-exist.invalid/" },
      method: "get",
      validateStatus: () => true,
    });

    expect(response.status).toBe(502);
    expect(response.data).toEqual({ error: "Proxy error" });
    expect(JSON.stringify(response.data)).not.toMatch(/stack|node_modules|ENOTFOUND/i);
  });
});
