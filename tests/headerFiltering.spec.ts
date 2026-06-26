import axios from "axios";

describe("Upstream response header filtering [HIGH-2]", () => {
  const TEST_SERVER_URL = "http://localhost:3000/proxy";

  it("does not forward a non-allowlisted upstream header to the client", async () => {
    const response = await axios.request({
      url:
        TEST_SERVER_URL +
        "/" +
        process.env.SERVER_ADDRESS +
        "/headertest/index.html",
      method: "get",
    });

    expect(response.status).toBe(200);
    expect(response.headers["x-internal-secret"]).toBeUndefined();
    expect(response.headers["content-type"]).toMatch(/text\/html/);
  });
});
