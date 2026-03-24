import { describe, it, expect } from "vitest";
import { HttpError, OfflineError } from "./http";

describe("HttpError", () => {
  it("contains status and url", () => {
    const err = new HttpError("Not Found", 404, "https://example.com");
    expect(err.status).toBe(404);
    expect(err.url).toBe("https://example.com");
    expect(err.name).toBe("HttpError");
    expect(err.message).toBe("Not Found");
  });
});

describe("OfflineError", () => {
  it("has correct name", () => {
    const err = new OfflineError("Network unavailable");
    expect(err.name).toBe("OfflineError");
    expect(err.message).toBe("Network unavailable");
  });
});
