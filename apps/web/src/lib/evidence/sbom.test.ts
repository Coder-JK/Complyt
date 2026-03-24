import { describe, it, expect } from "vitest";
import path from "path";
import { generateSbom } from "./sbom";

describe("generateSbom", () => {
  it("generates a CycloneDX BOM from package.json", async () => {
    const targetDir = path.resolve(process.cwd());
    const sbom = await generateSbom(targetDir);

    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.specVersion).toBe("1.5");
    expect(sbom.components).toBeDefined();
    expect(Array.isArray(sbom.components)).toBe(true);
    expect(sbom.components.length).toBeGreaterThan(0);

    const nextComponent = sbom.components.find((c) => c.name === "next");
    expect(nextComponent).toBeDefined();
    expect(nextComponent?.purl).toMatch(/^pkg:npm/);
    expect(nextComponent?.type).toBe("library");
  });

  it("includes metadata with timestamp and tool info", async () => {
    const targetDir = path.resolve(process.cwd());
    const sbom = await generateSbom(targetDir);

    expect(sbom.metadata.timestamp).toBeDefined();
    expect(sbom.metadata.tools).toContainEqual({
      name: "complyt",
      version: "0.1.0",
    });
  });

  it("throws if no package.json found", async () => {
    await expect(generateSbom("/nonexistent/path")).rejects.toThrow(
      "No package.json found"
    );
  });
});
