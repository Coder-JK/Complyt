import { describe, it, expect } from "vitest";

function escapeCsv(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

describe("CSV escaping", () => {
  it("passes through simple values", () => {
    expect(escapeCsv("hello")).toBe("hello");
  });

  it("wraps values with commas in quotes", () => {
    expect(escapeCsv("hello, world")).toBe('"hello, world"');
  });

  it("escapes double quotes", () => {
    expect(escapeCsv('say "hi"')).toBe('"say ""hi"""');
  });

  it("handles newlines", () => {
    expect(escapeCsv("line1\nline2")).toBe('"line1\nline2"');
  });
});
