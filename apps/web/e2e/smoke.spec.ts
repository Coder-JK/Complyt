import { test, expect } from "@playwright/test";

test.describe("Smoke tests", () => {
  test("dashboard page loads", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.locator("h2")).toContainText("Dashboard");
  });

  test("sidebar navigation works", async ({ page }) => {
    await page.goto("/dashboard");

    await page.getByRole("link", { name: "Controls" }).click();
    await expect(page).toHaveURL(/\/controls/);
    await expect(page.locator("h2")).toContainText("Controls");

    await page.getByRole("link", { name: "Evidence Runs" }).click();
    await expect(page).toHaveURL(/\/evidence/);

    await page.getByRole("link", { name: "Exports" }).click();
    await expect(page).toHaveURL(/\/exports/);

    await page.getByRole("link", { name: "Settings" }).click();
    await expect(page).toHaveURL(/\/settings/);
  });

  test("can create a workspace", async ({ page }) => {
    await page.goto("/settings");

    await page.getByLabel("Name").fill("Test Workspace");
    await page.getByRole("button", { name: "Create Workspace" }).click();

    await expect(page.getByText("Test Workspace")).toBeVisible();
  });
});
