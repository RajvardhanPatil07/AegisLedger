import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function expectNoSeriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
}

test("policy simulation is usable and has no serious accessibility violations", async ({ page, isMobile }) => {
  await page.goto("/");
  await expectNoSeriousViolations(page);
  if (isMobile) await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("button", { name: /policy lab/i }).click();
  await page.getByRole("button", { name: /run simulation/i }).click();

  await expect(page.locator(".result-card")).toContainText("ALLOW");
  await expectNoSeriousViolations(page);
});

test("mobile navigation reaches retained experiment evidence", async ({ page, isMobile }) => {
  test.skip(!isMobile, "mobile navigation assertion");
  await page.goto("/");
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("button", { name: /experiments/i }).click();
  await page.getByRole("button", { name: "Load" }).click();

  await expect(page.getByText("COMPLETED", { exact: true })).toBeVisible();
  await expect(page.getByText("240", { exact: true })).toBeVisible();
  await expectNoSeriousViolations(page);
});

test("evidence verification and audit inspection remain observational", async ({ page, isMobile }) => {
  await page.goto("/");
  if (isMobile) await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("button", { name: /evidence/i }).click();
  await page.getByRole("button", { name: "Load & verify" }).click();
  await page.getByRole("button", { name: "Load stream" }).click();

  await expect(page.getByText("Cryptographically valid")).toBeVisible();
  await expect(page.getByRole("radio", { name: "Complete attestation" })).toBeChecked();
  await expect(page.getByRole("table")).toContainText("POLICY VERSION ACTIVATED");
  await expect(page.getByRole("button", { name: /sign|submit transaction/i })).toHaveCount(0);
  await expectNoSeriousViolations(page);
});
