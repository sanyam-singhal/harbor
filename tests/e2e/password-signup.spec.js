const { test, expect } = require("@playwright/test");

test("email password signup verifies by email link and signs in", async ({ page }) => {
  const email = `browser-${Date.now()}@example.com`;
  const password = "correct horse battery staple";

  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create account" }).click();

  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.getByTestId("verification-link").click();

  await expect(page.getByTestId("status")).toHaveText("Email verified. Sign in to continue.");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  await page.getByTestId("account-link").click();

  await expect(page.getByTestId("account-status")).toHaveText("Signed in");
});
