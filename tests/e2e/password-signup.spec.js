const { test, expect } = require("@playwright/test");

async function signUpAndVerify(page, email, password) {
  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create account" }).click();

  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.getByTestId("verification-link").click();

  await expect(page.getByTestId("status")).toHaveText("Email verified. Sign in to continue.");
  await expect(page).toHaveURL(/\/signin\?verified=1$/);
}

async function signInWithPassword(page, email, password) {
  await page.goto("/signin");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  await page.getByTestId("account-link").click();
  await expect(page.getByTestId("account-status")).toHaveText("Signed in");
}

test("email password signup verifies by email link and signs in", async ({ page, context }) => {
  const email = `browser-${Date.now()}@example.com`;
  const password = "correct horse battery staple";

  await signUpAndVerify(page, email, password);
  expect(page.url()).not.toContain("challenge=");
  expect(page.url()).not.toContain("token=");
  await signInWithPassword(page, email, password);

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "harbor_session");
  expect(session).toMatchObject({
    httpOnly: true,
    sameSite: "Lax"
  });
});

test("email magic link creates a session and cleans token URL", async ({ page }) => {
  const email = `magic-${Date.now()}@example.com`;

  await page.goto("/signin/email-link");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send magic link" }).click();

  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.getByTestId("email-link").click();

  await expect(page.getByTestId("account-status")).toHaveText("Signed in");
  await expect(page).toHaveURL(/\/account$/);
  expect(page.url()).not.toContain("challenge=");
  expect(page.url()).not.toContain("token=");
});

test("email OTP creates a session", async ({ page }) => {
  const email = `otp-${Date.now()}@example.com`;

  await page.goto("/signin/email-code");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send code" }).click();

  await expect(page.getByRole("heading", { name: "Enter code" })).toBeVisible();
  const code = await page.getByTestId("recorded-code").textContent();
  expect(code).toMatch(/^[0-9]{8}$/);
  await page.getByLabel("Code").fill(code);
  await page.getByRole("button", { name: "Verify code" }).click();

  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  await page.getByTestId("account-link").click();
  await expect(page.getByTestId("account-status")).toHaveText("Signed in");
});

test("forgot password resets password without auto login", async ({ page }) => {
  const email = `reset-${Date.now()}@example.com`;
  const oldPassword = "correct horse battery staple";
  const newPassword = "new correct horse battery staple";

  await signUpAndVerify(page, email, oldPassword);
  await page.goto("/forgot-password");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send reset link" }).click();

  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await page.getByTestId("reset-link").click();
  await expect(page.getByRole("heading", { name: "Reset password" })).toBeVisible();
  await page.getByLabel("New password").fill(newPassword);
  await page.getByRole("button", { name: "Reset password" }).click();

  await expect(page.getByRole("heading", { name: "Password reset" })).toBeVisible();
  await page.goto("/account");
  await expect(page.getByTestId("account-status")).toHaveText("Signed out");

  await signInWithPassword(page, email, newPassword);
});

test("signout revokes the browser session cookie", async ({ page }) => {
  const email = `signout-${Date.now()}@example.com`;
  const password = "correct horse battery staple";

  await signUpAndVerify(page, email, password);
  await signInWithPassword(page, email, password);
  await page.getByRole("button", { name: "Sign out" }).click();

  await expect(page.getByTestId("account-status")).toHaveText("Signed out");
  await page.goto("/account");
  await expect(page.getByTestId("account-status")).toHaveText("Signed out");
});
