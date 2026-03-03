const { test, expect } = require("@playwright/test");

test.describe("Wax browser passkey E2E", () => {
  test("registers and authenticates using a virtual authenticator", async ({ page, context }) => {
    const client = await context.newCDPSession(page);

    await client.send("WebAuthn.enable");

    const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true
      }
    });

    try {
      await page.goto("/");
      await expect(page.getByTestId("status")).toContainText("Ready");

      await page.getByTestId("register-btn").click();
      await expect(page.getByTestId("status")).toContainText("Registration verified");

      await page.getByTestId("login-btn").click();
      await expect(page.getByTestId("status")).toContainText("Authentication verified");

      const { credentials } = await client.send("WebAuthn.getCredentials", { authenticatorId });
      expect(credentials.length).toBeGreaterThan(0);
    } finally {
      await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
      await client.send("WebAuthn.disable");
    }
  });
});
