import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { App, hasRealmRole } from "./App";

describe("AegisLedger console", () => {
  it("derives auditor access from the mapped Keycloak realm roles", () => {
    expect(
      hasRealmRole({ realm_access: { roles: ["viewer", "auditor"] } }, "auditor"),
    ).toBe(true);
    expect(hasRealmRole({ realm_access: { roles: ["viewer"] } }, "auditor")).toBe(false);
    expect(hasRealmRole({ realm_access: "malformed" }, "auditor")).toBe(false);
  });

  it("shows the runtime posture in demo mode", async () => {
    render(<App demoMode />);

    expect(
      screen.getByRole("heading", { name: "A quiet system is a system you can inspect." }),
    ).toBeInTheDocument();
    expect(await screen.findByText("API", { selector: ".status" })).toBeInTheDocument();
    expect(screen.getByText("Non-custodial boundary")).toBeInTheDocument();
  });

  it("runs a side-effect-free policy simulation", async () => {
    const user = userEvent.setup();
    render(<App demoMode />);

    await user.click(screen.getByRole("button", { name: /policy lab/i }));
    await user.click(screen.getByRole("button", { name: /run simulation/i }));

    expect(await screen.findByText("ALLOW", { selector: ".result-card strong" })).toBeVisible();
    expect(screen.getByText("No denial reasons")).toBeVisible();
  });

  it("resolves a proposal lifecycle without exposing signing controls", async () => {
    const user = userEvent.setup();
    render(<App demoMode />);

    await user.click(screen.getByRole("button", { name: /transactions/i }));
    await user.click(screen.getByRole("button", { name: /inspect lifecycle/i }));

    expect(await screen.findByRole("heading", { name: "RESERVED" })).toBeVisible();
    expect(screen.queryByRole("button", { name: /sign|submit transaction/i })).not.toBeInTheDocument();
  });

  it("loads and verifies a retained complete attestation by proposal ID", async () => {
    const user = userEvent.setup();
    render(<App demoMode />);

    await user.click(screen.getByRole("button", { name: /evidence/i }));
    await user.click(screen.getByRole("button", { name: /load & verify/i }));

    expect(await screen.findByText("Cryptographically valid")).toBeVisible();
    expect(screen.getByRole("radio", { name: "Complete attestation" })).toBeChecked();
    expect((screen.getByLabelText("Artifact JSON") as HTMLTextAreaElement).value).toContain(
      "aegisledger.complete_attestation.v1",
    );
    expect(screen.queryByRole("button", { name: /sign|submit transaction/i })).not.toBeInTheDocument();
  });
});
