import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { App } from "./App";

describe("AegisLedger console", () => {
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
});
