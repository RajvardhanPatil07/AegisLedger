import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";

import { createDemoApi, DEMO_PROPOSAL_ID } from "../demo";
import { Evidence } from "./Evidence";

describe("Evidence", () => {
  it("prevents non-auditors from issuing a doomed audit request", async () => {
    const user = userEvent.setup();
    const api = createDemoApi();
    const auditEvents = vi.spyOn(api, "auditEvents");

    render(
      <Evidence
        api={api}
        canReadAudit={false}
        initialProposalId={DEMO_PROPOSAL_ID}
        notify={vi.fn()}
      />,
    );

    const loadStream = screen.getByRole("button", { name: "Load stream" });
    expect(loadStream).toBeDisabled();
    expect(screen.getByText("Auditor role required")).toBeVisible();

    await user.click(loadStream);
    expect(auditEvents).not.toHaveBeenCalled();
  });
});
