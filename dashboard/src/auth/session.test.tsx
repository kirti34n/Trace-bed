import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { notifyAuthenticationChanged } from "../api/client";
import { anonymousSession, authenticatedSession } from "../test/fixtures";
import { SessionProvider, useSession } from "./session";

function response(body: unknown) {
  return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
}

function ViewState() {
  const { epoch, phase, logout } = useSession();
  return <ViewStateValue key={epoch} phase={phase} logout={logout} />;
}

function ViewStateValue({ phase, logout }: { phase: string; logout: () => Promise<void> }) {
  const [selection, setSelection] = useState("clean");
  return <><p>phase:{phase}</p><p>selection:{selection}</p><button type="button" onClick={() => setSelection("stale")}>Select</button><button type="button" onClick={() => void logout()}>Sign out</button></>;
}

describe("SessionProvider", () => {
  it("drops view-local state when authentication changes", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(response(authenticatedSession)).mockResolvedValueOnce(response(anonymousSession)));
    render(<SessionProvider><ViewState /></SessionProvider>);
    await screen.findByText("phase:authenticated");
    fireEvent.click(screen.getByRole("button", { name: "Select" }));
    expect(screen.getByText("selection:stale")).toBeInTheDocument();
    notifyAuthenticationChanged();
    await waitFor(() => expect(screen.getByText("phase:anonymous")).toBeInTheDocument());
    expect(screen.getByText("selection:clean")).toBeInTheDocument();
  });

  it("clears stale state before a failing logout can complete its follow-up probe", async () => {
    let resolveProbe: ((value: Response) => void) | undefined;
    const delayedProbe = new Promise<Response>((resolve) => { resolveProbe = resolve; });
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(response(authenticatedSession))
      .mockRejectedValueOnce(new Error("logout transport failed"))
      .mockReturnValueOnce(delayedProbe));
    render(<SessionProvider><ViewState /></SessionProvider>);
    await screen.findByText("phase:authenticated");
    fireEvent.click(screen.getByRole("button", { name: "Select" }));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(screen.getByText("phase:loading")).toBeInTheDocument();
    expect(screen.getByText("selection:clean")).toBeInTheDocument();
    resolveProbe?.(response(anonymousSession));
    await screen.findByText("phase:anonymous");
  });
});
