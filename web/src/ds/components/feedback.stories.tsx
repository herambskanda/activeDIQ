import type { Meta, StoryObj } from "@storybook/react-vite";
import { useState } from "react";

import "./components.css";
import { Banner, Button, Chip, Kbd, Progress, StatePanel } from "./index";

/** Fixture text: the reports state messages (reports-2a-flows.md §3). Real screens pass their own. */
const meta: Meta = { title: "Design system/Feedback", parameters: { layout: "padded" } };
export default meta;
type Story = StoryObj;

const STALE =
  "The last successful sync of emea.corp.example was 3 hours ago (06:41) because that connection is waiting for a full resync. This report ran on what activeDIQ last saw.";

export const Banners: Story = {
  render: () => (
    <div>
      <Banner tone="info" title="Not synced yet: labs.example">
        That domain has not finished its first sync, so it is skipped. The rows below cover the
        other 2 of 3 domains.
      </Banner>
      <Banner tone="warn" title="Stale data" actions={<Button>Open the connection</Button>}>
        {STALE}
      </Banner>
      <Banner tone="crit" title="Sync failed">
        The connection to emea.corp.example was refused. Nothing was changed.
      </Banner>
    </div>
  ),
};

export const BannerLongContent: Story = {
  name: "Banner, long and RTL content",
  render: () => (
    <div>
      <Banner tone="warn" title={"Stale data: " + "emea-".repeat(14) + "corp.example"}>
        dc-ams-03.emea.corp.example did not answer (LDAP timeout after 30 s) for the very long
        organisational unit path corp.example/Offices/Regions/Northern
        Europe/Netherlands/Amsterdam/Finance/Contractors
      </Banner>
      <div dir="rtl" lang="ar">
        <Banner tone="info" title="بيانات قديمة">
          آخر مزامنة ناجحة قبل ثلاث ساعات.
        </Banner>
      </div>
    </div>
  ),
};

export const Chips: Story = {
  render: () => (
    <p style={{ display: "flex", gap: "var(--diq-space-2)", flexWrap: "wrap" }}>
      <Chip tone="ok">✓ Synced</Chip>
      <Chip tone="muted">○ Expired: was synced 09:41 on 23 Oct</Chip>
      <Chip tone="warn">Stale: last sync 3 h ago (emea.corp.example)</Chip>
      <Chip tone="crit">Failed</Chip>
    </p>
  ),
};

export const ProgressStates: Story = {
  name: "Progress",
  render: () => (
    <div style={{ display: "grid", gap: "var(--diq-space-4)", maxInlineSize: "40ch" }}>
      <div>
        <p>33% · 4,102 of 12,431 accounts read across 6 DCs</p>
        <Progress label="Run progress" value={33} />
      </div>
      <div>
        <p>Waiting for the first domain controller…</p>
        <Progress label="Run progress" />
      </div>
      <Progress label="Complete" value={100} />
    </div>
  ),
};

export const Keys: Story = {
  render: () => (
    <p>
      <Button>
        Export <Kbd>E</Kbd>
      </Button>{" "}
      <Button variant="primary">
        Schedule <Kbd>S</Kbd>
      </Button>{" "}
      Press <Kbd>/</Kbd> to search, <Kbd>Esc</Kbd> to close.
    </p>
  ),
};

export const StatePanelWithActions: Story = {
  render: () => {
    const [n, setN] = useState(0);
    return (
      <div>
        <StatePanel
          title="Your role covers no directory objects"
          actions={
            <Button onClick={() => setN(n + 1)}>Copy a request for your administrator</Button>
          }
        >
          <p>Ask an administrator to grant a scope. Nothing is broken. Copied {n} times.</p>
        </StatePanel>
        <StatePanel
          tone="error"
          title="This run failed: the query timed out"
          actions={
            <>
              <Button variant="primary">Retry</Button>
              <Button>Back to the library</Button>
            </>
          }
        >
          <p>The database did not answer within 30 s. Nothing was changed.</p>
        </StatePanel>
      </div>
    );
  },
};
