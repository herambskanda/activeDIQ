import type { Meta, StoryObj } from "@storybook/react-vite";
import { useState } from "react";

import "./components.css";
import {
  Button,
  Popover,
  PopoverMenu,
  type PopoverMenuItem,
  SideSheet,
  Toast,
  ToastRegion,
  TextInput,
} from "./index";

/** Fixture data: invented names only. Real screens pass their own items. */
const meta: Meta = { title: "Design system/Overlays" };
export default meta;
type Story = StoryObj;

const Stage = ({ children }: { readonly children: React.ReactNode }) => (
  <div style={{ padding: "var(--diq-space-5)", minHeight: "360px" }}>{children}</div>
);

const exportItems = (over: boolean): PopoverMenuItem[] => [
  {
    id: "xlsx",
    label: "XLSX",
    description: "About sheet with scope, filters, freshness and digest",
    accelerator: "x",
    onSelect: () => undefined,
  },
  {
    id: "csv",
    label: "CSV",
    description: over ? "limit 100,000 rows" : "table only, opens in any spreadsheet",
    accelerator: "c",
    disabled: over,
    onSelect: () => undefined,
  },
];

export const MenuClosed: Story = {
  render: () => (
    <Stage>
      <PopoverMenu
        label="Export format"
        items={exportItems(false)}
        trigger={(p) => (
          <Button variant="primary" {...p}>
            Export
          </Button>
        )}
      />
    </Stage>
  ),
};

export const MenuOpen: Story = {
  render: () => (
    <Stage>
      <PopoverMenu
        label="Export format"
        defaultOpen
        header="12,431 rows · 8 columns as shown · the full result, not just this page"
        items={exportItems(false)}
        trigger={(p) => (
          <Button variant="primary" {...p}>
            Export
          </Button>
        )}
      />
    </Stage>
  ),
};

export const MenuDisabledItemWithError: Story = {
  render: () => (
    <Stage>
      <PopoverMenu
        label="Export format"
        defaultOpen
        items={exportItems(true)}
        footer={
          <p role="alert" className="diq-menu__note">
            This export has 250,000 rows. Your organisation limits CSV to 100,000. No file was
            created: choose XLSX (X), or narrow the filters.
          </p>
        }
        trigger={(p) => <Button {...p}>Export</Button>}
      />
    </Stage>
  ),
};

export const MenuAlignedEndLongContent: Story = {
  render: () => (
    <Stage>
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <PopoverMenu
          label="Row actions"
          align="end"
          defaultOpen
          items={[
            {
              id: "a",
              label:
                "Reset password for Ünïcödé Bjørn Lindqvist-Haddad (corp.example/Offices/Finance/Region 7)",
              description: "Sends the one-time code to the manager, not the user",
              accelerator: "r",
              onSelect: () => undefined,
            },
            { id: "b", label: "مدير النظام", accelerator: "m", onSelect: () => undefined },
          ]}
          trigger={(p) => <Button {...p}>Actions</Button>}
        />
      </div>
    </Stage>
  ),
};

export const PopoverForm: Story = {
  render: () => (
    <Stage>
      <Popover label="Columns" defaultOpen trigger={(p) => <Button {...p}>Columns</Button>}>
        {["Display name", "sAMAccountName", "Department", "Last logon"].map((c, i) => (
          <label key={c} style={{ display: "flex", gap: "var(--diq-space-2)" }}>
            <input type="checkbox" defaultChecked={i < 2} disabled={i === 0} /> {c}
          </label>
        ))}
      </Popover>
    </Stage>
  ),
};

function SheetDemo({ wide, startOpen }: { readonly wide?: boolean; readonly startOpen: boolean }) {
  const [open, setOpen] = useState(startOpen);
  return (
    <Stage>
      <Button onClick={() => setOpen(true)}>Schedule this report</Button>
      <SideSheet
        open={open}
        onClose={() => setOpen(false)}
        title="Schedule this report"
        description="Exactly what is on screen: Password expiry, last 30 days, 8 columns."
        width={wide ? "wide" : "default"}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setOpen(false);
          }}
          style={{ display: "flex", flexDirection: "column", gap: "var(--diq-space-3)" }}
        >
          <TextInput label="Name" defaultValue="Password expiry, monthly" />
          <TextInput label="Recipients" defaultValue="compliance@example.test" />
          <div style={{ display: "flex", gap: "var(--diq-space-2)" }}>
            <Button type="submit" variant="primary">
              Save schedule
            </Button>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
          </div>
        </form>
      </SideSheet>
    </Stage>
  );
}
export const SideSheetOpen: Story = { render: () => <SheetDemo startOpen /> };
export const SideSheetWide: Story = { render: () => <SheetDemo startOpen wide /> };
export const SideSheetClosed: Story = { render: () => <SheetDemo startOpen={false} /> };

export const Toasts: Story = {
  render: () => (
    <Stage>
      <ToastRegion>
        <Toast
          tone="ok"
          action={{ label: "Run details", onAction: () => undefined }}
          onDismiss={() => undefined}
        >
          <strong>XLSX ready:</strong>{" "}
          <span className="diq-mono">password-expiry-30d-20261030-0943Z.xlsx</span> · 12,431 rows ·
          data as of 09:43 UTC.
        </Toast>
      </ToastRegion>
    </Stage>
  ),
};

export const ToastInfoNoAction: Story = {
  render: () => (
    <Stage>
      <ToastRegion>
        <Toast onDismiss={() => undefined}>Schedule removed. Nothing was sent.</Toast>
      </ToastRegion>
    </Stage>
  ),
};
