import { type FormEvent, useEffect, useRef, useState } from "react";

import {
  Checkbox,
  RadioCardGroup,
  Select,
  SideSheet,
  type Token,
  TokenInput,
} from "../../ds/components";
import { ACCOUNTS, ALLOWED_DOMAINS, ZONE, type SchedRecipient, type Schedule } from "./fixtures";

export interface Perms {
  readonly run: boolean;
  readonly exportFiles: boolean;
  readonly schedule: boolean;
  readonly external: boolean;
}
export const ALL_PERMS: Perms = { run: true, exportFiles: true, schedule: true, external: true };

export interface Subject {
  readonly title: string;
  readonly filters: string;
  readonly columns: number;
  readonly scope: string;
  readonly rows: number;
  readonly perDc: boolean;
}

const PRESETS = [
  {
    id: "daily",
    label: "Daily",
    when: "08:00",
    next: "Sat 31 Oct 2026 08:00",
    text: "Daily at 08:00",
  },
  {
    id: "weekly",
    label: "Weekly",
    when: "Monday 08:00",
    next: "Mon 2 Nov 2026 08:00",
    text: "Weekly, Monday at 08:00",
  },
  {
    id: "monthly",
    label: "Monthly",
    when: "1st 08:00",
    next: "Tue 1 Dec 2026 08:00",
    text: "Monthly, 1st at 08:00",
  },
] as const;
type PresetId = (typeof PRESETS)[number]["id"] | "custom";

const MAX_RECIPIENTS = 50;
const MAIL = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;

/** A recipient as a token: outside addresses say so in words, and a malformed one is flagged for review. */
function toToken(addr: string): Token {
  const mail = MAIL.test(addr);
  return {
    id: addr,
    label: addr,
    badge: !mail ? "Check" : isExternal(addr) ? "Outside" : "Inside",
    invalid: !mail,
  };
}

function isExternal(addr: string): boolean {
  const domain = addr.split("@")[1]?.toLowerCase() ?? "";
  return !ALLOWED_DOMAINS.some((d) => d === domain);
}

export interface SheetInitial {
  readonly preset?: PresetId;
  readonly recipients?: readonly string[];
  readonly typed?: string;
  readonly confirmed?: boolean;
  readonly customHourly?: boolean;
  readonly saveAttempt?: boolean;
}

export function ScheduleSheet(props: {
  readonly subject: Subject;
  readonly perms: Perms;
  readonly initial?: SheetInitial | undefined;
  readonly onTick: (label: string) => void;
  readonly onSave: (s: Schedule) => void;
  readonly onClose: () => void;
}) {
  const { subject, perms, initial = {}, onTick, onSave, onClose } = props;
  const [preset, setPreset] = useState<PresetId | null>(initial.preset ?? null);
  const [hourly, setHourly] = useState(initial.customHourly ?? false);
  const [list, setList] = useState<string[]>([...(initial.recipients ?? [])]);
  const [typed, setTyped] = useState(initial.typed ?? "");
  const [format, setFormat] = useState<"XLSX" | "CSV">("XLSX");
  const [method, setMethod] = useState<"Attachment" | "Link">("Attachment");
  const [onlyIfData, setOnlyIfData] = useState(false);
  const [confirmed, setConfirmed] = useState(initial.confirmed ?? false);
  const [name, setName] = useState(`${subject.title}, ${subject.filters.split(" · ")[0] ?? ""}`);
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const typedOnce = useRef(false);
  const form = useRef<HTMLFormElement>(null);

  useEffect(() => {
    form.current?.querySelector<HTMLInputElement>("input[type=radio]")?.focus();
  }, []);

  // The saved name follows the chosen cadence until the admin edits it (it is prefilled, 0 interactions).
  const nameTouched = useRef(false);
  useEffect(() => {
    if (nameTouched.current) return;
    const p = PRESETS.find((x) => x.id === preset);
    setName(`${subject.title}${p ? `, ${p.label.toLowerCase()}` : ""}`);
  }, [preset, subject.title]);

  const all = (() => {
    const t = typed.trim();
    return t && !list.includes(t) ? [...list, t] : list;
  })();
  const external = all.filter((a) => MAIL.test(a) && isExternal(a));
  const needsConfirm = external.length > 0 && perms.external;
  const chosen = PRESETS.find((x) => x.id === preset);

  const commit = () => {
    const t = typed.trim().replace(/[,;]$/, "");
    if (t && !list.includes(t)) setList([...list, t]);
    setTyped("");
  };

  const validate = (): string[] => {
    const e: string[] = [];
    if (!preset) e.push("Choose when it runs.");
    if (preset === "custom" && hourly && subject.perDc)
      e.push(
        "This report reads domain controllers, so it can run no more often than daily. Choose Daily or slower.",
      );
    if (all.length === 0) e.push("Add at least one recipient.");
    if (all.length > MAX_RECIPIENTS)
      e.push(`A schedule can have at most ${MAX_RECIPIENTS} recipients.`);
    for (const a of all)
      if (!MAIL.test(a)) e.push(`“${a}” is not an e-mail address. Remove it or fix the spelling.`);
    if (external.length > 0 && !perms.external)
      e.push(
        `You can't send to ${external.join(", ")}: it is outside your organisation's allowed domains and you don't have permission to deliver outside it (reports.deliver.external). Remove it, or ask an administrator.`,
      );
    if (needsConfirm && !confirmed)
      e.push("Tick the box to confirm data leaves your organisation.");
    return e;
  };

  useEffect(() => {
    if (initial.saveAttempt) setErrors(validate());
  }, []);

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    onTick("Save");
    commit();
    const e = validate();
    setErrors(e);
    if (e.length > 0) return;
    setSaving(true);
    const recipients: SchedRecipient[] = all.map((a) => ({
      who: a,
      external: isExternal(a),
      format,
      method: isExternal(a) ? "Attachment" : method,
      state: "queued",
      detail: "Queued for the first run.",
    }));
    setTimeout(() => {
      onSave({
        id: `S-${Date.now() % 100000}`,
        name,
        report: subject.title,
        when: chosen?.text ?? "Hourly",
        next: `${chosen?.next ?? "Fri 30 Oct 2026 10:00"} ${ZONE}`,
        owner: "You",
        state: "active",
        last: "Not run yet",
        lastTone: "muted",
        notifyOnlyIfData: onlyIfData,
        recipients,
        runs: [],
      });
    }, 350);
  };

  const accountMatches =
    typed.trim().length > 1
      ? ACCOUNTS.filter(
          (a) =>
            !list.includes(a.mail) &&
            `${a.name} ${a.mail}`.toLowerCase().includes(typed.trim().toLowerCase()),
        )
      : [];

  return (
    <SideSheet
      open
      onClose={onClose}
      title="Schedule this report"
      description={`Exactly what is on screen: ${subject.title}, ${subject.filters}, ${subject.columns} columns.`}
    >
      <form ref={form} className="pt__form" onSubmit={submit} noValidate>
        <fieldset className="rp__fs">
          <legend>When</legend>
          <RadioCardGroup
            label="When it runs"
            value={preset}
            options={[
              ...PRESETS.map((p) => ({ value: p.id, label: p.label, description: p.when })),
              { value: "custom", label: "Custom", description: "every n hours, days…" },
            ]}
            onChange={(id) => {
              if (id === null) return;
              setPreset(id as PresetId);
              onTick(
                `preset: ${id === "custom" ? "Custom" : `${PRESETS.find((p) => p.id === id)?.label ?? ""} ${PRESETS.find((p) => p.id === id)?.when ?? ""}`}`,
              );
            }}
          />
          {preset === "custom" ? (
            <div className="rp__row">
              <Select
                label="Repeat every"
                value={hourly ? "hours" : "days"}
                onChange={(v) => setHourly(v === "hours")}
                options={[
                  { value: "hours", label: "1 hour" },
                  { value: "days", label: "1 day" },
                ]}
              />
              <p className="pt__sub">
                Shortest allowed: 1 hour. Time zone: Europe/London ({ZONE}).
              </p>
            </div>
          ) : null}
          <p className="pt__sub">
            {chosen
              ? `First run: ${chosen.next} ${ZONE}. A missed run (server down) runs once, never as a burst.`
              : "Time zone: Europe/London (GMT). Daylight-saving changes are handled for you."}
          </p>
        </fieldset>

        <TokenInput
          label="To"
          value={list.map(toToken)}
          onChange={(tokens) => setList(tokens.map((t) => t.id))}
          query={typed}
          onQueryChange={(q) => {
            if (!typedOnce.current && q !== "") {
              typedOnce.current = true;
              onTick("type recipient");
            }
            setTyped(q);
          }}
          parse={(text) => (text === "" ? null : toToken(text))}
          suggestions={accountMatches.map((a) => ({
            id: a.mail,
            label: a.name,
            detail: a.mail,
          }))}
          placeholder="Name or e-mail address"
          tokensLabel="Recipients"
          hint={`Enter or comma adds an address; Save adds what you typed. Organisation domains: ${ALLOWED_DOMAINS.join(", ")}.`}
        />

        <div className="pt__box" role="note">
          <strong>Recipients receive what you can see:</strong> {subject.scope}. If your access
          shrinks, later runs shrink with it.
        </div>

        {needsConfirm ? (
          <div className="pt__banner rp__ext" role="alert">
            <Checkbox
              checked={confirmed}
              onChange={(on) => {
                setConfirmed(on);
                onTick("confirm: data leaves organisation");
              }}
              label={
                <>
                  <strong>Data leaves your organisation:</strong> {external.join(", ")}. I confirm
                  these addresses may receive this report.
                </>
              }
            />
          </div>
        ) : null}

        <fieldset className="rp__fs">
          <legend>Delivery</legend>
          <div className="rp__row">
            <Select
              label="Format"
              value={format}
              onChange={(v) => setFormat(v as "XLSX" | "CSV")}
              options={[
                { value: "XLSX", label: "XLSX (with About sheet)" },
                { value: "CSV", label: "CSV (table only)" },
              ]}
            />
            <Select
              label="Send as"
              value={method}
              onChange={(v) => setMethod(v as "Attachment" | "Link")}
              options={[
                { value: "Attachment", label: "Attachment" },
                { value: "Link", label: "Link (accounts only)" },
              ]}
            />
          </div>
          {method === "Link" && external.length > 0 ? (
            <p className="pt__sub">
              Links work only for people with an activeDIQ account, so outside addresses get an
              attachment.
            </p>
          ) : null}
          <Checkbox
            checked={onlyIfData}
            onChange={setOnlyIfData}
            label="Only send if there is data (a run with 0 rows sends nothing)"
          />
          <p className="pt__sub">
            Files over 10 MB go as a link to account recipients; for outside addresses that delivery
            fails and says why.
          </p>
        </fieldset>

        <label className="pt__field">
          <span>Name</span>
          <input
            className="rp__input"
            value={name}
            onChange={(e) => {
              nameTouched.current = true;
              setName(e.target.value);
            }}
          />
        </label>

        {errors.length > 0 ? (
          <div className="pt__banner" role="alert">
            <ul className="rp__errors">
              {errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="pt__actions rp__sticky">
          <button type="submit" className="btn btn--primary" disabled={saving} aria-busy={saving}>
            {saving ? "Saving…" : "Save schedule"}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            Cancel <span className="pt__kbd">Esc</span>
          </button>
          <span className="pt__sub">
            Saved as an action you can undo. Runs as you, with your access at each run.
          </span>
        </div>
      </form>
    </SideSheet>
  );
}
