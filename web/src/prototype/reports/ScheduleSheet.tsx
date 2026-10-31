import { type FormEvent, useEffect, useId, useRef, useState } from "react";

import { SideSheet } from "../../ds/components";
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
  const uid = useId();
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
      <form className="pt__form" onSubmit={submit} noValidate>
        <fieldset className="rp__fs">
          <legend>When</legend>
          <div className="rp__radios" role="radiogroup" aria-label="When it runs">
            {PRESETS.map((p, i) => (
              <label key={p.id} className={`rp__radio${preset === p.id ? " rp__radio--on" : ""}`}>
                <input
                  data-autofocus={i === 0 ? "" : undefined}
                  type="radio"
                  name={`${uid}-when`}
                  checked={preset === p.id}
                  onChange={() => {
                    setPreset(p.id);
                    onTick(`preset: ${p.label} ${p.when}`);
                  }}
                />
                <b>{p.label}</b>
                <span>{p.when}</span>
              </label>
            ))}
            <label className={`rp__radio${preset === "custom" ? " rp__radio--on" : ""}`}>
              <input
                type="radio"
                name={`${uid}-when`}
                checked={preset === "custom"}
                onChange={() => {
                  setPreset("custom");
                  onTick("preset: Custom");
                }}
              />
              <b>Custom</b>
              <span>every n hours, days…</span>
            </label>
          </div>
          {preset === "custom" ? (
            <div className="rp__row">
              <label className="pt__field">
                <span>Repeat every</span>
                <select
                  className="rp__select"
                  value={hourly ? "hours" : "days"}
                  onChange={(e) => setHourly(e.target.value === "hours")}
                >
                  <option value="hours">1 hour</option>
                  <option value="days">1 day</option>
                </select>
              </label>
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

        <div className="pt__field">
          <label htmlFor={`${uid}-to`}>To</label>
          <div className="rp__tokens">
            {list.map((a) => (
              <span key={a} className={`chip ${isExternal(a) ? "chip--warn" : "chip--muted"}`}>
                {isExternal(a) ? "↗ Outside " : "● Inside "}
                {a}
                <button
                  type="button"
                  className="rp__x"
                  aria-label={`Remove ${a}`}
                  onClick={() => setList(list.filter((x) => x !== a))}
                >
                  ×
                </button>
              </span>
            ))}
            <input
              id={`${uid}-to`}
              className="rp__tokeninput"
              value={typed}
              autoComplete="off"
              spellCheck={false}
              placeholder="Name or e-mail address"
              aria-describedby={`${uid}-to-help`}
              onChange={(e) => {
                if (!typedOnce.current) {
                  typedOnce.current = true;
                  onTick("type recipient");
                }
                setTyped(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === ",") {
                  e.preventDefault();
                  commit();
                }
              }}
              onBlur={commit}
            />
          </div>
          {accountMatches.length > 0 ? (
            <ul className="pt__list" aria-label="Matching accounts">
              {accountMatches.map((a) => (
                <li key={a.mail}>
                  <button
                    type="button"
                    className="pt__row"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => {
                      setList([...list, a.mail]);
                      setTyped("");
                    }}
                  >
                    <span className="pt__name">{a.name}</span>
                    <span className="diq-mono pt__sub">{a.mail}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
          <p id={`${uid}-to-help`} className="pt__sub">
            Enter or comma adds an address; Save adds what you typed. Organisation domains:{" "}
            {ALLOWED_DOMAINS.join(", ")}.
          </p>
        </div>

        <div className="pt__box" role="note">
          <strong>Recipients receive what you can see:</strong> {subject.scope}. If your access
          shrinks, later runs shrink with it.
        </div>

        {needsConfirm ? (
          <div className="pt__banner rp__ext" role="alert">
            <label className="pt__check">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => {
                  setConfirmed(e.target.checked);
                  onTick("confirm: data leaves organisation");
                }}
              />
              <span>
                <strong>Data leaves your organisation:</strong> {external.join(", ")}. I confirm
                these addresses may receive this report.
              </span>
            </label>
          </div>
        ) : null}

        <fieldset className="rp__fs">
          <legend>Delivery</legend>
          <div className="rp__row">
            <label className="pt__field">
              <span>Format</span>
              <select
                className="rp__select"
                value={format}
                onChange={(e) => setFormat(e.target.value as "XLSX" | "CSV")}
              >
                <option value="XLSX">XLSX (with About sheet)</option>
                <option value="CSV">CSV (table only)</option>
              </select>
            </label>
            <label className="pt__field">
              <span>Send as</span>
              <select
                className="rp__select"
                value={method}
                onChange={(e) => setMethod(e.target.value as "Attachment" | "Link")}
              >
                <option value="Attachment">Attachment</option>
                <option value="Link">Link (accounts only)</option>
              </select>
            </label>
          </div>
          {method === "Link" && external.length > 0 ? (
            <p className="pt__sub">
              Links work only for people with an activeDIQ account, so outside addresses get an
              attachment.
            </p>
          ) : null}
          <label className="pt__check">
            <input
              type="checkbox"
              checked={onlyIfData}
              onChange={(e) => setOnlyIfData(e.target.checked)}
            />
            <span>Only send if there is data (a run with 0 rows sends nothing)</span>
          </label>
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
