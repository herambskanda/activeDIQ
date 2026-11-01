import { useState } from "react";

import {
  Button,
  Checkbox,
  Popover,
  Select,
  SegmentedControl,
  TextInput,
} from "../../ds/components";
import type { ColumnInfo, Definition, Run } from "./api";
import {
  filterProblem,
  needsValue,
  OPERATOR_LABEL,
  operatorsFor,
  PERIOD_DAYS,
  type UserFilter,
  type View,
} from "./model";

type Change = (next: Partial<View>) => void;

/** Preset chips (2 to 5), a select beyond that; the period when the preset has one; columns; filters. */
export function Controls({
  definition,
  run,
  view,
  change,
}: {
  readonly definition: Definition;
  readonly run: Run | null;
  readonly view: View;
  readonly change: Change;
}) {
  const presetId = view.preset ?? run?.presetId ?? null;
  const preset = definition.presets.find((p) => p.id === presetId);
  const presets = definition.presets.map((p) => ({ value: p.id, label: p.name }));
  const periodDays =
    view.days ??
    (run?.parameters.period?.kind === "ReportPeriodLastDays" ? run.parameters.period.days : null) ??
    preset?.periodDays ??
    null;
  const hasPeriod = preset?.periodDays !== null && preset?.periodDays !== undefined;
  const shown = view.columns ?? run?.parameters.columns ?? preset?.columns ?? [];
  const filterable = definition.columns.filter((c) => operatorsFor(c).length > 0);

  return (
    <div className="rp-controls">
      {presets.length >= 2 && presets.length <= 5 && (
        <SegmentedControl
          label="Preset"
          options={presets}
          value={presetId}
          onChange={(v) => v && change({ preset: v, days: null })}
        />
      )}
      {presets.length > 5 && (
        <Select
          label="Preset"
          options={presets}
          value={presetId ?? ""}
          onChange={(v) => v && change({ preset: v, days: null })}
        />
      )}
      {hasPeriod && (
        <Select
          label="Period"
          options={[
            ...(periodDays !== null && !PERIOD_DAYS.includes(periodDays)
              ? [{ value: String(periodDays), label: `Last ${periodDays} days` }]
              : []),
            ...PERIOD_DAYS.map((d) => ({ value: String(d), label: `Last ${d} days` })),
          ]}
          value={periodDays === null ? "" : String(periodDays)}
          onChange={(v) => change({ days: Number(v) })}
        />
      )}
      <ColumnChooser
        columns={definition.columns}
        shown={shown}
        onChange={(c) => change({ columns: c })}
      />
      {filterable.length > 0 && (
        <FilterPopover
          columns={filterable}
          onAdd={(f) => change({ filters: [...view.filters, f] })}
        />
      )}
    </div>
  );
}

function ColumnChooser({
  columns,
  shown,
  onChange,
}: {
  readonly columns: readonly ColumnInfo[];
  readonly shown: readonly string[];
  readonly onChange: (columns: string[]) => void;
}) {
  const toggle = (id: string, on: boolean) => {
    // Keep the definition's order; a report always shows at least one column.
    const next = columns.map((c) => c.id).filter((c) => (c === id ? on : shown.includes(c)));
    if (next.length > 0) onChange(next);
  };
  return (
    <Popover
      label="Columns"
      trigger={(p) => (
        <Button {...p}>
          Columns ({shown.length} of {columns.length})
        </Button>
      )}
    >
      <fieldset className="rp-cols">
        <legend className="diq-field__label">Columns shown</legend>
        {columns.map((c) => (
          <Checkbox
            key={c.id}
            label={c.label}
            checked={shown.includes(c.id)}
            disabled={shown.length === 1 && shown.includes(c.id)}
            onChange={(on) => toggle(c.id, on)}
          />
        ))}
      </fieldset>
    </Popover>
  );
}

function FilterPopover({
  columns,
  onAdd,
}: {
  readonly columns: readonly ColumnInfo[];
  readonly onAdd: (f: UserFilter) => void;
}) {
  const [open, setOpen] = useState(false);
  const [columnId, setColumnId] = useState("");
  const [operator, setOperator] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | undefined>();
  const column = columns.find((c) => c.id === columnId);
  const operators = column ? operatorsFor(column) : [];

  const reset = () => {
    setColumnId("");
    setOperator("");
    setValue("");
    setError(undefined);
  };
  const add = () => {
    if (!column || operator === "") {
      setError("Choose a column and how to compare it.");
      return;
    }
    const problem = filterProblem(column, operator, value);
    if (problem) {
      setError(problem);
      return;
    }
    onAdd({ column: column.id, operator, value: needsValue(operator) ? value.trim() : "" });
    reset();
    setOpen(false);
  };

  return (
    <Popover
      label="Add a filter"
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) reset();
      }}
      trigger={(p) => <Button {...p}>Filter a column</Button>}
    >
      <form
        className="rp-filter"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <Select
          label="Column"
          placeholder="Choose a column"
          options={columns.map((c) => ({ value: c.id, label: c.label }))}
          value={columnId}
          onChange={(v) => {
            setColumnId(v);
            const picked = columns.find((c) => c.id === v);
            setOperator(picked ? (operatorsFor(picked)[0] ?? "") : "");
            setValue("");
            setError(undefined);
          }}
        />
        {column && (
          <Select
            label="Match"
            options={operators.map((o) => ({ value: o, label: OPERATOR_LABEL[o] ?? o }))}
            value={operator}
            onChange={(v) => {
              setOperator(v);
              setError(undefined);
            }}
          />
        )}
        {column && needsValue(operator) && column.type === "enum" && (
          <Select
            label="Value"
            placeholder="Choose a value"
            options={column.choices.map((c) => ({ value: c.id, label: c.label }))}
            value={value}
            onChange={setValue}
            error={error}
          />
        )}
        {column && needsValue(operator) && column.type === "boolean" && (
          <Select
            label="Value"
            placeholder="Choose a value"
            options={[
              { value: "true", label: "Yes" },
              { value: "false", label: "No" },
            ]}
            value={value}
            onChange={setValue}
            error={error}
          />
        )}
        {column && needsValue(operator) && column.type !== "enum" && column.type !== "boolean" && (
          <TextInput
            label="Value"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            error={error}
          />
        )}
        {error !== undefined && (!column || !needsValue(operator)) && (
          <p role="alert" className="diq-field__error">
            {error}
          </p>
        )}
        <Button variant="primary" type="submit">
          Apply filter (new run)
        </Button>
      </form>
    </Popover>
  );
}
