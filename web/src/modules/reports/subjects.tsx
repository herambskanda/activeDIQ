import { useState } from "react";

import { api } from "../../api/client";
import { Button, ObjectPicker, type PickerObject } from "../../ds/components";
import { type ApiClient, searchSubjects } from "./api";
import { MAX_SUBJECTS } from "./model";

type Kind = "group" | "user";

/**
 * Chooses the groups or users a subject report covers (GRP-02, GRP-03) and runs it for them. Nothing
 * runs until "Run" is pressed; the chosen GUIDs then live in the address bar. A GUID that came from the
 * address bar has no name until it is chosen again, so it is shown by GUID.
 */
export function SubjectPicker({
  client = api,
  kind,
  applied,
  onRun,
}: {
  readonly client?: ApiClient;
  readonly kind: Kind;
  readonly applied: readonly string[];
  readonly onRun: (guids: readonly string[]) => void;
}) {
  const [chosen, setChosen] = useState<readonly PickerObject[]>(() =>
    applied.map((id) => ({ id, name: id })),
  );
  const same = chosen.length === applied.length && chosen.every((o, i) => o.id === applied[i]);
  return (
    <form
      className="rp-subjects"
      onSubmit={(e) => {
        e.preventDefault();
        if (chosen.length > 0) onRun(chosen.map((o) => o.id));
      }}
    >
      <ObjectPicker
        label={kind === "group" ? "Groups" : "Users"}
        kind={kind}
        value={chosen}
        onChange={setChosen}
        max={MAX_SUBJECTS}
        search={async (text, signal) => {
          const r = await searchSubjects(client, kind, text, signal);
          return {
            refine: r.refine,
            more: r.more,
            items: r.items.map((h) => ({
              id: h.objectId,
              name: h.displayName,
              identifier: [h.samAccountName, h.userPrincipalName ?? h.mail]
                .filter(Boolean)
                .join(" · "),
              path: h.distinguishedName,
              domain: h.domain,
              enabled: !h.status.some((s) => s.kind === "disabled"),
            })),
          };
        }}
      />
      <Button type="submit" variant="primary" disabled={chosen.length === 0 || same}>
        {chosen.length === 0
          ? "Run report"
          : `Run for ${chosen.length} ${kind}${chosen.length === 1 ? "" : "s"}`}
      </Button>
    </form>
  );
}
