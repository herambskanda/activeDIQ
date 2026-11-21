import { describe, expect, it } from "vitest";
import { createApiClient, unwrap } from "../api/client";
import type { components, paths } from "../api/schema.gen";

type Read = components["schemas"]["ReportPolicyDomainRead"];
type ColumnId = components["schemas"]["ReportColumnId"];
type TargetsOp = paths["/reports/runs/{runId}/policies/{policyId}/targets"]["get"];

// T-1718: the SYS-01 contract as the console's types see it. The switch is exhaustive over the three
// kinds with no default, so tsc fails here if `unreadable` ever stops being a member of its own, and the
// run proves that a container that could not be read is never described as one that is empty.
function describeRead(read: Read): string {
  switch (read.kind) {
    case "readable":
      return `${read.psoCount} policies`;
    case "none_exist":
      return `none exist, read at ${read.readAt}`;
    case "unreadable":
      return `not readable: ${read.reason} (${read.containerName})`;
  }
}

describe("SYS-01 policy contract types", () => {
  it("keeps unreadable distinct from none_exist", () => {
    const ids = {
      domainId: "00000000-0000-0000-0000-00000000000a",
      domainName: "corp.example",
      domainPolicyRowKey: "00000000-0000-0000-0000-0000000000c1",
    };
    const none: Read = { kind: "none_exist", ...ids, readAt: "2026-11-07T14:02:00Z" };
    const unreadable: Read = {
      kind: "unreadable",
      ...ids,
      containerName: "Password Settings Container",
      reason: "permission_denied",
    };
    expect(describeRead(none)).toContain("none exist");
    expect(describeRead(unreadable)).toContain("not readable");
    expect(describeRead(unreadable)).not.toContain("none exist");
  });

  it("types the policy columns and the paged direct-targets read", async () => {
    const cols: ColumnId[] = ["policy_name", "precedence", "max_age", "lockout_window"];
    expect(cols).toHaveLength(4);

    const wire = {
      runId: "00000000-0000-0000-0000-000000000001",
      policyId: "00000000-0000-0000-0000-0000000000c1",
      policyName: "PSO-Finance",
      kind: "pso",
      basis: "direct_targets",
      count: 1,
      targets: [
        {
          objectGuid: "00000000-0000-0000-0000-0000000000d1",
          name: "svc-sql01",
          targetClass: "user",
          domain: "corp.example",
        },
      ],
      page: { nextCursor: null },
    };
    const client = createApiClient({
      baseUrl: "http://localhost/api/v1",
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify(wire), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    });
    const page = await unwrap(
      client.GET("/reports/runs/{runId}/policies/{policyId}/targets", {
        params: { path: { runId: wire.runId, policyId: wire.policyId }, query: { limit: 40 } },
      }),
    );
    const typed: TargetsOp["responses"][200]["content"]["application/json"] = page;
    expect(typed.basis).toBe("direct_targets");
    expect(typed.targets[0]?.name).toBe("svc-sql01");
  });
});
