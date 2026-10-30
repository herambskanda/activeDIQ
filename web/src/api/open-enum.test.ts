import { describe, expect, it } from "vitest";
import { createApiClient, unwrap } from "./client";
import type { components } from "./schema.gen";

type DirectoryUser = components["schemas"]["DirectoryUser"];

// openapi-fetch maps a response through `Readable<T>`, which used to rebuild the open-enum member
// `(string & {})` as a copy of `String`. Assigning the data to the declared type is the compile-time
// proof that open enums flow through `unwrap()` unchanged (tsc fails here if the helper shim in
// `openapi-typescript-helpers.d.ts` stops applying); the run proves a value from a newer server survives.
describe("open enums in responses", () => {
  it("reach the declared type without a cast, known value or not", async () => {
    const wire = {
      items: [user("matched"), user("a-state-from-a-newer-server")],
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

    const list = await unwrap(client.GET("/directory/users", { params: { query: { q: "a" } } }));
    const users: readonly DirectoryUser[] = list.items;

    expect(users.map((u) => u.hybrid.state)).toEqual(["matched", "a-state-from-a-newer-server"]);
  });
});

function user(state: string) {
  return {
    objectGuid: "00000000-0000-0000-0000-000000000001",
    samAccountName: "ada",
    userPrincipalName: "ada@example.test",
    displayName: "Ada",
    enabled: true,
    hybrid: { state, carriesAuthority: false },
  };
}
