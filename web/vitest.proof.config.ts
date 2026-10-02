import { defineConfig } from "vitest/config";

// Used only by tools/ci/proof.sh: runs the deliberately failing test in proof/.
export default defineConfig({ test: { environment: "node", include: ["proof/**/*.test.ts"] } });
