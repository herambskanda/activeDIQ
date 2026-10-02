import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Output goes to web/dist; the Go build copies it into internal/webui for go:embed
// (blueprint §1). There is no runtime Node process (ADR-0001 tier W).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
