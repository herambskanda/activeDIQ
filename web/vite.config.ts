import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// Output goes to web/dist; the Go build copies it into internal/webui for go:embed
// (blueprint §1). There is no runtime Node process (ADR-0001 tier W).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  // In development Vite serves the console and forwards /api to a running server: set ADIQ_API_URL
  // to its address (the API listener is TLS-only, so https://… with its certificate trusted).
  server: {
    proxy: { "/api": loadEnv(mode, ".", "ADIQ_")["ADIQ_API_URL"] ?? "http://127.0.0.1:8080" },
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
}));
