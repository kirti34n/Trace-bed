// PLAN.md §3: dashboard on :8111, talking only to the API on :8110. The dev
// server proxies the exact path prefixes the real API exposes (routes_v1.py's
// /v1/*, admin.py's /admin/* and /export/*, plus main.py's /healthz) so
// `src/api/client.ts` can use same-origin relative paths in both dev (this
// proxy) and prod (nginx.conf's reverse proxy) without branching on
// environment.
//
// /healthz is here because nginx.conf proxies it in production: without it the
// Health view's only genuinely live call 404s under `npm run dev`, which reads
// as a dead API to anyone developing locally.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const API_ORIGIN = "http://localhost:8110";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8111,
    strictPort: true,
    proxy: {
      "/v1": { target: API_ORIGIN, changeOrigin: true },
      "/admin": { target: API_ORIGIN, changeOrigin: true },
      "/export": { target: API_ORIGIN, changeOrigin: true },
      "/healthz": { target: API_ORIGIN, changeOrigin: true },
    },
  },
  preview: {
    port: 8111,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
