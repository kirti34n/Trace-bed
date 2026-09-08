// Development mirrors production: only exact browser-approved routes reach
// the same-origin edge BFF. There is no broad direct API proxy.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { EDGE_PROXY_CONTEXTS } from "./src/lib/edgeRoutePolicy";

const EDGE_ORIGIN = "http://localhost:8120";
const EDGE_PROXY = Object.fromEntries(
  EDGE_PROXY_CONTEXTS.map((context) => [context, { target: EDGE_ORIGIN, changeOrigin: false }])
);

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8111,
    strictPort: true,
    proxy: EDGE_PROXY,
  },
  preview: {
    port: 8111,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    clearMocks: true,
  },
});
