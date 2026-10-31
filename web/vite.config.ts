import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies API calls to a local server on :8080.
const api = "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
  server: {
    proxy: {
      "/whalescale.v1.AdminService": api,
      "/auth": api,
      "/healthz": api,
    },
  },
});
