import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run dev` proxies API calls to a local server on :8080.
const api = "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // "@/components/ui/…" and "@/lib/…", as shadcn components expect.
  resolve: { alias: { "@": "/src" } },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
  server: {
    proxy: {
      "/whalescale.v1.AdminService": api,
      "/auth": api,
      "/healthz": api,
    },
  },
});
