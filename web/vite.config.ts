import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [tailwindcss(), solidPlugin()],
  resolve: {
    alias: {
      "~": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    target: "esnext",
    outDir: "dist",
  },
  server: {
    port: 3000,
    host: true,
    allowedHosts: true,
    proxy: {
      // changeOrigin:false so the API sees the original Host header
      // (matters for OAuth's post-login redirect, which is derived from r.Host).
      "/api":    { target: "http://localhost:8080", changeOrigin: false },
      "/auth":   { target: "http://localhost:8080", changeOrigin: false },
      "/health": { target: "http://localhost:8080", changeOrigin: false },
      "/ready":  { target: "http://localhost:8080", changeOrigin: false },
    },
  },
  test: {
    environment: "node",
    environmentMatchGlobs: [
      ["**/*.test.tsx", "happy-dom"],
    ],
  },
});
