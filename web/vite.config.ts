import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import license from "rollup-plugin-license";

export default defineConfig({
  plugins: [
    tailwindcss(),
    solidPlugin(),
    // License texts of every third-party package in the bundle, served at
    // /third-party-licenses.txt and copied to /licenses in the web image (ocidex-9rqq).
    // A bundled package with no license fails the build.
    license({
      thirdParty: {
        output: path.resolve(import.meta.dirname, "dist/third-party-licenses.txt"),
        allow: { test: () => true, failOnUnlicensed: true },
      },
    }),
  ],
  resolve: {
    alias: {
      "~": path.resolve(import.meta.dirname, "./src"),
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
