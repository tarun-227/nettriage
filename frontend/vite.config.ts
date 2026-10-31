import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build goes straight into the Python package, so judges only need Python.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../backend/nettriage/static",
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8765", changeOrigin: true } },
  },
});
