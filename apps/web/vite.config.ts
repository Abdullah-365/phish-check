import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Off in production: maps would publish the full source from the live site.
    sourcemap: false,
    // Inlined assets become data: URIs, which the strict CSP (font-src 'self') rightly blocks.
    assetsInlineLimit: 0,
  },
});
