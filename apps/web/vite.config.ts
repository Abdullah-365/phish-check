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
    // The engine chunk (email parser, HTML parser, public suffix list) is about 530 kB and loads
    // after the page paints; every check needs all of it, so splitting it wouldn't save a byte.
    // The limit sits just above it, so real growth still warns.
    chunkSizeWarningLimit: 600,
  },
});
