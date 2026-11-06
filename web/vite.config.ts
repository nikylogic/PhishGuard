import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig, type Plugin } from "vite"

// sonner injects its stylesheet with a runtime <style> tag, which PhishGuard's
// Content-Security-Policy blocks. We import sonner/dist/styles.css as a normal file
// instead (see index.css) and turn the runtime injection into a no-op.
function sonnerNoInlineCss(): Plugin {
  return {
    name: "phishguard-sonner-no-inline-css",
    enforce: "pre",
    transform(code, id) {
      if (!/[\/]sonner[\/]dist[\/]index\.m?js$/.test(id)) return null
      const out = code.replace(/function __insertCSS\(code\) \{/, "function __insertCSS(code) { return;")
      if (out === code) this.error("sonner: __insertCSS not found, check the CSP workaround")
      return { code: out, map: null }
    },
  }
}

// Built into Flask's static folder; Flask finds the files through the manifest.
export default defineConfig({
  base: "/static/app/",
  plugins: [sonnerNoInlineCss(), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
  optimizeDeps: { exclude: ["sonner"] },
  build: {
    outDir: "../phishguard/static/app",
    emptyOutDir: true,
    manifest: true,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1200, // one bundle for a local app is fine
    rollupOptions: { input: "src/main.tsx" },
  },
})
