import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { setNonce } from "get-nonce"

import "./index.css"
import { boot } from "@/lib/api"
import App from "./App.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"

// Radix adds one small <style> tag for scroll locking; it carries this page's CSP nonce.
setNonce(boot.nonce)

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </StrictMode>
)
