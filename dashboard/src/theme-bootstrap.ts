// Same-origin module, deliberately external so the dashboard CSP does not
// need `unsafe-inline` for first-paint theme initialization.
import { initializeTheme } from "./lib/theme";

initializeTheme();
