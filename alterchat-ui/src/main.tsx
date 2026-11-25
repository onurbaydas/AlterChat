import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/vt323/400.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import App from "./App";
import "./theme-bunker.css";

function render() {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

// The browser demo (`npm run build:demo`) swaps the Tauri IPC bridge for a
// simulated backend before the first render. In the regular build this
// branch is statically false and the demo module is not bundled.
if (import.meta.env.VITE_DEMO) {
  import("./demo/mockBackend").then((m) => {
    m.installDemoBackend();
    render();
  });
} else {
  render();
}
