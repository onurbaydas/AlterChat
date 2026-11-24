import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/vt323/400.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import App from "./App";
import "./theme-bunker.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
