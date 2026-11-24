import { useEffect, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { detectLang, strings } from "../i18n";

/**
 * Checks GitHub Releases for a signed update once at startup and offers it.
 * Updates are verified against the public key in tauri.conf.json before
 * they are installed. Network or check failures are silent.
 */
export function UpdateChecker() {
  const t = strings(detectLang());
  const [update, setUpdate] = useState<Update | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    check()
      .then((u) => {
        if (u) setUpdate(u);
      })
      .catch(() => {
        /* offline, no release yet, or repository not public */
      });
  }, []);

  if (!update || dismissed) return null;

  const install = async () => {
    setBusy(true);
    let total = 0;
    let done = 0;
    try {
      await update.downloadAndInstall((event) => {
        if (event.event === "Started") total = event.data.contentLength ?? 0;
        if (event.event === "Progress") {
          done += event.data.chunkLength;
          if (total > 0) setProgress(Math.round((done / total) * 100));
        }
      });
      await relaunch();
    } catch (err) {
      alert(t.updateFailed + String(err));
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        bottom: 18,
        right: 18,
        zIndex: 2000,
        background: "#17190f",
        border: "1px solid var(--accent-amber)",
        borderRadius: 10,
        padding: "12px 16px",
        boxShadow: "0 10px 30px rgba(0,0,0,0.7)",
        maxWidth: 320,
      }}
    >
      <div style={{ fontFamily: "var(--font-display)", fontSize: 22, color: "var(--accent-amber)" }}>
        ⬆ {t.updateAvailable}: v{update.version}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button className="cyber-btn primary" onClick={install} disabled={busy}>
          {busy ? `${t.updating}${progress !== null ? ` ${progress}%` : ""}` : t.updateNow}
        </button>
        {!busy && (
          <button className="cyber-btn" onClick={() => setDismissed(true)}>
            {t.later}
          </button>
        )}
      </div>
    </div>
  );
}
