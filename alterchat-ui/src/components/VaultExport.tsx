import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onClose: () => void;
}

export function VaultExport({ onClose }: Props) {
  const [mode, setMode] = useState<"export" | "import">("export");
  const [password, setPassword] = useState("");
  const [exportData, setExportData] = useState("");
  const [importData, setImportData] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function doExport() {
    if (!password) { setError("Password required"); return; }
    setError(null); setStatus(null);
    try {
      const hex = await invoke<string>("export_vault_encrypted", { exportPassword: password });
      setExportData(hex);
      setStatus("Vault exported. Copy the hex string and import on your other device.");
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function doImport() {
    if (!password || !importData.trim()) { setError("Password and vault data required"); return; }
    setError(null); setStatus(null);
    try {
      await invoke("import_vault_encrypted", { encryptedHex: importData.trim(), importPassword: password });
      setStatus("✓ Vault imported successfully. Restart to apply settings.");
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function copyExport() {
    await navigator.clipboard.writeText(exportData);
    setStatus("Copied to clipboard!");
  }

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.9)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999
    }}>
      <div style={{
        background: "#0d1117", border: "1px solid #00f0ff",
        borderRadius: 12, padding: 28, maxWidth: 500, width: "100%",
        boxShadow: "0 0 40px rgba(0,240,255,0.15)"
      }}>
        <h2 style={{ color: "#00f0ff", marginBottom: 6, fontSize: 18 }}>
          🔑 Vault Export / Import
        </h2>
        <p style={{ color: "#666", fontSize: 12, marginBottom: 20 }}>
          Transfer your identity and settings to another device. Vault is encrypted with your password —
          only you can decrypt it. No servers involved.
        </p>

        {/* Tab Switch */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          {(["export", "import"] as const).map(m => (
            <button key={m} onClick={() => setMode(m)} style={{
              flex: 1, padding: "8px", borderRadius: 6, cursor: "pointer",
              background: mode === m ? "#00f0ff" : "transparent",
              color: mode === m ? "#000" : "#888",
              border: `1px solid ${mode === m ? "#00f0ff" : "#333"}`,
              fontWeight: "bold", textTransform: "uppercase", fontSize: 12
            }}>
              {m === "export" ? "📤 Export" : "📥 Import"}
            </button>
          ))}
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 6 }}>
            Encryption Password
          </label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Strong password for vault encryption"
            style={{
              width: "100%", background: "#050a0f", border: "1px solid #1a2a3a",
              borderRadius: 6, padding: "10px", color: "#fff", fontSize: 13,
              boxSizing: "border-box"
            }}
          />
        </div>

        {mode === "export" ? (
          <>
            <button onClick={doExport} style={{
              width: "100%", background: "#00f0ff", color: "#000",
              border: "none", borderRadius: 6, padding: "10px",
              cursor: "pointer", fontWeight: "bold", marginBottom: 12
            }}>
              Export Encrypted Vault
            </button>
            {exportData && (
              <div>
                <textarea
                  readOnly value={exportData}
                  style={{
                    width: "100%", height: 80, background: "#050a0f",
                    border: "1px solid #1a2a3a", borderRadius: 6, color: "#00f0ff",
                    fontSize: 10, padding: 8, fontFamily: "monospace", boxSizing: "border-box"
                  }}
                />
                <button onClick={copyExport} style={{
                  width: "100%", background: "#0a2a3a", color: "#00f0ff",
                  border: "1px solid #00f0ff", borderRadius: 6, padding: "8px",
                  cursor: "pointer", fontSize: 12
                }}>
                  Copy to Clipboard
                </button>
              </div>
            )}
          </>
        ) : (
          <>
            <div style={{ marginBottom: 12 }}>
              <label style={{ color: "#aaa", fontSize: 12, display: "block", marginBottom: 6 }}>
                Vault Data (hex)
              </label>
              <textarea
                value={importData}
                onChange={e => setImportData(e.target.value)}
                placeholder="Paste vault hex data here..."
                style={{
                  width: "100%", height: 80, background: "#050a0f",
                  border: "1px solid #1a2a3a", borderRadius: 6, color: "#ccc",
                  fontSize: 11, padding: 8, fontFamily: "monospace", boxSizing: "border-box"
                }}
              />
            </div>
            <button onClick={doImport} style={{
              width: "100%", background: "#00f0ff", color: "#000",
              border: "none", borderRadius: 6, padding: "10px",
              cursor: "pointer", fontWeight: "bold"
            }}>
              Import Vault
            </button>
          </>
        )}

        {status && (
          <div style={{ marginTop: 12, color: "#00cc66", fontSize: 12, padding: 8,
            background: "rgba(0,204,102,0.1)", borderRadius: 4 }}>
            {status}
          </div>
        )}
        {error && (
          <div style={{ marginTop: 12, color: "#cc4444", fontSize: 12, padding: 8,
            background: "rgba(204,68,68,0.1)", borderRadius: 4 }}>
            Error: {error}
          </div>
        )}

        <button onClick={onClose} style={{
          marginTop: 16, background: "transparent", color: "#666",
          border: "1px solid #333", borderRadius: 6, padding: "8px 20px",
          cursor: "pointer", width: "100%"
        }}>
          Close
        </button>
      </div>
    </div>
  );
}
