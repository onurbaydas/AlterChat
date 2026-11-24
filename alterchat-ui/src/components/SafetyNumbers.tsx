import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  peerPubkeyHex: string;
  peerNickname: string;
  onClose: () => void;
}

export function SafetyNumbers({ peerPubkeyHex, peerNickname, onClose }: Props) {
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [verified, setVerified] = useState(false);

  async function loadNumber() {
    setLoading(true);
    try {
      const num = await invoke<string>("get_safety_number", { peerPubkeyHex });
      setSafetyNumber(num);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  // Format safety number into readable 5-block display
  const blocks = safetyNumber ? safetyNumber.split(" ") : [];

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999
    }}>
      <div style={{
        background: "var(--bg-panel, #0d1117)", border: "1px solid var(--accent-cyan, #00f0ff)",
        borderRadius: 12, padding: 32, maxWidth: 480, width: "100%",
        boxShadow: "0 0 40px rgba(0,240,255,0.2)"
      }}>
        <h2 style={{ color: "var(--accent-cyan, #00f0ff)", marginBottom: 8, fontSize: 18 }}>
          🔐 Safety Numbers
        </h2>
        <p style={{ color: "#aaa", fontSize: 13, marginBottom: 20 }}>
          Compare these numbers with <strong style={{ color: "#fff" }}>{peerNickname}</strong> over a trusted channel
          (video call, in person). If they match, your conversation is secure.
        </p>

        {!safetyNumber && (
          <button
            onClick={loadNumber}
            disabled={loading}
            style={{
              background: "var(--accent-cyan, #00f0ff)", color: "#000",
              border: "none", borderRadius: 6, padding: "10px 24px",
              cursor: "pointer", fontWeight: "bold", fontSize: 14
            }}
          >
            {loading ? "Computing..." : "Generate Safety Number"}
          </button>
        )}

        {safetyNumber && (
          <>
            <div style={{
              display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20
            }}>
              {blocks.map((block, i) => (
                <div key={i} style={{
                  background: "#0a0f1a", border: "1px solid #1a2a3a",
                  borderRadius: 8, padding: "12px 16px", textAlign: "center",
                  fontFamily: "monospace", fontSize: 16, letterSpacing: 2,
                  color: "#00f0ff"
                }}>
                  {block}
                </div>
              ))}
            </div>

            {!verified ? (
              <div style={{ display: "flex", gap: 12 }}>
                <button
                  onClick={() => setVerified(true)}
                  style={{
                    flex: 1, background: "#00cc66", color: "#000",
                    border: "none", borderRadius: 6, padding: "10px",
                    cursor: "pointer", fontWeight: "bold"
                  }}
                >
                  ✓ Numbers Match — Verified
                </button>
                <button
                  onClick={onClose}
                  style={{
                    flex: 1, background: "#cc3333", color: "#fff",
                    border: "none", borderRadius: 6, padding: "10px",
                    cursor: "pointer", fontWeight: "bold"
                  }}
                >
                  ✗ Mismatch — Abort
                </button>
              </div>
            ) : (
              <div style={{
                background: "rgba(0,204,102,0.1)", border: "1px solid #00cc66",
                borderRadius: 8, padding: 16, textAlign: "center", color: "#00cc66"
              }}>
                ✓ Identity Verified — End-to-End Encrypted
              </div>
            )}
          </>
        )}

        <button
          onClick={onClose}
          style={{
            marginTop: 16, background: "transparent", color: "#666",
            border: "1px solid #333", borderRadius: 6, padding: "8px 20px",
            cursor: "pointer", width: "100%"
          }}
        >
          Close
        </button>
      </div>
    </div>
  );
}
