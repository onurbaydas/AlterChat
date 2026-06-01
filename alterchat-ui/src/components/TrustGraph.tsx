import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface TrustEdge {
  from_peer_id: string;
  to_peer_id: string;
  score: number;
  reason: string;
}

interface Friend {
  peer_id: string;
  nickname: string;
  trust_level?: number;
}

interface Props {
  myPeerId: string;
  friends: Friend[];
  onClose: () => void;
}

export function TrustGraph({ myPeerId, friends, onClose }: Props) {
  const [edges, setEdges] = useState<TrustEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [peerUri, setPeerUri] = useState<string>("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const rawEdges = await invoke<string[]>("list_trust_edges");
        const parsed: TrustEdge[] = rawEdges.flatMap(json => {
          try { return [JSON.parse(json)]; } catch { return []; }
        });
        setEdges(parsed);

        const uri = await invoke<string>("get_peer_uri");
        setPeerUri(uri);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  function shortId(id: string) {
    return id.length > 12 ? id.substring(0, 8) + "…" : id;
  }

  function getNick(peerId: string) {
    if (peerId === myPeerId) return "YOU";
    return friends.find(f => f.peer_id === peerId)?.nickname || shortId(peerId);
  }

  async function copyUri() {
    await navigator.clipboard.writeText(peerUri);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.9)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999
    }}>
      <div style={{
        background: "#0d1117", border: "1px solid #00f0ff",
        borderRadius: 12, padding: 28, maxWidth: 600, width: "100%", maxHeight: "80vh",
        overflow: "auto", boxShadow: "0 0 40px rgba(0,240,255,0.15)"
      }}>
        <h2 style={{ color: "#00f0ff", marginBottom: 6, fontSize: 18 }}>🕸 Trust Graph</h2>
        <p style={{ color: "#666", fontSize: 12, marginBottom: 20 }}>
          Web of trust — edges show verified trust between peers. Decentralized, no authority.
        </p>

        {/* #6 QR/URI Section */}
        <div style={{
          background: "#0a0f1a", border: "1px solid #1a2a3a",
          borderRadius: 8, padding: 12, marginBottom: 20
        }}>
          <div style={{ color: "#aaa", fontSize: 11, marginBottom: 6 }}>📡 Your alterchat:// URI (share to add contacts)</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <code style={{
              flex: 1, color: "#00f0ff", fontSize: 10, wordBreak: "break-all",
              background: "#050a0f", padding: "6px 8px", borderRadius: 4
            }}>
              {peerUri || "Loading…"}
            </code>
            <button
              onClick={copyUri}
              style={{
                background: copied ? "#00cc66" : "#00f0ff", color: "#000",
                border: "none", borderRadius: 4, padding: "6px 12px",
                cursor: "pointer", fontSize: 11, fontWeight: "bold", whiteSpace: "nowrap"
              }}
            >
              {copied ? "✓ Copied" : "Copy"}
            </button>
          </div>
        </div>

        {/* Trust Edges */}
        <div style={{ color: "#aaa", fontSize: 12, marginBottom: 8 }}>
          Trust Edges ({edges.length})
        </div>

        {loading ? (
          <div style={{ color: "#666", textAlign: "center", padding: 24 }}>Loading trust graph…</div>
        ) : edges.length === 0 ? (
          <div style={{ color: "#444", textAlign: "center", padding: 24 }}>
            No trust edges yet. Endorse peers to build the web of trust.
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {edges.map((e, i) => (
              <div key={i} style={{
                display: "flex", alignItems: "center", gap: 12,
                background: "#0a0f1a", borderRadius: 6, padding: "8px 12px",
                border: `1px solid ${e.score >= 0 ? "#1a3a1a" : "#3a1a1a"}`
              }}>
                <span style={{ color: "#00f0ff", fontSize: 12, minWidth: 80 }}>
                  {getNick(e.from_peer_id)}
                </span>
                <span style={{
                  color: e.score >= 5 ? "#00cc66" : e.score > 0 ? "#88cc88" : e.score === 0 ? "#666" : "#cc4444",
                  fontSize: 14
                }}>
                  {e.score >= 0 ? "▶" : "✗"}
                </span>
                <span style={{ color: "#fff", fontSize: 12, flex: 1 }}>
                  {getNick(e.to_peer_id)}
                </span>
                <span style={{
                  fontSize: 11, fontWeight: "bold",
                  color: e.score >= 0 ? "#00cc66" : "#cc4444"
                }}>
                  {e.score > 0 ? "+" : ""}{e.score}
                </span>
                {e.reason && (
                  <span style={{ fontSize: 10, color: "#555" }}>{e.reason}</span>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Friends trust summary */}
        {friends.length > 0 && (
          <>
            <div style={{ color: "#aaa", fontSize: 12, marginTop: 20, marginBottom: 8 }}>
              Friends Trust Levels
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
              {friends.map(f => (
                <div key={f.peer_id} style={{
                  background: "#0a0f1a", borderRadius: 6, padding: "6px 10px",
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  border: "1px solid #1a2a3a"
                }}>
                  <span style={{ color: "#ccc", fontSize: 12 }}>{f.nickname}</span>
                  <span style={{
                    fontSize: 11, fontWeight: "bold",
                    color: (f.trust_level || 0) >= 10 ? "#00cc66" : (f.trust_level || 0) < 0 ? "#cc4444" : "#888"
                  }}>
                    {(f.trust_level || 0) >= 0 ? "+" : ""}{f.trust_level || 0}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}

        <button
          onClick={onClose}
          style={{
            marginTop: 20, background: "transparent", color: "#666",
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
