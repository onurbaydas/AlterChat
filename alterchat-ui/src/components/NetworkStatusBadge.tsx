import React from "react";
import { detectLang } from "../i18n";

export type NetworkStatus = "online" | "connecting" | "offline";
export type Reachability = "direct" | "relayed" | "unreachable" | null;

interface NetworkStatusBadgeProps {
  status: NetworkStatus;
  reachability?: Reachability;
}

const DOT_BASE: React.CSSProperties = {
  display: "inline-block",
  width: 8,
  height: 8,
  borderRadius: "50%",
  marginRight: 5,
  flexShrink: 0,
};

const CONTAINER: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  fontSize: 11,
  fontFamily: "var(--font-ui)",
  padding: "3px 8px",
  borderRadius: 4,
  border: "1px solid rgba(255,255,255,0.08)",
  background: "rgba(0,0,0,0.25)",
  userSelect: "none",
  whiteSpace: "nowrap",
};

const LABELS = {
  tr: {
    online: "Bağlı",
    connecting: "Bağlanıyor...",
    offline: "Çevrimdışı",
    direct: "doğrudan",
    relayed: "relay üzerinden",
    unreachable: "dışarıdan erişilemez",
    title: "Ağ durumu",
  },
  en: {
    online: "Connected",
    connecting: "Connecting...",
    offline: "Offline",
    direct: "direct",
    relayed: "via relay",
    unreachable: "not reachable from outside",
    title: "Network",
  },
} as const;

const COLORS: Record<NetworkStatus, string> = {
  online: "#7cff6b",
  connecting: "#ffb000",
  offline: "#ff5b3a",
};

export function NetworkStatusBadge({ status, reachability = null }: NetworkStatusBadgeProps) {
  const l = LABELS[detectLang()];
  const color = COLORS[status];
  const reach = reachability ? l[reachability] : null;
  return (
    <div style={{ ...CONTAINER, color }} title={`${l.title}: ${l[status]}${reach ? ` (${reach})` : ""}`}>
      <span style={{ ...DOT_BASE, background: color, boxShadow: `0 0 4px ${color}` }} />
      {l[status]}
      {status === "online" && reachability === "relayed" ? " ⇄" : ""}
    </div>
  );
}
