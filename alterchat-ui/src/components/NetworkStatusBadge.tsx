import React from "react";
import { detectLang, strings, type Lang } from "../i18n";

export type NetworkStatus = "online" | "connecting" | "offline";
export type Reachability = "direct" | "relayed" | "unreachable" | null;

interface NetworkStatusBadgeProps {
  status: NetworkStatus;
  reachability?: Reachability;
  lang?: Lang;
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

const COLORS: Record<NetworkStatus, string> = {
  online: "#7cff6b",
  connecting: "#ffb000",
  offline: "#ff5b3a",
};

export function NetworkStatusBadge({ status, reachability = null, lang }: NetworkStatusBadgeProps) {
  const t = strings(lang ?? detectLang());
  const l = {
    online: t.netOnline,
    connecting: t.netConnecting,
    offline: t.netOffline,
    direct: t.netDirect,
    relayed: t.netRelayed,
    unreachable: t.netUnreachable,
    title: t.netTitle,
  };
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
