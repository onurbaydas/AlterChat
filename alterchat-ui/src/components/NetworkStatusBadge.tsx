import React from "react";

export type NetworkStatus = "online" | "connecting" | "offline";

interface NetworkStatusBadgeProps {
  status: NetworkStatus;
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
  fontFamily: "monospace",
  padding: "3px 8px",
  borderRadius: 4,
  border: "1px solid rgba(255,255,255,0.08)",
  background: "rgba(0,0,0,0.25)",
  userSelect: "none",
  whiteSpace: "nowrap",
};

const CONFIG: Record<NetworkStatus, { dotColor: string; label: string; textColor: string }> = {
  online: { dotColor: "#44cc66", label: "Connected", textColor: "#44cc66" },
  connecting: { dotColor: "#ffcc00", label: "Connecting...", textColor: "#ffcc00" },
  offline: { dotColor: "#ff4444", label: "Offline", textColor: "#ff4444" },
};

export function NetworkStatusBadge({ status }: NetworkStatusBadgeProps) {
  const { dotColor, label, textColor } = CONFIG[status];
  return (
    <div style={{ ...CONTAINER, color: textColor }} title={`Network: ${label}`}>
      <span style={{ ...DOT_BASE, background: dotColor, boxShadow: `0 0 4px ${dotColor}` }} />
      {label}
    </div>
  );
}
