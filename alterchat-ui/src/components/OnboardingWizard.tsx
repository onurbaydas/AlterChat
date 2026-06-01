import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface OnboardingWizardProps {
  onComplete: () => void;
}

type Mode = "choose" | "create" | "open";
type CreateStep = 1 | 2 | 3;

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: "fixed",
    inset: 0,
    background: "#050a0f",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 9999,
    fontFamily: "'Courier New', Courier, monospace",
  },
  card: {
    background: "#0d1117",
    border: "1px solid #1a3a2a",
    borderRadius: 8,
    padding: "40px 48px",
    width: 460,
    maxWidth: "90vw",
    boxShadow: "0 0 40px rgba(0, 240, 255, 0.08)",
  },
  logo: {
    fontSize: 28,
    color: "#00f0ff",
    letterSpacing: 4,
    textAlign: "center",
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 11,
    color: "#445",
    textAlign: "center",
    marginBottom: 32,
    letterSpacing: 2,
  },
  modeButtonRow: {
    display: "flex",
    gap: 12,
    marginTop: 8,
  },
  modeButton: {
    flex: 1,
    padding: "14px 8px",
    background: "transparent",
    border: "1px solid #1a3a2a",
    borderRadius: 6,
    color: "#aaa",
    fontSize: 13,
    cursor: "pointer",
    letterSpacing: 1,
  },
  modeButtonPrimary: {
    flex: 1,
    padding: "14px 8px",
    background: "transparent",
    border: "1px solid #00f0ff",
    borderRadius: 6,
    color: "#00f0ff",
    fontSize: 13,
    cursor: "pointer",
    letterSpacing: 1,
  },
  label: {
    display: "block",
    fontSize: 11,
    color: "#667",
    marginBottom: 4,
    letterSpacing: 1,
    textTransform: "uppercase" as const,
  },
  input: {
    width: "100%",
    padding: "10px 12px",
    background: "#080d12",
    border: "1px solid #1a2a3a",
    borderRadius: 4,
    color: "#ccc",
    fontSize: 13,
    outline: "none",
    boxSizing: "border-box" as const,
    marginBottom: 16,
    fontFamily: "inherit",
  },
  inputError: {
    width: "100%",
    padding: "10px 12px",
    background: "#080d12",
    border: "1px solid #cc3333",
    borderRadius: 4,
    color: "#ccc",
    fontSize: 13,
    outline: "none",
    boxSizing: "border-box" as const,
    marginBottom: 4,
    fontFamily: "inherit",
  },
  errorText: {
    fontSize: 11,
    color: "#cc4444",
    marginBottom: 12,
  },
  primaryBtn: {
    width: "100%",
    padding: "12px",
    background: "transparent",
    border: "1px solid #00f0ff",
    borderRadius: 4,
    color: "#00f0ff",
    fontSize: 13,
    cursor: "pointer",
    letterSpacing: 2,
    marginTop: 4,
    fontFamily: "inherit",
  },
  primaryBtnDisabled: {
    width: "100%",
    padding: "12px",
    background: "transparent",
    border: "1px solid #1a3a3a",
    borderRadius: 4,
    color: "#334",
    fontSize: 13,
    cursor: "not-allowed",
    letterSpacing: 2,
    marginTop: 4,
    fontFamily: "inherit",
  },
  backLink: {
    background: "none",
    border: "none",
    color: "#445",
    fontSize: 11,
    cursor: "pointer",
    padding: 0,
    marginTop: 16,
    display: "block",
    textAlign: "center" as const,
    letterSpacing: 1,
  },
  stepIndicator: {
    display: "flex",
    justifyContent: "center",
    gap: 8,
    marginBottom: 28,
  },
  stepDot: (active: boolean, done: boolean): React.CSSProperties => ({
    width: 8,
    height: 8,
    borderRadius: "50%",
    background: done ? "#00f0ff" : active ? "#00cc99" : "#1a2a3a",
    transition: "background 0.2s",
  }),
  heading: {
    fontSize: 15,
    color: "#ccc",
    marginBottom: 20,
    letterSpacing: 1,
  },
  warningBox: {
    background: "#0d1a0d",
    border: "1px solid #1a4a2a",
    borderRadius: 4,
    padding: "14px 16px",
    fontSize: 12,
    color: "#99bb99",
    lineHeight: 1.7,
    marginBottom: 20,
  },
  warningIcon: {
    color: "#ffcc44",
    marginRight: 4,
  },
  checkLabel: {
    display: "flex",
    alignItems: "flex-start",
    gap: 10,
    fontSize: 12,
    color: "#aaa",
    cursor: "pointer",
    marginBottom: 20,
    lineHeight: 1.5,
  },
  successBox: {
    background: "#080d0d",
    border: "1px solid #1a4a4a",
    borderRadius: 4,
    padding: "14px 16px",
    marginBottom: 20,
  },
  successTitle: {
    fontSize: 11,
    color: "#00cc99",
    letterSpacing: 2,
    marginBottom: 8,
    textTransform: "uppercase" as const,
  },
  peerIdText: {
    fontSize: 11,
    color: "#00f0ff",
    wordBreak: "break-all" as const,
    lineHeight: 1.6,
    fontFamily: "inherit",
  },
  copyBtn: {
    background: "transparent",
    border: "1px solid #1a4a4a",
    borderRadius: 4,
    color: "#00cc99",
    fontSize: 11,
    cursor: "pointer",
    padding: "4px 10px",
    marginTop: 8,
    fontFamily: "inherit",
    letterSpacing: 1,
  },
};

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const [mode, setMode] = useState<Mode>("choose");

  // Create profile state
  const [createStep, setCreateStep] = useState<CreateStep>(1);
  const [profileName, setProfileName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [createError, setCreateError] = useState("");
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createdPeerId, setCreatedPeerId] = useState("");
  const [copyLabel, setCopyLabel] = useState("Copy");

  // Open profile state
  const [openPassword, setOpenPassword] = useState("");
  const [openError, setOpenError] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);

  // --- Create profile handlers ---
  const handleStep1Next = () => {
    setCreateError("");
    if (!profileName.trim()) {
      setCreateError("Profile name is required.");
      return;
    }
    if (newPassword.length < 8) {
      setCreateError("Password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setCreateError("Passwords do not match.");
      return;
    }
    setCreateStep(2);
  };

  const handleStep2Next = async () => {
    if (!backupAcknowledged) return;
    setIsCreating(true);
    setCreateError("");
    try {
      // login_profile with a new password creates the keypair if it does not exist
      const peerId = await invoke<string>("login_profile", {
        password: newPassword,
        amnesic: false,
      });
      setCreatedPeerId(peerId);
      setCreateStep(3);
    } catch (err) {
      setCreateError("Failed to create profile: " + String(err));
      setCreateStep(1);
    } finally {
      setIsCreating(false);
    }
  };

  const handleCopyPeerId = async () => {
    try {
      await navigator.clipboard.writeText(createdPeerId);
      setCopyLabel("Copied!");
      setTimeout(() => setCopyLabel("Copy"), 2000);
    } catch {
      setCopyLabel("Copy failed");
    }
  };

  // --- Open profile handler ---
  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!openPassword.trim()) return;
    setIsUnlocking(true);
    setOpenError("");
    try {
      await invoke<string>("login_profile", {
        password: openPassword,
        amnesic: false,
      });
      onComplete();
    } catch (err) {
      setOpenError("Wrong password or corrupted vault: " + String(err));
    } finally {
      setIsUnlocking(false);
    }
  };

  // --- Render ---
  return (
    <div style={styles.overlay}>
      <div style={styles.card}>
        <div style={styles.logo}>ALTERCHAT</div>
        <div style={styles.subtitle}>SOVEREIGN ENCRYPTED MESH</div>

        {mode === "choose" && (
          <>
            <div style={{ fontSize: 13, color: "#556", textAlign: "center", marginBottom: 24, lineHeight: 1.6 }}>
              No active profile detected. Create a new identity or unlock an existing one.
            </div>
            <div style={styles.modeButtonRow}>
              <button style={styles.modeButtonPrimary} onClick={() => setMode("create")}>
                + New Profile
              </button>
              <button style={styles.modeButton} onClick={() => setMode("open")}>
                Unlock Existing
              </button>
            </div>
          </>
        )}

        {mode === "create" && (
          <>
            <div style={styles.stepIndicator}>
              {([1, 2, 3] as CreateStep[]).map((s) => (
                <div
                  key={s}
                  style={styles.stepDot(createStep === s, createStep > s)}
                />
              ))}
            </div>

            {createStep === 1 && (
              <>
                <div style={styles.heading}>Create New Profile</div>
                <label style={styles.label}>Profile Name</label>
                <input
                  style={newPassword && profileName === "" ? styles.inputError : styles.input}
                  type="text"
                  placeholder="e.g. main, work, anon..."
                  value={profileName}
                  onChange={(e) => setProfileName(e.target.value)}
                  autoFocus
                />
                <label style={styles.label}>Password</label>
                <input
                  style={styles.input}
                  type="password"
                  placeholder="Minimum 8 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
                <label style={styles.label}>Confirm Password</label>
                <input
                  style={createError.includes("match") ? styles.inputError : styles.input}
                  type="password"
                  placeholder="Repeat password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleStep1Next(); }}
                />
                {createError && <div style={styles.errorText}>{createError}</div>}
                <button style={styles.primaryBtn} onClick={handleStep1Next}>
                  CONTINUE
                </button>
              </>
            )}

            {createStep === 2 && (
              <>
                <div style={styles.heading}>Backup Warning</div>
                <div style={styles.warningBox}>
                  <span style={styles.warningIcon}>!</span>
                  If you lose your password, your messages and identity{" "}
                  <strong style={{ color: "#ffcc44" }}>cannot be recovered</strong>.
                  There is no reset option, no recovery email, and no central authority.
                  <br /><br />
                  Write down your password and keep it in a safe place before continuing.
                </div>
                <label style={styles.checkLabel}>
                  <input
                    type="checkbox"
                    checked={backupAcknowledged}
                    onChange={(e) => setBackupAcknowledged(e.target.checked)}
                    style={{ marginTop: 2, flexShrink: 0 }}
                  />
                  I understand and have saved my password in a safe place.
                </label>
                {createError && <div style={styles.errorText}>{createError}</div>}
                <button
                  style={backupAcknowledged && !isCreating ? styles.primaryBtn : styles.primaryBtnDisabled}
                  onClick={handleStep2Next}
                  disabled={!backupAcknowledged || isCreating}
                >
                  {isCreating ? "CREATING..." : "CREATE PROFILE"}
                </button>
                <button style={styles.backLink} onClick={() => setCreateStep(1)}>
                  back
                </button>
              </>
            )}

            {createStep === 3 && (
              <>
                <div style={styles.heading}>Profile Created</div>
                <div style={{ fontSize: 12, color: "#667", marginBottom: 16, lineHeight: 1.6 }}>
                  Your cryptographic identity has been generated and encrypted with your password.
                </div>
                <div style={styles.successBox}>
                  <div style={styles.successTitle}>Your Peer ID</div>
                  <div style={styles.peerIdText}>{createdPeerId}</div>
                  <button style={styles.copyBtn} onClick={handleCopyPeerId}>
                    {copyLabel}
                  </button>
                </div>
                <div style={{ fontSize: 11, color: "#445", marginBottom: 20, lineHeight: 1.6 }}>
                  Share this Peer ID so others can add you as a contact. It is derived from your public key and does not reveal your password.
                </div>
                <button style={styles.primaryBtn} onClick={onComplete}>
                  ENTER ALTERCHAT
                </button>
              </>
            )}

            {createStep !== 3 && (
              <button style={styles.backLink} onClick={() => { setMode("choose"); setCreateStep(1); setCreateError(""); setProfileName(""); setNewPassword(""); setConfirmPassword(""); setBackupAcknowledged(false); }}>
                back to start
              </button>
            )}
          </>
        )}

        {mode === "open" && (
          <>
            <div style={styles.heading}>Unlock Profile</div>
            <form onSubmit={handleUnlock}>
              <label style={styles.label}>Password</label>
              <input
                style={openError ? styles.inputError : styles.input}
                type="password"
                placeholder="Enter your vault password"
                value={openPassword}
                onChange={(e) => { setOpenPassword(e.target.value); setOpenError(""); }}
                autoFocus
              />
              {openError && <div style={styles.errorText}>{openError}</div>}
              <button
                type="submit"
                style={isUnlocking ? styles.primaryBtnDisabled : styles.primaryBtn}
                disabled={isUnlocking}
              >
                {isUnlocking ? "UNLOCKING..." : "UNLOCK"}
              </button>
            </form>
            <button style={styles.backLink} onClick={() => { setMode("choose"); setOpenError(""); setOpenPassword(""); }}>
              back to start
            </button>
          </>
        )}
      </div>
    </div>
  );
}
