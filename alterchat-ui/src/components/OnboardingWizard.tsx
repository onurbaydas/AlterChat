import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import bunkerRat from "../assets/bunker-rat.svg";
import { detectLang, saveLang, strings, type Lang } from "../i18n";

interface OnboardingWizardProps {
  onComplete: () => void;
  /** When given, the language is owned by the parent (App) instead of the wizard. */
  lang?: Lang;
  onLangChange?: (lang: Lang) => void;
}

type Mode = "choose" | "create" | "open";
type CreateStep = 1 | 2 | 3;

const C = {
  green: "var(--accent-green)",
  amber: "var(--accent-amber)",
  red: "var(--accent-red)",
  muted: "var(--text-muted)",
  dim: "var(--text-mono)",
  text: "var(--text-main)",
  screen: "#070a06",
  steel: "#3e4034",
};

const stepDot = (active: boolean, done: boolean): React.CSSProperties => ({
  width: 10,
  height: 10,
  borderRadius: "50%",
  background: done ? C.green : active ? C.amber : "#2a2c24",
  boxShadow: done || active ? "0 0 8px currentColor" : "none",
  color: done ? C.green : C.amber,
  transition: "background 0.2s",
});

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: "fixed",
    inset: 0,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1000,
    overflowY: "auto",
    padding: 24,
  },
  card: {
    width: "100%",
    maxWidth: 520,
    padding: "28px 32px 24px",
    background: "rgba(20, 22, 18, 0.94)",
    border: `2px solid ${C.steel}`,
    borderRadius: 14,
    boxShadow: "0 20px 60px rgba(0,0,0,0.8), inset 0 0 40px rgba(0,0,0,0.5)",
    position: "relative",
  },
  stripe: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    height: 8,
    background: "var(--hazard-stripe)",
    borderTopLeftRadius: 12,
    borderTopRightRadius: 12,
  },
  scene: {
    width: "100%",
    borderRadius: 10,
    border: `1px solid ${C.steel}`,
    display: "block",
    marginBottom: 18,
  },
  logo: {
    fontFamily: "var(--font-display)",
    fontSize: 46,
    lineHeight: 1,
    letterSpacing: 6,
    color: C.amber,
    textAlign: "center",
    textShadow: "0 0 14px rgba(255,176,0,0.45)",
  },
  subtitle: {
    fontFamily: "var(--font-display)",
    fontSize: 18,
    letterSpacing: 3,
    color: C.green,
    textAlign: "center",
    marginBottom: 14,
    textShadow: "0 0 8px var(--accent-cyan-glow)",
  },
  intro: {
    fontSize: 13,
    color: C.muted,
    textAlign: "center",
    marginBottom: 20,
    lineHeight: 1.6,
  },
  column: { display: "flex", flexDirection: "column", gap: 10 },
  heading: {
    fontFamily: "var(--font-display)",
    fontSize: 26,
    letterSpacing: 2,
    color: C.amber,
    marginBottom: 14,
  },
  label: { display: "block", fontSize: 12, color: C.muted, marginBottom: 6 },
  input: {
    width: "100%",
    padding: "10px 12px",
    background: C.screen,
    border: `1px solid ${C.steel}`,
    borderRadius: 6,
    color: C.green,
    fontSize: 14,
    outline: "none",
    marginBottom: 14,
    fontFamily: "inherit",
    caretColor: C.green,
  },
  errorText: { color: C.red, fontSize: 12, marginTop: -6, marginBottom: 12 },
  primaryBtn: {
    width: "100%",
    padding: "11px 0",
    background: "linear-gradient(180deg, #ffbf33, #c98a00)",
    border: "1px solid #7a5600",
    borderRadius: 6,
    color: "#1a1305",
    fontFamily: "var(--font-display)",
    fontSize: 22,
    letterSpacing: 3,
    cursor: "pointer",
  },
  secondaryBtn: {
    width: "100%",
    padding: "11px 0",
    background: "linear-gradient(180deg, #3a3c33, #24261f)",
    border: "1px solid #55574a",
    borderRadius: 6,
    color: C.text,
    fontFamily: "var(--font-display)",
    fontSize: 22,
    letterSpacing: 2,
    cursor: "pointer",
  },
  ghostBtn: {
    width: "100%",
    padding: "9px 0",
    background: "transparent",
    border: `1px dashed ${C.steel}`,
    borderRadius: 6,
    color: C.muted,
    fontFamily: "inherit",
    fontSize: 13,
    cursor: "pointer",
  },
  backLink: {
    background: "none",
    border: "none",
    color: C.dim,
    fontSize: 12,
    cursor: "pointer",
    marginTop: 14,
    display: "block",
    width: "100%",
    textAlign: "center",
    fontFamily: "inherit",
  },
  warningBox: {
    background: "rgba(201,154,30,0.08)",
    border: "1px solid rgba(201,154,30,0.45)",
    borderRadius: 8,
    padding: "14px 16px",
    fontSize: 13,
    color: C.text,
    lineHeight: 1.7,
    marginBottom: 16,
  },
  checkLabel: {
    display: "flex",
    gap: 10,
    alignItems: "flex-start",
    fontSize: 13,
    color: C.text,
    cursor: "pointer",
    marginBottom: 18,
  },
  inviteBox: {
    background: C.screen,
    border: "1px solid rgba(124,255,107,0.3)",
    borderRadius: 8,
    padding: 14,
    marginBottom: 12,
  },
  inviteText: {
    fontSize: 11,
    color: C.green,
    wordBreak: "break-all",
    lineHeight: 1.5,
    marginBottom: 10,
    textShadow: "0 0 6px rgba(124,255,107,0.35)",
    userSelect: "text",
  },
  copyBtn: {
    padding: "6px 14px",
    background: "transparent",
    border: `1px solid ${C.green}`,
    borderRadius: 4,
    color: C.green,
    fontFamily: "inherit",
    fontSize: 12,
    cursor: "pointer",
  },
  langBtn: {
    position: "absolute",
    top: 16,
    right: 16,
    background: "transparent",
    border: `1px solid ${C.steel}`,
    borderRadius: 4,
    color: C.muted,
    fontSize: 11,
    padding: "3px 8px",
    cursor: "pointer",
    fontFamily: "inherit",
  },
};

async function fetchInviteLink(): Promise<string> {
  // The session starts asynchronously right after login; retry briefly.
  for (let i = 0; i < 20; i++) {
    try {
      return await invoke<string>("get_peer_uri");
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  return "";
}

async function saveNickname(nick: string) {
  try {
    const config = await invoke<Record<string, unknown>>("get_full_config");
    await invoke("save_full_config", { config: { ...config, nick } });
  } catch (err) {
    console.error("could not save nickname", err);
  }
}

export function OnboardingWizard({ onComplete, lang: langProp, onLangChange }: OnboardingWizardProps) {
  const [ownLang, setOwnLang] = useState<Lang>(detectLang());
  const lang = langProp ?? ownLang;
  const t = strings(lang);
  const [mode, setMode] = useState<Mode>("choose");

  const [createStep, setCreateStep] = useState<CreateStep>(1);
  const [nickname, setNickname] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [createError, setCreateError] = useState("");
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [inviteLink, setInviteLink] = useState("");
  const [copyLabel, setCopyLabel] = useState<string>(t.copy);

  const [openPassword, setOpenPassword] = useState("");
  const [openError, setOpenError] = useState("");

  const toggleLang = () => {
    const next: Lang = lang === "tr" ? "en" : "tr";
    if (onLangChange) {
      onLangChange(next);
    } else {
      setOwnLang(next);
      saveLang(next);
    }
    setCopyLabel(strings(next).copy);
  };

  const resetCreate = () => {
    setMode("choose");
    setCreateStep(1);
    setCreateError("");
    setNickname("");
    setNewPassword("");
    setConfirmPassword("");
    setBackupAcknowledged(false);
  };

  const handleStep1Next = () => {
    setCreateError("");
    if (!nickname.trim()) return setCreateError(t.nickRequired);
    if (newPassword.length < 8) return setCreateError(t.pwShort);
    if (newPassword !== confirmPassword) return setCreateError(t.pwMismatch);
    setCreateStep(2);
  };

  const handleCreate = async () => {
    if (!backupAcknowledged) return;
    setBusy(true);
    setCreateError("");
    try {
      await invoke<string>("login_profile", { password: newPassword, amnesic: false, create: true });
      await saveNickname(nickname.trim());
      setInviteLink(await fetchInviteLink());
      setCreateStep(3);
    } catch (err) {
      setCreateError(t.failed + String(err));
      setCreateStep(1);
    } finally {
      setBusy(false);
    }
  };

  const handleAmnesic = async () => {
    setBusy(true);
    try {
      await invoke<string>("login_profile", { password: "", amnesic: true });
      onComplete();
    } catch (err) {
      alert(t.failed + String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(inviteLink);
      setCopyLabel(t.copied);
      setTimeout(() => setCopyLabel(t.copy), 2000);
    } catch {
      setCopyLabel(t.copyFailed);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!openPassword) return;
    setBusy(true);
    setOpenError("");
    try {
      await invoke<string>("login_profile", { password: openPassword, amnesic: false, create: false });
      onComplete();
    } catch (err) {
      const msg = String(err);
      setOpenError(msg.includes("No profile matches") ? t.wrongPw : t.failed + msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.card}>
        <div style={styles.stripe} />
        <button style={styles.langBtn} onClick={toggleLang}>{t.lang}</button>

        {mode === "choose" && (
          <img src={bunkerRat} alt="" style={styles.scene} />
        )}
        <div style={styles.logo}>ALTERCHAT</div>
        <div style={styles.subtitle}>{t.tagline}</div>

        {mode === "choose" && (
          <>
            <div style={styles.intro}>{t.intro}</div>
            <div style={styles.column}>
              <button style={styles.primaryBtn} onClick={() => setMode("create")} disabled={busy}>
                {t.newProfile}
              </button>
              <button style={styles.secondaryBtn} onClick={() => setMode("open")} disabled={busy}>
                {t.unlock}
              </button>
              <button style={styles.ghostBtn} onClick={handleAmnesic} disabled={busy} title={t.amnesicHint}>
                {t.amnesic}
              </button>
              <div style={{ fontSize: 11, color: C.dim, textAlign: "center" }}>{t.amnesicHint}</div>
            </div>
          </>
        )}

        {mode === "create" && (
          <>
            <div style={{ display: "flex", justifyContent: "center", gap: 10, margin: "8px 0 18px" }}>
              {([1, 2, 3] as CreateStep[]).map((s) => (
                <div key={s} style={stepDot(createStep === s, createStep > s)} />
              ))}
            </div>

            {createStep === 1 && (
              <>
                <label style={styles.label}>{t.nickname}</label>
                <input
                  style={styles.input}
                  placeholder={t.nicknamePh}
                  value={nickname}
                  maxLength={32}
                  onChange={(e) => setNickname(e.target.value)}
                  autoFocus
                />
                <label style={styles.label}>{t.password}</label>
                <input
                  style={styles.input}
                  type="password"
                  placeholder={t.passwordPh}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
                <label style={styles.label}>{t.confirm}</label>
                <input
                  style={styles.input}
                  type="password"
                  placeholder={t.confirmPh}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleStep1Next(); }}
                />
                {createError && <div style={styles.errorText}>{createError}</div>}
                <button style={styles.primaryBtn} onClick={handleStep1Next}>{t.continue}</button>
              </>
            )}

            {createStep === 2 && (
              <>
                <div style={styles.heading}>⚠ {t.backupTitle}</div>
                <div style={styles.warningBox}>
                  {t.backupBody1} <strong style={{ color: C.amber }}>{t.backupBodyStrong}</strong>.{" "}
                  {t.backupBody2}
                  <br /><br />
                  {t.backupBody3}
                </div>
                <label style={styles.checkLabel}>
                  <input
                    type="checkbox"
                    checked={backupAcknowledged}
                    onChange={(e) => setBackupAcknowledged(e.target.checked)}
                    style={{ marginTop: 3, flexShrink: 0 }}
                  />
                  {t.backupAck}
                </label>
                {createError && <div style={styles.errorText}>{createError}</div>}
                <button
                  style={{ ...styles.primaryBtn, opacity: backupAcknowledged && !busy ? 1 : 0.45 }}
                  onClick={handleCreate}
                  disabled={!backupAcknowledged || busy}
                >
                  {busy ? t.creating : t.create}
                </button>
                <button style={styles.backLink} onClick={() => setCreateStep(1)}>{t.back}</button>
              </>
            )}

            {createStep === 3 && (
              <>
                <div style={styles.heading}>🐀 {t.created}</div>
                <div style={{ ...styles.intro, textAlign: "left" }}>{t.createdBody}</div>
                <div style={styles.inviteBox}>
                  <div style={styles.label}>{t.yourInvite}</div>
                  <div style={styles.inviteText}>{inviteLink || "…"}</div>
                  <button style={styles.copyBtn} onClick={handleCopy} disabled={!inviteLink}>{copyLabel}</button>
                </div>
                <div style={{ fontSize: 11, color: C.dim, marginBottom: 18 }}>{t.inviteLater}</div>
                <button style={styles.primaryBtn} onClick={onComplete}>{t.enter}</button>
              </>
            )}

            {createStep !== 3 && (
              <button style={styles.backLink} onClick={resetCreate}>{t.backToStart}</button>
            )}
          </>
        )}

        {mode === "open" && (
          <>
            <div style={styles.heading}>{t.unlockTitle}</div>
            <form onSubmit={handleUnlock}>
              <label style={styles.label}>{t.password}</label>
              <input
                style={{ ...styles.input, borderColor: openError ? "var(--accent-red)" : undefined }}
                type="password"
                placeholder={t.unlockPh}
                value={openPassword}
                onChange={(e) => { setOpenPassword(e.target.value); setOpenError(""); }}
                autoFocus
              />
              {openError && <div style={styles.errorText}>{openError}</div>}
              <button type="submit" style={{ ...styles.primaryBtn, opacity: busy ? 0.5 : 1 }} disabled={busy}>
                {busy ? t.unlocking : t.unlockBtn}
              </button>
            </form>
            <button style={styles.backLink} onClick={() => { setMode("choose"); setOpenError(""); setOpenPassword(""); }}>
              {t.backToStart}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
