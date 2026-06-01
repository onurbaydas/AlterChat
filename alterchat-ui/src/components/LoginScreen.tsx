import React from 'react';

interface LoginScreenProps {
  loginPassword: string;
  setLoginPassword: (val: string) => void;
  amnesicMode: boolean;
  setAmnesicMode: (val: boolean) => void;
  isLoggingIn: boolean;
  handleLogin: (e: React.FormEvent) => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({
  loginPassword,
  setLoginPassword,
  amnesicMode,
  setAmnesicMode,
  isLoggingIn,
  handleLogin
}) => {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#0f172a' }}>
      <div style={{ background: '#020817', padding: '48px', borderRadius: 16, width: 400, boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 42, marginBottom: 8 }}>🔐</div>
          <h1 style={{ background: 'linear-gradient(135deg, #34d399, #06b6d4)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontSize: 28, fontWeight: 800, margin: 0 }}>AlterChat</h1>
          <p style={{ color: '#64748b', marginTop: 8, fontSize: 14 }}>Enter your vault password to decrypt your identity</p>
        </div>
        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Vault Password</label>
            <input
              type="password"
              value={loginPassword}
              onChange={e => setLoginPassword(e.target.value)}
              placeholder="Enter your password..."
              autoFocus
              style={{ width: '100%', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, padding: '12px 16px', color: '#e2e8f0', fontSize: 15, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input 
              type="checkbox" 
              id="amnesic" 
              checked={amnesicMode} 
              onChange={e => setAmnesicMode(e.target.checked)} 
              style={{ width: 16, height: 16, accentColor: '#ff2a2a', cursor: 'pointer' }}
            />
            <label htmlFor="amnesic" style={{ color: '#94a3b8', fontSize: 13, cursor: 'pointer' }}>
              <strong style={{ color: '#ff2a2a' }}>Amnesic Mode</strong> (RAM-only, never touches disk)
            </label>
          </div>
          <button
            type="submit"
            disabled={isLoggingIn}
            style={{ background: isLoggingIn ? '#1e293b' : 'linear-gradient(135deg, #10b981, #0891b2)', color: '#fff', border: 'none', borderRadius: 8, padding: '14px 0', fontSize: 15, fontWeight: 700, cursor: isLoggingIn ? 'not-allowed' : 'pointer' }}
          >
            {isLoggingIn ? '⏳ Decrypting...' : '🔓 Unlock Vault'}
          </button>
          <button
            type="button"
            disabled={isLoggingIn}
            onClick={() => {
              setLoginPassword("default_quick_start");
              setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 10);
            }}
            style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '12px 0', fontSize: 14, fontWeight: 600, cursor: isLoggingIn ? 'not-allowed' : 'pointer', marginTop: 8 }}
          >
            ⚡ Quick Start (Guest Mode)
          </button>
        </form>
        <div style={{ marginTop: 24, paddingTop: 24, borderTop: '1px solid #1e293b', textAlign: 'center' }}>
          <p style={{ color: '#334155', fontSize: 12, margin: 0 }}>✦ Plausible deniability active — any password unlocks a unique encrypted vault</p>
        </div>
      </div>
    </div>
  );
};
