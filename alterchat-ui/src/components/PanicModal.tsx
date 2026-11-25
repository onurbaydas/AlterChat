import React from 'react';
import { detectLang, strings, type Lang } from '../i18n';

interface PanicModalProps {
  showPanicModal: boolean;
  setShowPanicModal: (show: boolean) => void;
  panicScope: string;
  setPanicScope: (scope: string) => void;
  executePanicWipe: () => void;
  lang?: Lang;
}

export const PanicModal: React.FC<PanicModalProps> = ({
  showPanicModal,
  setShowPanicModal,
  panicScope,
  setPanicScope,
  executePanicWipe,
  lang,
}) => {
  if (!showPanicModal) return null;
  const t = strings(lang ?? detectLang());

  return (
    <div className="modal-overlay" style={{ zIndex: 9999 }}>
      <div className="modal-content" style={{ maxWidth: 450, borderColor: '#ef4444', background: '#2b2d31' }}>
        <h3 style={{ color: '#da373c' }}>🚨 {t.panicTitle} 🚨</h3>
        <p style={{ color: '#dbdee1', fontSize: 14 }}>
          {t.panicBody}
        </p>
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#949ba4', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{t.panicScopePrompt}</label>
          <select
            value={panicScope}
            onChange={e => setPanicScope(e.target.value)}
            style={{ width: '100%', background: '#1e1f22', border: '1px solid #da373c', borderRadius: 4, padding: '10px', color: '#dbdee1', fontSize: 14 }}
          >
            <option value="active_profile">{`🔥 ${t.panicOptActive}`}</option>
            <option value="message_db_only">{`🗑️ ${t.panicOptMsgDb}`}</option>
            <option value="all_profiles">{`💥 ${t.panicOptAll}`}</option>
          </select>
        </div>
        <div className="modal-actions">
          <button className="peer-btn" onClick={() => setShowPanicModal(false)}>{t.panicCancel}</button>
          <button className="peer-btn danger" onClick={executePanicWipe}>
            {panicScope === 'all_profiles' ? t.panicConfirmAll : t.panicConfirmData}
          </button>
        </div>
      </div>
    </div>
  );
};
