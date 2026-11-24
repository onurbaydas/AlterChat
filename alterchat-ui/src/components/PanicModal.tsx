import React from 'react';

interface PanicModalProps {
  showPanicModal: boolean;
  setShowPanicModal: (show: boolean) => void;
  panicScope: string;
  setPanicScope: (scope: string) => void;
  executePanicWipe: () => void;
}

export const PanicModal: React.FC<PanicModalProps> = ({
  showPanicModal,
  setShowPanicModal,
  panicScope,
  setPanicScope,
  executePanicWipe,
}) => {
  if (!showPanicModal) return null;

  return (
    <div className="modal-overlay" style={{ zIndex: 9999 }}>
      <div className="modal-content" style={{ maxWidth: 450, borderColor: '#ef4444', background: '#2b2d31' }}>
        <h3 style={{ color: '#da373c' }}>🚨 CRITICAL: PANIC WIPE 🚨</h3>
        <p style={{ color: '#dbdee1', fontSize: 14 }}>
          Bu işlem seçilen kapsamdaki tüm verileri kalıcı olarak (secure zeroing) siler. İşlem tamamlandıktan sonra uygulama anında kapanır. Geri dönüşü yoktur.
        </p>
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#949ba4', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Silinecek Kapsamı Seçin:</label>
          <select 
            value={panicScope} 
            onChange={e => setPanicScope(e.target.value)} 
            style={{ width: '100%', background: '#1e1f22', border: '1px solid #da373c', borderRadius: 4, padding: '10px', color: '#dbdee1', fontSize: 14 }}
          >
            <option value="active_profile">🔥 Sadece Aktif Profil (DB + Anahtarlar)</option>
            <option value="message_db_only">🗑️ Sadece Mesaj Veritabanı (Anahtarlar Kalır)</option>
            <option value="all_profiles">💥 TÜM PROFİLLER (Her Şeyi Sil)</option>
          </select>
        </div>
        <div className="modal-actions">
          <button className="peer-btn" onClick={() => setShowPanicModal(false)}>Vazgeç</button>
          <button className="peer-btn danger" onClick={executePanicWipe}>
            Evet, {panicScope === 'all_profiles' ? 'Her Şeyi' : 'Verileri'} Sil!
          </button>
        </div>
      </div>
    </div>
  );
};
