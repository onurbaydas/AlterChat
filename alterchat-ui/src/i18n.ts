// Minimal i18n: Turkish and English. Default follows the system language.

export type Lang = "tr" | "en";

const STORAGE_KEY = "alterchat.lang";

export function detectLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "tr" || saved === "en") return saved;
  } catch {
    /* storage unavailable */
  }
  return navigator.language?.toLowerCase().startsWith("tr") ? "tr" : "en";
}

export function saveLang(lang: Lang) {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    /* ignore */
  }
}

const dict = {
  tr: {
    tagline: "Yeraltı şifreli mesajlaşma",
    intro: "Hesap yok, sunucu yok. Kimliğin ve mesajların sadece bu bilgisayarda, şifreli durur.",
    newProfile: "Yeni sığınak kur",
    unlock: "Sığınağımı aç",
    amnesic: "Geçici oturum (iz bırakmaz)",
    amnesicHint: "Kapatınca her şey silinir. Hiçbir şey diske kalıcı yazılmaz.",
    nickname: "Takma adın",
    nicknamePh: "ör. kör_köstebek",
    password: "Şifre",
    passwordPh: "En az 8 karakter",
    confirm: "Şifre tekrar",
    confirmPh: "Şifreyi tekrar yaz",
    continue: "DEVAM",
    nickRequired: "Bir takma ad yaz.",
    pwShort: "Şifre en az 8 karakter olmalı.",
    pwMismatch: "Şifreler aynı değil.",
    backupTitle: "Önemli: Şifreni kaybetme",
    backupBody1: "Şifreni unutursan mesajların ve kimliğin",
    backupBodyStrong: "geri getirilemez",
    backupBody2: "Şifre sıfırlama, kurtarma e-postası veya merkezi bir yönetici yok.",
    backupBody3: "Devam etmeden önce şifreni güvenli bir yere not et.",
    backupAck: "Anladım, şifremi güvenli bir yere kaydettim.",
    create: "SIĞINAĞI KUR",
    creating: "KURULUYOR...",
    created: "Sığınak hazır!",
    createdBody: "Kimliğin oluşturuldu ve şifrenle kilitlendi. Arkadaşlarının seni eklemesi için aşağıdaki davet bağlantını gönder.",
    yourInvite: "Davet bağlantın",
    copy: "Kopyala",
    copied: "Kopyalandı!",
    copyFailed: "Kopyalanamadı",
    inviteLater: "Davet bağlantını daha sonra sol alttaki profilinden de kopyalayabilirsin.",
    enter: "BUNKERE GİR",
    unlockTitle: "Sığınağı aç",
    unlockPh: "Şifren",
    unlocking: "AÇILIYOR...",
    unlockBtn: "AÇ",
    wrongPw: "Bu şifreyle eşleşen sığınak bulunamadı.",
    back: "geri",
    backToStart: "başa dön",
    failed: "Bir şeyler ters gitti: ",
    lang: "English",
  },
  en: {
    tagline: "Underground encrypted messaging",
    intro: "No accounts, no servers. Your identity and messages stay encrypted on this computer only.",
    newProfile: "Build a new bunker",
    unlock: "Open my bunker",
    amnesic: "Temporary session (leaves no trace)",
    amnesicHint: "Everything is wiped when you close the app. Nothing is kept on disk.",
    nickname: "Your nickname",
    nicknamePh: "e.g. blind_mole",
    password: "Password",
    passwordPh: "At least 8 characters",
    confirm: "Confirm password",
    confirmPh: "Repeat password",
    continue: "CONTINUE",
    nickRequired: "Pick a nickname.",
    pwShort: "Password must be at least 8 characters.",
    pwMismatch: "Passwords do not match.",
    backupTitle: "Important: don't lose your password",
    backupBody1: "If you forget your password, your messages and identity",
    backupBodyStrong: "cannot be recovered",
    backupBody2: "There is no reset, no recovery e-mail and no central admin.",
    backupBody3: "Write your password down somewhere safe before continuing.",
    backupAck: "I understand and have saved my password somewhere safe.",
    create: "BUILD BUNKER",
    creating: "BUILDING...",
    created: "Bunker ready!",
    createdBody: "Your identity was created and locked with your password. Send the invite link below so friends can add you.",
    yourInvite: "Your invite link",
    copy: "Copy",
    copied: "Copied!",
    copyFailed: "Copy failed",
    inviteLater: "You can also copy your invite link later from your profile in the bottom-left corner.",
    enter: "ENTER THE BUNKER",
    unlockTitle: "Open your bunker",
    unlockPh: "Your password",
    unlocking: "OPENING...",
    unlockBtn: "OPEN",
    wrongPw: "No bunker matches this password.",
    back: "back",
    backToStart: "back to start",
    failed: "Something went wrong: ",
    lang: "Türkçe",
  },
} as const;

export type Strings = { [K in keyof (typeof dict)["tr"]]: string };

export function strings(lang: Lang): Strings {
  return dict[lang];
}
