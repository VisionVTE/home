// studio-auth.js
// Simple client-side protection for a local "devs only" area.
// WARNING: This is NOT secure for production. It's a basic convenience gate for local/dev use.
// To set your password: compute the SHA-256 hex of your password and replace STORED_HASH below.

const STORED_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // empty string hash placeholder
const STORAGE_KEY = 'studioAuthToken';
const TOKEN_VALUE = 'authenticated';

function buf2hex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return buf2hex(hash);
}

async function login(password) {
  const hash = await sha256hex(password || '');
  if (hash === STORED_HASH) {
    localStorage.setItem(STORAGE_KEY, TOKEN_VALUE);
    return true;
  }
  return false;
}

function logout() {
  localStorage.removeItem(STORAGE_KEY);
  if (location.pathname.endsWith('studio-dashboard.html')) {
    location.href = 'studio-login.html';
  }
}

function isAuthenticated() {
  return localStorage.getItem(STORAGE_KEY) === TOKEN_VALUE;
}

function protect() {
  if (!isAuthenticated()) {
    location.href = 'studio-login.html';
  }
}

window.studioAuth = { login, logout, isAuthenticated, protect, sha256hex };

// --- 2FA (TOTP) helpers ---
// Stored in localStorage under keys below. CLIENT-SIDE ONLY — not secure for production.
const KEY_2FA_SECRET = 'studio_2fa_secret';
const KEY_2FA_ENABLED = 'studio_2fa_enabled';
const KEY_2FA_PROMPT_SHOWN = 'studio_2fa_prompt_shown'; // ISO date string of last prompt shown

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  while (output.length % 8 !== 0) output += '=';
  return output;
}

function base32ToBytes(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = base32.replace(/=+$/,'').toUpperCase();
  let bits = 0, value = 0, index = 0;
  const bytes = [];
  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xFF);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

function randomBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

function generateSecretBase32() {
  const bytes = randomBytes(20); // 160-bit secret
  return base32Encode(bytes).replace(/=+$/,'');
}

async function computeTOTPWithSecret(secretBase32, forTime = Date.now()) {
  const keyBytes = base32ToBytes(secretBase32);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const timestep = 30;
  const counter = Math.floor(forTime / 1000 / timestep);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // big-endian counter
  view.setUint32(4, counter >>> 0);
  // left 32 bits zero (for counters < 2^32)
  const hmac = await crypto.subtle.sign('HMAC', key, buf);
  const h = new Uint8Array(hmac);
  const offset = h[h.length - 1] & 0xf;
  const code = ((h[offset] & 0x7f) << 24) | ((h[offset+1] & 0xff) << 16) | ((h[offset+2] & 0xff) << 8) | (h[offset+3] & 0xff);
  const totp = (code % 1000000).toString().padStart(6, '0');
  return totp;
}

async function verifyTOTP(secretBase32, code) {
  // allow -1, 0, +1 windows
  const now = Date.now();
  for (let i = -1; i <= 1; i++) {
    const t = now + i * 30000;
    const c = await computeTOTPWithSecret(secretBase32, t);
    if (c === String(code).padStart(6,'0')) return true;
  }
  return false;
}

function is2FAEnabled() {
  return localStorage.getItem(KEY_2FA_ENABLED) === '1';
}

function get2FASecret() {
  return localStorage.getItem(KEY_2FA_SECRET) || null;
}

function enable2FA(secretBase32) {
  localStorage.setItem(KEY_2FA_SECRET, secretBase32);
  localStorage.setItem(KEY_2FA_ENABLED, '1');
}

function disable2FA() {
  localStorage.removeItem(KEY_2FA_SECRET);
  localStorage.removeItem(KEY_2FA_ENABLED);
}

function mark2FAPromptShownToday() {
  const today = new Date().toISOString().slice(0,10);
  localStorage.setItem(KEY_2FA_PROMPT_SHOWN, today);
}

function shouldShow2FAPrompt() {
  if (is2FAEnabled()) return false;
  const last = localStorage.getItem(KEY_2FA_PROMPT_SHOWN);
  const today = new Date().toISOString().slice(0,10);
  return last !== today;
}

window.studioAuth = Object.assign(window.studioAuth, {
  // 2FA API
  generateSecretBase32,
  verifyTOTP,
  enable2FA,
  disable2FA,
  is2FAEnabled,
  get2FASecret,
  mark2FAPromptShownToday,
  shouldShow2FAPrompt
});

// --- Backup codes and encryption helpers ---
const KEY_BACKUPS = 'studio_2fa_backups';

function randomAlphaNum(len){
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567890abcdefghijklmnopqrstuvwxyz';
  let out = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for(let i=0;i<len;i++) out += chars[arr[i] % chars.length];
  return out;
}

function generateBackupCodes(count=10){
  const codes = [];
  for(let i=0;i<count;i++) codes.push(randomAlphaNum(10));
  // store plain backup codes in localStorage for convenience (encrypted file recommended)
  localStorage.setItem(KEY_BACKUPS, JSON.stringify(codes));
  return codes;
}

async function deriveKeyFromPassword(password, salt){
  const enc = new TextEncoder();
  const pw = enc.encode(password);
  const baseKey = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

async function encryptTextWithPassword(password, plain){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password, salt);
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(plain));
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  combined.set(salt,0); combined.set(iv,salt.byteLength); combined.set(new Uint8Array(ct), salt.byteLength+iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

async function decryptTextWithPassword(password, dataB64){
  const raw = atob(dataB64);
  const arr = Uint8Array.from(raw.split('').map(c=>c.charCodeAt(0)));
  const salt = arr.slice(0,16);
  const iv = arr.slice(16,28);
  const ct = arr.slice(28);
  const key = await deriveKeyFromPassword(password, salt);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  return new TextDecoder().decode(pt);
}

function downloadEncryptedBackupFile(password, codes){
  return encryptTextWithPassword(password, JSON.stringify(codes)).then(b64=>{
    const blob = new Blob([b64], {type:'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'studio-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

window.studioAuth = Object.assign(window.studioAuth, {
  generateBackupCodes,
  encryptTextWithPassword,
  decryptTextWithPassword,
  downloadEncryptedBackupFile
});
