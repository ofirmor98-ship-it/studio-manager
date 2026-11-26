'use strict';
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = process.env.STUDIO_DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'proposals.json');
const MANAGER_DB_FILE = path.join(DATA_DIR, 'manager-db.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const SESSION_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
let auth = { password: null, sessions: {}, icsToken: null };
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const BACKUP_KEEP = 45;
const CAL_TZ = 'Asia/Jerusalem';
const CAL_TYPE_NAMES = { wedding: 'חתונה', bar: 'בר מצווה', bat: 'בת מצווה', henna: 'חינה', brit: 'ברית / בריתה', other: 'אירוע' };
const CAL_COLORS = { wedding: '5', henna: '6', bar: '9', bat: '3', brit: '10', other: '8' };
let calendarStatus = { lastRunAt: null, ok: null, message: 'טרם בוצע סנכרון', created: 0, updated: 0, deleted: 0, skipped: 0, errors: [], needsReconnect: false };
let calendarQueue = Promise.resolve();
let calendarTimer = null;
let cachedAccessToken = null;
const loginAttempts = new Map();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = String(process.env.STUDIO_BASE_URL || '').replace(/\/$/, '');
const ADMIN_KEY = String(process.env.STUDIO_ADMIN_KEY || '');
const TOKEN_TTL_MS = 60 * 24 * 60 * 60 * 1000;
const MAX_BODY = 16 * 1024 * 1024;
let store = { proposals: {}, calendarLinks: {} };
let googleToken = null;
const oauthStates = new Map();
let writeQueue = Promise.resolve();

function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': data.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  res.end(data);
}
function html(res, status, body) {
  const data = Buffer.from(body);
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': data.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' });
  res.end(data);
}
function adminKeyMatches(candidate) {
  if (!ADMIN_KEY || !candidate) return false;
  const a = Buffer.from(candidate); const b = Buffer.from(ADMIN_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sessionFor(candidate) {
  if (!candidate || !candidate.startsWith('sess_')) return null;
  const s = auth.sessions[hashToken(candidate)];
  if (!s || Date.now() > Date.parse(s.expiresAt)) return null;
  return s;
}
function adminAuthorized(req) {
  const candidate = String(req.headers['x-admin-key'] || '').trim();
  return adminKeyMatches(candidate) || !!sessionFor(candidate);
}
async function persistAuth() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const tmp = AUTH_FILE + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(auth, null, 2), { mode: 0o600 });
  await fs.rename(tmp, AUTH_FILE);
}
async function loadAuth() {
  try {
    const parsed = JSON.parse(await fs.readFile(AUTH_FILE, 'utf8'));
    auth = { password: parsed.password || null, sessions: parsed.sessions && typeof parsed.sessions === 'object' ? parsed.sessions : {}, icsToken: typeof parsed.icsToken === 'string' ? parsed.icsToken : null };
    const now = Date.now();
    for (const [k, v] of Object.entries(auth.sessions)) if (!v || now > Date.parse(v.expiresAt)) delete auth.sessions[k];
  } catch (e) { if (e.code !== 'ENOENT') console.error('Auth file parse error:', e.message); auth = { password: null, sessions: {}, icsToken: null }; }
}
function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key)));
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt);
  return { algo: 'scrypt', salt: salt.toString('base64'), hash: key.toString('base64'), setAt: new Date().toISOString() };
}
async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const key = await scryptAsync(password, Buffer.from(record.salt, 'base64'));
  const expected = Buffer.from(record.hash, 'base64');
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
function clientIp(req) {
  return String(req.headers['cf-connecting-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket.remoteAddress || '').trim();
}
function loginRateLimited(ip) {
  const now = Date.now(), rec = loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) return false;
  return rec.count >= LOGIN_MAX_ATTEMPTS;
}
function recordFailedLogin(ip) {
  const now = Date.now(), rec = loginAttempts.get(ip);
  if (!rec || now > rec.resetAt) loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else rec.count += 1;
}
async function createSession(req, label) {
  const token = 'sess_' + crypto.randomBytes(32).toString('base64url');
  const createdAt = new Date().toISOString(), expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  auth.sessions[hashToken(token)] = { createdAt, expiresAt, label: safeString(label, 80), userAgent: safeString(req.headers['user-agent'], 200) };
  await persistAuth();
  return { token, expiresAt };
}
async function readBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > MAX_BODY) throw Object.assign(new Error('הבקשה גדולה מדי'), { status: 413 }); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw Object.assign(new Error('גוף הבקשה אינו JSON תקין'), { status: 400 }); }
}
async function persist() {
  writeQueue = writeQueue.then(async () => {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmp = DB_FILE + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
    await fs.rename(tmp, DB_FILE);
  });
  return writeQueue;
}
async function load() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try { store = JSON.parse(await fs.readFile(DB_FILE, 'utf8')); if (!store || typeof store.proposals !== 'object') throw new Error('invalid'); store.calendarLinks = store.calendarLinks && typeof store.calendarLinks === 'object' ? store.calendarLinks : {}; }
  catch (e) { if (e.code !== 'ENOENT') console.error('Database parse error:', e.message); store = { proposals: {}, calendarLinks: {} }; }
  await loadGoogleToken();
  await loadAuth();
}
function requestBase(req) {
  if (BASE_URL) return BASE_URL;
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const host = String(req.headers.host || '');
  const proto = forwarded || ((host.startsWith('localhost') || host.startsWith('127.0.0.1') || host.startsWith('[::1]')) ? 'http' : 'https');
  return `${proto}://${req.headers.host}`;
}
function googleRedirectUri(req) {
  return String(process.env.GOOGLE_REDIRECT_URI || `${requestBase(req)}/auth/google/callback`).trim();
}
function googleCredentialsReady() {
  return !!(process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET);
}
function googleTokenFile() { return path.join(DATA_DIR, 'google-calendar-token.enc'); }
function tokenEncryptionKey() {
  const raw = process.env.GOOGLE_TOKEN_ENCRYPTION_KEY || ADMIN_KEY;
  if (!raw) throw new Error('חסר מפתח הצפנה לשמירת אסימון Google');
  return crypto.createHash('sha256').update(`studio-manager-google-calendar:${raw}`).digest();
}
function encryptJson(value) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', tokenEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') });
}
function decryptJson(value) {
  const box = JSON.parse(value);
  if (box.v !== 1) throw new Error('גרסת קובץ אסימון Google אינה מוכרת');
  const decipher = crypto.createDecipheriv('aes-256-gcm', tokenEncryptionKey(), Buffer.from(box.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data, 'base64')), decipher.final()]).toString('utf8'));
}
async function saveGoogleToken() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const tmp = googleTokenFile() + '.tmp';
  await fs.writeFile(tmp, encryptJson(googleToken), { mode: 0o600 });
  await fs.rename(tmp, googleTokenFile());
}
async function loadGoogleToken() {
  try { googleToken = decryptJson(await fs.readFile(googleTokenFile(), 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') console.error('Google Calendar token could not be decrypted:', e.message); googleToken = null; }
}
async function googleAccessToken() {
  if (!googleCredentialsReady()) throw Object.assign(new Error('חסרים פרטי OAuth של Google בשרת'), { status: 503 });
  if (!googleToken?.refresh_token) throw Object.assign(new Error('יומן Google עדיין לא חובר. פתח הגדרות ולחץ על התחברות ל-Google Calendar.'), { status: 409 });
  if (googleToken.invalid) throw Object.assign(new Error('ההרשאה של Google פגה או בוטלה. יש ללחוץ שוב על "התחברות ל-Google Calendar" בהגדרות.'), { status: 409, needsReconnect: true });
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 60_000) return cachedAccessToken.token;
  const form = new URLSearchParams({ client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET, refresh_token: googleToken.refresh_token, grant_type: 'refresh_token' });
  const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    if (data.error === 'invalid_grant') {
      // Refresh token expired/revoked. Most common cause: the OAuth app is in "Testing" mode, where Google expires tokens after 7 days.
      googleToken.invalid = true; googleToken.invalidAt = new Date().toISOString(); cachedAccessToken = null;
      await saveGoogleToken().catch(() => {});
      throw Object.assign(new Error('ההרשאה של Google פגה (invalid_grant). אם אפליקציית ה-OAuth ב-Google Cloud במצב "Testing" – ההרשאה פגה כל 7 ימים. יש להעביר אותה ל-"In production" ולהתחבר מחדש.'), { status: 409, needsReconnect: true });
    }
    throw Object.assign(new Error(data.error_description || data.error || 'לא ניתן לחדש הרשאה ל-Google Calendar'), { status: 502 });
  }
  cachedAccessToken = { token: data.access_token, expiresAt: Date.now() + (Number(data.expires_in) || 3000) * 1000 };
  googleToken.lastAccessTokenAt = new Date().toISOString();
  if (data.refresh_token) { googleToken.refresh_token = data.refresh_token; await saveGoogleToken(); }
  return data.access_token;
}
async function googleCalendarRequest(method, apiPath, accessToken, body) {
  const response = await fetch(`https://www.googleapis.com/calendar/v3${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(data.error?.message || `Google Calendar API error ${response.status}`), { status: 502, httpStatus: response.status });
  return data;
}
function validTime(value) { return /^([01]\d|2[0-3]):[0-5]\d$/.test(String(value || '')); }
function shiftLocal(date, time, minutes) {
  const [y, mo, d] = date.split('-').map(Number), [h, mi] = time.split(':').map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi + minutes));
  return { date: t.toISOString().slice(0, 10), time: t.toISOString().slice(11, 16) };
}
function tzOffsetMinutes(utcMs, tz) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(new Date(utcMs)).map(p => [p.type, p.value]));
  return (Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour, +parts.minute, +parts.second) - utcMs) / 60000;
}
function zonedToUtcMs(date, time, tz = CAL_TZ) {
  const [y, mo, d] = date.split('-').map(Number), [h, mi] = time.split(':').map(Number);
  const guess = Date.UTC(y, mo - 1, d, h, mi);
  let ms = guess - tzOffsetMinutes(guess, tz) * 60000;
  const second = tzOffsetMinutes(ms, tz);
  ms = guess - second * 60000;
  return ms;
}
function eventTiming(e) {
  const date = String(e.date || '');
  if (!validIsoDate(date)) return null;
  const start = validTime(e.time) ? e.time : '';
  if (!start) return { allDay: true, startDate: date, endDate: addOneDay(date) };
  const endRaw = validTime(e.endTime) ? e.endTime : (validTime(e.contract?.endTime) ? e.contract.endTime : '');
  let end;
  if (endRaw) { end = { date: endRaw > start ? date : addOneDay(date), time: endRaw }; }
  else end = shiftLocal(date, start, 6 * 60);
  return { allDay: false, startDate: date, startTime: start, endDate: end.date, endTime: end.time, defaultEnd: !endRaw };
}
function eventDueAmount(e) {
  const paid = (Array.isArray(e.payments) ? e.payments : []).reduce((s, p) => s + (Number(p?.amount) || 0), 0);
  return Math.max(0, (Number(e.price) || 0) - (Number(e.discount) || 0) - paid);
}
function calendarEventText(e, data, base) {
  const typeName = CAL_TYPE_NAMES[e.type] || 'אירוע';
  const names = [e.clientName, e.clientSecondName].map(x => String(x || '').trim()).filter(Boolean);
  const who = names.length > 1 ? `${names[0]} ו${names[1]}` : (names[0] || 'לקוח');
  const timing = eventTiming(e);
  const due = eventDueAmount(e);
  const money = n => '₪' + Math.round(Number(n) || 0).toLocaleString('he-IL');
  const dmy = iso => /^\d{4}-\d{2}-\d{2}$/.test(String(iso || '')) ? String(iso).split('-').reverse().join('.') : String(iso || '');
  const q = e.questionnaire || {}, c = e.contract || {};
  const payments = Array.isArray(e.payments) ? e.payments.filter(p => Number(p?.amount)) : [];
  const paid = payments.reduce((sum, p) => sum + (Number(p.amount) || 0), 0);
  const net = Math.max(0, (Number(e.price) || 0) - (Number(e.discount) || 0));
  const section = (title, rows) => { const r = rows.filter(Boolean); return r.length ? [`\n━━ ${title} ━━`, ...r] : []; };
  const lines = [
    `📸 ${typeName} – ${who}`,
    ...section('👤 לקוח', [
      `שם: ${who}`,
      e.clientPhone ? `טלפון: ${e.clientPhone}` : '',
      e.clientEmail ? `דוא״ל: ${e.clientEmail}` : '',
      e.clientAddress ? `כתובת המזמין: ${e.clientAddress}` : ''
    ]),
    ...section('📅 האירוע', [
      `סוג: ${typeName}`,
      `תאריך: ${dmy(e.date)}`,
      timing && !timing.allDay ? `שעות: ${timing.startTime}–${timing.endTime}${timing.defaultEnd ? ' (שעת סיום משוערת)' : ''}` : '',
      e.venue ? `מקום: ${e.venue}` : '',
      e.venueAddress ? `כתובת / הגעה: ${e.venueAddress}` : '',
      e.deliveryDate ? `תאריך יעד למסירה: ${dmy(e.deliveryDate)}` : ''
    ]),
    ...section('📦 חבילה', [
      e.packageName ? `חבילה: ${e.packageName}` : '',
      e.packageDetails ? String(e.packageDetails).replace(/\r/g, '').trim() : ''
    ]),
    ...section('💰 כספים', [
      net ? `מחיר: ${money(net)}${Number(e.discount) ? ` (אחרי הנחה של ${money(e.discount)})` : ''}` : '',
      net || paid ? `שולם: ${money(paid)} · יתרה לתשלום: ${money(due)}` : '',
      ...payments.slice(0, 12).map(p => `• ${money(p.amount)}${p.date ? ' – ' + dmy(p.date) : ''}${p.method ? ' – ' + p.method : ''}${p.note ? ' (' + p.note + ')' : ''}`)
    ]),
    ...section('✍️ חוזה', [
      c.signed || c.status === 'signed' ? 'סטטוס: חתום ✓' : (c.sent || c.status === 'sent' ? 'סטטוס: נשלח, ממתין לחתימה' : 'סטטוס: טרם נשלח'),
      c.endTime ? `שעת סיום לפי החוזה: ${c.endTime}` : '',
      c.extraHourRate ? `שעה נוספת: ${money(c.extraHourRate)}` : ''
    ]),
    ...section('📝 שאלון הזוג', [
      q.coupleNames ? `שמות: ${q.coupleNames}` : '',
      q.dayContact ? `איש קשר ביום האירוע: ${q.dayContact}${q.dayPhone ? ' – ' + q.dayPhone : ''}` : '',
      q.prepTime ? `התארגנות / תחילת צילום: ${q.prepTime}` : '',
      q.timeline ? `לוח זמנים:\n${q.timeline}` : '',
      q.mustPhotograph ? `חובה לצלם:\n${q.mustPhotograph}` : '',
      q.styleRequests ? `בקשות וסגנון:\n${q.styleRequests}` : '',
      q.restrictions ? `מגבלות / דגשים:\n${q.restrictions}` : ''
    ]),
    ...section('🗒️ הערות', [e.notes ? String(e.notes).trim() : '', e.clientNote ? `הערות הלקוח: ${String(e.clientNote).trim()}` : '']),
    base ? `\n🔗 פתיחת כרטיס האירוע במערכת:\n${base}/?event=${encodeURIComponent(e.id)}` : '',
    `\n${safeString(data?.business?.name || 'Studio Manager', 120)}`
  ].filter(Boolean);
  let description = lines.join('\n');
  if (description.length > 7800) description = description.slice(0, 7700) + '\n…(ההמשך בכרטיס האירוע במערכת)';
  return { summary: `📸 ${typeName} – ${who}`, description, location: [e.venue, e.venueAddress].map(x => String(x || '').trim()).filter(Boolean).join(', ') };
}
function calendarReminderList(e, data) {
  const s = data?.reminderSettings || {}, r = e.reminders || {};
  const list = [];
  if (s.weekBefore !== false && r.weekBefore !== false) list.push(10080);
  if (s.dayBefore !== false && r.dayBefore !== false) list.push(1440);
  const extra = Math.round(Number(data?.cloud?.googleCalendarReminderMinutes) || 0);
  if (extra >= 5 && extra <= 40320) list.push(extra);
  return [...new Set(list)].slice(0, 5);
}
function buildGoogleEvent(e, data, base) {
  const timing = eventTiming(e);
  if (!timing) return null;
  const text = calendarEventText(e, data, base);
  const body = {
    summary: safeString(text.summary, 220), description: safeString(text.description, 8000), location: safeString(text.location, 500),
    start: timing.allDay ? { date: timing.startDate } : { dateTime: `${timing.startDate}T${timing.startTime}:00`, timeZone: CAL_TZ },
    end: timing.allDay ? { date: timing.endDate } : { dateTime: `${timing.endDate}T${timing.endTime}:00`, timeZone: CAL_TZ },
    reminders: { useDefault: false, overrides: calendarReminderList(e, data).map(minutes => ({ method: 'popup', minutes })) },
    visibility: 'default', transparency: 'opaque', colorId: CAL_COLORS[e.type] || '8', status: 'confirmed',
    extendedProperties: { private: { studioManagerEventId: safeString(e.id, 120) } }
  };
  return body;
}
function calendarLink(eventId) {
  const v = store.calendarLinks[eventId];
  if (!v) return null;
  return typeof v === 'string' ? { googleId: v } : v;
}
async function readManagerData() {
  try { return JSON.parse(await fs.readFile(MANAGER_DB_FILE, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
function scheduleCalendarSync(base, delay = 2500) {
  clearTimeout(calendarTimer);
  calendarTimer = setTimeout(() => { runCalendarSync({ base }).catch(e => console.error('Calendar sync failed:', e.message)); }, delay);
}
function runCalendarSync(options = {}) {
  const job = calendarQueue.then(() => doCalendarSync(options));
  calendarQueue = job.catch(() => {});
  return job;
}
async function doCalendarSync({ force = false, base = BASE_URL, onlyEventId = '' } = {}) {
  const started = new Date().toISOString();
  const finish = (patch) => { calendarStatus = { ...calendarStatus, lastRunAt: started, ...patch }; return calendarStatus; };
  if (!googleCredentialsReady()) return finish({ ok: false, message: 'חסרים בשרת GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET', needsReconnect: false });
  if (!googleToken?.refresh_token) return finish({ ok: false, message: 'יומן Google לא מחובר', needsReconnect: true });
  const data = await readManagerData();
  if (!data || !Array.isArray(data.events)) return finish({ ok: true, message: 'אין עדיין נתונים בשרת לסנכרון' });
  if (data.cloud?.googleCalendarSyncEnabled === false) return finish({ ok: true, message: 'הסנכרון האוטומטי כבוי בהגדרות' });
  let accessToken;
  try { accessToken = await googleAccessToken(); }
  catch (err) { return finish({ ok: false, message: err.message, needsReconnect: !!err.needsReconnect }); }
  let created = 0, updated = 0, deleted = 0, skipped = 0; const errors = []; let changedLinks = false;
  const events = data.events.filter(e => e && e.id && (!onlyEventId || e.id === onlyEventId));
  for (const e of events) {
    const body = buildGoogleEvent(e, data, base);
    const link = calendarLink(e.id);
    if (!body) {
      // Event lost its date: remove it from Google so the calendar doesn't show stale bookings.
      if (link?.googleId) {
        try { await googleCalendarRequest('DELETE', `/calendars/primary/events/${encodeURIComponent(link.googleId)}?sendUpdates=none`, accessToken); } catch (err) { if (![404, 410].includes(err.httpStatus)) { errors.push({ eventId: e.id, name: e.clientName || '', message: err.message }); continue; } }
        delete store.calendarLinks[e.id]; changedLinks = true; deleted++;
      }
      continue;
    }
    const hash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 32);
    if (!force && link?.googleId && link.hash === hash) { skipped++; continue; }
    try {
      let result = null, action = 'updated';
      if (link?.googleId) {
        try { result = await googleCalendarRequest('PATCH', `/calendars/primary/events/${encodeURIComponent(link.googleId)}?sendUpdates=none`, accessToken, body); }
        catch (err) { if (![404, 410].includes(err.httpStatus)) throw err; }
      }
      if (!result) { result = await googleCalendarRequest('POST', '/calendars/primary/events?sendUpdates=none', accessToken, body); action = 'created'; }
      store.calendarLinks[e.id] = { googleId: result.id, htmlLink: result.htmlLink || '', hash, syncedAt: new Date().toISOString() };
      changedLinks = true;
      if (action === 'created') created++; else updated++;
    } catch (err) {
      if (err.needsReconnect) return finish({ ok: false, message: err.message, needsReconnect: true });
      errors.push({ eventId: e.id, name: e.clientName || '', message: err.message });
    }
  }
  if (!onlyEventId) {
    const liveIds = new Set(data.events.map(e => e?.id).filter(Boolean));
    for (const key of Object.keys(data.deleted || {})) {
      if (!key.startsWith('events:')) continue;
      const id = key.slice(7);
      if (liveIds.has(id)) continue;
      const link = calendarLink(id);
      if (!link?.googleId) continue;
      try { await googleCalendarRequest('DELETE', `/calendars/primary/events/${encodeURIComponent(link.googleId)}?sendUpdates=none`, accessToken); }
      catch (err) { if (![404, 410].includes(err.httpStatus)) { errors.push({ eventId: id, name: '', message: err.message }); continue; } }
      delete store.calendarLinks[id]; changedLinks = true; deleted++;
    }
  }
  if (changedLinks) await persist();
  const msg = errors.length ? `${errors.length} אירועים לא סונכרנו` : 'היומן מעודכן';
  return finish({ ok: errors.length === 0, message: msg, created, updated, deleted, skipped, errors: errors.slice(0, 50), needsReconnect: false });
}
function publicCalendarStatus() {
  const links = {};
  for (const [id, v] of Object.entries(store.calendarLinks || {})) { const l = typeof v === 'string' ? { googleId: v } : v; links[id] = { syncedAt: l.syncedAt || null, htmlLink: l.htmlLink || '' }; }
  return { ...calendarStatus, links };
}
/* ---------- ICS calendar feed (subscribe from Google / Apple / Outlook without OAuth) ---------- */
function icsEscape(v) { return String(v ?? '').replace(/\\/g, '\\\\').replace(/\r?\n/g, '\\n').replace(/([;,])/g, '\\$1'); }
function icsFold(line) {
  const out = []; let cur = ''; let bytes = 0;
  for (const ch of line) {
    const b = Buffer.byteLength(ch);
    if (bytes + b > (out.length ? 74 : 75)) { out.push(cur); cur = ''; bytes = 0; }
    cur += ch; bytes += b;
  }
  out.push(cur);
  return out.join('\r\n ');
}
function icsUtc(ms) { return new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''); }
function buildIcsFeed(data, base) {
  const name = safeString(data?.business?.name || 'Studio Manager', 120);
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Studio Manager PRO//HE', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH', `X-WR-CALNAME:${icsEscape('אירועי צילום · ' + name)}`, `X-WR-TIMEZONE:${CAL_TZ}`, 'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H'];
  const stamp = icsUtc(Date.now());
  for (const e of (data?.events || [])) {
    if (!e?.id) continue;
    const timing = eventTiming(e); if (!timing) continue;
    const text = calendarEventText(e, data, base);
    lines.push('BEGIN:VEVENT', `UID:${icsEscape(e.id)}@studio-manager`, `DTSTAMP:${stamp}`);
    if (timing.allDay) lines.push(`DTSTART;VALUE=DATE:${timing.startDate.replace(/-/g, '')}`, `DTEND;VALUE=DATE:${timing.endDate.replace(/-/g, '')}`);
    else lines.push(`DTSTART:${icsUtc(zonedToUtcMs(timing.startDate, timing.startTime))}`, `DTEND:${icsUtc(zonedToUtcMs(timing.endDate, timing.endTime))}`);
    lines.push(`SUMMARY:${icsEscape(text.summary)}`, `DESCRIPTION:${icsEscape(text.description)}`);
    if (text.location) lines.push(`LOCATION:${icsEscape(text.location)}`);
    if (e.updatedAt) { const t = Date.parse(e.updatedAt); if (Number.isFinite(t)) lines.push(`LAST-MODIFIED:${icsUtc(t)}`); }
    for (const minutes of calendarReminderList(e, data)) lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${icsEscape(text.summary)}`, `TRIGGER:-PT${minutes}M`, 'END:VALARM');
    lines.push('END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return lines.map(icsFold).join('\r\n') + '\r\n';
}
async function writeDailyBackup(existingRaw) {
  try {
    await fs.mkdir(BACKUP_DIR, { recursive: true });
    const day = new Date().toISOString().slice(0, 10);
    const file = path.join(BACKUP_DIR, `manager-db-${day}.json`);
    try { await fs.access(file); return; } catch {}
    await fs.writeFile(file, existingRaw, { mode: 0o600 });
    const all = (await fs.readdir(BACKUP_DIR)).filter(f => /^manager-db-\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort();
    for (const old of all.slice(0, Math.max(0, all.length - BACKUP_KEEP))) await fs.unlink(path.join(BACKUP_DIR, old)).catch(() => {});
  } catch (e) { console.error('Daily backup failed:', e.message); }
}
function validIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ''))) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === value;
}
function addOneDay(isoDate) {
  const d = new Date(`${isoDate}T00:00:00Z`); d.setUTCDate(d.getUTCDate() + 1); return d.toISOString().slice(0, 10);
}
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function safeString(v, max = 5000) { return String(v ?? '').slice(0, max); }
function validSignature(v) { return typeof v === 'string' && v.startsWith('data:image/png;base64,') && v.length < 1_800_000 && /^[A-Za-z0-9+/=,]+$/.test(v.slice('data:image/png;base64,'.length)); }
function authFailure(res) { json(res, 401, { error: 'אין הרשאת מנהל. בדוק את מפתח המנהל בהגדרות.' }); }
function cleanSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') throw Object.assign(new Error('נתוני ההצעה חסרים'), { status: 400 });
  const event = snapshot.event || {}, business = snapshot.business || {}, contract = snapshot.contract || {};
  const packages = Array.isArray(snapshot.packages) ? snapshot.packages.slice(0, 30) : [];
  if (!safeString(event.id, 120) || !safeString(event.clientName, 120) || !safeString(event.date, 20) || !packages.length) throw Object.assign(new Error('יש להשלים שם לקוח, תאריך אירוע ולפחות חבילה אחת'), { status: 400 });
  const normalizedPackages = packages.map(p => ({
    id: safeString(p.id, 120), name: safeString(p.name, 120), badge: safeString(p.badge, 60), description: safeString(p.description, 400),
    type: safeString(p.type, 60), price: Math.max(0, Math.round(Number(p.price) || 0)), details: safeString(p.details, 12000), image: safeString(p.image, 2_500_000), isBuilder:p.isBuilder===true, imagePlacement:['top','bottom','right','left'].includes(p.imagePlacement)?p.imagePlacement:'top', imageFit:p.imageFit==='contain'?'contain':'cover', imagePosition:['center center','center top','center bottom','right center','left center'].includes(p.imagePosition)?p.imagePosition:'center center', imageHeight:Math.max(140,Math.min(420,Number(p.imageHeight)||260)), textAlign:['right','center','left'].includes(p.textAlign)?p.textAlign:'right', badgePosition:['top-right','top-left','bottom-right','bottom-left'].includes(p.badgePosition)?p.badgePosition:'top-right', cardSize:['normal','wide','full'].includes(p.cardSize)?p.cardSize:'normal'
  }));
  if (normalizedPackages.some(p => !p.id || !p.name)) throw Object.assign(new Error('חבילה לא תקינה'), { status: 400 });
  return {
    business: { name: safeString(business.name, 160), phone: safeString(business.phone, 50), email: safeString(business.email, 160), website: safeString(business.website, 220) },
    event: { id: safeString(event.id, 120), clientName: safeString(event.clientName, 120), clientSecondName: safeString(event.clientSecondName, 120), clientPhone: safeString(event.clientPhone, 40), clientEmail: safeString(event.clientEmail, 160), clientIdNumber: safeString(event.clientIdNumber, 60), clientAddress: safeString(event.clientAddress, 250), type: safeString(event.type, 60), typeLabel: safeString(event.typeLabel, 80), date: safeString(event.date, 20), venue: safeString(event.venue, 200), payments: Array.isArray(event.payments) ? event.payments.slice(0, 100).map(x => ({ amount: Math.max(0, Number(x.amount)||0), date: safeString(x.date, 20), method: safeString(x.method, 60), note: safeString(x.note, 200) })) : [] },
    contract: { terms: safeString(contract.terms, 25000), endTime: safeString(contract.endTime, 10), extraHourRate: safeString(contract.extraHourRate, 30), vatStatus: safeString(contract.vatStatus, 30), photoDeliveryDays: safeString(contract.photoDeliveryDays, 20), videoDeliveryDays: safeString(contract.videoDeliveryDays, 20), albumDeliveryDays: safeString(contract.albumDeliveryDays, 20), publicationConsent: safeString(contract.publicationConsent, 10), paymentTerms: safeString(contract.paymentTerms, 3000), cancellationTerms: safeString(contract.cancellationTerms, 4000), extraConditions: safeString(contract.extraConditions, 4000) },
    packages: normalizedPackages, builderOptions: (Array.isArray(snapshot.builderOptions)?snapshot.builderOptions.slice(0,100):[]).map(o=>({id:safeString(o.id,120),name:safeString(o.name,120),category:safeString(o.category,80),unit:safeString(o.unit,40),selectionType:o.selectionType==='yesno'?'yesno':'quantity',active:o.active!==false})).filter(o=>o.id&&o.name&&o.active), contractStyle: snapshot.contractStyle || {}
  };
}
function validateBuilderSelection(snapshot, rawItems) {
  if (!Array.isArray(rawItems) || !rawItems.length || rawItems.length > 60) throw Object.assign(new Error('יש לבחור שירותים בחבילה העצמית'), { status: 400 });
  const catalog = new Map((snapshot.builderOptions || []).filter(o => o.active !== false).map(o => [o.id, o]));
  const items = [];
  const seen = new Set();
  for (const raw of rawItems) {
    const option = catalog.get(safeString(raw.id, 120));
    const quantity = Math.floor(Number(raw.quantity));
    if (!option || !Number.isFinite(quantity) || quantity < 1 || quantity > (option.selectionType === 'yesno' ? 1 : 10) || seen.has(option.id)) throw Object.assign(new Error('אחת מבחירות החבילה אינה תקינה. רעננו את הקישור ונסו שוב.'), { status: 400 });
    seen.add(option.id);
    items.push({ id: option.id, name: option.name, category: option.category, unit: option.unit, selectionType: option.selectionType === 'yesno' ? 'yesno' : 'quantity', quantity });
  }
  return { items };
}
function publicProposal(p) {
  const mode = p.mode || 'contract';
  const event = { ...(p.snapshot.event || {}) };
  let packages = p.snapshot.packages || [];
  let contract = p.snapshot.contract || {};
  if (mode === 'quote' || mode === 'catalog') { event.clientIdNumber = ''; event.clientAddress = ''; event.payments = []; contract = {}; if (p.showPrices === false) { delete event.price; delete event.discount; packages = packages.map(({ price, ...rest }) => rest); } }
  return { id: p.id, mode, showPrices: p.showPrices !== false, demoMode: mode === 'demo', event, business: p.snapshot.business, contract, packages, builderOptions: (p.snapshot.builderOptions||[]).map(o=>({id:o.id,name:o.name,category:o.category,unit:o.unit,selectionType:o.selectionType==='yesno'?'yesno':'quantity',active:o.active!==false})), contractStyle: p.snapshot.contractStyle, status: p.status, expiresAt: p.expiresAt, quoteRequestSent: p.status === 'quote-requested', submission: p.submission || null };
}
function parsePath(pathname) { return pathname.split('/').filter(Boolean).map(decodeURIComponent); }
async function serveFile(res, file, type) {
  try { const data = await fs.readFile(file); res.writeHead(200, { 'Content-Type': type, 'Content-Length': data.length, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' }); res.end(data); }
  catch { json(res, 404, { error: 'הקובץ לא נמצא' }); }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const parts = parsePath(url.pathname);
  try {
    if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, { ok: true, service: 'Studio Manager Online', time: new Date().toISOString() });
    if (req.method === 'GET' && url.pathname === '/api/auth/status') return json(res, 200, { passwordSet: !!auth.password });
    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
      const ip = clientIp(req);
      if (loginRateLimited(ip)) return json(res, 429, { error: 'יותר מדי ניסיונות כניסה. נסו שוב בעוד רבע שעה.' });
      if (!auth.password) return json(res, 409, { error: 'עדיין לא הוגדרה סיסמת כניסה. הגדירו אותה במחשב: הגדרות וגיבוי ← כניסה עם סיסמה.' });
      const body = await readBody(req);
      const password = safeString(body.password, 200);
      if (!password || !(await verifyPassword(password, auth.password))) { recordFailedLogin(ip); return json(res, 401, { error: 'הסיסמה שגויה' }); }
      loginAttempts.delete(ip);
      const session = await createSession(req, body.deviceLabel);
      return json(res, 200, { ok: true, ...session });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/password') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      const password = String(body.password ?? '');
      if (password.length < 6 || password.length > 200) return json(res, 400, { error: 'הסיסמה חייבת להכיל לפחות 6 תווים' });
      auth.password = await hashPassword(password);
      auth.sessions = {};
      const caller = String(req.headers['x-admin-key'] || '').trim();
      let session = null;
      if (caller.startsWith('sess_')) session = await createSession(req, 'password-change');
      else await persistAuth();
      return json(res, 200, { ok: true, passwordSet: true, ...(session || {}) });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/logout') {
      const caller = String(req.headers['x-admin-key'] || '').trim();
      if (caller.startsWith('sess_') && auth.sessions[hashToken(caller)]) { delete auth.sessions[hashToken(caller)]; await persistAuth(); }
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/logout-all') {
      if (!adminAuthorized(req)) return authFailure(res);
      auth.sessions = {}; await persistAuth();
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.pathname === '/auth/google/callback') {
      const state = safeString(url.searchParams.get('state'), 200), stateRecord = oauthStates.get(state);
      oauthStates.delete(state);
      if (url.searchParams.get('error')) return html(res, 400, '<!doctype html><meta charset="utf-8"><title>חיבור בוטל</title><body dir="rtl" style="font-family:Arial;padding:40px"><h2>חיבור Google Calendar בוטל</h2><p>אפשר לחזור ל-Studio Manager ולנסות שוב.</p><a href="/">חזרה למערכת</a></body>');
      if (!stateRecord || Date.now() > stateRecord.expiresAt) return html(res, 400, '<!doctype html><meta charset="utf-8"><body dir="rtl" style="font-family:Arial;padding:40px"><h2>בקשת החיבור פגה או אינה תקפה</h2><a href="/">חזרה למערכת</a></body>');
      if (!googleCredentialsReady()) return html(res, 503, '<!doctype html><meta charset="utf-8"><body dir="rtl" style="font-family:Arial;padding:40px"><h2>חסרים פרטי Google OAuth בשרת</h2><p>יש להגדיר GOOGLE_OAUTH_CLIENT_ID ו-GOOGLE_OAUTH_CLIENT_SECRET.</p></body>');
      const code = url.searchParams.get('code');
      if (!code) return json(res, 400, { error: 'Google לא החזיר קוד הרשאה' });
      const form = new URLSearchParams({ code, client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET, redirect_uri: googleRedirectUri(req), grant_type: 'authorization_code' });
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
      const tokenData = await tokenResponse.json().catch(() => ({}));
      if (!tokenResponse.ok || (!tokenData.refresh_token && !googleToken?.refresh_token)) return html(res, 502, '<!doctype html><meta charset="utf-8"><body dir="rtl" style="font-family:Arial;padding:40px"><h2>לא התקבלה הרשאת גישה מתמשכת</h2><p>חזור להגדרות והתחבר מחדש עם אישור הרשאה.</p><a href="/">חזרה למערכת</a></body>');
      googleToken = { refresh_token: tokenData.refresh_token || googleToken.refresh_token, connectedAt: new Date().toISOString(), scope: tokenData.scope || 'https://www.googleapis.com/auth/calendar.events' };
      try {
        const userInfo = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
        if (userInfo.ok) { const profile = await userInfo.json(); googleToken.email = safeString(profile.email, 200); }
      } catch {}
      cachedAccessToken = null;
      await saveGoogleToken();
      calendarStatus = { ...calendarStatus, needsReconnect: false, message: 'החיבור הושלם – מסנכרן…' };
      runCalendarSync({ force: true, base: requestBase(req) }).catch(e => console.error('Initial calendar sync failed:', e.message));
      res.writeHead(302, { Location: `${requestBase(req)}/?google_calendar=connected`, 'Cache-Control': 'no-store' }); res.end(); return;
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/google-calendar/status') {
      if (!adminAuthorized(req)) return authFailure(res);
      return json(res, 200, { configured: googleCredentialsReady(), connected: !!googleToken?.refresh_token && !googleToken?.invalid, needsReconnect: !!googleToken?.invalid || !!calendarStatus.needsReconnect && !!googleToken?.refresh_token, email: googleToken?.email || '', connectedAt: googleToken?.connectedAt || null, timeZone: CAL_TZ, redirectUri: googleRedirectUri(req), sync: publicCalendarStatus() });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/google-calendar/sync') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      const result = await runCalendarSync({ force: body.force === true, base: requestBase(req), onlyEventId: safeString(body.eventId, 120) });
      return json(res, 200, { ...publicCalendarStatus(), ...result, links: publicCalendarStatus().links });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/calendar-feed') {
      if (!adminAuthorized(req)) return authFailure(res);
      if (!auth.icsToken) { auth.icsToken = crypto.randomBytes(24).toString('base64url'); await persistAuth(); }
      return json(res, 200, { url: `${requestBase(req)}/calendar/${auth.icsToken}.ics` });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/calendar-feed/rotate') {
      if (!adminAuthorized(req)) return authFailure(res);
      auth.icsToken = crypto.randomBytes(24).toString('base64url'); await persistAuth();
      return json(res, 200, { url: `${requestBase(req)}/calendar/${auth.icsToken}.ics` });
    }
    if (req.method === 'GET' && parts[0] === 'calendar' && parts.length === 2 && /\.ics$/.test(parts[1])) {
      const token = parts[1].slice(0, -4);
      const a = Buffer.from(token), b = Buffer.from(String(auth.icsToken || ''));
      if (!auth.icsToken || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return json(res, 404, { error: 'הקישור אינו קיים' });
      const data = await readManagerData();
      const body = Buffer.from(buildIcsFeed(data || { events: [] }, requestBase(req)));
      res.writeHead(200, { 'Content-Type': 'text/calendar; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-cache, max-age=0', 'Content-Disposition': 'inline; filename="studio-manager.ics"', 'X-Content-Type-Options': 'nosniff' });
      res.end(body); return;
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/backups') {
      if (!adminAuthorized(req)) return authFailure(res);
      let files = [];
      try { files = (await fs.readdir(BACKUP_DIR)).filter(f => /^manager-db-\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort().reverse(); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      const rows = [];
      for (const f of files) { const st = await fs.stat(path.join(BACKUP_DIR, f)).catch(() => null); rows.push({ name: f, date: f.slice(11, 21), bytes: st?.size || 0 }); }
      let revision = null; try { revision = (await readManagerData())?.meta?.serverRevision || null; } catch {}
      return json(res, 200, { backups: rows, revision });
    }
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'backups' && parts[3]) {
      if (!adminAuthorized(req)) return authFailure(res);
      if (!/^manager-db-\d{4}-\d{2}-\d{2}\.json$/.test(parts[3])) return json(res, 400, { error: 'שם גיבוי לא תקין' });
      try { return json(res, 200, { ok: true, data: JSON.parse(await fs.readFile(path.join(BACKUP_DIR, parts[3]), 'utf8')) }); }
      catch (e) { if (e.code === 'ENOENT') return json(res, 404, { error: 'הגיבוי לא נמצא' }); throw e; }
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/google-calendar/connect') {
      if (!adminAuthorized(req)) return authFailure(res);
      if (!googleCredentialsReady()) return json(res, 503, { error: 'יש להגדיר בשרת GOOGLE_OAUTH_CLIENT_ID ו-GOOGLE_OAUTH_CLIENT_SECRET לפני החיבור.' });
      const state = crypto.randomBytes(32).toString('base64url');
      oauthStates.set(state, { expiresAt: Date.now() + 10 * 60 * 1000 });
      const redirectUri = googleRedirectUri(req);
      const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      auth.search = new URLSearchParams({ client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email https://www.googleapis.com/auth/calendar.events', access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state }).toString();
      return json(res, 200, { authorizationUrl: auth.toString(), redirectUri });
    }
    if (req.method === 'DELETE' && url.pathname === '/api/admin/google-calendar') {
      if (!adminAuthorized(req)) return authFailure(res);
      googleToken = null; cachedAccessToken = null;
      calendarStatus = { ...calendarStatus, ok: null, message: 'יומן Google נותק', needsReconnect: false };
      try { await fs.unlink(googleTokenFile()); } catch {}
      return json(res, 200, { ok: true, connected: false });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/google-calendar/events') {
      // Legacy endpoint used by older app versions. The event is synced from the full server copy when it exists there.
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      const eventId = safeString(body.eventId, 120), date = safeString(body.date, 10);
      if (!eventId || !validIsoDate(date)) return json(res, 400, { error: 'חסרים מזהה אירוע או תאריך תקין' });
      const data = await readManagerData().catch(() => null);
      if (data?.events?.some(e => e?.id === eventId && e.date === date)) {
        const result = await runCalendarSync({ force: true, base: requestBase(req), onlyEventId: eventId });
        const link = calendarLink(eventId), err = (result.errors || []).find(x => x.eventId === eventId);
        if (!link || err) return json(res, result.needsReconnect ? 409 : 502, { error: err?.message || result.message || 'הסנכרון נכשל' });
        return json(res, 200, { ok: true, action: 'updated', googleEventId: link.googleId, htmlLink: link.htmlLink || '' });
      }
      const fallback = { id: eventId, date, clientName: safeString(body.summary, 220), venue: safeString(body.location, 500), notes: safeString(body.description, 3000), type: 'other' };
      const job = calendarQueue.then(async () => {
        const accessToken = await googleAccessToken();
        const eventBody = buildGoogleEvent(fallback, data || {}, requestBase(req));
        eventBody.summary = safeString(body.summary, 220) || eventBody.summary;
        eventBody.description = safeString(body.description, 4000);
        const existing = calendarLink(eventId);
        let apiResult = null;
        if (existing?.googleId) { try { apiResult = await googleCalendarRequest('PATCH', `/calendars/primary/events/${encodeURIComponent(existing.googleId)}?sendUpdates=none`, accessToken, eventBody); } catch (err) { if (![404, 410].includes(err.httpStatus)) throw err; } }
        if (!apiResult) apiResult = await googleCalendarRequest('POST', '/calendars/primary/events?sendUpdates=none', accessToken, eventBody);
        store.calendarLinks[eventId] = { googleId: apiResult.id, htmlLink: apiResult.htmlLink || '', hash: '', syncedAt: new Date().toISOString() };
        await persist();
        return apiResult;
      });
      calendarQueue = job.catch(() => {});
      const apiResult = await job;
      return json(res, 200, { ok: true, action: 'updated', googleEventId: apiResult.id, htmlLink: apiResult.htmlLink || '', summary: apiResult.summary || '' });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/manager-db') {
      if (!adminAuthorized(req)) return authFailure(res);
      try {
        const raw = await fs.readFile(MANAGER_DB_FILE, 'utf8');
        const data = JSON.parse(raw);
        return json(res, 200, { ok: true, data, revision: data?.meta?.serverRevision || null, updatedAt: data?.meta?.serverRevision || data?.meta?.lastCloudSync || data?.meta?.lastSavedAt || null });
      } catch (e) {
        if (e.code === 'ENOENT') return json(res, 200, { ok: true, data: null, updatedAt: null });
        console.error('Manager database read error:', e.message);
        return json(res, 500, { error: 'לא ניתן לקרוא את גיבוי הענן' });
      }
    }
    if (req.method === 'PUT' && url.pathname === '/api/admin/manager-db') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req), data = body.data;
      if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.events) || !Array.isArray(data.packages)) return json(res, 400, { error: 'מבנה גיבוי לא תקין' });
      let currentRevision = null, currentRaw = null, currentEvents = 0;
      try { currentRaw = await fs.readFile(MANAGER_DB_FILE, 'utf8'); const cur = JSON.parse(currentRaw); currentRevision = cur?.meta?.serverRevision || null; currentEvents = Array.isArray(cur?.events) ? cur.events.length : 0; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      // A device that does not know the current revision must merge first – never blindly overwrite the server copy.
      const baseRevision = body.baseRevision || null;
      if (currentRevision && baseRevision !== currentRevision) return json(res, 409, { error: 'הנתונים עודכנו ממכשיר אחר', revision: currentRevision });
      if (currentEvents >= 3 && data.events.length === 0 && body.allowEmpty !== true) return json(res, 409, { error: 'נחסמה שמירה של מאגר ריק במקום נתונים קיימים. רעננו את הדף.', revision: currentRevision });
      const revision = new Date().toISOString() + '-' + crypto.randomBytes(4).toString('hex');
      const safeData = { ...data, cloud: { ...(data.cloud || {}), adminKey: '' }, meta: { ...(data.meta || {}), serverRevision: revision } };
      const serialized = JSON.stringify(safeData, null, 2);
      if (Buffer.byteLength(serialized) > 15 * 1024 * 1024) return json(res, 413, { error: 'גיבוי הענן גדול מדי. הסר תמונות כבדות ונסה שוב.' });
      await fs.mkdir(DATA_DIR, { recursive: true });
      if (currentRaw) await writeDailyBackup(currentRaw);
      try {
        const existing = await fs.readFile(MANAGER_DB_FILE, 'utf8');
        const previousTmp = MANAGER_DB_FILE + '.previous.tmp';
        await fs.writeFile(previousTmp, existing, { mode: 0o600 });
        await fs.rename(previousTmp, MANAGER_DB_FILE + '.previous.json');
      } catch (e) { if (e.code !== 'ENOENT') throw e; }
      const tmp = MANAGER_DB_FILE + '.tmp';
      await fs.writeFile(tmp, serialized, { mode: 0o600 });
      await fs.rename(tmp, MANAGER_DB_FILE);
      if (googleCredentialsReady() && googleToken?.refresh_token && !googleToken.invalid) scheduleCalendarSync(requestBase(req));
      return json(res, 200, { ok: true, savedAt: new Date().toISOString(), revision, bytes: Buffer.byteLength(serialized) });
    }
    if (req.method === 'GET' && url.pathname === '/privacy') return html(res, 200, '<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>מדיניות פרטיות – Studio Manager</title><body style="font-family:Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;line-height:1.8;color:#222"><h1>מדיניות פרטיות – Studio Manager</h1><p>Studio Manager היא מערכת ניהול פנימית של העסק "צילום ברמה אחרת – אופיר מרדכי", המשמשת לניהול אירועי צילום, לקוחות, חוזים ותשלומים.</p><h3>חיבור ליומן Google</h3><p>המערכת מבקשת הרשאה ליומן Google של בעל העסק בלבד (calendar.events), כדי ליצור, לעדכן ולמחוק ביומן את אירועי הצילום שנרשמו במערכת. המערכת אינה קוראת אירועים אחרים ביומן, אינה משתפת את המידע עם צד שלישי ואינה משתמשת בו לפרסום.</p><h3>שמירת מידע</h3><p>פרטי לקוחות ואירועים נשמרים בשרת העסק לצורך ניהול ההזמנות בלבד. אסימון הגישה ל-Google נשמר בשרת בצורה מוצפנת, ואפשר לבטל אותו בכל עת מהגדרות המערכת או מהגדרות חשבון Google.</p><h3>יצירת קשר</h3><p>טלפון: 050-7464905</p></body></html>');
    if (req.method === 'GET' && url.pathname === '/') return serveFile(res, path.join(PUBLIC, 'index.html'), 'text/html; charset=utf-8');
    if (req.method === 'GET' && url.pathname === '/manager.webmanifest') return serveFile(res, path.join(PUBLIC, 'manager.webmanifest'), 'application/manifest+json; charset=utf-8');
    if (req.method === 'GET' && url.pathname === '/manager-sw.js') { const file = await fs.readFile(path.join(PUBLIC, 'manager-sw.js')); res.writeHead(200, { 'Content-Type':'application/javascript; charset=utf-8', 'Cache-Control':'no-cache', 'Service-Worker-Allowed':'/' }); res.end(file); return; }
    if (req.method === 'GET' && url.pathname === '/apple-touch-icon.png') return serveFile(res, path.join(PUBLIC, 'apple-touch-icon.png'), 'image/png');
    if (req.method === 'GET' && url.pathname === '/app-icon-maskable-512.png') return serveFile(res, path.join(PUBLIC, 'app-icon-maskable-512.png'), 'image/png');
    if (req.method === 'GET' && url.pathname === '/p/service-worker.js') { const file = await fs.readFile(path.join(PUBLIC, 'guest-sw.js')); res.writeHead(200, { 'Content-Type':'application/javascript; charset=utf-8', 'Cache-Control':'no-cache', 'Service-Worker-Allowed':'/p/' }); res.end(file); return; }
    if (req.method === 'GET' && url.pathname === '/app-icon.svg') return serveFile(res, path.join(PUBLIC, 'app-icon.svg'), 'image/svg+xml');
    if (req.method === 'GET' && url.pathname === '/app-icon-192.png') return serveFile(res, path.join(PUBLIC, 'app-icon-192.png'), 'image/png');
    if (req.method === 'GET' && url.pathname === '/app-icon-512.png') return serveFile(res, path.join(PUBLIC, 'app-icon-512.png'), 'image/png');
    if (req.method === 'GET' && url.pathname === '/app.webmanifest') { const token=safeString(url.searchParams.get('token'),200), p=store.proposals[hashToken(token)]; if(!p || p.status==='revoked' || Date.now()>Date.parse(p.expiresAt)) return json(res,404,{error:'קישור לא זמין'}); const name=safeString(p.snapshot.business?.name||'Studio Manager',60); const body=Buffer.from(JSON.stringify({name:`${name} – הצעת צילום`,short_name:'הצעת צילום',start_url:`/p/${encodeURIComponent(token)}?from=home`,scope:'/p/',display:'standalone',background_color:'#f4f1eb',theme_color:'#1d1d1c',lang:'he',dir:'rtl',icons:[{src:'/app-icon-192.png',sizes:'192x192',type:'image/png',purpose:'any maskable'},{src:'/app-icon-512.png',sizes:'512x512',type:'image/png',purpose:'any maskable'},{src:'/app-icon.svg',sizes:'any',type:'image/svg+xml'}]})); res.writeHead(200,{'Content-Type':'application/manifest+json; charset=utf-8','Content-Length':body.length,'Cache-Control':'no-store'});res.end(body);return; }
    if (req.method === 'GET' && parts[0] === 'p' && parts[1]) return serveFile(res, path.join(PUBLIC, 'guest.html'), 'text/html; charset=utf-8');
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'public' && parts[2] === 'proposals' && parts[3]) {
      const token = parts[3], p = store.proposals[hashToken(token)];
      if (!p || p.status === 'revoked' || Date.now() > Date.parse(p.expiresAt)) return json(res, 404, { error: 'הקישור אינו קיים, בוטל או שפג תוקפו' });
      return json(res, 200, publicProposal(p));
    }
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'public' && parts[2] === 'proposals' && parts[3] && parts[4] === 'sign') {
      const token = parts[3], key = hashToken(token), p = store.proposals[key];
      if (!p || p.status === 'revoked' || Date.now() > Date.parse(p.expiresAt)) return json(res, 404, { error: 'הקישור אינו קיים, בוטל או שפג תוקפו' });
      if (p.status === 'signed' || p.status === 'demo-completed') return json(res, 409, { error: 'הקישור כבר הושלם. אם נדרש ניסיון נוסף, יש ליצור קישור חדש.' });
      const body = await readBody(req);
      let selected = p.snapshot.packages.find(x => x.id === body.selectedPackageId);
      if (!selected) return json(res, 400, { error: 'יש לבחור חבילה מתוך ההצעה' });
      if (selected.isBuilder) return json(res, 409, { error: 'בחבילה אישית שולחים לצלם את בחירת השירותים. הצלם יחזור אליכם עם הצעת מחיר, ורק לאחר אישור המחיר יישלח חוזה לחתימה.' });
      if (!safeString(body.signer1Name, 120).trim() || !safeString(body.signer2Name, 120).trim()) return json(res, 400, { error: 'יש למלא את שמות שני המזמינים' });
      if (!validSignature(body.signature1) || !validSignature(body.signature2)) return json(res, 400, { error: 'נדרשות שתי חתימות תקינות' });
      if (!['yes', 'no'].includes(body.publicationConsent) || body.agreementAccepted !== true || body.clientDetailsConfirmed !== true) return json(res, 400, { error: 'יש לאשר את פרטי המזמינים, לבחור מדיניות פרסום ולאשר את תנאי ההסכם' });
      const clientPhone = safeString(body.clientPhone, 40).trim();
      const clientEmail = safeString(body.clientEmail, 160).trim();
      if (!clientPhone) return json(res, 400, { error: 'יש להזין טלפון ליצירת קשר' });
      if (clientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clientEmail)) return json(res, 400, { error: 'כתובת הדוא״ל אינה תקינה' });
      const signedAt = new Date().toISOString();
      const agreementHash = crypto.createHash('sha256').update(JSON.stringify({ snapshot: p.snapshot, selectedPackage: selected })).digest('hex');
      p.status = p.mode === 'demo' ? 'demo-completed' : 'signed';
      const questionnaireBody = body.questionnaire && typeof body.questionnaire === 'object' ? body.questionnaire : {};
      const questionnaire = { dayContact: safeString(questionnaireBody.dayContact, 120).trim(), dayPhone: safeString(questionnaireBody.dayPhone, 40).trim(), prepTime: safeString(questionnaireBody.prepTime, 10), timeline: safeString(questionnaireBody.timeline, 3000).trim(), mustPhotograph: safeString(questionnaireBody.mustPhotograph, 1000).trim(), styleRequests: safeString(questionnaireBody.styleRequests, 2000).trim(), restrictions: safeString(questionnaireBody.restrictions, 2000).trim(), completed: true };
      p.submission = { selectedPackage: selected, signer1Name: safeString(body.signer1Name, 120).trim(), signer2Name: safeString(body.signer2Name, 120).trim(), clientPhone, clientEmail, clientIdNumber: safeString(body.clientIdNumber, 60).trim(), clientAddress: safeString(body.clientAddress, 250).trim(), clientNote: safeString(body.clientNote, 1500).trim(), questionnaire, clientDetailsConfirmed: true, signature1: body.signature1, signature2: body.signature2, publicationConsent: body.publicationConsent, agreementAccepted: true, signedAt, agreementHash, userAgent: safeString(req.headers['user-agent'], 300) };
      await persist();
      return json(res, 200, { ok: true, submission: { selectedPackage: selected, signer1Name: p.submission.signer1Name, signer2Name: p.submission.signer2Name, signedAt } });
    }
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'public' && parts[2] === 'proposals' && parts[3] && parts[4] === 'quote') {
      const token = parts[3], key = hashToken(token), p = store.proposals[key];
      if (!p || p.mode !== 'quote' || p.status !== 'open' || Date.now() > Date.parse(p.expiresAt)) return json(res, 404, { error: 'הצעת המחיר אינה זמינה או שפג תוקפה' });
      const body = await readBody(req), selected = (p.snapshot.packages || []).find(x => x.id === safeString(body.selectedPackageId, 120));
      if (!selected || selected.isBuilder) return json(res, 400, { error: 'יש לבחור אחת מהחבילות המוצגות' });
      const clientName = safeString(body.clientName, 120).trim(), clientPhone = safeString(body.clientPhone, 40).trim();
      if (!clientName || !clientPhone) return json(res, 400, { error: 'יש למלא שם וטלפון ליצירת קשר' });
      const clientEmail = safeString(body.clientEmail, 160).trim();
      if (clientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clientEmail)) return json(res, 400, { error: 'כתובת הדוא״ל אינה תקינה' });
      const requestedAt = new Date().toISOString();
      p.quoteRequest = { kind:'package', packageId:selected.id, packageName:selected.name, packageDetails:selected.details, displayedPrice:p.showPrices?selected.price:null, clientName, clientPhone, clientEmail, clientNote:safeString(body.clientNote,1500).trim(), requestedAt };
      p.status = 'quote-requested'; await persist();
      return json(res, 201, { ok:true, requestedAt, selectedPackage:{id:selected.id,name:selected.name}, message:'הבחירה התקבלה ותועבר לצלם' });
    }
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'public' && parts[2] === 'proposals' && parts[3] && parts[4] === 'request') {
      const token = parts[3], key = hashToken(token), p = store.proposals[key];
      if (!p || p.status !== 'open' || new Date(p.expiresAt).getTime() < Date.now()) return json(res, 404, { error: 'ההצעה אינה זמינה או שפג תוקפה' });
      const body = await readBody(req), chosen = validateBuilderSelection(p.snapshot, body.items);
      const clientName = safeString(body.clientName, 120).trim(), clientPhone = safeString(body.clientPhone, 40).trim();
      if (!clientName || !clientPhone) return json(res, 400, { error: 'יש למלא שם וטלפון ליצירת קשר' });
      const clientEmail = safeString(body.clientEmail, 160).trim();
      if (clientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clientEmail)) return json(res, 400, { error: 'כתובת הדוא״ל אינה תקינה' });
      const requestedAt = new Date().toISOString();
      p.customRequest = { clientName, clientPhone, clientEmail, clientAddress: safeString(body.clientAddress, 250).trim(), clientNote: safeString(body.clientNote, 1500).trim(), extraRequests: safeString(body.extraRequests, 1500).trim(), items: chosen.items, details: chosen.items.map(x => x.selectionType === 'yesno' ? `${x.name} – ✓` : `${x.name} – ${x.quantity} ${x.unit}`).join('\n'), requestedAt };
      if (p.mode === 'quote') p.status = 'quote-requested';
      await persist();
      return json(res, 201, { ok: true, requestedAt, message: 'הבחירה התקבלה ותועבר לצלם להצעת מחיר' });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/catalog-links') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      const raw = body.snapshot && typeof body.snapshot === 'object' ? body.snapshot : {};
      const snapshot = cleanSnapshot({ ...raw, event: { id: 'catalog', clientName: 'catalog', date: '2000-01-01' } });
      snapshot.event = { id: 'catalog', clientName: '', clientSecondName: '', clientPhone: '', clientEmail: '', clientIdNumber: '', clientAddress: '', type: '', typeLabel: '', date: '', venue: '', payments: [] };
      snapshot.contract = {};
      const token = crypto.randomBytes(24).toString('base64url'), id = crypto.randomUUID();
      const createdAt = new Date().toISOString(), expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
      store.proposals[hashToken(token)] = { id, eventId: 'catalog', snapshot, mode: 'catalog', showPrices: body.showPrices !== false, status: 'open', createdAt, expiresAt, requests: [] };
      await persist();
      return json(res, 201, { id, token, url: `${requestBase(req)}/p/${token}`, createdAt, expiresAt });
    }
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'public' && parts[2] === 'proposals' && parts[3] && parts[4] === 'catalog-request') {
      const p = store.proposals[hashToken(parts[3])];
      if (!p || p.mode !== 'catalog' || p.status !== 'open' || Date.now() > Date.parse(p.expiresAt)) return json(res, 404, { error: 'הקישור אינו זמין או שפג תוקפו' });
      p.requests = Array.isArray(p.requests) ? p.requests : [];
      if (p.requests.length >= 1000) return json(res, 429, { error: 'לא ניתן לקבל בקשות נוספות בקישור זה. פנו לצלם.' });
      const body = await readBody(req);
      const clientName = safeString(body.clientName, 120).trim(), clientPhone = safeString(body.clientPhone, 40).trim();
      if (!clientName || !clientPhone) return json(res, 400, { error: 'יש למלא שם וטלפון ליצירת קשר' });
      const clientEmail = safeString(body.clientEmail, 160).trim();
      if (clientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clientEmail)) return json(res, 400, { error: 'כתובת הדוא״ל אינה תקינה' });
      const eventDate = safeString(body.eventDate, 10);
      if (!validIsoDate(eventDate)) return json(res, 400, { error: 'יש לבחור את תאריך האירוע' });
      const eventType = ['wedding','bar','bat','henna','brit','other'].includes(body.eventType) ? body.eventType : 'other';
      let pkg = null, items = [], details = '';
      if (Array.isArray(body.items) && body.items.length) {
        items = validateBuilderSelection(p.snapshot, body.items).items;
        details = items.map(x => x.selectionType === 'yesno' ? `${x.name} – ✓` : `${x.name} – ${x.quantity} ${x.unit}`).join('\n');
      } else {
        const selected = (p.snapshot.packages || []).find(x => x.id === safeString(body.selectedPackageId, 120));
        if (!selected || selected.isBuilder) return json(res, 400, { error: 'יש לבחור אחת מהחבילות המוצגות' });
        pkg = { id: selected.id, name: selected.name, type: selected.type || '', price: selected.price, details: selected.details };
        details = selected.details || '';
      }
      const request = { id: crypto.randomUUID(), requestedAt: new Date().toISOString(), clientName, clientPhone, clientEmail, eventDate, eventType, venue: safeString(body.venue, 200).trim(), clientNote: safeString(body.clientNote, 1500).trim(), extraRequests: safeString(body.extraRequests, 1500).trim(), package: pkg, items, details, handled: false };
      p.requests.push(request); await persist();
      return json(res, 201, { ok: true, requestedAt: request.requestedAt, message: 'הבחירה התקבלה ותועבר לצלם' });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/catalog-requests') {
      if (!adminAuthorized(req)) return authFailure(res);
      const rows = [];
      for (const p of Object.values(store.proposals)) if (p.mode === 'catalog') for (const r of (p.requests || [])) rows.push({ ...r, linkId: p.id });
      rows.sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
      return json(res, 200, { requests: rows });
    }
    if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'catalog-requests' && parts[3] && parts[4] === 'handled') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      for (const p of Object.values(store.proposals)) { if (p.mode !== 'catalog') continue; const r = (p.requests || []).find(x => x.id === parts[3]); if (r) { r.handled = body.handled !== false; r.eventId = safeString(body.eventId, 120) || r.eventId || ''; await persist(); return json(res, 200, { ok: true }); } }
      return json(res, 404, { error: 'הבקשה לא נמצאה' });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/proposals') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req), snapshot = cleanSnapshot(body.snapshot);
      if (safeString(body.eventId, 120) !== snapshot.event.id) return json(res, 400, { error: 'מזהה האירוע אינו תואם להצעה' });
      const mode = ['contract','quote','demo'].includes(body.mode) ? body.mode : 'contract';
      const token = crypto.randomBytes(32).toString('base64url'), id = crypto.randomUUID();
      for (const old of Object.values(store.proposals)) { if (old.eventId === snapshot.event.id && old.mode === mode && old.status === 'open') old.status = 'revoked'; }
      const createdAt = new Date().toISOString(), expiresAt = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
      const p = { id, eventId: snapshot.event.id, snapshot, mode, showPrices: body.showPrices !== false, status: 'open', createdAt, expiresAt, submission: null, quoteRequest: null, customRequest: null };
      store.proposals[hashToken(token)] = p; await persist();
      const base = BASE_URL || `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
      return json(res, 201, { id, token, url: `${base}/p/${token}`, createdAt, expiresAt });
    }
    if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'admin' && parts[2] === 'proposals') {
      if (!adminAuthorized(req)) return authFailure(res);
      const eventId = url.searchParams.get('eventId');
      const rows = Object.values(store.proposals).filter(p => !eventId || p.eventId === eventId).sort((a,b) => b.createdAt.localeCompare(a.createdAt));
      return json(res, 200, { proposals: rows.map(p => ({ id: p.id, eventId: p.eventId, mode:p.mode||'contract', showPrices:p.showPrices!==false, status: p.status, createdAt: p.createdAt, expiresAt: p.expiresAt, snapshot: p.snapshot, submission: p.submission, quoteRequest:p.quoteRequest||null, customRequest: p.customRequest || null })) });
    }
    if (req.method === 'GET' && parts[0] === 'assets' && parts.length === 2 && /^[\w.-]+$/.test(parts[1])) return serveFile(res, path.join(PUBLIC, 'assets', parts[1]), 'application/octet-stream');
    return json(res, 404, { error: 'הכתובת אינה קיימת' });
  } catch (err) {
    console.error(err);
    return json(res, err.status || 500, { error: err.status ? err.message : 'שגיאה פנימית בשרת. נסה שוב או פנה למנהל המערכת.' });
  }
});

load().then(() => {
  if (!ADMIN_KEY) console.warn('WARNING: STUDIO_ADMIN_KEY is not set. Admin API requests will be rejected. Set a long random secret before use.');
  console.log(`Data directory: ${DATA_DIR}${DATA_DIR.startsWith(ROOT) ? ' (inside the app folder – keep it when uploading updates, or set STUDIO_DATA_DIR to a persistent location)' : ''}`);
  console.log(`Google Calendar OAuth: ${googleCredentialsReady() ? 'configured' : 'NOT configured (GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET)'}${googleToken?.refresh_token ? ', account connected' : ''}${googleToken?.invalid ? ' – NEEDS RECONNECT' : ''}`);
  if (googleCredentialsReady() && googleToken?.refresh_token && !googleToken.invalid) setTimeout(() => runCalendarSync({}).catch(e => console.error('Startup calendar sync failed:', e.message)), 8000);
  server.listen(PORT, '0.0.0.0', () => console.log(`Studio Manager Online listening on port ${PORT}${BASE_URL ? ` (${BASE_URL})` : ''}`));
}).catch(err => { console.error(err); process.exit(1); });
