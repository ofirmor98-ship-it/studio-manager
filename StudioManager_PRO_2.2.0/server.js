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
function adminAuthorized(req) {
  if (!ADMIN_KEY) return false;
  const candidate = String(req.headers['x-admin-key'] || '').trim();
  const a = Buffer.from(candidate); const b = Buffer.from(ADMIN_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
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
  const form = new URLSearchParams({ client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET, refresh_token: googleToken.refresh_token, grant_type: 'refresh_token' });
  const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw Object.assign(new Error(data.error_description || data.error || 'לא ניתן לחדש הרשאה ל-Google Calendar'), { status: 502 });
  googleToken.lastAccessTokenAt = new Date().toISOString();
  if (data.refresh_token) googleToken.refresh_token = data.refresh_token;
  await saveGoogleToken();
  return data.access_token;
}
async function googleCalendarRequest(method, apiPath, accessToken, body) {
  const response = await fetch(`https://www.googleapis.com/calendar/v3${apiPath}`, {
    method,
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(data.error?.message || `Google Calendar API error ${response.status}`), { status: 502 });
  return data;
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
    packages: normalizedPackages, builderOptions: (Array.isArray(snapshot.builderOptions)?snapshot.builderOptions.slice(0,100):[]).map(o=>({id:safeString(o.id,120),name:safeString(o.name,120),category:safeString(o.category,80),unit:safeString(o.unit,40),active:o.active!==false})).filter(o=>o.id&&o.name&&o.active), contractStyle: snapshot.contractStyle || {}
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
    if (!option || !Number.isFinite(quantity) || quantity < 1 || quantity > 10 || seen.has(option.id)) throw Object.assign(new Error('אחת מבחירות החבילה אינה תקינה. רעננו את הקישור ונסו שוב.'), { status: 400 });
    seen.add(option.id);
    items.push({ id: option.id, name: option.name, category: option.category, unit: option.unit, quantity });
  }
  return { items };
}
function publicProposal(p) {
  const mode = p.mode || 'contract';
  const event = { ...(p.snapshot.event || {}) };
  let packages = p.snapshot.packages || [];
  let contract = p.snapshot.contract || {};
  if (mode === 'quote') { event.clientIdNumber = ''; event.clientAddress = ''; event.payments = []; contract = {}; if (p.showPrices === false) { delete event.price; delete event.discount; packages = packages.map(({ price, ...rest }) => rest); } }
  return { id: p.id, mode, showPrices: p.showPrices !== false, demoMode: mode === 'demo', event, business: p.snapshot.business, contract, packages, builderOptions: (p.snapshot.builderOptions||[]).map(o=>({id:o.id,name:o.name,category:o.category,unit:o.unit,active:o.active!==false})), contractStyle: p.snapshot.contractStyle, status: p.status, expiresAt: p.expiresAt, quoteRequestSent: p.status === 'quote-requested', submission: p.submission || null };
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
      await saveGoogleToken();
      res.writeHead(302, { Location: `${requestBase(req)}/?google_calendar=connected`, 'Cache-Control': 'no-store' }); res.end(); return;
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/google-calendar/status') {
      if (!adminAuthorized(req)) return authFailure(res);
      return json(res, 200, { configured: googleCredentialsReady(), connected: !!googleToken?.refresh_token, email: googleToken?.email || '', connectedAt: googleToken?.connectedAt || null, timeZone: 'Asia/Jerusalem' });
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
      googleToken = null;
      try { await fs.unlink(googleTokenFile()); } catch {}
      return json(res, 200, { ok: true, connected: false });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/google-calendar/events') {
      if (!adminAuthorized(req)) return authFailure(res);
      const body = await readBody(req);
      const eventId = safeString(body.eventId, 120), date = safeString(body.date, 10);
      if (!eventId || !validIsoDate(date)) return json(res, 400, { error: 'חסרים מזהה אירוע או תאריך תקין' });
      const reminderMinutes = Math.min(10080, Math.max(5, Math.round(Number(body.reminderMinutes) || 1440)));
      const reminderList = Array.isArray(body.reminderMinutesList) ? [...new Set(body.reminderMinutesList.map(x => Math.min(10080, Math.max(5, Math.round(Number(x) || 0)))).filter(x => x >= 5))].slice(0, 5) : [reminderMinutes];
      const eventBody = {
        summary: safeString(body.summary, 220) || 'אירוע צילום',
        location: safeString(body.location, 500),
        description: safeString(body.description, 4000),
        start: { date }, end: { date: addOneDay(date) },
        reminders: { useDefault: false, overrides: reminderList.map(minutes => ({ method: 'popup', minutes })) },
        visibility: 'private', colorId: '5'
      };
      const accessToken = await googleAccessToken();
      const existingId = safeString(body.googleEventId || store.calendarLinks[eventId] || '', 200);
      const apiResult = existingId
        ? await googleCalendarRequest('PATCH', `/calendars/primary/events/${encodeURIComponent(existingId)}?sendUpdates=none`, accessToken, eventBody)
        : await googleCalendarRequest('POST', '/calendars/primary/events?sendUpdates=none', accessToken, eventBody);
      store.calendarLinks[eventId] = apiResult.id;
      await persist();
      return json(res, 200, { ok: true, action: existingId ? 'updated' : 'created', googleEventId: apiResult.id, htmlLink: apiResult.htmlLink || '', summary: apiResult.summary || eventBody.summary });
    }
    if (req.method === 'GET' && url.pathname === '/api/admin/manager-db') {
      if (!adminAuthorized(req)) return authFailure(res);
      try {
        const raw = await fs.readFile(MANAGER_DB_FILE, 'utf8');
        const data = JSON.parse(raw);
        return json(res, 200, { ok: true, data, updatedAt: data?.meta?.lastCloudSync || data?.meta?.lastSavedAt || null });
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
      const safeData = { ...data, cloud: { ...(data.cloud || {}), adminKey: '' } };
      const serialized = JSON.stringify(safeData, null, 2);
      if (Buffer.byteLength(serialized) > 15 * 1024 * 1024) return json(res, 413, { error: 'גיבוי הענן גדול מדי. הסר תמונות כבדות ונסה שוב.' });
      await fs.mkdir(DATA_DIR, { recursive: true });
      try {
        const existing = await fs.readFile(MANAGER_DB_FILE, 'utf8');
        const previousTmp = MANAGER_DB_FILE + '.previous.tmp';
        await fs.writeFile(previousTmp, existing, { mode: 0o600 });
        await fs.rename(previousTmp, MANAGER_DB_FILE + '.previous.json');
      } catch (e) { if (e.code !== 'ENOENT') throw e; }
      const tmp = MANAGER_DB_FILE + '.tmp';
      await fs.writeFile(tmp, serialized, { mode: 0o600 });
      await fs.rename(tmp, MANAGER_DB_FILE);
      return json(res, 200, { ok: true, savedAt: new Date().toISOString(), bytes: Buffer.byteLength(serialized) });
    }
    if (req.method === 'GET' && url.pathname === '/') return serveFile(res, path.join(PUBLIC, 'index.html'), 'text/html; charset=utf-8');
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
      p.customRequest = { clientName, clientPhone, clientEmail, clientAddress: safeString(body.clientAddress, 250).trim(), clientNote: safeString(body.clientNote, 1500).trim(), extraRequests: safeString(body.extraRequests, 1500).trim(), items: chosen.items, details: chosen.items.map(x => `${x.name} – ${x.quantity} ${x.unit}`).join('\n'), requestedAt };
      if (p.mode === 'quote') p.status = 'quote-requested';
      await persist();
      return json(res, 201, { ok: true, requestedAt, message: 'הבחירה התקבלה ותועבר לצלם להצעת מחיר' });
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
  server.listen(PORT, '0.0.0.0', () => console.log(`Studio Manager Online listening on port ${PORT}${BASE_URL ? ` (${BASE_URL})` : ''}`));
}).catch(err => { console.error(err); process.exit(1); });
