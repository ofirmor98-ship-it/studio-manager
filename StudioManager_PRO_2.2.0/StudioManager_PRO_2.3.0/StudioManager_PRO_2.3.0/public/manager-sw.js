// Studio Manager – service worker for the management app.
// It only makes the app installable; it never caches data, so what you see is always current.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/p/') || url.pathname.startsWith('/api/')) return;
  if (event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).catch(() => new Response(
      '<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>אין חיבור</title><body style="font-family:Arial;background:#111318;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:24px"><div><h2>אין חיבור לאינטרנט</h2><p>בדקו את החיבור ונסו שוב.</p><button onclick="location.reload()" style="padding:12px 22px;border-radius:10px;border:0;background:#c6a45b;font-weight:bold">נסו שוב</button></div></body></html>',
      { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
  }
});
