'use strict';
self.addEventListener('install', event => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
// The personal offer and all customer data are served from the network; do not cache sensitive responses.
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method === 'GET' && url.origin === self.location.origin) {
    event.respondWith(fetch(event.request));
  }
});
