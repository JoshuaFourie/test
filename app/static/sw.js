const CACHE = 'xg-v1';
const PRECACHE = [
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Never intercept dynamic endpoints
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/toggle/') ||
    url.pathname === '/health' ||
    url.pathname === '/sw.js'
  ) return;

  // Cache-first for CDN assets (Bootstrap, icons)
  if (url.origin !== self.location.origin) {
    e.respondWith(
      caches.match(e.request).then(cached =>
        cached || fetch(e.request).then(resp => {
          caches.open(CACHE).then(c => c.put(e.request, resp.clone()));
          return resp;
        })
      )
    );
    return;
  }

  // Network-first for app pages; fall back to cache if offline
  e.respondWith(
    fetch(e.request)
      .then(resp => {
        caches.open(CACHE).then(c => c.put(e.request, resp.clone()));
        return resp;
      })
      .catch(() => caches.match(e.request))
  );
});
