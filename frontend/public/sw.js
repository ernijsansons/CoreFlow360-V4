// Service Worker for CoreFlow360 V4
// Implements offline-first caching strategy

const CACHE_NAME = 'coreflow360-v4-cache'
const API_CACHE_NAME = 'coreflow360-v4-api-cache'
const STATIC_CACHE_NAME = 'coreflow360-v4-static-cache'

// Cache duration constants
const STATIC_CACHE_DURATION = 7 * 24 * 60 * 60 * 1000 // 7 days
const API_CACHE_DURATION = 5 * 60 * 1000 // 5 minutes
const OFFLINE_CACHE_DURATION = 30 * 24 * 60 * 60 * 1000 // 30 days

// Static assets to cache
const STATIC_ASSETS = [
  '/',
  '/login',
  '/manifest.json',
  '/offline.html',
]

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE_NAME)
      .then((cache) => {
        return cache.addAll(STATIC_ASSETS)
      })
      .then(() => {
        return self.skipWaiting()
      })
  )
})

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (
              cacheName !== CACHE_NAME &&
              cacheName !== API_CACHE_NAME &&
              cacheName !== STATIC_CACHE_NAME
            ) {
              return caches.delete(cacheName)
            }
          })
        )
      })
      .then(() => {
        return self.clients.claim()
      })
  )
})

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return
  }

  // Handle API requests
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(handleApiRequest(request))
    return
  }

  // Handle static assets
  if (
    request.destination === 'script' ||
    request.destination === 'style' ||
    request.destination === 'image' ||
    request.destination === 'font'
  ) {
    event.respondWith(handleStaticAsset(request))
    return
  }

  // Handle navigation requests
  if (request.mode === 'navigate') {
    event.respondWith(handleNavigation(request))
    return
  }

  // Default: network first
  event.respondWith(
    fetch(request).catch(() => {
      return caches.match(request)
    })
  )
})

// Handle API requests with network-first strategy
async function handleApiRequest(request) {
  const cache = await caches.open(API_CACHE_NAME)

  try {
    // Try network first
    const networkResponse = await fetch(request)

    if (networkResponse.ok) {
      // Cache successful responses
      const responseClone = networkResponse.clone()

      // Add timestamp for cache validation
      const response = new Response(responseClone.body, {
        status: responseClone.status,
        statusText: responseClone.statusText,
        headers: {
          ...Object.fromEntries(responseClone.headers.entries()),
          'sw-cache-timestamp': Date.now().toString(),
        },
      })

      cache.put(request, response)
    }

    return networkResponse
  } catch (error) {
    // Network failed, try cache
    const cachedResponse = await cache.match(request)

    if (cachedResponse) {
      const cacheTimestamp = cachedResponse.headers.get('sw-cache-timestamp')
      const isExpired = cacheTimestamp &&
        (Date.now() - parseInt(cacheTimestamp)) > API_CACHE_DURATION

      if (!isExpired) {
        return cachedResponse
      }
    }

    // If no cache or expired, return offline response
    return new Response(
      JSON.stringify({
        error: 'Offline',
        message: 'This request requires an internet connection',
        offline: true,
      }),
      {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }
}

// Handle static assets with cache-first strategy
async function handleStaticAsset(request) {
  const cache = await caches.open(STATIC_CACHE_NAME)
  const cachedResponse = await cache.match(request)

  if (cachedResponse) {
    // Return cached version and update in background
    fetchAndCache(request, cache)
    return cachedResponse
  }

  try {
    const networkResponse = await fetch(request)

    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone())
    }

    return networkResponse
  } catch (error) {
    // Return offline fallback for images
    if (request.destination === 'image') {
      return new Response(
        '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" fill="#f3f4f6"/><text x="50%" y="50%" text-anchor="middle" dy="0.3em" fill="#6b7280">Image unavailable</text></svg>',
        { headers: { 'Content-Type': 'image/svg+xml' } }
      )
    }

    throw error
  }
}

// Handle navigation requests
async function handleNavigation(request) {
  try {
    const networkResponse = await fetch(request)

    if (networkResponse.ok) {
      const cache = await caches.open(CACHE_NAME)
      cache.put(request, networkResponse.clone())
    }

    return networkResponse
  } catch (error) {
    // Try to return cached version
    const cache = await caches.open(CACHE_NAME)
    const cachedResponse = await cache.match(request)

    if (cachedResponse) {
      return cachedResponse
    }

    // Return offline page
    const offlineResponse = await cache.match('/offline.html')
    if (offlineResponse) {
      return offlineResponse
    }

    // Fallback offline page
    return new Response(
      `
      <!DOCTYPE html>
      <html>
        <head>
          <title>CoreFlow360 - Offline</title>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            body {
              font-family: system-ui, sans-serif;
              text-align: center;
              padding: 2rem;
              color: #374151;
            }
            .container {
              max-width: 400px;
              margin: 0 auto;
              padding: 2rem;
            }
            .icon {
              font-size: 4rem;
              margin-bottom: 1rem;
            }
            h1 {
              color: #1f2937;
              margin-bottom: 1rem;
            }
            p {
              margin-bottom: 1rem;
              line-height: 1.6;
            }
            button {
              background: #3b82f6;
              color: white;
              border: none;
              padding: 0.75rem 1.5rem;
              border-radius: 0.5rem;
              cursor: pointer;
              font-size: 1rem;
            }
            button:hover {
              background: #2563eb;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon">📱</div>
            <h1>You're Offline</h1>
            <p>CoreFlow360 is not available right now. Check your internet connection and try again.</p>
            <p>Your data is safe and will sync when you're back online.</p>
            <button onclick="window.location.reload()">Try Again</button>
          </div>
        </body>
      </html>
      `,
      {
        headers: { 'Content-Type': 'text/html' },
      }
    )
  }
}

// Background fetch and cache update
async function fetchAndCache(request, cache) {
  try {
    const response = await fetch(request)
    if (response.ok) {
      cache.put(request, response)
    }
  } catch (error) {
    // Ignore background update errors
  }
}

// Background sync for failed requests
self.addEventListener('sync', (event) => {
  if (event.tag === 'background-sync') {
    event.waitUntil(handleBackgroundSync())
  }
})

async function handleBackgroundSync() {
  // This would integrate with the sync store to retry failed requests
  console.log('Background sync triggered')

  // Notify clients that sync is happening
  const clients = await self.clients.matchAll()
  clients.forEach(client => {
    client.postMessage({
      type: 'BACKGROUND_SYNC',
      data: { status: 'processing' }
    })
  })
}

// Push notification handling
self.addEventListener('push', (event) => {
  if (!event.data) return

  const data = event.data.json()

  const options = {
    body: data.message,
    icon: '/icon-192x192.png',
    badge: '/badge-72x72.png',
    data: data.data,
    actions: data.actions || [],
    tag: data.tag || 'default',
    renotify: true,
  }

  event.waitUntil(
    self.registration.showNotification(data.title || 'CoreFlow360', options)
  )
})

// Notification click handling
self.addEventListener('notificationclick', (event) => {
  event.notification.close()

  const data = event.notification.data
  let url = '/'

  if (data && data.url) {
    url = data.url
  }

  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clients) => {
      // Check if there's already a window/tab open with the target URL
      for (const client of clients) {
        if (client.url === url && 'focus' in client) {
          return client.focus()
        }
      }

      // If not, open a new window/tab
      if (self.clients.openWindow) {
        return self.clients.openWindow(url)
      }
    })
  )
})

// Message handling from main thread
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting()
  }
})