import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/test')({
  component: TestRoute,
})

function TestRoute() {
  return (
    <div
      style={{
        padding: '40px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        maxWidth: '800px',
        margin: '0 auto'
      }}
    >
      <h1 style={{ color: '#667eea', fontSize: '36px', marginBottom: '20px' }}>
        ✅ Test Route Works!
      </h1>

      <div style={{ background: '#f0f0f0', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '10px' }}>System Status</h2>
        <ul style={{ lineHeight: '1.8' }}>
          <li>✅ React is rendering correctly</li>
          <li>✅ TanStack Router is working</li>
          <li>✅ File-based routing is functional</li>
          <li>✅ TypeScript compilation successful</li>
        </ul>
      </div>

      <div style={{ background: '#e3f2fd', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '10px' }}>Navigation Tests</h2>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <a
            href="/"
            style={{
              padding: '10px 20px',
              background: '#667eea',
              color: 'white',
              textDecoration: 'none',
              borderRadius: '4px'
            }}
          >
            Go to Home
          </a>
          <a
            href="/login"
            style={{
              padding: '10px 20px',
              background: '#764ba2',
              color: 'white',
              textDecoration: 'none',
              borderRadius: '4px'
            }}
          >
            Go to Login
          </a>
        </div>
      </div>

      <div style={{ background: '#fff3e0', padding: '20px', borderRadius: '8px' }}>
        <h2 style={{ fontSize: '20px', marginBottom: '10px' }}>Debug Information</h2>
        <pre style={{ background: 'white', padding: '15px', borderRadius: '4px', overflow: 'auto' }}>
          {JSON.stringify(
            {
              route: '/test',
              timestamp: new Date().toISOString(),
              userAgent: navigator.userAgent,
              location: window.location.href
            },
            null,
            2
          )}
        </pre>
      </div>
    </div>
  )
}
