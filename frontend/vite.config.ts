import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc' // Use SWC for production
import { TanStackRouterVite } from '@tanstack/router-vite-plugin'
import { sentryVitePlugin } from '@sentry/vite-plugin'
import path from 'path'
import fs from 'fs'

// Custom plugin to copy _headers to dist
function copyHeadersPlugin() {
  return {
    name: 'copy-headers',
    closeBundle() {
      const headersFile = path.resolve(__dirname, '_headers')
      const distHeadersFile = path.resolve(__dirname, 'dist/_headers')
      if (fs.existsSync(headersFile)) {
        fs.copyFileSync(headersFile, distHeadersFile)
        console.log('✅ Copied _headers to dist/')
      }
    }
  }
}



// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    TanStackRouterVite(),
    sentryVitePlugin({
      org: process.env.SENTRY_ORG,
      project: process.env.SENTRY_PROJECT,
      authToken: process.env.SENTRY_AUTH_TOKEN,
      telemetry: false,
      silent: true
    }),
    copyHeadersPlugin(),

  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/lib': path.resolve(__dirname, './src/lib'),
      '@/modules': path.resolve(__dirname, './src/modules'),
      '@/stores': path.resolve(__dirname, './src/stores'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/styles': path.resolve(__dirname, './src/styles'),
      '@/layouts': path.resolve(__dirname, './src/layouts'),
      '@/workers': path.resolve(__dirname, './src/workers'),
      '@design-system': path.resolve(__dirname, '../design-system'),
    },
  },
  build: {
    commonjsOptions: {
      include: [/node_modules/],
      transformMixedEsModules: true,
    },
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // CRITICAL: DO NOT separate React into its own chunk
          // This was causing async loading issues where main bundle executed before React loaded

          // Split marketing routes from authenticated app routes
          if (!id.includes('node_modules')) {
            // Marketing pages (public, unauthenticated)
            if (id.includes('/routes/landing') ||
                id.includes('/routes/pricing') ||
                id.includes('/routes/about') ||
                id.includes('/routes/contact') ||
                id.includes('/routes/help') ||
                id.includes('/components/marketing/')) {
              return 'marketing';
            }

            // Authenticated app routes
            if (id.includes('/routes/dashboard') ||
                id.includes('/routes/crm') ||
                id.includes('/routes/finance') ||
                id.includes('/routes/settings') ||
                id.includes('/routes/admin')) {
              return 'app';
            }

            // Auth pages (lightweight, frequently accessed)
            if (id.includes('/routes/auth/')) {
              return 'auth';
            }
          }

          if (id.includes('node_modules')) {
            // Let React stay in the main index chunk
            if (id.includes('react') || id.includes('react-dom')) {
              return undefined; // Stay in main bundle
            }
            // Only separate non-React vendors
            if (id.includes('@tanstack/react-router')) {
              return 'vendor-router';
            }
            if (id.includes('@tanstack/react-table')) {
              return 'vendor-table';
            }
            if (id.includes('recharts') || id.includes('d3-')) {
              return 'vendor-charts';
            }
            if (id.includes('lucide-react') || id.includes('sonner')) {
              return 'vendor-ui';
            }
            if (id.includes('react-hook-form') || id.includes('@hookform') || id.includes('zod')) {
              return 'vendor-forms';
            }
            if (id.includes('zustand') || id.includes('immer')) {
              return 'vendor-state';
            }
            if (id.includes('date-fns')) {
              return 'vendor-date';
            }
            if (id.includes('framer-motion')) {
              return 'vendor-animations';
            }
            if (id.includes('@headlessui') || id.includes('react-hot-toast') || id.includes('@heroicons')) {
              return 'vendor-landing';
            }
            // Other node_modules go into generic vendor chunk
            return 'vendor';
          }
        },
      },
    },
    sourcemap: false, // Disable source maps in production for security
    minify: 'esbuild', // Enable minification for production
    target: 'esnext',
    reportCompressedSize: false,
    chunkSizeWarningLimit: 200, // Aggressive chunk size limit for optimal loading
    cssCodeSplit: true, // Split CSS for better caching
    terserOptions: {
      compress: {
        drop_console: true, // Remove console logs in production
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.debug', 'console.info'],
        passes: 2, // Multiple passes for better compression
      },
      mangle: {
        properties: {
          regex: /^_private/,
        },
      },
    },
    assetsInlineLimit: 4096, // Inline small assets
    cssMinify: true,
  },
  optimizeDeps: {
    include: [
      'react',
      'react/jsx-runtime',
      'react-dom',
      'react-dom/client',
      '@tanstack/react-router',
      'zustand',
      'zustand/middleware',
      'zustand/middleware/immer',
      'react-hook-form',
      '@hookform/resolvers/zod',
      'zod',
      'clsx',
      'tailwind-merge',
      'lucide-react',
      'sonner',
      'recharts',
      '@tanstack/react-table',
      'date-fns',
      'framer-motion',
      '@headlessui/react',
      '@heroicons/react/24/outline',
      '@heroicons/react/24/solid'
    ],
    exclude: [
      '@sentry/react',
      'web-vitals',
      '@tanstack/router-devtools'
    ],
  },
  server: {
    port: 3000,
    hmr: {
      overlay: true,
    },
  },
})