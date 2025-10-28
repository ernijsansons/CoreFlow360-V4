import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { TanStackRouterVite } from '@tanstack/router-vite-plugin'
import { sentryVitePlugin } from '@sentry/vite-plugin'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    // TanStackRouterVite(), // DISABLED - using manual routing instead
    react(),
    sentryVitePlugin({
      org: process.env.SENTRY_ORG,
      project: process.env.SENTRY_PROJECT,
      authToken: process.env.SENTRY_AUTH_TOKEN,
      telemetry: false,
      silent: true
    }),
  ],
  cacheDir: 'node_modules/.vite', // Persistent cache for faster rebuilds
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
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Enhanced chunk splitting strategy for optimal performance
          if (id.includes('node_modules')) {
            // DO NOT split React, React Router, or Framer Motion - keep in main bundle
            // These libraries use React hooks at module level and must load with React
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router') || id.includes('framer-motion')) {
              return undefined; // Include in main bundle
            }
            
            // UI frameworks - medium priority, can be cached aggressively
            if (id.includes('@radix-ui') || id.includes('class-variance-authority') || 
                id.includes('clsx') || id.includes('tailwind-merge')) {
              return 'ui-framework';
            }
            
            // State management - high priority for app functionality
            if (id.includes('zustand') || id.includes('immer')) {
              return 'state-management';
            }
            
            // Forms - medium priority, used frequently
            if (id.includes('react-hook-form') || id.includes('@hookform') || 
                id.includes('zod')) {
              return 'forms-validation';
            }
            
            // Charts and visualization - lazy loaded, lowest priority
            if (id.includes('recharts') || id.includes('d3')) {
              return 'data-visualization';
            }
            // Date utilities - medium priority
            if (id.includes('date-fns') || id.includes('react-day-picker')) {
              return 'date-utilities';
            }
            
            // Icons - can be cached aggressively
            if (id.includes('lucide-react')) {
              return 'icon-library';
            }
            
            // Other utilities - small utilities grouped together
            if (id.includes('sonner') || id.includes('vaul') || 
                id.includes('next-themes') || id.includes('idb')) {
              return 'utilities';
            }
            
            // Monitoring and analytics - separate chunk for optional features
            if (id.includes('@sentry') || id.includes('web-vitals')) {
              return 'monitoring';
            }

            // Command palette - lazy loaded feature
            if (id.includes('cmdk')) {
              return 'command-palette';
            }

            // PWA / Service Worker - loaded on demand
            if (id.includes('workbox')) {
              return 'pwa-utilities';
            }

            // Dev tools - only in development, tree-shaken in production
            if (id.includes('router-devtools') || id.includes('devtools')) {
              return 'dev-tools';
            }

            // Everything else goes to main bundle to avoid module initialization timing issues
            // This prevents libraries using React hooks from loading before React
            return undefined;
          }
          
          // App code chunking based on feature areas
          if (id.includes('/components/agents/')) {
            return 'feature-agents';
          }
          if (id.includes('/components/chat/')) {
            return 'feature-chat';
          }
          if (id.includes('/components/dashboard/')) {
            return 'feature-dashboard';
          }
          if (id.includes('/components/business/') || id.includes('/components/finance/')) {
            return 'feature-business';
          }
          if (id.includes('/components/workflow/')) {
            return 'feature-workflow';
          }
        },
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId ? chunkInfo.facadeModuleId.split('/').pop() : 'chunk';
          return `assets/[name]-[hash]-${facadeModuleId}.js`;
        },
      },
    },
    sourcemap: process.env.NODE_ENV === 'development',
    minify: 'terser',
    target: 'esnext',
    reportCompressedSize: false,
    chunkSizeWarningLimit: 200, // Optimized chunk size for better caching and HTTP/2
    cssCodeSplit: true, // Split CSS for better caching
    terserOptions: {
      compress: {
        drop_console: process.env.NODE_ENV === 'production',
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.debug', 'console.info'],
        passes: 2, // Multiple passes for better compression
      },
      mangle: false, // Disable mangling to fix TanStack Router production build issue
      format: {
        comments: false, // Remove all comments for smaller bundles
      },
    },
    assetsInlineLimit: 4096, // Inline small assets
    cssMinify: true,
  },
  optimizeDeps: {
    include: [
      'react', 
      'react-dom', 
      '@tanstack/react-router', 
      'zustand',
      'react-hook-form',
      '@hookform/resolvers',
      'zod',
      'clsx',
      'tailwind-merge',
      'lucide-react'
    ],
    exclude: [
      'recharts',
      'd3',
      '@sentry/react',
      'web-vitals'
    ],
    force: true, // Force pre-bundling for better performance
  },
  server: {
    port: 3000,
    hmr: {
      overlay: true,
    },
  },
})