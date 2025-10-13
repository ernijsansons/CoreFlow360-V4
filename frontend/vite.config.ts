import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
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
  // Define environment variables with fallbacks for production builds
  define: {
    'import.meta.env.VITE_API_URL': JSON.stringify(
      process.env.VITE_API_URL || 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev'
    ),
    'import.meta.env.VITE_ENVIRONMENT': JSON.stringify(
      process.env.VITE_ENVIRONMENT || process.env.NODE_ENV || 'production'
    ),
  },
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
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Enhanced chunk splitting strategy for optimal performance
          if (id.includes('node_modules')) {
            // Split React core from React DOM for better caching
            if (id.includes('react/') || id.includes('scheduler/')) {
              return 'react-core';
            }
            if (id.includes('react-dom/')) {
              return 'react-dom';
            }
            // Router split into core and devtools
            if (id.includes('@tanstack/react-router') && !id.includes('devtools')) {
              return 'router-core';
            }
            if (id.includes('@tanstack/router-devtools')) {
              return 'router-devtools';
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
            
            // Animation libraries - lazy loaded
            if (id.includes('framer-motion')) {
              return 'animations';
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
            
            // Everything else goes to vendor chunk
            return 'vendor-misc';
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
    chunkSizeWarningLimit: 200, // Aggressive chunk size limit for optimal loading
    cssCodeSplit: true, // Split CSS for better caching
    terserOptions: {
      compress: {
        drop_console: process.env.NODE_ENV === 'production',
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
      'sonner'
    ],
    exclude: [
      'recharts',
      'd3',
      'framer-motion',
      '@sentry/react',
      'web-vitals',
      '@tanstack/router-devtools'
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