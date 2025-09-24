import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { TanStackRouterVite } from '@tanstack/router-vite-plugin'
import { sentryVitePlugin } from '@sentry/vite-plugin'
import path from 'path'

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
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Enhanced chunk splitting strategy for optimal performance
          if (id.includes('node_modules')) {
            // Core React and routing - highest priority
            if (id.includes('react') || id.includes('react-dom')) {
              return 'react-vendor';
            }
            if (id.includes('@tanstack/react-router')) {
              return 'router';
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
    chunkSizeWarningLimit: 500, // Smaller chunks for better caching
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
      'framer-motion',
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