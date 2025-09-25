/**
 * Lighthouse CI Configuration for Performance Monitoring
 * Comprehensive performance testing and monitoring setup
 */

module.exports = {
  ci: {
    collect: {
      // URLs to test
      url: [
        'http://localhost:3000',
        'http://localhost:3000/dashboard',
        'http://localhost:3000/agents',
        'http://localhost:3000/finance/reports',
        'http://localhost:3000/workflow'
      ],
      // Performance testing settings
      numberOfRuns: 3,
      settings: {
        chromeFlags: [
          '--headless',
          '--no-sandbox',
          '--disable-gpu',
          '--disable-web-security',
          '--disable-dev-shm-usage'
        ],
        // Simulated network conditions
        throttling: {
          rttMs: 150,
          throughputKbps: 1600,
          cpuSlowdownMultiplier: 4
        },
        // Extended timeout for complex pages
        maxWaitForLoad: 45000,
        skipAudits: [
          'uses-http2',
          'canonical', 
          'structured-data'
        ],
        onlyAudits: [
          // Core Web Vitals
          'largest-contentful-paint',
          'first-input-delay',
          'cumulative-layout-shift',
          'first-contentful-paint',
          'speed-index',
          'total-blocking-time',
          
          // Resource optimization
          'unused-javascript',
          'unused-css-rules',
          'unminified-javascript',
          'unminified-css',
          'render-blocking-resources',
          'efficient-animated-content',
          
          // Image optimization
          'modern-image-formats',
          'optimized-images',
          'responsive-images',
          'properly-sized-images',
          
          // Caching and compression
          'uses-text-compression',
          'uses-long-cache-ttl',
          'uses-rel-preconnect',
          'uses-rel-preload',
          
          // Bundle optimization
          'legacy-javascript',
          'duplicated-javascript',
          'tree-shaking'
        ]
      }
    },
    
    upload: {
      target: 'temporary-public-storage'
    },
    
    assert: {
      assertions: {
        // Performance score thresholds
        'categories:performance': ['error', { minScore: 0.9 }],
        'categories:accessibility': ['warn', { minScore: 0.9 }],
        'categories:best-practices': ['warn', { minScore: 0.9 }],
        'categories:seo': ['warn', { minScore: 0.8 }],
        
        // Core Web Vitals thresholds
        'categories.performance.auditRefs[id="largest-contentful-paint"].result.numericValue': ['error', { maxNumericValue: 2500 }],
        'categories.performance.auditRefs[id="first-input-delay"].result.numericValue': ['error', { maxNumericValue: 100 }],
        'categories.performance.auditRefs[id="cumulative-layout-shift"].result.numericValue': ['error', { maxNumericValue: 0.1 }],
        'categories.performance.auditRefs[id="first-contentful-paint"].result.numericValue': ['error', { maxNumericValue: 1800 }],
        'categories.performance.auditRefs[id="speed-index"].result.numericValue': ['error', { maxNumericValue: 3400 }],
        'categories.performance.auditRefs[id="total-blocking-time"].result.numericValue': ['error', { maxNumericValue: 300 }],
        
        // Resource optimization thresholds
        'categories.performance.auditRefs[id="unused-javascript"].result.numericValue': ['warn', { maxNumericValue: 200000 }], // 200KB
        'categories.performance.auditRefs[id="unused-css-rules"].result.numericValue': ['warn', { maxNumericValue: 50000 }], // 50KB
        'categories.performance.auditRefs[id="render-blocking-resources"].result.numericValue': ['warn', { maxNumericValue: 500 }],
        
        // Bundle size warnings
        'categories.performance.auditRefs[id="legacy-javascript"].result.numericValue': ['warn', { maxNumericValue: 100000 }], // 100KB
        'categories.performance.auditRefs[id="duplicated-javascript"].result.numericValue': ['warn', { maxNumericValue: 50000 }] // 50KB
      },
      
      // Custom assertion presets for different page types
      preset: 'lighthouse:recommended',
      
      includePassedAssertions: false
    },
    
    // Server configuration for local testing
    server: {
      command: 'npm start',
      port: 3000,
      waitForServer: {
        timeout: 30000,
        interval: 1000,
        path: '/health'
      }
    }
  },
  
  // Custom performance budgets by route
  budgets: [
    {
      // Main dashboard performance budget
      path: '/dashboard',
      resourceSizes: [
        { resourceType: 'script', budget: 600 }, // 600KB JS budget
        { resourceType: 'stylesheet', budget: 100 }, // 100KB CSS budget
        { resourceType: 'image', budget: 500 }, // 500KB images budget
        { resourceType: 'font', budget: 200 }, // 200KB fonts budget
        { resourceType: 'total', budget: 1500 } // 1.5MB total budget
      ],
      resourceCounts: [
        { resourceType: 'script', budget: 10 },
        { resourceType: 'stylesheet', budget: 5 },
        { resourceType: 'font', budget: 4 }
      ],
      timings: [
        { metric: 'first-contentful-paint', budget: 1800 },
        { metric: 'largest-contentful-paint', budget: 2500 },
        { metric: 'speed-index', budget: 3000 },
        { metric: 'interactive', budget: 4000 }
      ]
    },
    
    {
      // Financial reports page budget (data-heavy)
      path: '/finance/reports',
      resourceSizes: [
        { resourceType: 'script', budget: 800 }, // Larger budget for complex reports
        { resourceType: 'stylesheet', budget: 150 },
        { resourceType: 'total', budget: 2000 }
      ],
      timings: [
        { metric: 'first-contentful-paint', budget: 2000 },
        { metric: 'largest-contentful-paint', budget: 3000 },
        { metric: 'speed-index', budget: 4000 }
      ]
    },
    
    {
      // Agent system page budget
      path: '/agents',
      resourceSizes: [
        { resourceType: 'script', budget: 700 },
        { resourceType: 'stylesheet', budget: 120 },
        { resourceType: 'total', budget: 1800 }
      ],
      timings: [
        { metric: 'first-contentful-paint', budget: 1600 },
        { metric: 'largest-contentful-paint', budget: 2200 },
        { metric: 'speed-index', budget: 3200 }
      ]
    }
  ]
};