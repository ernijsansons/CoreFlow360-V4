#!/usr/bin/env node

/**
 * CoreFlow360 V4 - Simple Production Server
 * Minimal Node.js/Express server for traditional hosting environments
 * Includes graceful shutdown, health checks, and production optimizations
 */

const express = require('express');
const { createServer } = require('http');
const path = require('path');
const crypto = require('crypto');

// Polyfill for crypto.randomUUID if not available (Node.js < 14.17.0)
if (!crypto.randomUUID) {
  crypto.randomUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };
}

// Environment configuration
const NODE_ENV = process.env.NODE_ENV || 'production';
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

// Server state tracking
let isShuttingDown = false;
const startTime = Date.now();
const serverMetrics = {
  requests: 0,
  errors: 0,
  lastHealthCheck: null
};

// Create Express app
const app = express();

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request tracking middleware
app.use((req, res, next) => {
  if (isShuttingDown) {
    return res.status(503).json({
      error: 'Server is shutting down',
      timestamp: new Date().toISOString()
    });
  }

  serverMetrics.requests++;
  const requestId = crypto.randomUUID();
  req.requestId = requestId;

  // Add response headers
  res.set({
    'X-Request-ID': requestId,
    'X-Server-Start': new Date(startTime).toISOString(),
    'X-Environment': NODE_ENV
  });

  next();
});

// Security headers middleware
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
    'Strict-Transport-Security': NODE_ENV === 'production' ? 'max-age=31536000; includeSubDomains' : undefined
  });
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  const uptime = Date.now() - startTime;
  serverMetrics.lastHealthCheck = Date.now();

  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(uptime / 1000),
    environment: NODE_ENV,
    version: process.env.npm_package_version || '4.0.0',
    node_version: process.version,
    memory: {
      used: Math.round(process.memoryUsage().rss / 1024 / 1024),
      heap_used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      heap_total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
    },
    metrics: {
      requests: serverMetrics.requests,
      errors: serverMetrics.errors,
      request_rate: serverMetrics.requests / (uptime / 1000 / 60) // requests per minute
    }
  };

  res.json(health);
});

// Readiness check endpoint
app.get('/ready', (req, res) => {
  if (isShuttingDown) {
    return res.status(503).json({
      status: 'not_ready',
      reason: 'shutting_down',
      timestamp: new Date().toISOString()
    });
  }

  res.json({
    status: 'ready',
    timestamp: new Date().toISOString(),
    server: 'server-simple',
    environment: NODE_ENV
  });
});

// Status endpoint with detailed system information
app.get('/api/status', (req, res) => {
  const uptime = process.uptime();

  res.json({
    server: 'CoreFlow360 V4 Simple Server',
    status: 'operational',
    timestamp: new Date().toISOString(),
    uptime: {
      seconds: Math.floor(uptime),
      human: `${Math.floor(uptime / 86400)}d ${Math.floor((uptime % 86400) / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
    },
    system: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
      memory_usage: process.memoryUsage(),
      cpu_usage: process.cpuUsage()
    },
    environment: {
      node_env: NODE_ENV,
      port: PORT,
      host: HOST
    },
    metrics: serverMetrics
  });
});

// Static file serving for production builds
if (NODE_ENV === 'production') {
  // Serve frontend build files
  const frontendBuild = path.join(__dirname, 'frontend', 'dist');
  app.use(express.static(frontendBuild, {
    maxAge: '1d',
    etag: true,
    lastModified: true
  }));

  // Serve design system assets
  const designSystemAssets = path.join(__dirname, 'design-system', 'dist');
  app.use('/design-system', express.static(designSystemAssets, {
    maxAge: '1d',
    etag: true
  }));
}

// API proxy to Cloudflare Worker (if running in hybrid mode)
app.use('/api/v1', (req, res) => {
  // In a real deployment, this would proxy to the Cloudflare Worker
  // For now, return a helpful message
  res.json({
    message: 'API endpoints are served by Cloudflare Workers',
    worker_url: process.env.WORKER_URL || 'https://api.coreflow360.com',
    local_mode: NODE_ENV === 'development',
    note: 'In production, API requests should go directly to the worker endpoint'
  });
});

// Catch-all handler for SPA routing
app.get('*', (req, res) => {
  if (NODE_ENV === 'production') {
    const indexPath = path.join(__dirname, 'frontend', 'dist', 'index.html');
    res.sendFile(indexPath, (err) => {
      if (err) {
        res.status(404).json({
          error: 'Frontend not found',
          message: 'Please build the frontend first: cd frontend && npm run build'
        });
      }
    });
  } else {
    res.json({
      server: 'CoreFlow360 V4 Simple Server',
      environment: 'development',
      message: 'Development server running',
      available_endpoints: [
        'GET /health - Health check',
        'GET /ready - Readiness check',
        'GET /api/status - Detailed status',
        'GET /api/v1/* - API proxy (Cloudflare Workers)'
      ]
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  serverMetrics.errors++;
  console.error(`Error processing request ${req.requestId}:`, err);

  if (res.headersSent) {
    return next(err);
  }

  const error = {
    message: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    request_id: req.requestId,
    timestamp: new Date().toISOString()
  };

  if (NODE_ENV === 'development') {
    error.stack = err.stack;
    error.details = err.details;
  }

  res.status(err.status || 500).json(error);
});

// Create HTTP server
const server = createServer(app);

// Graceful shutdown handling
const gracefulShutdown = async (signal) => {
  console.log(`\n🔄 Received ${signal}. Starting graceful shutdown...`);
  isShuttingDown = true;

  // Close server and stop accepting new connections
  server.close((err) => {
    if (err) {
      console.error('❌ Error during server shutdown:', err);
      process.exit(1);
    }

    console.log('✅ Server closed successfully');

    // Cleanup tasks
    const cleanup = async () => {
      try {
        console.log('🧹 Performing cleanup tasks...');

        // Wait for pending requests to complete (max 10 seconds)
        await new Promise(resolve => setTimeout(resolve, Math.min(10000, 2000)));

        console.log('✅ Cleanup completed');
        process.exit(0);
      } catch (cleanupError) {
        console.error('❌ Error during cleanup:', cleanupError);
        process.exit(1);
      }
    };

    cleanup();
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    console.error('❌ Forced shutdown after 30 seconds');
    process.exit(1);
  }, 30000);
};

// Register signal handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  if (!isShuttingDown) {
    gracefulShutdown('uncaughtException');
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  if (!isShuttingDown) {
    gracefulShutdown('unhandledRejection');
  }
});

// Start server
server.listen(PORT, HOST, () => {
  console.log(`\n🚀 CoreFlow360 V4 Simple Server`);
  console.log(`📍 Environment: ${NODE_ENV}`);
  console.log(`🌐 Server: http://${HOST}:${PORT}`);
  console.log(`💚 Health: http://${HOST}:${PORT}/health`);
  console.log(`📊 Status: http://${HOST}:${PORT}/api/status`);
  console.log(`⚡ Ready: http://${HOST}:${PORT}/ready`);
  console.log(`\n📅 Started: ${new Date().toISOString()}`);
  console.log(`🆔 PID: ${process.pid}`);
  console.log(`📈 Node: ${process.version}`);
  console.log(`\n✅ Server is ready to accept connections`);
});

// Export for testing purposes
module.exports = { app, server };