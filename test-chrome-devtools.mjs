#!/usr/bin/env node

import { chromium } from 'playwright';

async function testChromeDevTools() {
  console.log('🚀 Starting Chrome DevTools MCP test...');
  
  // Launch Chrome with DevTools enabled
  const browser = await chromium.launch({
    headless: false, // Set to true for headless mode
    devtools: true,  // Enable DevTools
    args: [
      '--remote-debugging-port=9222', // Enable remote debugging
      '--disable-web-security',
      '--disable-features=VizDisplayCompositor'
    ]
  });

  try {
    // Create a new page
    const page = await browser.newPage();
    
    // Navigate to your CoreFlow360 application
    console.log('📱 Navigating to CoreFlow360...');
    await page.goto('https://8eb14753.coreflow360-frontend.pages.dev/', { waitUntil: 'networkidle' });
    
    // Wait a moment for the page to load
    await page.waitForTimeout(2000);
    
    // Get page title
    const title = await page.title();
    console.log(`📄 Page title: ${title}`);
    
    // Take a screenshot
    await page.screenshot({ path: 'chrome-devtools-test.png' });
    console.log('📸 Screenshot saved as chrome-devtools-test.png');
    
    // Get console logs
    page.on('console', msg => {
      console.log(`🖥️  Console ${msg.type()}: ${msg.text()}`);
    });
    
    // Get network requests
    page.on('request', request => {
      console.log(`🌐 Request: ${request.method()} ${request.url()}`);
    });
    
    // Get page metrics
    const metrics = await page.evaluate(() => {
      return {
        url: window.location.href,
        userAgent: navigator.userAgent,
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight
        },
        performance: performance.timing ? {
          loadTime: performance.timing.loadEventEnd - performance.timing.navigationStart,
          domContentLoaded: performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart
        } : null
      };
    });
    
    console.log('📊 Page metrics:', JSON.stringify(metrics, null, 2));
    
    // Keep browser open for DevTools inspection
    console.log('🔧 Chrome DevTools should now be accessible at:');
    console.log('   - Local DevTools: http://localhost:9222');
    console.log('   - Or use the DevTools panel in the opened browser window');
    console.log('   - Press Ctrl+C to close the browser');
    
    // Wait for user to close manually or timeout after 5 minutes
    await page.waitForTimeout(300000); // 5 minutes
    
  } catch (error) {
    console.error('❌ Error during Chrome DevTools test:', error);
  } finally {
    await browser.close();
    console.log('✅ Chrome DevTools test completed');
  }
}

// Run the test
testChromeDevTools().catch(console.error);
