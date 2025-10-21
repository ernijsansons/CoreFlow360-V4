#!/usr/bin/env node

import { chromium } from 'playwright';

async function advancedChromeDevTools() {
  console.log('🚀 Starting Advanced Chrome DevTools Protocol test...');
  
  const browser = await chromium.launch({
    headless: false,
    devtools: true,
    args: [
      '--remote-debugging-port=9222',
      '--disable-web-security',
      '--enable-logging',
      '--v=1'
    ]
  });

  try {
    const page = await browser.newPage();
    
    // Get the CDP session
    const cdp = await page.context().newCDPSession(page);
    
    // Enable various CDP domains
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.enable');
    await cdp.send('DOM.enable');
    await cdp.send('CSS.enable');
    await cdp.send('Performance.enable');
    
    console.log('🔧 CDP domains enabled successfully');
    
    // Navigate to your app
    await page.goto('https://8eb14753.coreflow360-frontend.pages.dev/', { waitUntil: 'networkidle' });
    
    // Get DOM information using a safer approach
    try {
      const domSnapshot = await cdp.send('DOMSnapshot.getSnapshot', {
        computedStyles: ['display', 'visibility', 'opacity']
      });
      
      console.log('📊 DOM snapshot captured:', {
        documents: domSnapshot.documents?.length || 0,
        nodes: domSnapshot.domNodes?.length || 0
      });
    } catch (error) {
      console.log('📊 DOM snapshot failed, using alternative method:', error.message);
      
      // Alternative: Get DOM info via Runtime.evaluate
      const domInfo = await cdp.send('Runtime.evaluate', {
        expression: `
          ({
            totalElements: document.querySelectorAll('*').length,
            scripts: document.querySelectorAll('script').length,
            stylesheets: document.querySelectorAll('link[rel="stylesheet"]').length,
            images: document.querySelectorAll('img').length,
            forms: document.querySelectorAll('form').length,
            inputs: document.querySelectorAll('input').length,
            buttons: document.querySelectorAll('button').length,
            divs: document.querySelectorAll('div').length,
            bodyHTML: document.body ? document.body.innerHTML.length : 0
          })
        `
      });
      
      console.log('📊 DOM analysis (alternative):', domInfo.result.value);
    }
    
    // Get performance metrics
    const performanceMetrics = await cdp.send('Performance.getMetrics');
    console.log('⚡ Performance metrics:', performanceMetrics.metrics);
    
    // Get CSS coverage
    const cssCoverage = await cdp.send('CSS.startRuleUsageTracking');
    await page.waitForTimeout(2000);
    const cssUsage = await cdp.send('CSS.takeCoverageDelta');
    
    console.log('🎨 CSS coverage data:', {
      timestamp: cssUsage.timestamp,
      coverage: cssUsage.coverage?.length || 0
    });
    
    // Monitor network events
    cdp.on('Network.responseReceived', (params) => {
      console.log(`🌐 Network response: ${params.response.url} - ${params.response.status}`);
    });
    
    // Monitor console events
    cdp.on('Runtime.consoleAPICalled', (params) => {
      console.log(`🖥️  Console ${params.type}:`, params.args.map(arg => arg.value).join(' '));
    });
    
    // Get memory usage
    const memoryInfo = await cdp.send('Runtime.evaluate', {
      expression: 'performance.memory ? { used: performance.memory.usedJSHeapSize, total: performance.memory.totalJSHeapSize, limit: performance.memory.jsHeapSizeLimit } : null'
    });
    
    if (memoryInfo.result.value) {
      console.log('💾 Memory usage:', memoryInfo.result.value);
    }
    
    // Execute custom JavaScript
    const customResult = await cdp.send('Runtime.evaluate', {
      expression: `
        ({
          title: document.title,
          url: window.location.href,
          elements: document.querySelectorAll('*').length,
          scripts: document.querySelectorAll('script').length,
          stylesheets: document.querySelectorAll('link[rel="stylesheet"]').length
        })
      `
    });
    
    console.log('🔍 Custom analysis:', customResult.result.value);
    
    console.log('🔧 Advanced Chrome DevTools Protocol test running...');
    console.log('   - CDP session active');
    console.log('   - Multiple domains enabled');
    console.log('   - Real-time monitoring active');
    console.log('   - Press Ctrl+C to stop');
    
    // Keep running for inspection
    await page.waitForTimeout(300000); // 5 minutes
    
  } catch (error) {
    console.error('❌ Error during advanced CDP test:', error);
  } finally {
    await browser.close();
    console.log('✅ Advanced Chrome DevTools Protocol test completed');
  }
}

// Run the advanced test
advancedChromeDevTools().catch(console.error);
