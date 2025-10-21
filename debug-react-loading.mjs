#!/usr/bin/env node

import { chromium } from 'playwright';

async function debugReactLoading() {
  console.log('🔍 Starting React Loading Debug Analysis...');
  
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
    const cdp = await page.context().newCDPSession(page);
    
    // Enable CDP domains
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('Page.enable');
    
    console.log('🔧 CDP domains enabled for React debugging');
    
    // Set up comprehensive monitoring
    const networkRequests = [];
    const consoleMessages = [];
    const errors = [];
    
    // Monitor network requests
    cdp.on('Network.requestWillBeSent', (params) => {
      const request = {
        url: params.request.url,
        method: params.request.method,
        headers: params.request.headers,
        timestamp: new Date().toISOString()
      };
      networkRequests.push(request);
      
      // Focus on JavaScript and CSS files
      if (request.url.includes('.js') || request.url.includes('.css') || request.url.includes('bundle')) {
        console.log(`📦 Resource: ${request.method} ${request.url}`);
      }
    });
    
    // Monitor network responses
    cdp.on('Network.responseReceived', (params) => {
      const response = {
        url: params.response.url,
        status: params.response.status,
        statusText: params.response.statusText,
        headers: params.response.headers,
        timestamp: new Date().toISOString()
      };
      
      if (response.status >= 400) {
        console.log(`❌ Failed request: ${response.status} ${response.url}`);
        errors.push(response);
      }
    });
    
    // Monitor console messages
    cdp.on('Runtime.consoleAPICalled', (params) => {
      const message = {
        type: params.type,
        text: params.args.map(arg => arg.value || arg.description || '').join(' '),
        timestamp: new Date().toISOString()
      };
      consoleMessages.push(message);
      
      if (message.type === 'error' || message.text.includes('error') || message.text.includes('Error')) {
        console.log(`🚨 Console ${message.type}: ${message.text}`);
      }
    });
    
    // Monitor exceptions
    cdp.on('Runtime.exceptionThrown', (params) => {
      const exception = {
        message: params.exceptionDetails.exception?.description || 'Unknown error',
        stack: params.exceptionDetails.stackTrace,
        timestamp: new Date().toISOString()
      };
      errors.push(exception);
      console.log(`💥 Exception: ${exception.message}`);
    });
    
    // Navigate to the app
    console.log('📱 Navigating to CoreFlow360...');
    await page.goto('https://8eb14753.coreflow360-frontend.pages.dev/', { 
      waitUntil: 'domcontentloaded',
      timeout: 30000 
    });
    
    // Wait for potential React initialization
    console.log('⏳ Waiting for React initialization...');
    await page.waitForTimeout(5000);
    
    // Check for React in the page
    const reactCheck = await cdp.send('Runtime.evaluate', {
      expression: `
        ({
          hasReact: typeof React !== 'undefined',
          hasReactDOM: typeof ReactDOM !== 'undefined',
          hasReactRoot: typeof ReactDOMClient !== 'undefined',
          reactVersion: typeof React !== 'undefined' ? React.version : null,
          reactDOMVersion: typeof ReactDOM !== 'undefined' ? ReactDOM.version : null,
          rootElement: document.getElementById('root') ? 'found' : 'missing',
          appElement: document.querySelector('[data-reactroot]') ? 'found' : 'missing',
          scripts: Array.from(document.querySelectorAll('script')).map(s => s.src || 'inline'),
          stylesheets: Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map(l => l.href),
          bodyContent: document.body ? document.body.innerHTML.substring(0, 500) : 'no body'
        })
      `
    });
    
    console.log('🔍 React Analysis:', JSON.stringify(reactCheck.result.value, null, 2));
    
    // Check for specific error patterns
    const errorAnalysis = await cdp.send('Runtime.evaluate', {
      expression: `
        ({
          hasErrors: document.querySelectorAll('.error, [class*="error"]').length,
          hasLoading: document.querySelectorAll('.loading, [class*="loading"]').length,
          hasTimeout: document.querySelectorAll('[class*="timeout"]').length,
          textContent: document.body ? document.body.textContent.substring(0, 1000) : 'no body',
          allScripts: Array.from(document.querySelectorAll('script')).map(s => ({
            src: s.src,
            type: s.type,
            hasContent: s.innerHTML.length > 0
          }))
        })
      `
    });
    
    console.log('🔍 Error Analysis:', JSON.stringify(errorAnalysis.result.value, null, 2));
    
    // Summary
    console.log('\n📊 DEBUGGING SUMMARY:');
    console.log(`📦 Network requests: ${networkRequests.length}`);
    console.log(`💬 Console messages: ${consoleMessages.length}`);
    console.log(`❌ Errors found: ${errors.length}`);
    
    if (errors.length > 0) {
      console.log('\n🚨 ERRORS DETECTED:');
      errors.forEach((error, index) => {
        console.log(`${index + 1}. ${JSON.stringify(error, null, 2)}`);
      });
    }
    
    // Check for failed JavaScript loads
    const failedJS = networkRequests.filter(req => 
      req.url.includes('.js') && 
      errors.some(err => err.url === req.url)
    );
    
    if (failedJS.length > 0) {
      console.log('\n📦 FAILED JAVASCRIPT LOADS:');
      failedJS.forEach(js => console.log(`- ${js.url}`));
    }
    
    console.log('\n🔧 Chrome DevTools accessible at: http://localhost:9222');
    console.log('⏳ Keeping browser open for 2 minutes for manual inspection...');
    
    await page.waitForTimeout(120000); // 2 minutes
    
  } catch (error) {
    console.error('❌ Error during React debugging:', error);
  } finally {
    await browser.close();
    console.log('✅ React loading debug analysis completed');
  }
}

// Run the React debugging
debugReactLoading().catch(console.error);

