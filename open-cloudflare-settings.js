// Simple script to open Cloudflare Pages Settings in browser
import { chromium } from 'playwright';

(async () => {
  console.log('🚀 Opening Cloudflare Pages Settings...\n');

  const browser = await chromium.launch({
    headless: false,
    args: ['--start-maximized']
  });

  const context = await browser.newContext({
    viewport: null
  });

  const page = await context.newPage();

  // Navigate to Cloudflare Dashboard
  console.log('📍 Step 1: Navigate to Cloudflare Dashboard');
  await page.goto('https://dash.cloudflare.com');

  console.log('⏳ Waiting for you to log in (if needed)...');
  await page.waitForURL('**/dash.cloudflare.com/**', { timeout: 120000 });

  console.log('✅ Logged in!\n');

  // Navigate to Pages Settings
  console.log('📍 Step 2: Opening Pages Settings');
  await page.goto('https://dash.cloudflare.com/?to=/:account/pages');
  await page.waitForTimeout(2000);

  console.log('\n📋 INSTRUCTIONS:');
  console.log('════════════════════════════════════════════════════════');
  console.log('1. Find and click on "coreflow360-frontend" project');
  console.log('2. Click the "Settings" tab at the top');
  console.log('3. Scroll down to "Environment variables" section');
  console.log('4. Click "Add variable" button');
  console.log('5. Enter:');
  console.log('   • Variable name: VITE_API_URL');
  console.log('   • Value: https://coreflow360-v4-prod.ernijs-ansons.workers.dev');
  console.log('   • Check the "Production" checkbox');
  console.log('6. Click "Save"');
  console.log('7. Go to "Deployments" tab');
  console.log('8. Click the "..." menu on the latest deployment');
  console.log('9. Click "Retry deployment"');
  console.log('════════════════════════════════════════════════════════\n');
  console.log('👉 Browser will stay open for you to complete these steps');
  console.log('💡 Press Ctrl+C in terminal when done\n');

  // Keep browser open
  await page.pause();

  await browser.close();
})();
