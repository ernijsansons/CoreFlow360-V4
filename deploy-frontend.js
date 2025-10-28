const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 CoreFlow360 V4 Frontend Deployment Script\n');

// Step 1: Build the frontend
console.log('📦 Step 1: Building frontend...\n');

const buildProcess = spawn('npm', ['run', 'build'], {
  cwd: path.join(__dirname, 'frontend'),
  shell: true,
  stdio: 'inherit'
});

buildProcess.on('close', (code) => {
  if (code !== 0) {
    console.error(`\n❌ Build failed with code ${code}`);
    process.exit(code);
  }

  console.log('\n✅ Build completed successfully!\n');

  // Step 2: Deploy to Cloudflare Pages
  console.log('🌐 Step 2: Deploying to Cloudflare Pages...\n');
  console.log('⚠️  This will open a browser for authentication if needed.\n');

  const deployProcess = spawn('npx', [
    'wrangler',
    'pages',
    'deploy',
    'dist',
    '--project-name=coreflow360-v4-prod'
  ], {
    cwd: path.join(__dirname, 'frontend'),
    shell: true,
    stdio: 'inherit',
    env: {
      ...process.env,
      CLOUDFLARE_API_TOKEN: '' // Clear any existing token to force OAuth
    }
  });

  deployProcess.on('close', (deployCode) => {
    if (deployCode !== 0) {
      console.error(`\n❌ Deployment failed with code ${deployCode}`);
      console.log('\nℹ️  If authentication failed, please run:');
      console.log('   wrangler logout');
      console.log('   wrangler login');
      console.log('   Then run this script again.\n');
      process.exit(deployCode);
    }

    console.log('\n✅ Deployment completed successfully!\n');
    console.log('🎉 Your frontend is now live on Cloudflare Pages!\n');
  });
});
