#!/usr/bin/env node

/**
 * CoreFlow360 V4 - Development Environment Setup Script
 *
 * This script collects comprehensive metadata about the development stack,
 * validates the environment, and generates a detailed setup report.
 *
 * Usage: node scripts/setup-report.mjs
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const frontendDir = join(rootDir, 'frontend');

// Utility functions
const execCommand = (command, options = {}) => {
  try {
    return execSync(command, {
      encoding: 'utf8',
      cwd: options.cwd || rootDir,
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch (error) {
    return `Error: ${error.message}`;
  }
};

const readJsonFile = (path) => {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
};

const checkFileExists = (path) => existsSync(path);

// Data collection functions
const collectSystemInfo = () => {
  const nodeVersion = execCommand('node --version');
  const npmVersion = execCommand('npm --version');
  const gitVersion = execCommand('git --version');
  const dockerVersion = execCommand('docker --version');

  return {
    node: nodeVersion,
    npm: npmVersion,
    git: gitVersion,
    docker: dockerVersion,
    platform: process.platform,
    arch: process.arch,
    timestamp: new Date().toISOString()
  };
};

const collectPackageInfo = () => {
  const rootPackage = readJsonFile(join(rootDir, 'package.json'));
  const frontendPackage = readJsonFile(join(frontendDir, 'package.json'));

  return {
    root: {
      name: rootPackage?.name || 'Unknown',
      version: rootPackage?.version || '0.0.0',
      dependencies: Object.keys(rootPackage?.dependencies || {}),
      devDependencies: Object.keys(rootPackage?.devDependencies || {}),
      scripts: Object.keys(rootPackage?.scripts || {})
    },
    frontend: {
      name: frontendPackage?.name || 'Unknown',
      version: frontendPackage?.version || '0.0.0',
      dependencies: Object.keys(frontendPackage?.dependencies || {}),
      devDependencies: Object.keys(frontendPackage?.devDependencies || {}),
      scripts: Object.keys(frontendPackage?.scripts || {})
    }
  };
};

const collectFrameworkInfo = () => {
  const frontendPackage = readJsonFile(join(frontendDir, 'package.json'));
  const dependencies = frontendPackage?.dependencies || {};
  const devDependencies = frontendPackage?.devDependencies || {};

  const getVersion = (pkg) => dependencies[pkg] || devDependencies[pkg] || 'Not installed';

  // Count Radix UI components
  const radixComponents = Object.keys(dependencies)
    .filter(key => key.startsWith('@radix-ui/react-'))
    .length;

  return {
    react: getVersion('react'),
    'react-dom': getVersion('react-dom'),
    typescript: getVersion('typescript'),
    vite: getVersion('vite'),
    tailwindcss: getVersion('tailwindcss'),
    '@tanstack/react-router': getVersion('@tanstack/react-router'),
    '@tanstack/router-vite-plugin': getVersion('@tanstack/router-vite-plugin'),
    zustand: getVersion('zustand'),
    '@radix-ui components': `${radixComponents} components`,
    '@sentry/vite-plugin': getVersion('@sentry/vite-plugin'),
    storybook: getVersion('storybook'),
    vitest: getVersion('vitest'),
    playwright: getVersion('playwright'),
    '@axe-core/playwright': getVersion('@axe-core/playwright'),
    'eslint-plugin-jsx-a11y': getVersion('eslint-plugin-jsx-a11y'),
    stylelint: getVersion('stylelint'),
    eslint: getVersion('eslint'),
    'lucide-react': getVersion('lucide-react'),
    'framer-motion': getVersion('framer-motion')
  };
};

const collectConfigurationFiles = () => {
  const configFiles = [
    'package.json',
    'frontend/package.json',
    'frontend/vite.config.ts',
    'frontend/tailwind.config.js',
    'frontend/tsconfig.json',
    'wrangler.toml',
    'docker-compose.yml',
    'Dockerfile',
    '.gitignore',
    '.dockerignore'
  ];

  return configFiles.map(file => ({
    file,
    exists: checkFileExists(join(rootDir, file)),
    path: join(rootDir, file)
  }));
};

const collectBuildInfo = () => {
  const distExists = checkFileExists(join(frontendDir, 'dist'));
  const nodeModulesExists = checkFileExists(join(frontendDir, 'node_modules'));

  let buildInfo = {};

  if (distExists) {
    try {
      const buildOutput = execCommand('du -sh frontend/dist 2>/dev/null || echo "Unknown size"');
      buildInfo.distSize = buildOutput;
    } catch {
      buildInfo.distSize = 'Unknown';
    }
  }

  return {
    distExists,
    nodeModulesExists,
    ...buildInfo,
    lastBuild: distExists ? execCommand('stat -c %Y frontend/dist 2>/dev/null || stat -f %m frontend/dist 2>/dev/null || echo "Unknown"') : 'Never'
  };
};

const validateEnvironment = () => {
  const issues = [];
  const recommendations = [];

  // Check Node.js version
  const nodeVersion = execCommand('node --version').replace('v', '');
  const [major] = nodeVersion.split('.');
  if (parseInt(major) < 18) {
    issues.push(`Node.js version ${nodeVersion} is below recommended 18.x`);
    recommendations.push('Upgrade to Node.js 18.x or higher');
  }

  // Check if frontend dependencies are installed
  if (!checkFileExists(join(frontendDir, 'node_modules'))) {
    issues.push('Frontend dependencies not installed');
    recommendations.push('Run: cd frontend && npm install');
  }

  // Check TypeScript configuration
  if (!checkFileExists(join(frontendDir, 'tsconfig.json'))) {
    issues.push('TypeScript configuration missing');
    recommendations.push('Create tsconfig.json in frontend directory');
  }

  // Check if Wrangler is configured
  if (!checkFileExists(join(rootDir, 'wrangler.toml'))) {
    issues.push('Wrangler configuration missing');
    recommendations.push('Run: npx wrangler init to setup Cloudflare Workers');
  }

  // Check for critical build files
  if (!checkFileExists(join(frontendDir, 'vite.config.ts'))) {
    issues.push('Vite configuration missing');
    recommendations.push('Create vite.config.ts in frontend directory');
  }

  if (!checkFileExists(join(frontendDir, 'tailwind.config.js'))) {
    issues.push('Tailwind CSS configuration missing');
    recommendations.push('Run: npx tailwindcss init');
  }

  // Check for testing setup
  const frontendPackage = readJsonFile(join(frontendDir, 'package.json'));
  const devDeps = frontendPackage?.devDependencies || {};

  if (!devDeps.playwright) {
    recommendations.push('Consider adding Playwright for E2E testing');
  }

  if (!devDeps['@axe-core/playwright']) {
    recommendations.push('Consider adding @axe-core/playwright for accessibility testing');
  }

  return { issues, recommendations };
};

const generateReport = (data) => {
  const report = `# CoreFlow360 V4 - Development Environment Report

**Generated**: ${data.system.timestamp}
**Script**: setup-report.mjs

---

## 🖥️ **System Environment**

- **Node.js**: ${data.system.node}
- **npm**: ${data.system.npm}
- **Git**: ${data.system.git}
- **Docker**: ${data.system.docker}
- **Platform**: ${data.system.platform} (${data.system.arch})

---

## 📦 **Package Information**

### Root Package
- **Name**: ${data.packages.root.name}
- **Version**: ${data.packages.root.version}
- **Dependencies**: ${data.packages.root.dependencies.length}
- **Dev Dependencies**: ${data.packages.root.devDependencies.length}
- **Scripts**: ${data.packages.root.scripts.join(', ')}

### Frontend Package
- **Name**: ${data.packages.frontend.name}
- **Version**: ${data.packages.frontend.version}
- **Dependencies**: ${data.packages.frontend.dependencies.length}
- **Dev Dependencies**: ${data.packages.frontend.devDependencies.length}
- **Scripts**: ${data.packages.frontend.scripts.join(', ')}

---

## 🛠️ **Framework Versions**

${Object.entries(data.frameworks)
  .map(([name, version]) => `- **${name}**: ${version}`)
  .join('\n')}

---

## ⚙️ **Configuration Files**

${data.configFiles
  .map(({ file, exists }) => `- **${file}**: ${exists ? '✅ Exists' : '❌ Missing'}`)
  .join('\n')}

---

## 🏗️ **Build Status**

- **Frontend Built**: ${data.build.distExists ? '✅ Yes' : '❌ No'}
- **Dependencies Installed**: ${data.build.nodeModulesExists ? '✅ Yes' : '❌ No'}
${data.build.distSize ? `- **Build Size**: ${data.build.distSize}` : ''}
- **Last Build**: ${data.build.lastBuild}

---

## 🔍 **Environment Validation**

### Issues Found (${data.validation.issues.length})
${data.validation.issues.length > 0
  ? data.validation.issues.map(issue => `- ❌ ${issue}`).join('\n')
  : '✅ No issues found'
}

### Recommendations (${data.validation.recommendations.length})
${data.validation.recommendations.length > 0
  ? data.validation.recommendations.map(rec => `- 💡 ${rec}`).join('\n')
  : '✅ Environment is properly configured'
}

---

## 🚀 **Quick Start Commands**

### Development
\`\`\`bash
# Install dependencies
cd frontend && npm install

# Start development server
npm run dev

# Start Storybook
npm run storybook

# Run tests
npm run test
\`\`\`

### Production
\`\`\`bash
# Build frontend
cd frontend && npm run build

# Deploy to Cloudflare
npx wrangler deploy

# Docker build
docker build -t coreflow360-v4 .
\`\`\`

### Quality Assurance
\`\`\`bash
# Type checking
npm run typecheck

# Linting
npm run lint

# Unit tests
npm run test

# E2E tests
npm run test:e2e
\`\`\`

---

**Environment Report Complete** ✅
**Generated by**: CoreFlow360 V4 Setup Script
**Next Steps**: Address any issues listed above, then proceed with development.
`;

  return report;
};

// Main execution
const main = async () => {
  console.log('🔍 Collecting CoreFlow360 V4 environment information...\n');

  const data = {
    system: collectSystemInfo(),
    packages: collectPackageInfo(),
    frameworks: collectFrameworkInfo(),
    configFiles: collectConfigurationFiles(),
    build: collectBuildInfo(),
    validation: validateEnvironment()
  };

  console.log('📊 System Information:');
  console.log(`   Node.js: ${data.system.node}`);
  console.log(`   npm: ${data.system.npm}`);
  console.log(`   Platform: ${data.system.platform}\n`);

  console.log('📦 Package Analysis:');
  console.log(`   Root dependencies: ${data.packages.root.dependencies.length}`);
  console.log(`   Frontend dependencies: ${data.packages.frontend.dependencies.length}\n`);

  if (data.validation.issues.length > 0) {
    console.log('⚠️  Issues found:');
    data.validation.issues.forEach(issue => console.log(`   - ${issue}`));
    console.log('');
  }

  const report = generateReport(data);
  const reportPath = join(rootDir, '.reports', 'environment-report.md');

  writeFileSync(reportPath, report);

  console.log('✅ Environment report generated successfully!');
  console.log(`📄 Report saved to: ${reportPath}`);
  console.log('🚀 Ready for development!\n');

  // Output validation summary
  if (data.validation.issues.length === 0) {
    console.log('🎉 Environment validation passed - no issues found!');
  } else {
    console.log(`⚠️  Found ${data.validation.issues.length} issue(s) - check the report for details.`);
  }
};

// Execute the script
main().catch(error => {
  console.error('❌ Script failed:', error.message);
  process.exit(1);
});