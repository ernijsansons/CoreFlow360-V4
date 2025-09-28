#!/usr/bin/env node

/**
 * Deployment Dry-Run Script
 * Validates deployment readiness without actually deploying
 */

import { spawn } from 'child_process';
import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

class DeploymentValidator {
  constructor(environment = 'production') {
    this.environment = environment;
    this.checks = [];
    this.errors = [];
    this.warnings = [];
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = type === 'error' ? '❌' : type === 'warning' ? '⚠️' : type === 'success' ? '✅' : 'ℹ️';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  addCheck(name, status, message = '') {
    this.checks.push({ name, status, message });

    if (status === 'error') {
      this.errors.push(message || name);
      this.log(`${name}: ${message}`, 'error');
    } else if (status === 'warning') {
      this.warnings.push(message || name);
      this.log(`${name}: ${message}`, 'warning');
    } else if (status === 'success') {
      this.log(`${name}: ${message || 'OK'}`, 'success');
    }
  }

  async runCommand(command, args = [], options = {}) {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        cwd: projectRoot,
        stdio: 'pipe',
        ...options
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        resolve({
          code,
          stdout: stdout.trim(),
          stderr: stderr.trim()
        });
      });

      child.on('error', (error) => {
        reject(error);
      });
    });
  }

  async checkWranglerInstallation() {
    this.log('Checking Wrangler installation...');

    try {
      const result = await this.runCommand('wrangler', ['--version']);
      if (result.code === 0) {
        this.addCheck('Wrangler Installation', 'success', `Version: ${result.stdout}`);
        return true;
      } else {
        this.addCheck('Wrangler Installation', 'error', 'Wrangler not found or not working');
        return false;
      }
    } catch (error) {
      this.addCheck('Wrangler Installation', 'error', `Wrangler not found: ${error.message}`);
      return false;
    }
  }

  async checkAuthentication() {
    this.log('Checking Cloudflare authentication...');

    try {
      const result = await this.runCommand('wrangler', ['whoami']);
      if (result.code === 0) {
        this.addCheck('Cloudflare Authentication', 'success', 'Authenticated');
        return true;
      } else {
        this.addCheck('Cloudflare Authentication', 'error', 'Not authenticated - run: wrangler login');
        return false;
      }
    } catch (error) {
      this.addCheck('Cloudflare Authentication', 'error', `Authentication check failed: ${error.message}`);
      return false;
    }
  }

  async checkConfiguration() {
    this.log('Validating Wrangler configuration...');

    try {
      const configFile = `wrangler.${this.environment}.toml`;
      const result = await this.runCommand('node', ['scripts/validate-wrangler-config.js', this.environment]);

      if (result.code === 0) {
        this.addCheck('Configuration Validation', 'success', 'Configuration is valid');
        return true;
      } else {
        this.addCheck('Configuration Validation', 'error', result.stderr || result.stdout);
        return false;
      }
    } catch (error) {
      this.addCheck('Configuration Validation', 'error', `Configuration validation failed: ${error.message}`);
      return false;
    }
  }

  async checkBuild() {
    this.log('Testing build process...');

    try {
      const result = await this.runCommand('npm', ['run', `build:${this.environment}`]);

      if (result.code === 0) {
        this.addCheck('Build Process', 'success', 'Build completed successfully');
        return true;
      } else {
        this.addCheck('Build Process', 'error', result.stderr || 'Build failed');
        return false;
      }
    } catch (error) {
      this.addCheck('Build Process', 'error', `Build process failed: ${error.message}`);
      return false;
    }
  }

  async checkDryRun() {
    this.log('Running Wrangler dry-run...');

    try {
      const configFile = `wrangler.${this.environment}.toml`;
      const result = await this.runCommand('wrangler', [
        'deploy',
        '--config', configFile,
        '--dry-run',
        '--outdir', 'dist'
      ]);

      if (result.code === 0) {
        this.addCheck('Deployment Dry-Run', 'success', 'Dry-run completed successfully');
        return true;
      } else {
        this.addCheck('Deployment Dry-Run', 'error', result.stderr || result.stdout);
        return false;
      }
    } catch (error) {
      this.addCheck('Deployment Dry-Run', 'error', `Dry-run failed: ${error.message}`);
      return false;
    }
  }

  async checkSecrets() {
    this.log('Checking secret configuration...');

    try {
      const result = await this.runCommand('wrangler', ['secret', 'list', '--env', this.environment]);

      if (result.code === 0) {
        const secrets = result.stdout.split('\n').filter(line => line.trim());
        if (secrets.length > 1) { // Account for header line
          this.addCheck('Secret Configuration', 'success', `${secrets.length - 1} secrets configured`);
        } else {
          this.addCheck('Secret Configuration', 'warning', 'No secrets found - ensure required secrets are set');
        }
        return true;
      } else {
        this.addCheck('Secret Configuration', 'warning', 'Could not check secrets');
        return false;
      }
    } catch (error) {
      this.addCheck('Secret Configuration', 'warning', `Secret check failed: ${error.message}`);
      return false;
    }
  }

  async checkEnvironmentSpecific() {
    if (this.environment === 'production') {
      this.log('Running production-specific checks...');

      // Check for monitoring configuration
      try {
        const configContent = await readFile(join(projectRoot, `wrangler.${this.environment}.toml`), 'utf-8');

        if (configContent.includes('[observability]')) {
          this.addCheck('Observability Configuration', 'success', 'Observability is configured');
        } else {
          this.addCheck('Observability Configuration', 'warning', 'Consider enabling observability for production');
        }

        if (configContent.includes('[limits]')) {
          this.addCheck('Resource Limits', 'success', 'Resource limits are configured');
        } else {
          this.addCheck('Resource Limits', 'warning', 'Consider setting resource limits for production');
        }

        if (configContent.includes('[[routes]]')) {
          this.addCheck('Custom Routes', 'success', 'Custom routes are configured');
        } else {
          this.addCheck('Custom Routes', 'warning', 'No custom routes found');
        }

      } catch (error) {
        this.addCheck('Production Checks', 'error', `Could not read configuration: ${error.message}`);
      }
    }
  }

  async runAllChecks() {
    console.log('🚀 Deployment Dry-Run Validator');
    console.log(`Environment: ${this.environment}`);
    console.log('===================================');

    const checks = [
      () => this.checkWranglerInstallation(),
      () => this.checkAuthentication(),
      () => this.checkConfiguration(),
      () => this.checkBuild(),
      () => this.checkSecrets(),
      () => this.checkEnvironmentSpecific(),
      () => this.checkDryRun(),
    ];

    for (const check of checks) {
      try {
        await check();
      } catch (error) {
        this.log(`Check failed: ${error.message}`, 'error');
      }
    }

    return this.getResults();
  }

  getResults() {
    const successCount = this.checks.filter(c => c.status === 'success').length;
    const errorCount = this.errors.length;
    const warningCount = this.warnings.length;

    return {
      success: errorCount === 0,
      checks: this.checks,
      errors: this.errors,
      warnings: this.warnings,
      summary: {
        total: this.checks.length,
        success: successCount,
        errors: errorCount,
        warnings: warningCount,
        environment: this.environment
      }
    };
  }

  printSummary(results) {
    console.log('\n📊 Deployment Readiness Summary');
    console.log('================================');
    console.log(`Environment: ${results.summary.environment}`);
    console.log(`Total Checks: ${results.summary.total}`);
    console.log(`✅ Passed: ${results.summary.success}`);
    console.log(`❌ Failed: ${results.summary.errors}`);
    console.log(`⚠️ Warnings: ${results.summary.warnings}`);

    if (results.errors.length > 0) {
      console.log('\n❌ Critical Issues:');
      results.errors.forEach((error, index) => {
        console.log(`  ${index + 1}. ${error}`);
      });
    }

    if (results.warnings.length > 0) {
      console.log('\n⚠️ Warnings:');
      results.warnings.forEach((warning, index) => {
        console.log(`  ${index + 1}. ${warning}`);
      });
    }

    if (results.success) {
      console.log('\n🎉 Deployment Ready!');
      console.log(`✅ All checks passed for ${results.summary.environment} environment`);
      console.log('You can now run the actual deployment.');
    } else {
      console.log('\n🛑 Deployment Not Ready');
      console.log('❌ Please fix the critical issues before deploying.');
    }

    return results.success;
  }
}

// CLI execution
async function main() {
  const args = process.argv.slice(2);
  const environment = args[0] || 'production';

  const validator = new DeploymentValidator(environment);
  const results = await validator.runAllChecks();
  const isReady = validator.printSummary(results);

  process.exit(isReady ? 0 : 1);
}

// Export for programmatic use
export { DeploymentValidator };

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}