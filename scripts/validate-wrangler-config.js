#!/usr/bin/env node

/**
 * Wrangler Configuration Validation Script
 * Validates wrangler.toml configurations for production deployment
 */

import { readFile, access } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

class WranglerConfigValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.configPath = '';
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = type === 'error' ? '❌' : type === 'warning' ? '⚠️' : '✅';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  addError(message) {
    this.errors.push(message);
    this.log(message, 'error');
  }

  addWarning(message) {
    this.warnings.push(message);
    this.log(message, 'warning');
  }

  async validateFileExists(filePath) {
    try {
      await access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async parseToml(filePath) {
    try {
      const content = await readFile(filePath, 'utf-8');
      // Simple TOML parser for validation - in production, use @iarna/toml
      return { content, raw: content };
    } catch (error) {
      throw new Error(`Failed to read ${filePath}: ${error.message}`);
    }
  }

  validateRequiredFields(config, environment) {
    const requiredFields = ['name', 'main', 'compatibility_date'];

    for (const field of requiredFields) {
      if (!config.content.includes(`${field} =`)) {
        this.addError(`Missing required field: ${field}`);
      }
    }

    // Validate production-specific requirements
    if (environment === 'production') {
      const productionRequirements = [
        'observability',
        'placement',
        'limits'
      ];

      for (const requirement of productionRequirements) {
        if (!config.content.includes(`[${requirement}]`)) {
          this.addWarning(`Production deployment should include [${requirement}] configuration`);
        }
      }
    }
  }

  validateDatabaseBindings(config) {
    const dbBindings = config.content.match(/\[\[d1_databases\]\]/g);
    if (!dbBindings || dbBindings.length === 0) {
      this.addError('No D1 database bindings found');
      return;
    }

    // Check for placeholder IDs
    if (config.content.includes('prod-database-id-here') ||
        config.content.includes('prod-analytics-db-id-here')) {
      this.addError('Found placeholder database IDs - replace with actual values');
    }

    // Validate database ID format (UUID)
    const uuidRegex = /database_id = "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"/g;
    const matches = [...config.content.matchAll(uuidRegex)];

    if (matches.length === 0) {
      this.addError('No valid database IDs found (should be UUIDs)');
    } else {
      this.log(`Found ${matches.length} valid database ID(s)`);
    }
  }

  validateKVBindings(config) {
    const kvBindings = config.content.match(/\[\[kv_namespaces\]\]/g);
    if (!kvBindings || kvBindings.length === 0) {
      this.addWarning('No KV namespace bindings found');
      return;
    }

    // Check for placeholder IDs
    if (config.content.includes('prod-cache-namespace-id') ||
        config.content.includes('prod-session-namespace-id')) {
      this.addError('Found placeholder KV namespace IDs - replace with actual values');
    }

    this.log(`Found ${kvBindings.length} KV namespace binding(s)`);
  }

  validateR2Bindings(config) {
    const r2Bindings = config.content.match(/\[\[r2_buckets\]\]/g);
    if (!r2Bindings || r2Bindings.length === 0) {
      this.addWarning('No R2 bucket bindings found');
      return;
    }

    this.log(`Found ${r2Bindings.length} R2 bucket binding(s)`);
  }

  validateDurableObjects(config) {
    const doBindings = config.content.match(/\[\[durable_objects\.bindings\]\]/g);
    if (!doBindings || doBindings.length === 0) {
      this.addWarning('No Durable Object bindings found');
      return;
    }

    this.log(`Found ${doBindings.length} Durable Object binding(s)`);
  }

  validateInvalidFields(config) {
    const invalidFields = [
      'watch_paths',
      '[deploy]',
      '[site]'
    ];

    for (const field of invalidFields) {
      if (config.content.includes(field)) {
        if (field === 'watch_paths') {
          this.addError(`Invalid field: ${field} (not supported in Wrangler v3+)`);
        } else if (field === '[deploy]') {
          this.addError(`Invalid section: ${field} (not a valid Wrangler configuration)`);
        } else if (field === '[site]') {
          if (!config.content.includes('bucket =')) {
            this.addError(`Invalid [site] configuration: missing required 'bucket' field`);
          }
        }
      }
    }
  }

  validateRoutes(config) {
    const routes = config.content.match(/\[\[routes\]\]/g);
    if (!routes || routes.length === 0) {
      this.addWarning('No route configurations found');
      return;
    }

    // Validate route patterns
    if (config.content.includes('pattern =')) {
      this.log(`Found route configurations`);
    } else {
      this.addError('Route configurations found but missing pattern definitions');
    }
  }

  validateSecrets(config) {
    const secretComments = config.content.match(/#\s*(JWT_SECRET|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY)/g);
    if (secretComments && secretComments.length > 0) {
      this.log(`Found ${secretComments.length} documented secret(s) - ensure these are set via 'wrangler secret put'`);
    }
  }

  async validateConfiguration(configPath, environment = 'production') {
    this.configPath = configPath;
    this.log(`Validating Wrangler configuration: ${configPath}`);

    try {
      // Check if file exists
      const exists = await this.validateFileExists(configPath);
      if (!exists) {
        this.addError(`Configuration file not found: ${configPath}`);
        return this.getResults();
      }

      // Parse configuration
      const config = await this.parseToml(configPath);

      // Run validations
      this.validateRequiredFields(config, environment);
      this.validateDatabaseBindings(config);
      this.validateKVBindings(config);
      this.validateR2Bindings(config);
      this.validateDurableObjects(config);
      this.validateInvalidFields(config);
      this.validateRoutes(config);
      this.validateSecrets(config);

      return this.getResults();

    } catch (error) {
      this.addError(`Validation failed: ${error.message}`);
      return this.getResults();
    }
  }

  getResults() {
    const hasErrors = this.errors.length > 0;
    const hasWarnings = this.warnings.length > 0;

    return {
      success: !hasErrors,
      errors: this.errors,
      warnings: this.warnings,
      summary: {
        errors: this.errors.length,
        warnings: this.warnings.length,
        configPath: this.configPath
      }
    };
  }
}

// CLI execution
async function main() {
  const args = process.argv.slice(2);
  const environment = args[0] || 'production';
  const configFileName = args[1] || `wrangler.${environment}.toml`;
  const configPath = join(projectRoot, configFileName);

  console.log('🔍 Wrangler Configuration Validator');
  console.log('=====================================');

  const validator = new WranglerConfigValidator();
  const results = await validator.validateConfiguration(configPath, environment);

  console.log('\n📊 Validation Results');
  console.log('=====================');
  console.log(`Configuration: ${results.summary.configPath}`);
  console.log(`Errors: ${results.summary.errors}`);
  console.log(`Warnings: ${results.summary.warnings}`);

  if (results.errors.length > 0) {
    console.log('\n❌ Errors found:');
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
    console.log('\n✅ Configuration validation passed!');
    console.log('Ready for deployment.');
  } else {
    console.log('\n❌ Configuration validation failed!');
    console.log('Please fix the errors before deploying.');
    process.exit(1);
  }
}

// Export for programmatic use
export { WranglerConfigValidator };

// Run if called directly
const isMainModule = process.argv[1] && process.argv[1].endsWith('validate-wrangler-config.js');
if (isMainModule) {
  main().catch(console.error);
}