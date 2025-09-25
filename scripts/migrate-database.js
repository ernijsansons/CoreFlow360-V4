#!/usr/bin/env node
/**
 * Database Migration Script for CoreFlow360 V4
 * Handles D1 database setup and migrations
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

class DatabaseMigrator {
  constructor() {
    this.env = process.env.NODE_ENV || 'development';
    this.dryRun = process.argv.includes('--dry-run');
    this.force = process.argv.includes('--force');
  }

  async migrate() {
    console.log('🗄️ COREFLOW360 V4 - DATABASE MIGRATION');
    console.log('=====================================');
    console.log(`Environment: ${this.env}`);
    console.log(`Dry Run: ${this.dryRun}`);
    console.log('');

    try {
      // Check D1 database exists
      await this.checkDatabase();

      // Run schema migrations
      await this.runMigrations();

      // Seed initial data if needed
      if (this.env === 'development') {
        await this.seedData();
      }

      console.log('✅ Database migration completed successfully!');

    } catch (error) {
      console.error('❌ Migration failed:', error.message);
      process.exit(1);
    }
  }

  async checkDatabase() {
    console.log('🔍 Checking D1 database...');

    try {
      const result = this.execCommand('wrangler d1 list', true);
      const dbName = `coreflow360-${this.env}`;

      if (!result.includes(dbName)) {
        console.log(`  📦 Creating database: ${dbName}`);
        if (!this.dryRun) {
          this.execCommand(`wrangler d1 create ${dbName}`);
        }
      } else {
        console.log(`  ✅ Database exists: ${dbName}`);
      }
    } catch (error) {
      console.warn('  ⚠️ Could not verify database:', error.message);
    }
  }

  async runMigrations() {
    console.log('📝 Running schema migrations...');

    const schemaPath = path.join(process.cwd(), 'src/database/schema.sql');

    if (!fs.existsSync(schemaPath)) {
      throw new Error('Schema file not found: src/database/schema.sql');
    }

    if (this.dryRun) {
      console.log(`  Would execute: ${schemaPath}`);
      return;
    }

    try {
      const command = `wrangler d1 execute coreflow360-${this.env} --file=${schemaPath}`;
      console.log(`  📋 Executing: ${command}`);
      this.execCommand(command);
      console.log('  ✅ Schema migration completed');
    } catch (error) {
      console.error('  ❌ Schema migration failed:', error.message);
      throw error;
    }
  }

  async seedData() {
    console.log('🌱 Seeding development data...');

    const seedData = this.generateSeedData();

    for (const [table, data] of Object.entries(seedData)) {
      console.log(`  📦 Seeding ${table}...`);

      if (this.dryRun) {
        console.log(`    Would insert ${data.length} records`);
        continue;
      }

      try {
        for (const record of data) {
          const columns = Object.keys(record).join(', ');
          const values = Object.values(record).map(v =>
            typeof v === 'string' ? `'${v.replace(/'/g, "''")}'` : v
          ).join(', ');

          const sql = `INSERT OR IGNORE INTO ${table} (${columns}) VALUES (${values});`;

          await this.execSql(sql);
        }
        console.log(`    ✅ Seeded ${data.length} records in ${table}`);
      } catch (error) {
        console.warn(`    ⚠️ Seeding ${table} failed:`, error.message);
      }
    }
  }

  generateSeedData() {
    const now = new Date().toISOString();

    return {
      businesses: [
        {
          id: 'demo-business',
          name: 'Demo Company',
          settings: JSON.stringify({ theme: 'light', timezone: 'UTC' }),
          created_at: now,
          updated_at: now
        }
      ],
      users: [
        {
          id: 'demo-user',
          business_id: 'demo-business',
          email: 'demo@example.com',
          role: 'admin',
          settings: JSON.stringify({ notifications: true }),
          created_at: now
        }
      ],
      ledger_entries: [
        {
          id: 'demo-entry-1',
          business_id: 'demo-business',
          account_id: 'cash',
          amount: 1000.00,
          type: 'debit',
          description: 'Initial cash deposit',
          metadata: JSON.stringify({ source: 'seed' }),
          created_at: now
        },
        {
          id: 'demo-entry-2',
          business_id: 'demo-business',
          account_id: 'equity',
          amount: 1000.00,
          type: 'credit',
          description: 'Owner equity',
          metadata: JSON.stringify({ source: 'seed' }),
          created_at: now
        }
      ]
    };
  }

  async execSql(sql) {
    const tempFile = path.join(process.cwd(), '.temp-migration.sql');
    fs.writeFileSync(tempFile, sql);

    try {
      this.execCommand(`wrangler d1 execute coreflow360-${this.env} --file=${tempFile}`);
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  }

  execCommand(command, silent = false) {
    if (!silent) {
      console.log(`    $ ${command}`);
    }

    try {
      return execSync(command, {
        encoding: 'utf8',
        stdio: silent ? 'pipe' : 'inherit'
      });
    } catch (error) {
      if (silent) {
        return '';
      }
      throw error;
    }
  }
}

// CLI interface
async function main() {
  const migrator = new DatabaseMigrator();

  if (process.argv.includes('--help')) {
    console.log(`
Database Migration Script for CoreFlow360 V4

Usage: node scripts/migrate-database.js [options]

Options:
  --dry-run     Show what would be executed without running
  --force       Force migration even if database exists
  --help        Show this help message

Environment Variables:
  NODE_ENV      Target environment (development, staging, production)

Examples:
  # Run migrations for development
  npm run db:migrate

  # Run migrations for staging
  NODE_ENV=staging npm run db:migrate

  # Dry run to see what would happen
  npm run db:migrate -- --dry-run
`);
    process.exit(0);
  }

  await migrator.migrate();
}

main().catch(error => {
  console.error('Migration script failed:', error);
  process.exit(1);
});

export { DatabaseMigrator };