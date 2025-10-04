// Database migration SQL queries

export const migrations = [
  {
    version: 1,
    name: 'initial_setup',
    sql: `
      CREATE TABLE IF NOT EXISTS migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `
  },
  {
    version: 2,
    name: 'users_table',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        first_name TEXT,
        last_name TEXT,
        business_id TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `
  },
  {
    version: 3,
    name: 'businesses_table',
    sql: `
      CREATE TABLE IF NOT EXISTS businesses (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        domain TEXT,
        industry TEXT,
        size TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `
  },
  {
    version: 4,
    name: 'leads_table',
    sql: `
      CREATE TABLE IF NOT EXISTS leads (
        id TEXT PRIMARY KEY,
        business_id TEXT NOT NULL,
        email TEXT,
        first_name TEXT,
        last_name TEXT,
        company_name TEXT,
        status TEXT,
        score REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id)
      );
    `
  },
  {
    version: 5,
    name: 'contacts_table',
    sql: `
      CREATE TABLE IF NOT EXISTS contacts (
        id TEXT PRIMARY KEY,
        business_id TEXT NOT NULL,
        email TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        title TEXT,
        company_id TEXT,
        phone TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id)
      );
    `
  },
  {
    version: 6,
    name: 'companies_table',
    sql: `
      CREATE TABLE IF NOT EXISTS companies (
        id TEXT PRIMARY KEY,
        business_id TEXT NOT NULL,
        name TEXT NOT NULL,
        domain TEXT,
        industry TEXT,
        size TEXT,
        revenue REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id)
      );
    `
  }
];

export function getMigration(version: number) {
  return migrations.find(m => m.version === version);
}

export function getLatestVersion(): number {
  return Math.max(...migrations.map(m => m.version));
}

export function getMigrationsToApply(currentVersion: number): typeof migrations {
  return migrations.filter(m => m.version > currentVersion);
}

// Aliases for compatibility - return functions to match expected API
export async function loadMigrations() {
  return migrations;
}

export async function loadRollbacks() {
  return [];
}