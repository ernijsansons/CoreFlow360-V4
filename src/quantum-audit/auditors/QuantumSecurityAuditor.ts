import * as fs from 'fs/promises';
import * as path from 'path';
import { SecurityAuditResult, Issue } from '../types/index.js';

export class QuantumSecurityAuditor {
  async performSecurityAudit(): Promise<SecurityAuditResult> {

    const [
      vulnerabilities,
      misconfigurations,
      authIssues,
      encryptionIssues
    ] = await Promise.all([
      this.scanVulnerabilities(),
      this.checkMisconfigurations(),
      this.auditAuthentication(),
      this.checkEncryption()
    ]);

    const allIssues = [
      ...vulnerabilities,
      ...misconfigurations,
      ...authIssues,
      ...encryptionIssues
    ];

    const score = this.calculateSecurityScore(allIssues);


    return {
      vulnerabilities,
      misconfigurations,
      authIssues,
      encryptionIssues,
      score
    };
  }

  private async scanVulnerabilities(): Promise<Issue[]> {
    const issues: Issue[] = [];

    const codeFiles = await this.findSourceFiles();

    for (const file of codeFiles) {
      const content = await fs.readFile(file, 'utf-8');

      if (content.includes('eval(') || content.includes('Function(')) {
        issues.push({
          id: `vuln-${Date.now()}-eval`,
          category: 'security',
          severity: 'CRITICAL',
          description: 'Potential code injection vulnerability - eval() usage detected',
          file,
          autoFixable: false,
          impact: ['security', 'compliance'],
          recommendation: 'Replace eval() with safer alternatives'
        });
      }

      if (content.includes('innerHTML') && !content.includes('sanitize')) {
        issues.push({
          id: `vuln-${Date.now()}-xss`,
          category: 'security',
          severity: 'HIGH',
          description: 'Potential XSS vulnerability - unsanitized innerHTML usage',
          file,
          autoFixable: true,
          impact: ['security'],
          recommendation: 'Sanitize input before using innerHTML'
        });
      }

      if (content.includes('SELECT * FROM') || content.includes('select * from')) {
        issues.push({
          id: `vuln-${Date.now()}-sql`,
          category: 'security',
          severity: 'MEDIUM',
          description: 'Potential SQL injection - string concatenation in queries',
          file,
          autoFixable: true,
          impact: ['security', 'data-integrity'],
          recommendation: 'Use parameterized queries'
        });
      }

      const secretPatterns = [
        /password\s*=\s*['"][^'"]+['"]/gi,
        /api[_-]?key\s*=\s*['"][^'"]+['"]/gi,
        /secret\s*=\s*['"][^'"]+['"]/gi,
        /token\s*=\s*['"][^'"]+['"]/gi
      ];

      for (const pattern of secretPatterns) {
        if (pattern.test(content)) {
          issues.push({
            id: `vuln-${Date.now()}-secret`,
            category: 'security',
            severity: 'CRITICAL',
            description: 'Hardcoded secrets detected in source code',
            file,
            autoFixable: false,
            impact: ['security', 'compliance'],
            recommendation: 'Move secrets to environment variables'
          });
        }
      }
    }

    return issues;
  }

  private async checkMisconfigurations(): Promise<Issue[]> {
    const issues: Issue[] = [];

    try {
      const tsConfig = await fs.readFile('tsconfig.json', 'utf-8');
      const config = JSON.parse(tsConfig);

      if (!config.compilerOptions?.strict) {
        issues.push({
          id: `config-${Date.now()}-strict`,
          category: 'security',
          severity: 'MEDIUM',
          description: 'TypeScript strict mode not enabled',
          file: 'tsconfig.json',
          autoFixable: true,
          impact: ['code-quality', 'security'],
          recommendation: 'Enable strict mode in TypeScript configuration'
        });
      }

      if (!config.compilerOptions?.noImplicitAny) {
        issues.push({
          id: `config-${Date.now()}-implicit-any`,
          category: 'security',
          severity: 'LOW',
          description: 'Implicit any types allowed',
          file: 'tsconfig.json',
          autoFixable: true,
          impact: ['code-quality'],
          recommendation: 'Enable noImplicitAny for better type safety'
        });
      }
    } catch (error) {
      issues.push({
        id: `config-${Date.now()}-missing`,
        category: 'security',
        severity: 'HIGH',
        description: 'TypeScript configuration file missing or invalid',
        autoFixable: false,
        impact: ['security', 'code-quality'],
        recommendation: 'Create proper TypeScript configuration'
      });
    }

    try {
      const packageJson = await fs.readFile('package.json', 'utf-8');
      const pkg = JSON.parse(packageJson);

      if (!pkg.scripts?.audit) {
        issues.push({
          id: `config-${Date.now()}-audit-script`,
          category: 'security',
          severity: 'MEDIUM',
          description: 'No npm audit script configured',
          file: 'package.json',
          autoFixable: true,
          impact: ['security'],
          recommendation: 'Add npm audit script to package.json'
        });
      }
    } catch (error) {
      // Package.json already exists, this is expected
    }

    return issues;
  }

  private async auditAuthentication(): Promise<Issue[]> {
    const issues: Issue[] = [];

    const authFiles = await this.findFiles('**/auth/**/*.ts');

    for (const file of authFiles) {
      const content = await fs.readFile(file, 'utf-8');

      if (!content.includes('bcrypt') && !content.includes('argon2')) {
        issues.push({
          id: `auth-${Date.now()}-weak-hash`,
          category: 'security',
          severity: 'HIGH',
          description: 'Weak password hashing detected',
          file,
          autoFixable: false,
          impact: ['security', 'compliance'],
          recommendation: 'Use bcrypt or argon2 for password hashing'
        });
      }

      if (!content.includes('rate') && !content.includes('limit')) {
        issues.push({
          id: `auth-${Date.now()}-no-rate-limit`,
          category: 'security',
          severity: 'HIGH',
          description: 'No rate limiting on authentication endpoints',
          file,
          autoFixable: true,
          impact: ['security'],
          recommendation: 'Implement rate limiting for authentication'
        });
      }

      if (!content.includes('mfa') && !content.includes('2fa')) {
        issues.push({
          id: `auth-${Date.now()}-no-mfa`,
          category: 'security',
          severity: 'MEDIUM',
          description: 'Multi-factor authentication not implemented',
          file,
          autoFixable: false,
          impact: ['security', 'compliance'],
          recommendation: 'Implement multi-factor authentication'
        });
      }

      if (content.includes('jwt') && !content.includes('verify')) {
        issues.push({
          id: `auth-${Date.now()}-jwt-verify`,
          category: 'security',
          severity: 'CRITICAL',
          description: 'JWT tokens used without proper verification',
          file,
          autoFixable: false,
          impact: ['security'],
          recommendation: 'Always verify JWT tokens and signatures'
        });
      }
    }

    return issues;
  }

  private async checkEncryption(): Promise<Issue[]> {
    const issues: Issue[] = [];

    const allFiles = await this.findSourceFiles();

    for (const file of allFiles) {
      const content = await fs.readFile(file, 'utf-8');

      if (content.includes('http://') && !file.includes('test')) {
        issues.push({
          id: `encrypt-${Date.now()}-http`,
          category: 'security',
          severity: 'HIGH',
          description: 'Unencrypted HTTP connections detected',
          file,
          autoFixable: true,
          impact: ['security', 'compliance'],
          recommendation: 'Use HTTPS for all communications'
        });
      }

      if (content.includes('AES') && content.includes('ECB')) {
        issues.push({
          id: `encrypt-${Date.now()}-weak-cipher`,
          category: 'security',
          severity: 'HIGH',
          description: 'Weak encryption mode (ECB) detected',
          file,
          autoFixable: false,
          impact: ['security'],
          recommendation: 'Use CBC, GCM, or other secure encryption modes'
        });
      }

      if (content.includes('localStorage') || content.includes('sessionStorage')) {
        issues.push({
          id: `encrypt-${Date.now()}-storage`,
          category: 'security',
          severity: 'MEDIUM',
          description: 'Sensitive data may be stored unencrypted in browser storage',
          file,
          autoFixable: false,
          impact: ['security', 'privacy'],
          recommendation: 'Encrypt sensitive data before storing in browser'
        });
      }
    }

    return issues;
  }

  private calculateSecurityScore(issues: Issue[]): number {
    let score = 100;

    for (const issue of issues) {
      switch (issue.severity) {
        case 'CRITICAL':
          score -= 20;
          break;
        case 'HIGH':
          score -= 10;
          break;
        case 'MEDIUM':
          score -= 5;
          break;
        case 'LOW':
          score -= 2;
          break;
      }
    }

    return Math.max(0, score);
  }

  private async findSourceFiles(): Promise<string[]> {
    const extensions = ['.ts', '.js', '.tsx', '.jsx'];
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
    return files;
  }

  private async findFiles(pattern: string): Promise<string[]> {
    const files: string[] = [];

    async function scanDirectory(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && fullPath.includes('auth') && entry.name.endsWith('.ts')) {
            files.push(fullPath);
          }
        }
      } catch (error) {
        // Skip directories we can't read
      }
    }

    await scanDirectory('./src');
    return files;
  }
}