import * as fs from 'fs/promises';
import * as path from 'path';
import { ComplianceAuditResult, Issue } from '../types/index.js';

export class QuantumComplianceAuditor {
  async auditCompliance(): Promise<ComplianceAuditResult> {

    const [
      gdprIssues,
      ccpaIssues,
      hipaaIssues,
      pciDssIssues
    ] = await Promise.all([
      this.auditGDPR(),
      this.auditCCPA(),
      this.auditHIPAA(),
      this.auditPCIDSS()
    ]);

    const allIssues = [
      ...gdprIssues,
      ...ccpaIssues,
      ...hipaaIssues,
      ...pciDssIssues
    ];

    const score = this.calculateComplianceScore(allIssues);


    return {
      gdprIssues,
      ccpaIssues,
      hipaaIssues,
      pciDssIssues,
      score
    };
  }

  private async auditGDPR(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for consent management
      if (content.includes('personal') || content.includes('user') || content.includes('profile')) {
        if (!content.includes('consent') && !content.includes('permission')) {
          issues.push({
            id: `gdpr-${Date.now()}-no-consent`,
            category: 'compliance',
            severity: 'CRITICAL',
            description: 'Personal data processing without explicit consent mechanisms',
            file,
            autoFixable: false,
            impact: ['legal-compliance', 'privacy', 'fines'],
            recommendation: 'Implement explicit consent collection and management'
          });
        }
      }

      // Check for data subject rights
      if (content.includes('user') && content.includes('data')) {
        if (!content.includes('delete') && !content.includes('export') && !content.includes('portability')) {
          issues.push({
            id: `gdpr-${Date.now()}-no-data-rights`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Missing data subject rights implementation (access, deletion, portability)',
            file,
            autoFixable: false,
            impact: ['legal-compliance', 'user-rights'],
            recommendation: 'Implement data subject rights: access, rectification, erasure, portability'
          });
        }
      }

      // Check for privacy by design
      if (content.includes('CREATE TABLE') || content.includes('schema')) {
        if (!content.includes('encrypted') && !content.includes('hashed') && content.includes('email')) {
          issues.push({
            id: `gdpr-${Date.now()}-no-privacy-by-design`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Personal data storage without privacy by design principles',
            file,
            autoFixable: false,
            impact: ['privacy', 'data-protection'],
            recommendation: 'Implement privacy by design: data minimization, encryption, pseudonymization'
          });
        }
      }

      // Check for data retention policies
      if (content.includes('personal') || content.includes('user_data')) {
        if (!content.includes('retention') && !content.includes('expire')) {
          issues.push({
            id: `gdpr-${Date.now()}-no-retention-policy`,
            category: 'compliance',
            severity: 'MEDIUM',
            description: 'Personal data without retention period definition',
            file,
            autoFixable: false,
            impact: ['compliance', 'data-governance'],
            recommendation: 'Define and implement data retention policies'
          });
        }
      }

      // Check for lawful basis documentation
      if (content.includes('process') && content.includes('personal')) {
        if (!content.includes('lawful_basis') && !content.includes('legal_basis')) {
          issues.push({
            id: `gdpr-${Date.now()}-no-lawful-basis`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Personal data processing without documented lawful basis',
            file,
            autoFixable: false,
            impact: ['legal-compliance', 'documentation'],
            recommendation: 'Document lawful basis for all personal data processing'
          });
        }
      }

      // Check for cross-border transfer safeguards
      if (content.includes('transfer') || content.includes('export')) {
        if (content.includes('international') || content.includes('cross_border')) {
          if (!content.includes('adequacy') && !content.includes('safeguards')) {
            issues.push({
              id: `gdpr-${Date.now()}-no-transfer-safeguards`,
              category: 'compliance',
              severity: 'CRITICAL',
              description: 'International data transfers without adequate safeguards',
              file,
              autoFixable: false,
              impact: ['legal-compliance', 'data-protection'],
              recommendation: 'Implement adequate safeguards for international data transfers'
            });
          }
        }
      }
    }

    return issues;
  }

  private async auditCCPA(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for consumer rights
      if (content.includes('california') || content.includes('consumer')) {
        if (!content.includes('opt_out') && !content.includes('do_not_sell')) {
          issues.push({
            id: `ccpa-${Date.now()}-no-opt-out`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Missing California consumer opt-out mechanisms',
            file,
            autoFixable: false,
            impact: ['legal-compliance', 'privacy-rights'],
            recommendation: 'Implement Do Not Sell opt-out for California consumers'
          });
        }
      }

      // Check for personal information disclosure
      if (content.includes('sell') || content.includes('share') || content.includes('disclose')) {
        if (!content.includes('notice') && !content.includes('disclosure')) {
          issues.push({
            id: `ccpa-${Date.now()}-no-disclosure-notice`,
            category: 'compliance',
            severity: 'MEDIUM',
            description: 'Personal information sharing without proper notice',
            file,
            autoFixable: false,
            impact: ['transparency', 'compliance'],
            recommendation: 'Provide clear notices about personal information disclosure'
          });
        }
      }

      // Check for age verification
      if (content.includes('age') || content.includes('minor') || content.includes('child')) {
        if (!content.includes('verify') && !content.includes('parental_consent')) {
          issues.push({
            id: `ccpa-${Date.now()}-no-age-verification`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Processing of minor data without age verification',
            file,
            autoFixable: false,
            impact: ['child-protection', 'legal-compliance'],
            recommendation: 'Implement age verification and parental consent mechanisms'
          });
        }
      }
    }

    return issues;
  }

  private async auditHIPAA(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for PHI (Protected Health Information)
      const phiKeywords = ['health', 'medical', 'patient', 'diagnosis', 'treatment'];
      const containsPHI = phiKeywords.some(keyword => content.includes(keyword));

      if (containsPHI) {
        // Check for encryption at rest
        if (!content.includes('encrypt') && !content.includes('AES')) {
          issues.push({
            id: `hipaa-${Date.now()}-no-encryption`,
            category: 'compliance',
            severity: 'CRITICAL',
            description: 'PHI stored without encryption',
            file,
            autoFixable: false,
            impact: ['data-protection', 'legal-compliance'],
            recommendation: 'Encrypt all PHI at rest using AES-256 or equivalent'
          });
        }

        // Check for access controls
        if (!content.includes('authorization') && !content.includes('access_control')) {
          issues.push({
            id: `hipaa-${Date.now()}-no-access-control`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'PHI access without proper authorization controls',
            file,
            autoFixable: false,
            impact: ['access-control', 'privacy'],
            recommendation: 'Implement role-based access controls for PHI'
          });
        }

        // Check for audit logging
        if (!content.includes('audit') && !content.includes('log')) {
          issues.push({
            id: `hipaa-${Date.now()}-no-audit-log`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'PHI access without audit logging',
            file,
            autoFixable: true,
            impact: ['audit-trail', 'compliance'],
            recommendation: 'Implement comprehensive audit logging for PHI access'
          });
        }

        // Check for minimum necessary principle
        if (content.includes('SELECT *') && containsPHI) {
          issues.push({
            id: `hipaa-${Date.now()}-minimum-necessary`,
            category: 'compliance',
            severity: 'MEDIUM',
            description: 'PHI queries not following minimum necessary principle',
            file,
            autoFixable: true,
            impact: ['privacy', 'data-minimization'],
            recommendation: 'Query only necessary PHI fields, avoid SELECT *'
          });
        }
      }
    }

    return issues;
  }

  private async auditPCIDSS(): Promise<Issue[]> {
    const issues: Issue[] = [];
    const sourceFiles = await this.findSourceFiles();

    for (const file of sourceFiles) {
      const content = await fs.readFile(file, 'utf-8');

      // Check for payment card data
      const pciKeywords = ['card', 'payment', 'credit', 'cardholder', 'pan', 'cvv'];
      const containsPCI = pciKeywords.some(keyword => content.includes(keyword));

      if (containsPCI) {
        // Check for cardholder data encryption
        if (!content.includes('encrypt') && !content.includes('tokenize')) {
          issues.push({
            id: `pci-${Date.now()}-no-encryption`,
            category: 'compliance',
            severity: 'CRITICAL',
            description: 'Cardholder data stored without encryption or tokenization',
            file,
            autoFixable: false,
            impact: ['data-protection', 'financial-security'],
            recommendation: 'Encrypt or tokenize all cardholder data'
          });
        }

        // Check for secure transmission
        if (content.includes('http://') && containsPCI) {
          issues.push({
            id: `pci-${Date.now()}-insecure-transmission`,
            category: 'compliance',
            severity: 'CRITICAL',
            description: 'Cardholder data transmitted over insecure connections',
            file,
            autoFixable: true,
            impact: ['data-protection', 'transmission-security'],
            recommendation: 'Use HTTPS/TLS for all cardholder data transmission'
          });
        }

        // Check for access restrictions
        if (!content.includes('role') && !content.includes('permission')) {
          issues.push({
            id: `pci-${Date.now()}-no-access-restriction`,
            category: 'compliance',
            severity: 'HIGH',
            description: 'Cardholder data access without role-based restrictions',
            file,
            autoFixable: false,
            impact: ['access-control', 'data-protection'],
            recommendation: 'Implement strict role-based access controls for cardholder data'
          });
        }

        // Check for CVV storage
        if (content.includes('cvv') && content.includes('store')) {
          issues.push({
            id: `pci-${Date.now()}-cvv-storage`,
            category: 'compliance',
            severity: 'CRITICAL',
            description: 'CVV data storage detected - prohibited by PCI DSS',
            file,
            autoFixable: false,
            impact: ['compliance-violation', 'security'],
            recommendation: 'Remove CVV storage - CVV must never be stored after authorization'
          });
        }

        // Check for vulnerability management
        if (!content.includes('scan') && !content.includes('vulnerability')) {
          issues.push({
            id: `pci-${Date.now()}-no-vulnerability-management`,
            category: 'compliance',
            severity: 'MEDIUM',
            description: 'Payment systems without vulnerability management',
            file,
            autoFixable: false,
            impact: ['security', 'compliance'],
            recommendation: 'Implement regular vulnerability scanning and management'
          });
        }
      }
    }

    return issues;
  }

  private calculateComplianceScore(issues: Issue[]): number {
    let score = 100;

    for (const issue of issues) {
      switch (issue.severity) {
        case 'CRITICAL':
          score -= 25; // Compliance violations are severe
          break;
        case 'HIGH':
          score -= 15;
          break;
        case 'MEDIUM':
          score -= 8;
          break;
        case 'LOW':
          score -= 3;
          break;
      }
    }

    return Math.max(0, score);
  }

  private async findSourceFiles(): Promise<string[]> {
    const extensions = ['.ts', '.js', '.tsx', '.jsx', '.sql'];
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
    await scanDirectory('./database');
    return files;
  }
}