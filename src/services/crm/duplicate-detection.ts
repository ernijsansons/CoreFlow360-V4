// @ts-nocheck
/**
 * CRM Duplicate Detection & Merge Engine
 * AI-powered fuzzy matching for contacts and companies
 * Inspired by Salesforce Einstein Duplicate Management
 */

import type { D1Database } from '@cloudflare/workers-types';
import type { Contact, Company } from '../../types/crm';

// ============================================================
// TYPES
// ============================================================

export interface DuplicateMatch {
  entity_type: 'contact' | 'company';
  primary_id: string;
  duplicate_id: string;
  match_score: number; // 0-100
  match_reasons: MatchReason[];
  confidence: 'low' | 'medium' | 'high';
  auto_merge_eligible: boolean;
}

export interface MatchReason {
  field: string;
  similarity: number; // 0-1
  method: 'exact' | 'fuzzy' | 'domain' | 'phonetic';
  weight: number;
}

export interface MergeStrategy {
  primary_id: string;
  duplicate_ids: string[];
  field_resolution: Record<string, 'primary' | 'duplicate' | 'merge'>;
  preserve_history: boolean;
}

export interface MergeResult {
  merged_id: string;
  absorbed_ids: string[];
  conflicts_resolved: number;
  records_updated: number;
}

// ============================================================
// DUPLICATE DETECTION ENGINE
// ============================================================

export class DuplicateDetectionEngine {
  constructor(
    private db: D1Database,
    private businessId: string
  ) {}

  // ============================================================
  // CONTACT DUPLICATE DETECTION
  // ============================================================

  async findContactDuplicates(
    contact: Partial<Contact>,
    threshold: number = 70
  ): Promise<DuplicateMatch[]> {
    const matches: DuplicateMatch[] = [];

    // Strategy 1: Exact email match (highest confidence)
    if (contact.email) {
      const emailMatches = await this.db
        .prepare(`
          SELECT * FROM crm_contacts
          WHERE business_id = ? AND email = ? AND deleted_at IS NULL
          ${contact.id ? 'AND id != ?' : ''}
        `)
        .bind(
          this.businessId,
          contact.email.toLowerCase().trim(),
          ...(contact.id ? [contact.id] : [])
        )
        .all<Contact>();

      for (const match of (emailMatches.results || [])) {
        matches.push({
          entity_type: 'contact',
          primary_id: contact.id || '',
          duplicate_id: match.id,
          match_score: 100,
          match_reasons: [{
            field: 'email',
            similarity: 1.0,
            method: 'exact',
            weight: 50
          }],
          confidence: 'high',
          auto_merge_eligible: true
        });
      }
    }

    // Strategy 2: Name + Company combination
    if (contact.first_name && contact.last_name && contact.company_id) {
      const nameCompanyMatches = await this.db
        .prepare(`
          SELECT * FROM crm_contacts
          WHERE business_id = ?
            AND company_id = ?
            AND deleted_at IS NULL
            ${contact.id ? 'AND id != ?' : ''}
        `)
        .bind(
          this.businessId,
          contact.company_id,
          ...(contact.id ? [contact.id] : [])
        )
        .all<Contact>();

      for (const match of (nameCompanyMatches.results || [])) {
        const nameSimilarity = this.calculateNameSimilarity(
          contact.first_name,
          contact.last_name,
          match.first_name,
          match.last_name
        );

        if (nameSimilarity > 0.8) {
          const score = nameSimilarity * 100;
          matches.push({
            entity_type: 'contact',
            primary_id: contact.id || '',
            duplicate_id: match.id,
            match_score: score,
            match_reasons: [
              {
                field: 'name',
                similarity: nameSimilarity,
                method: 'fuzzy',
                weight: 30
              },
              {
                field: 'company_id',
                similarity: 1.0,
                method: 'exact',
                weight: 20
              }
            ],
            confidence: score > 90 ? 'high' : 'medium',
            auto_merge_eligible: score > 95
          });
        }
      }
    }

    // Strategy 3: Phone number match
    if (contact.phone) {
      const normalizedPhone = this.normalizePhone(contact.phone);
      const phoneMatches = await this.db
        .prepare(`
          SELECT * FROM crm_contacts
          WHERE business_id = ? AND phone IS NOT NULL AND deleted_at IS NULL
          ${contact.id ? 'AND id != ?' : ''}
        `)
        .bind(
          this.businessId,
          ...(contact.id ? [contact.id] : [])
        )
        .all<Contact>();

      for (const match of (phoneMatches.results || [])) {
        if (match.phone && this.normalizePhone(match.phone) === normalizedPhone) {
          matches.push({
            entity_type: 'contact',
            primary_id: contact.id || '',
            duplicate_id: match.id,
            match_score: 85,
            match_reasons: [{
              field: 'phone',
              similarity: 1.0,
              method: 'exact',
              weight: 35
            }],
            confidence: 'high',
            auto_merge_eligible: false // Phones can be shared
          });
        }
      }
    }

    // Filter by threshold and deduplicate
    return this.deduplicateMatches(
      matches.filter(m => m.match_score >= threshold)
    );
  }

  // ============================================================
  // COMPANY DUPLICATE DETECTION
  // ============================================================

  async findCompanyDuplicates(
    company: Partial<Company>,
    threshold: number = 70
  ): Promise<DuplicateMatch[]> {
    const matches: DuplicateMatch[] = [];

    // Strategy 1: Exact domain match (highest confidence)
    if (company.domain) {
      const domainMatches = await this.db
        .prepare(`
          SELECT * FROM crm_companies
          WHERE business_id = ? AND domain = ? AND deleted_at IS NULL
          ${company.id ? 'AND id != ?' : ''}
        `)
        .bind(
          this.businessId,
          company.domain.toLowerCase().trim(),
          ...(company.id ? [company.id] : [])
        )
        .all<Company>();

      for (const match of (domainMatches.results || [])) {
        matches.push({
          entity_type: 'company',
          primary_id: company.id || '',
          duplicate_id: match.id,
          match_score: 100,
          match_reasons: [{
            field: 'domain',
            similarity: 1.0,
            method: 'domain',
            weight: 50
          }],
          confidence: 'high',
          auto_merge_eligible: true
        });
      }
    }

    // Strategy 2: Fuzzy name matching
    if (company.name) {
      const nameMatches = await this.db
        .prepare(`
          SELECT * FROM crm_companies
          WHERE business_id = ? AND deleted_at IS NULL
          ${company.id ? 'AND id != ?' : ''}
        `)
        .bind(
          this.businessId,
          ...(company.id ? [company.id] : [])
        )
        .all<Company>();

      const normalizedName = this.normalizeCompanyName(company.name);

      for (const match of (nameMatches.results || [])) {
        const matchNormalizedName = this.normalizeCompanyName(match.name);
        const similarity = this.calculateStringSimilarity(normalizedName, matchNormalizedName);

        if (similarity > 0.75) {
          const score = similarity * 100;
          matches.push({
            entity_type: 'company',
            primary_id: company.id || '',
            duplicate_id: match.id,
            match_score: score,
            match_reasons: [{
              field: 'name',
              similarity: similarity,
              method: 'fuzzy',
              weight: 40
            }],
            confidence: score > 90 ? 'high' : score > 80 ? 'medium' : 'low',
            auto_merge_eligible: score > 95
          });
        }
      }
    }

    // Strategy 3: Email domain match
    if (company.email) {
      const emailDomain = this.extractDomain(company.email);
      if (emailDomain) {
        const emailDomainMatches = await this.db
          .prepare(`
            SELECT * FROM crm_companies
            WHERE business_id = ? AND email LIKE ? AND deleted_at IS NULL
            ${company.id ? 'AND id != ?' : ''}
          `)
          .bind(
            this.businessId,
            `%@${emailDomain}`,
            ...(company.id ? [company.id] : [])
          )
          .all<Company>();

        for (const match of (emailDomainMatches.results || [])) {
          matches.push({
            entity_type: 'company',
            primary_id: company.id || '',
            duplicate_id: match.id,
            match_score: 80,
            match_reasons: [{
              field: 'email_domain',
              similarity: 1.0,
              method: 'domain',
              weight: 30
            }],
            confidence: 'medium',
            auto_merge_eligible: false
          });
        }
      }
    }

    return this.deduplicateMatches(
      matches.filter(m => m.match_score >= threshold)
    );
  }

  // ============================================================
  // MERGE OPERATIONS
  // ============================================================

  async mergeContacts(strategy: MergeStrategy): Promise<MergeResult> {
    const { primary_id, duplicate_ids, field_resolution, preserve_history } = strategy;

    // Fetch primary and duplicate records
    const primary = await this.db
      .prepare('SELECT * FROM crm_contacts WHERE id = ?')
      .bind(primary_id)
      .first<Contact>();

    if (!primary) {
      throw new Error('Primary contact not found');
    }

    const duplicates = await this.db
      .prepare(`SELECT * FROM crm_contacts WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(...duplicate_ids)
      .all<Contact>();

    // Build merged record
    const mergedData: Partial<Contact> = { ...primary };
    let conflictsResolved = 0;

    for (const [field, resolution] of Object.entries(field_resolution)) {
      if (resolution === 'merge') {
        // Merge arrays or concatenate strings
        const values = [primary[field as keyof Contact], ...duplicates.results!.map(d => d[field as keyof Contact])];
        mergedData[field as keyof Contact] = this.mergeFieldValues(values) as any;
        conflictsResolved++;
      } else if (resolution === 'duplicate') {
        // Take first non-null value from duplicates
        for (const dup of duplicates.results!) {
          if (dup[field as keyof Contact]) {
            mergedData[field as keyof Contact] = dup[field as keyof Contact];
            conflictsResolved++;
            break;
          }
        }
      }
    }

    // Update primary record
    const updateFields = Object.keys(mergedData).filter(k => k !== 'id');
    await this.db
      .prepare(`
        UPDATE crm_contacts
        SET ${updateFields.map(f => `${f} = ?`).join(', ')}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(...updateFields.map(f => mergedData[f as keyof Contact]), primary_id)
      .run();

    // Reassign related records
    let recordsUpdated = 0;

    // Update leads
    await this.db
      .prepare(`UPDATE crm_leads SET contact_id = ? WHERE contact_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    // Update activities
    await this.db
      .prepare(`UPDATE crm_activities SET contact_id = ? WHERE contact_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    // Update deals
    await this.db
      .prepare(`UPDATE crm_deals SET primary_contact_id = ? WHERE primary_contact_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    recordsUpdated += 3;

    // Soft delete or hard delete duplicates
    if (preserve_history) {
      await this.db
        .prepare(`UPDATE crm_contacts SET deleted_at = CURRENT_TIMESTAMP WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
        .bind(...duplicate_ids)
        .run();
    } else {
      await this.db
        .prepare(`DELETE FROM crm_contacts WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
        .bind(...duplicate_ids)
        .run();
    }

    return {
      merged_id: primary_id,
      absorbed_ids: duplicate_ids,
      conflicts_resolved: conflictsResolved,
      records_updated: recordsUpdated
    };
  }

  async mergeCompanies(strategy: MergeStrategy): Promise<MergeResult> {
    const { primary_id, duplicate_ids, field_resolution, preserve_history } = strategy;

    // Similar logic to mergeContacts but for companies
    const primary = await this.db
      .prepare('SELECT * FROM crm_companies WHERE id = ?')
      .bind(primary_id)
      .first<Company>();

    if (!primary) {
      throw new Error('Primary company not found');
    }

    const duplicates = await this.db
      .prepare(`SELECT * FROM crm_companies WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(...duplicate_ids)
      .all<Company>();

    // Merge logic (similar to contacts)
    const mergedData: Partial<Company> = { ...primary };
    let conflictsResolved = 0;

    for (const [field, resolution] of Object.entries(field_resolution)) {
      if (resolution === 'merge') {
        const values = [primary[field as keyof Company], ...duplicates.results!.map(d => d[field as keyof Company])];
        mergedData[field as keyof Company] = this.mergeFieldValues(values) as any;
        conflictsResolved++;
      } else if (resolution === 'duplicate') {
        for (const dup of duplicates.results!) {
          if (dup[field as keyof Company]) {
            mergedData[field as keyof Company] = dup[field as keyof Company];
            conflictsResolved++;
            break;
          }
        }
      }
    }

    // Update primary
    const updateFields = Object.keys(mergedData).filter(k => k !== 'id');
    await this.db
      .prepare(`
        UPDATE crm_companies
        SET ${updateFields.map(f => `${f} = ?`).join(', ')}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(...updateFields.map(f => mergedData[f as keyof Company]), primary_id)
      .run();

    // Reassign related records
    let recordsUpdated = 0;

    await this.db
      .prepare(`UPDATE crm_contacts SET company_id = ? WHERE company_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    await this.db
      .prepare(`UPDATE crm_leads SET company_id = ? WHERE company_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    await this.db
      .prepare(`UPDATE crm_deals SET company_id = ? WHERE company_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    await this.db
      .prepare(`UPDATE crm_activities SET company_id = ? WHERE company_id IN (${duplicate_ids.map(() => '?').join(',')})`)
      .bind(primary_id, ...duplicate_ids)
      .run();

    recordsUpdated += 4;

    // Delete duplicates
    if (preserve_history) {
      await this.db
        .prepare(`UPDATE crm_companies SET deleted_at = CURRENT_TIMESTAMP WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
        .bind(...duplicate_ids)
        .run();
    } else {
      await this.db
        .prepare(`DELETE FROM crm_companies WHERE id IN (${duplicate_ids.map(() => '?').join(',')})`)
        .bind(...duplicate_ids)
        .run();
    }

    return {
      merged_id: primary_id,
      absorbed_ids: duplicate_ids,
      conflicts_resolved: conflictsResolved,
      records_updated: recordsUpdated
    };
  }

  // ============================================================
  // SIMILARITY ALGORITHMS
  // ============================================================

  private calculateNameSimilarity(
    firstName1: string,
    lastName1: string,
    firstName2: string,
    lastName2: string
  ): number {
    const firstSim = this.calculateStringSimilarity(
      firstName1.toLowerCase(),
      firstName2.toLowerCase()
    );
    const lastSim = this.calculateStringSimilarity(
      lastName1.toLowerCase(),
      lastName2.toLowerCase()
    );

    return (firstSim + lastSim) / 2;
  }

  private calculateStringSimilarity(str1: string, str2: string): number {
    // Levenshtein distance-based similarity
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 1.0;

    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  private normalizeCompanyName(name: string): string {
    return name
      .toLowerCase()
      .replace(/\b(inc|llc|ltd|corp|corporation|company|co|limited)\b/g, '')
      .replace(/[^a-z0-9]/g, '')
      .trim();
  }

  private normalizePhone(phone: string): string {
    return phone.replace(/[^0-9]/g, '');
  }

  private extractDomain(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match ? match[1].toLowerCase() : null;
  }

  private deduplicateMatches(matches: DuplicateMatch[]): DuplicateMatch[] {
    const seen = new Set<string>();
    return matches.filter(m => {
      const key = `${m.primary_id}-${m.duplicate_id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private mergeFieldValues(values: any[]): any {
    // Remove nulls and undefined
    const validValues = values.filter(v => v !== null && v !== undefined);
    if (validValues.length === 0) return null;

    // If all values are strings, concatenate unique ones
    if (validValues.every(v => typeof v === 'string')) {
      return [...new Set(validValues)].join('; ');
    }

    // If all values are arrays, merge them
    if (validValues.every(v => Array.isArray(v))) {
      return [...new Set(validValues.flat())];
    }

    // Otherwise return first non-null value
    return validValues[0];
  }

  // ============================================================
  // BATCH DUPLICATE DETECTION
  // ============================================================

  async scanAllContactsForDuplicates(): Promise<DuplicateMatch[]> {
    const allContacts = await this.db
      .prepare('SELECT * FROM crm_contacts WHERE business_id = ? AND deleted_at IS NULL')
      .bind(this.businessId)
      .all<Contact>();

    const allMatches: DuplicateMatch[] = [];

    for (const contact of (allContacts.results || [])) {
      const matches = await this.findContactDuplicates(contact, 75);
      allMatches.push(...matches);
    }

    return this.deduplicateMatches(allMatches);
  }

  async scanAllCompaniesForDuplicates(): Promise<DuplicateMatch[]> {
    const allCompanies = await this.db
      .prepare('SELECT * FROM crm_companies WHERE business_id = ? AND deleted_at IS NULL')
      .bind(this.businessId)
      .all<Company>();

    const allMatches: DuplicateMatch[] = [];

    for (const company of (allCompanies.results || [])) {
      const matches = await this.findCompanyDuplicates(company, 75);
      allMatches.push(...matches);
    }

    return this.deduplicateMatches(allMatches);
  }
}
