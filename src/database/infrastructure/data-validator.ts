/**
 * Data Validator - Single Responsibility Principle Compliant
 * Focused solely on data validation and sanitization for database operations
 */

import { z } from 'zod';
import { IDataValidator, CreateLead, CreateContact, CreateCompany } from '../repositories/interfaces';
import { Logger } from '../../shared/logger';

// Validation Schemas
export const CreateCompanySchema = z.object({
  business_id: z.string(),
  name: z.string().min(1),
  domain: z.string().optional(),
  industry: z.string().optional(),
  size_range: z.enum(['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']).optional(),
  revenue_range: z.enum(['0-1M', '1M-5M', '5M-10M', '10M-50M', '50M-100M', '100M+']).optional(),
  ai_summary: z.string().optional(),
  ai_pain_points: z.string().optional(),
  ai_icp_score: z.number().min(0).max(100).optional(),
  technologies: z.string().optional(),
  funding: z.string().optional(),
  news: z.string().optional(),
  social_profiles: z.string().optional()
});

export const CreateContactSchema = z.object({
  business_id: z.string(),
  company_id: z.string().optional(),
  email: z.string().email(),
  phone: z.string().optional(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  title: z.string().optional(),
  seniority_level: z.enum(['individual_contributor', 'team_lead', 'manager', 'director', 'vp', 'c_level', 'founder']).optional(),
  department: z.enum(['engineering', 'sales', 'marketing', 'hr', 'finance', 'operations', 'legal', 'executive', 'other']).optional(),
  linkedin_url: z.string().optional(),
  ai_personality: z.string().optional(),
  ai_communication_style: z.string().optional(),
  ai_interests: z.string().optional(),
  verified_phone: z.boolean().optional(),
  verified_email: z.boolean().optional(),
  timezone: z.string().optional(),
  preferred_contact_method: z.enum(['email', 'phone', 'linkedin', 'sms']).optional()
});

export const CreateLeadSchema = z.object({
  business_id: z.string(),
  contact_id: z.string().optional(),
  company_id: z.string().optional(),
  source: z.string(),
  source_campaign: z.string().optional(),
  status: z.enum(['new', 'qualifying', 'qualified', 'meeting_scheduled', 'opportunity', 'unqualified', 'closed_won', 'closed_lost']).optional(),
  ai_qualification_score: z.number().min(0).max(100).optional(),
  ai_qualification_summary: z.string().optional(),
  ai_next_best_action: z.string().optional(),
  ai_predicted_value: z.number().optional(),
  ai_close_probability: z.number().min(0).max(1).optional(),
  ai_estimated_close_date: z.string().optional(),
  assigned_to: z.string().optional(),
  assigned_type: z.enum(['ai', 'human']).optional()
});

export class DataValidator implements IDataValidator {
  private readonly logger: Logger;

  // Allowed fields for each table to prevent injection
  private readonly allowedFields: Record<string, string[]> = {
    companies: [
      'business_id', 'name', 'domain', 'industry', 'size_range', 'revenue_range',
      'ai_summary', 'ai_pain_points', 'ai_icp_score', 'technologies', 'funding',
      'news', 'social_profiles', 'created_at', 'updated_at'
    ],
    contacts: [
      'business_id', 'company_id', 'email', 'phone', 'first_name', 'last_name',
      'title', 'seniority_level', 'department', 'linkedin_url', 'ai_personality',
      'ai_communication_style', 'ai_interests', 'verified_phone', 'verified_email',
      'timezone', 'preferred_contact_method', 'created_at', 'updated_at'
    ],
    leads: [
      'business_id', 'contact_id', 'company_id', 'source', 'source_campaign',
      'status', 'ai_qualification_score', 'ai_qualification_summary',
      'ai_next_best_action', 'ai_predicted_value', 'ai_close_probability',
      'ai_estimated_close_date', 'assigned_to', 'assigned_type', 'created_at', 'updated_at'
    ],
    ai_tasks: [
      'business_id', 'type', 'priority', 'payload', 'assigned_agent',
      'scheduled_at', 'expires_at', 'status', 'created_at', 'updated_at'
    ],
    conversations: [
      'business_id', 'lead_id', 'contact_id', 'type', 'direction',
      'participant_type', 'subject', 'transcript', 'duration_seconds',
      'external_id', 'ai_summary', 'ai_sentiment', 'ai_objections',
      'ai_commitments', 'ai_next_steps', 'created_at', 'updated_at'
    ]
  };

  constructor() {
    this.logger = new Logger();
  }

  validateLead(lead: CreateLead): { success: boolean; error?: string } {
    try {
      CreateLeadSchema.parse(lead);

      // Additional business logic validation
      const validationResult = this.validateBusinessRules(lead, 'lead');
      if (!validationResult.success) {
        return validationResult;
      }

      return { success: true };
    } catch (error: any) {
      this.logger.warn('Lead validation failed', {
        error: error.message,
        leadData: this.sanitizeForLogging(lead)
      });
      return {
        success: false,
        error: `Lead validation failed: ${error.message}`
      };
    }
  }

  validateContact(contact: CreateContact): { success: boolean; error?: string } {
    try {
      CreateContactSchema.parse(contact);

      // Additional business logic validation
      const validationResult = this.validateBusinessRules(contact, 'contact');
      if (!validationResult.success) {
        return validationResult;
      }

      // Email format validation
      if (!this.isValidEmail(contact.email)) {
        return {
          success: false,
          error: 'Invalid email format'
        };
      }

      // Phone validation if provided
      if (contact.phone && !this.isValidPhone(contact.phone)) {
        return {
          success: false,
          error: 'Invalid phone format'
        };
      }

      return { success: true };
    } catch (error: any) {
      this.logger.warn('Contact validation failed', {
        error: error.message,
        contactData: this.sanitizeForLogging(contact)
      });
      return {
        success: false,
        error: `Contact validation failed: ${error.message}`
      };
    }
  }

  validateCompany(company: CreateCompany): { success: boolean; error?: string } {
    try {
      CreateCompanySchema.parse(company);

      // Additional business logic validation
      const validationResult = this.validateBusinessRules(company, 'company');
      if (!validationResult.success) {
        return validationResult;
      }

      // Domain validation if provided
      if (company.domain && !this.isValidDomain(company.domain)) {
        return {
          success: false,
          error: 'Invalid domain format'
        };
      }

      // ICP score validation
      if (company.ai_icp_score !== undefined &&
          (company.ai_icp_score < 0 || company.ai_icp_score > 100)) {
        return {
          success: false,
          error: 'ICP score must be between 0 and 100'
        };
      }

      return { success: true };
    } catch (error: any) {
      this.logger.warn('Company validation failed', {
        error: error.message,
        companyData: this.sanitizeForLogging(company)
      });
      return {
        success: false,
        error: `Company validation failed: ${error.message}`
      };
    }
  }

  sanitizeFields(fields: string[], tableName: string): string[] {
    const tableFields = this.allowedFields[tableName];
    if (!tableFields) {
      this.logger.error('Unknown table for field sanitization', { tableName });
      throw new Error(`Unknown table: ${tableName}`);
    }

    const sanitizedFields = fields.filter(field => {
      // Only allow alphanumeric characters and underscores
      const isValidFormat = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(field);
      const isAllowedField = tableFields.includes(field);

      if (!isValidFormat || !isAllowedField) {
        this.logger.warn('Invalid field name rejected', {
          field,
          tableName,
          operation: 'sanitizeFields'
        });
        return false;
      }

      return true;
    });

    if (sanitizedFields.length === 0) {
      throw new Error(`No valid fields provided for table: ${tableName}`);
    }

    return sanitizedFields;
  }

  // Batch validation methods
  validateLeadBatch(leads: CreateLead[]): {
    valid: CreateLead[];
    invalid: Array<{ lead: CreateLead; error: string; index: number }>
  } {
    const valid: CreateLead[] = [];
    const invalid: Array<{ lead: CreateLead; error: string; index: number }> = [];

    leads.forEach((lead, index) => {
      const validation = this.validateLead(lead);
      if (validation.success) {
        valid.push(lead);
      } else {
        invalid.push({
          lead,
          error: validation.error || 'Validation failed',
          index
        });
      }
    });

    this.logger.info('Batch lead validation completed', {
      totalLeads: leads.length,
      validLeads: valid.length,
      invalidLeads: invalid.length
    });

    return { valid, invalid };
  }

  validateContactBatch(contacts: CreateContact[]): {
    valid: CreateContact[];
    invalid: Array<{ contact: CreateContact; error: string; index: number }>
  } {
    const valid: CreateContact[] = [];
    const invalid: Array<{ contact: CreateContact; error: string; index: number }> = [];

    contacts.forEach((contact, index) => {
      const validation = this.validateContact(contact);
      if (validation.success) {
        valid.push(contact);
      } else {
        invalid.push({
          contact,
          error: validation.error || 'Validation failed',
          index
        });
      }
    });

    this.logger.info('Batch contact validation completed', {
      totalContacts: contacts.length,
      validContacts: valid.length,
      invalidContacts: invalid.length
    });

    return { valid, invalid };
  }

  validateCompanyBatch(companies: CreateCompany[]): {
    valid: CreateCompany[];
    invalid: Array<{ company: CreateCompany; error: string; index: number }>
  } {
    const valid: CreateCompany[] = [];
    const invalid: Array<{ company: CreateCompany; error: string; index: number }> = [];

    companies.forEach((company, index) => {
      const validation = this.validateCompany(company);
      if (validation.success) {
        valid.push(company);
      } else {
        invalid.push({
          company,
          error: validation.error || 'Validation failed',
          index
        });
      }
    });

    this.logger.info('Batch company validation completed', {
      totalCompanies: companies.length,
      validCompanies: valid.length,
      invalidCompanies: invalid.length
    });

    return { valid, invalid };
  }

  // Utility validation methods
  private validateBusinessRules(data: any, type: string): { success: boolean; error?: string } {
    // Business ID is required for all entities
    if (!data.business_id || typeof data.business_id !== 'string') {
      return {
        success: false,
        error: 'Business ID is required and must be a string'
      };
    }

    // Validate business ID format (UUID-like)
    if (!this.isValidBusinessId(data.business_id)) {
      return {
        success: false,
        error: 'Invalid business ID format'
      };
    }

    // Type-specific validations
    switch (type) {
      case 'lead':
        return this.validateLeadBusinessRules(data);
      case 'contact':
        return this.validateContactBusinessRules(data);
      case 'company':
        return this.validateCompanyBusinessRules(data);
      default:
        return { success: true };
    }
  }

  private validateLeadBusinessRules(lead: CreateLead): { success: boolean; error?: string } {
    // Source is required
    if (!lead.source || lead.source.trim().length === 0) {
      return {
        success: false,
        error: 'Source is required for leads'
      };
    }

    // AI qualification score validation
    if (lead.ai_qualification_score !== undefined) {
      if (lead.ai_qualification_score < 0 || lead.ai_qualification_score > 100) {
        return {
          success: false,
          error: 'AI qualification score must be between 0 and 100'
        };
      }
    }

    // Close probability validation
    if (lead.ai_close_probability !== undefined) {
      if (lead.ai_close_probability < 0 || lead.ai_close_probability > 1) {
        return {
          success: false,
          error: 'Close probability must be between 0 and 1'
        };
      }
    }

    return { success: true };
  }

  private validateContactBusinessRules(contact: CreateContact): { success: boolean; error?: string } {
    // Email is required
    if (!contact.email || contact.email.trim().length === 0) {
      return {
        success: false,
        error: 'Email is required for contacts'
      };
    }

    return { success: true };
  }

  private validateCompanyBusinessRules(company: CreateCompany): { success: boolean; error?: string } {
    // Name is required
    if (!company.name || company.name.trim().length === 0) {
      return {
        success: false,
        error: 'Name is required for companies'
      };
    }

    // Name length validation
    if (company.name.length > 255) {
      return {
        success: false,
        error: 'Company name must be 255 characters or less'
      };
    }

    return { success: true };
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
  }

  private isValidPhone(phone: string): boolean {
    // Allow various phone formats
    const phoneRegex = /^[\+]?[\d\s\-\(\)]{7,20}$/;
    return phoneRegex.test(phone);
  }

  private isValidDomain(domain: string): boolean {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$/;
    return domainRegex.test(domain) && domain.length <= 255;
  }

  private isValidBusinessId(businessId: string): boolean {
    // Allow UUID format or alphanumeric IDs
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const alphanumericRegex = /^[a-zA-Z0-9_-]{8,64}$/;

    return uuidRegex.test(businessId) || alphanumericRegex.test(businessId);
  }

  private sanitizeForLogging(data: any): any {
    // Remove sensitive fields from logging
    const sanitized = { ...data };
    const sensitiveFields = ['email', 'phone', 'linkedin_url'];

    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  // SQL injection prevention
  validateSQLSafety(value: string): boolean {
    const forbiddenPatterns = [
      /;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/i,
      /--/,
      /\/\*/,
      /\*\//,
      /xp_cmdshell/i,
      /sp_executesql/i,
      /<script/i,
      /javascript:/i
    ];

    return !forbiddenPatterns.some(pattern => pattern.test(value));
  }

  // XSS prevention
  validateXSSSafety(value: string): boolean {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i
    ];

    return !xssPatterns.some(pattern => pattern.test(value));
  }

  // General data sanitization
  sanitizeString(value: string, maxLength: number = 1000): string {
    if (typeof value !== 'string') {
      return '';
    }

    return value
      .trim()
      .substring(0, maxLength)
      .replace(/[\x00-\x1F\x7F]/g, ''); // Remove control characters
  }

  // Validation for updates (partial data)
  validatePartialUpdate(data: Partial<any>, allowedFields: string[]): { success: boolean; error?: string } {
    const providedFields = Object.keys(data);

    if (providedFields.length === 0) {
      return {
        success: false,
        error: 'No data provided for update'
      };
    }

    const invalidFields = providedFields.filter(field => !allowedFields.includes(field));
    if (invalidFields.length > 0) {
      return {
        success: false,
        error: `Invalid fields for update: ${invalidFields.join(', ')}`
      };
    }

    return { success: true };
  }
}