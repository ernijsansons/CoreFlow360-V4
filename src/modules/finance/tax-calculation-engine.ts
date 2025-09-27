/**
 * Tax Calculation Engine
 * Advanced tax calculations for invoices with support for multiple tax types
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  TaxRate,
  TaxType,
  InvoiceLine,
  TaxLine,
  InvoiceAddress
} from './types';
import { validateBusinessId, roundToCurrency } from './utils';

export interface TaxCalculationResult {
  totalTax: number;
  taxLines: TaxLine[];
  lineTaxes: Array<{
    lineId: string;
    taxAmount: number;
    taxRates: Array<{
      taxRateId: string;
      taxRate: number;
      taxAmount: number;
    }>;
  }>;
}

export interface TaxJurisdiction {
  id: string;
  name: string;
  code: string;
  type: 'country' | 'state' | 'province' | 'city' | 'district';
  parentId?: string;
  taxRates: TaxRate[];
  businessId: string;
}

export class TaxCalculationEngine {
  private logger: Logger;
  private db: D1Database;
  private taxCache = new Map<string, TaxRate[]>();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Calculate taxes for invoice lines
   */
  async calculateInvoiceTaxes(
    lines: InvoiceLine[],
    businessId: string,
    shippingAddress?: InvoiceAddress,
    billingAddress?: InvoiceAddress
  ): Promise<TaxCalculationResult> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const taxLines: TaxLine[] = [];
      const lineTaxes: TaxCalculationResult['lineTaxes'] = [];
      let totalTax = 0;

      for (const line of lines) {
        const lineTaxResult = await this.calculateLineTax(
          line,
          validBusinessId,
          shippingAddress,
          billingAddress
        );

        lineTaxes.push(lineTaxResult);
        totalTax += lineTaxResult.taxAmount;

        // Create tax lines for each tax rate applied
        for (const taxRate of lineTaxResult.taxRates) {
          let existingTaxLine = taxLines.find(tl =>
            tl.taxRateId === taxRate.taxRateId &&
            tl.invoiceId === line.invoiceId
          );

          if (existingTaxLine) {
            existingTaxLine.taxableAmount += line.taxableAmount;
            existingTaxLine.taxAmount += taxRate.taxAmount;
          } else {
            const taxRateDetails = await this.getTaxRate(taxRate.taxRateId, validBusinessId);
            if (taxRateDetails) {
              taxLines.push({
                id: `tax_${line.invoiceId}_${taxRate.taxRateId}`,
                invoiceId: line.invoiceId,
                taxRateId: taxRate.taxRateId,
                taxName: taxRateDetails.name,
                taxRate: taxRateDetails.rate,
                taxableAmount: line.taxableAmount,
                taxAmount: taxRate.taxAmount,
                accountId: taxRateDetails.accountId
              });
            }
          }
        }
      }

      return {
        totalTax: roundToCurrency(totalTax),
        taxLines,
        lineTaxes
      };

    } catch (error: any) {
      this.logger.error('Failed to calculate invoice taxes', error, {
        lineCount: lines.length,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Calculate tax for a single line
   */
  async calculateLineTax(
    line: InvoiceLine,
    businessId: string,
    shippingAddress?: InvoiceAddress,
    billingAddress?: InvoiceAddress
  ): Promise<{
    lineId: string;
    taxAmount: number;
    taxRates: Array<{
      taxRateId: string;
      taxRate: number;
      taxAmount: number;
    }>;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      let applicableTaxRates: TaxRate[] = [];

      // If specific tax rate is specified for the line
      if (line.taxRateId) {
        const taxRate = await this.getTaxRate(line.taxRateId, validBusinessId);
        if (taxRate && taxRate.isActive) {
          applicableTaxRates = [taxRate];
        }
      } else {
        // Determine applicable tax rates based on jurisdiction
        applicableTaxRates = await this.determineApplicableTaxRates(
          validBusinessId,
          shippingAddress || billingAddress,
          line.productId
        );
      }

      const taxRateResults = [];
      let totalLineTax = 0;

      for (const taxRate of applicableTaxRates) {
        const taxAmount = this.calculateTaxAmount(line.taxableAmount, taxRate);
        totalLineTax += taxAmount;

        taxRateResults.push({
          taxRateId: taxRate.id,
          taxRate: taxRate.rate,
          taxAmount
        });
      }

      return {
        lineId: line.id,
        taxAmount: roundToCurrency(totalLineTax),
        taxRates: taxRateResults
      };

    } catch (error: any) {
      this.logger.error('Failed to calculate line tax', error, {
        lineId: line.id,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Calculate tax amount based on tax rate and amount
   */
  private calculateTaxAmount(taxableAmount: number, taxRate: TaxRate): number {
    switch (taxRate.type) {
      case TaxType.SALES_TAX:
      case TaxType.VAT:
      case TaxType.GST:
        return taxableAmount * (taxRate.rate / 100);

      case TaxType.EXCISE_TAX:
        // For excise tax, rate might be per unit
        return taxableAmount * (taxRate.rate / 100);

      case TaxType.CUSTOM:
        // Custom tax logic can be implemented here
        return taxableAmount * (taxRate.rate / 100);

      default:
        return taxableAmount * (taxRate.rate / 100);
    }
  }

  /**
   * Determine applicable tax rates based on jurisdiction and product
   */
  async determineApplicableTaxRates(
    businessId: string,
    address?: InvoiceAddress,
    productId?: string
  ): Promise<TaxRate[]> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Get business tax configuration
      const businessConfig = await this.getBusinessTaxConfiguration(validBusinessId);

      if (!address && businessConfig.defaultTaxRateId) {
        // Use default tax rate if no address provided
        const defaultTaxRate = await this.getTaxRate(businessConfig.defaultTaxRateId, validBusinessId);
        return defaultTaxRate ? [defaultTaxRate] : [];
      }

      if (!address) {
        return [];
      }

      // Determine jurisdiction based on address
      const jurisdiction = await this.determineJurisdiction(address, validBusinessId);

      if (!jurisdiction) {
        return [];
      }

      // Get applicable tax rates for jurisdiction
      let taxRates = await this.getTaxRatesForJurisdiction(jurisdiction.id, validBusinessId);

      // Filter by product type if applicable
      if (productId) {
        taxRates = await this.filterTaxRatesByProduct(taxRates, productId, validBusinessId);
      }

      // Filter by effective dates
      const now = Date.now();
      taxRates = taxRates.filter((rate: any) =>
        rate.isActive &&
        rate.effectiveDate <= now &&
        (!rate.expiryDate || rate.expiryDate > now)
      );

      return taxRates;

    } catch (error: any) {
      this.logger.error('Failed to determine applicable tax rates', error, {
        businessId: validBusinessId,
        address
      });
      return [];
    }
  }

  /**
   * Determine tax jurisdiction from address
   */
  async determineJurisdiction(
    address: InvoiceAddress,
    businessId: string
  ): Promise<TaxJurisdiction | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Simple jurisdiction lookup based on country/state
      const result = await this.db.prepare(`
        SELECT * FROM tax_jurisdictions
        WHERE business_id = ?
        AND (
          (type = 'country' AND LOWER(code) = LOWER(?)) OR
          (type = 'state' AND LOWER(code) = LOWER(?))
        )
        ORDER BY type DESC
        LIMIT 1
      `).bind(
        validBusinessId,
        address.country,
        address.state || ''
      ).first();

      if (!result) {
        return null;
      }

      return this.mapToTaxJurisdiction(result);

    } catch (error: any) {
      this.logger.error('Failed to determine jurisdiction', error, {
        address,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * Get tax rates for jurisdiction
   */
  async getTaxRatesForJurisdiction(
    jurisdictionId: string,
    businessId: string
  ): Promise<TaxRate[]> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM tax_rates
        WHERE business_id = ? AND jurisdiction = ?
        ORDER BY rate DESC
      `).bind(validBusinessId, jurisdictionId).all();

      return (result.results || []).map((row: any) => this.mapToTaxRate(row));

    } catch (error: any) {
      this.logger.error('Failed to get tax rates for jurisdiction', error, {
        jurisdictionId,
        businessId: validBusinessId
      });
      return [];
    }
  }

  /**
   * Filter tax rates by product
   */
  async filterTaxRatesByProduct(
    taxRates: TaxRate[],
    productId: string,
    businessId: string
  ): Promise<TaxRate[]> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Get product information and its category
      const productResult = await this.db.prepare(`
        SELECT p.*, pc.tax_category as category_tax_category
        FROM products p
        LEFT JOIN product_categories pc ON p.category_id = pc.id
        WHERE p.id = ? AND p.business_id = ? AND p.is_active = 1
      `).bind(productId, validBusinessId).first();

      if (!productResult) {
        // If product not found, return all tax rates (default behavior)
        return taxRates;
      }

      const product = {
        id: productResult.id as string,
        taxCategory: productResult.tax_category as string || productResult.category_tax_category as string,
        categoryId: productResult.category_id as string
      };

      // Get tax exemptions for this product
      const exemptionsResult = await this.db.prepare(`
        SELECT tax_rate_id, tax_type
        FROM tax_exemptions
        WHERE (product_id = ? OR product_category_id = ?)
        AND business_id = ?
        AND is_active = 1
        AND effective_date <= ?
        AND (expiry_date IS NULL OR expiry_date > ?)
      `).bind(
        productId,
        product.categoryId,
        validBusinessId,
        Date.now(),
        Date.now()
      ).all();

      const exemptTaxRateIds = new Set(
        (exemptionsResult.results || []).map((row: any) => row.tax_rate_id as string)
      );

      // Get specific tax rate mappings for this product
      const mappingsResult = await this.db.prepare(`
        SELECT ptr.tax_rate_id, ptr.is_exempt
        FROM product_tax_rates ptr
        WHERE (ptr.product_id = ? OR ptr.product_category_id = ?)
        AND ptr.business_id = ?
        AND ptr.effective_date <= ?
        AND (ptr.expiry_date IS NULL OR ptr.expiry_date > ?)
      `).bind(
        productId,
        product.categoryId,
        validBusinessId,
        Date.now(),
        Date.now()
      ).all();

      const taxRateMappings = new Map<string, boolean>();
      for (const row of mappingsResult.results || []) {
        taxRateMappings.set(row.tax_rate_id as string, (row.is_exempt as number) === 1);
      }

      // Filter tax rates based on product-specific rules
      const filteredRates = taxRates.filter((rate: any) => {
        // Check if this tax rate is specifically exempted
        if (exemptTaxRateIds.has(rate.id)) {
          return false;
        }

        // Check specific mappings
        if (taxRateMappings.has(rate.id)) {
          return !taxRateMappings.get(rate.id); // Return false if exempt, true if not exempt
        }

        // Apply category-based filtering
        if (product.taxCategory) {
          switch (product.taxCategory) {
            case 'exempt':
              return false; // Exempt products don't get any tax rates
            case 'reduced_rate':
              return rate.type === 'VAT' || rate.type === 'GST' || rate.rate <= 10; // Only reduced rates
            case 'exempt_or_reduced':
              return rate.rate <= 10; // Only low rates
            case 'special':
             
  return rate.type === 'SALES_TAX' || rate.jurisdiction === 'digital'; // Special handling for digital products
            case 'standard_or_higher':
              return true; // All rates apply
            case 'standard':
            default:
              return rate.type !== 'EXCISE_TAX'; // Standard rates, exclude excise
          }
        }

        // Default: return all rates if no specific rules apply
        return true;
      });

      this.logger.info('Filtered tax rates by product', {
        productId,
        originalCount: taxRates.length,
        filteredCount: filteredRates.length,
        taxCategory: product.taxCategory
      });

      return filteredRates;

    } catch (error: any) {
      this.logger.error('Failed to filter tax rates by product', error, {
        productId,
        businessId: validBusinessId
      });
      // Return all rates on error to avoid breaking tax calculation
      return taxRates;
    }
  }

  /**
   * Get single tax rate
   */
  async getTaxRate(taxRateId: string, businessId: string): Promise<TaxRate | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Check cache first
      const cacheKey = `${validBusinessId}:${taxRateId}`;
      if (this.taxCache.has(cacheKey)) {
        const cachedRates = this.taxCache.get(cacheKey)!;
        return cachedRates[0] || null;
      }

      const result = await this.db.prepare(`
        SELECT * FROM tax_rates
        WHERE id = ? AND business_id = ?
      `).bind(taxRateId, validBusinessId).first();

      if (!result) {
        return null;
      }

      const taxRate = this.mapToTaxRate(result);

      // Cache the result
      this.taxCache.set(cacheKey, [taxRate]);

      return taxRate;

    } catch (error: any) {
      this.logger.error('Failed to get tax rate', error, {
        taxRateId,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * Create tax rate
   */
  async createTaxRate(
    taxRate: Omit<TaxRate, 'id'>,
    createdBy: string,
    businessId: string
  ): Promise<TaxRate> {
    const validBusinessId = validateBusinessId(businessId);
    const now = Date.now();

    try {
      const taxRateId = `tax_${now}_${Math.random().toString(36).substring(2, 9)}`;

      const newTaxRate: TaxRate = {
        ...taxRate,
        id: taxRateId,
        businessId: validBusinessId
      };

      await this.db.prepare(`
        INSERT INTO tax_rates (
          id, name, rate, type, jurisdiction, account_id,
          is_active, effective_date, expiry_date, business_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        taxRateId,
        taxRate.name,
        taxRate.rate,
        taxRate.type,
        taxRate.jurisdiction,
        taxRate.accountId,
        taxRate.isActive ? 1 : 0,
        taxRate.effectiveDate,
        taxRate.expiryDate || null,
        validBusinessId
      ).run();

      // Clear cache
      this.clearTaxCache(validBusinessId);

      this.logger.info('Tax rate created', {
        taxRateId,
        name: taxRate.name,
        rate: taxRate.rate,
        businessId: validBusinessId
      });

      return newTaxRate;

    } catch (error: any) {
      this.logger.error('Failed to create tax rate', error, {
        name: taxRate.name,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Update tax rate
   */
  async updateTaxRate(
    taxRateId: string,
    updates: Partial<TaxRate>,
    updatedBy: string,
    businessId: string
  ): Promise<TaxRate> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const existingTaxRate = await this.getTaxRate(taxRateId, validBusinessId);
      if (!existingTaxRate) {
        throw new Error('Tax rate not found');
      }

      const updatedTaxRate = { ...existingTaxRate, ...updates };

      await this.db.prepare(`
        UPDATE tax_rates
        SET name = ?, rate = ?, type = ?, jurisdiction = ?, account_id = ?,
            is_active = ?, effective_date = ?, expiry_date = ?
        WHERE id = ? AND business_id = ?
      `).bind(
        updatedTaxRate.name,
        updatedTaxRate.rate,
        updatedTaxRate.type,
        updatedTaxRate.jurisdiction,
        updatedTaxRate.accountId,
        updatedTaxRate.isActive ? 1 : 0,
        updatedTaxRate.effectiveDate,
        updatedTaxRate.expiryDate || null,
        taxRateId,
        validBusinessId
      ).run();

      // Clear cache
      this.clearTaxCache(validBusinessId);

      this.logger.info('Tax rate updated', {
        taxRateId,
        businessId: validBusinessId
      });

      return updatedTaxRate;

    } catch (error: any) {
      this.logger.error('Failed to update tax rate', error, {
        taxRateId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get business tax configuration
   */
  private async getBusinessTaxConfiguration(businessId: string): Promise<{
    defaultTaxRateId?: string;
    taxCalculationMethod: 'line' | 'total';
    roundingMethod: 'standard' | 'up' | 'down';
  }> {
    const result = await this.db.prepare(`
      SELECT default_tax_rate_id, tax_calculation_method, tax_rounding_method
      FROM finance_config
      WHERE business_id = ?
    `).bind(businessId).first();

    return {
      defaultTaxRateId: result?.default_tax_rate_id as string || undefined,
      taxCalculationMethod: (result?.tax_calculation_method as 'line' | 'total') || 'line',
      roundingMethod: (result?.tax_rounding_method as 'standard' | 'up' | 'down') || 'standard'
    };
  }

  /**
   * Clear tax cache for business
   */
  private clearTaxCache(businessId: string): void {
    for (const key of this.taxCache.keys()) {
      if (key.startsWith(`${businessId}:`)) {
        this.taxCache.delete(key);
      }
    }
  }

  /**
   * Map database row to TaxRate
   */
  private mapToTaxRate(row: any): TaxRate {
    return {
      id: row.id,
      name: row.name,
      rate: row.rate,
      type: row.type as TaxType,
      jurisdiction: row.jurisdiction,
      accountId: row.account_id,
      isActive: Boolean(row.is_active),
      effectiveDate: row.effective_date,
      expiryDate: row.expiry_date || undefined,
      businessId: row.business_id
    };
  }

  /**
   * Map database row to TaxJurisdiction
   */
  private mapToTaxJurisdiction(row: any): TaxJurisdiction {
    return {
      id: row.id,
      name: row.name,
      code: row.code,
      type: row.type,
      parentId: row.parent_id || undefined,
      taxRates: [], // Will be loaded separately
      businessId: row.business_id
    };
  }
}