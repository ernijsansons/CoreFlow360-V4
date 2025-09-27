/**
 * Tax Calculation Engine
 * Advanced tax calculation with multi-jurisdiction support
 */

import { InvoiceLineItem, TaxConfig } from './types'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export interface TaxJurisdiction {
  id: string
  name: string
  country: string
  state?: string
  county?: string
  city?: string
  taxConfigs: TaxConfig[]
  isActive: boolean
}

export interface TaxCalculationRequest {
  lineItems: InvoiceLineItem[]
  customerAddress: {
    country: string
    state: string
    city: string
    postalCode: string
  }
  businessAddress: {
    country: string
    state: string
    city: string
    postalCode: string
  }
  invoiceDate: string
  exemptions?: {
    customerId?: string
    certificateNumber?: string
    exemptionType: 'resale' | 'nonprofit' | 'government' | 'export'
    validFrom: string
    validTo?: string
  }[]
}

export interface TaxCalculationResult {
  lineItems: (InvoiceLineItem & {
    appliedTaxes: {
      configId: string
      name: string
      rate: number
      amount: number
      jurisdiction: string
    }[]
  })[]
  totalTax: number
  taxSummary: {
    jurisdiction: string
    taxName: string
    taxableAmount: number
    rate: number
    amount: number
  }[]
  exemptionsApplied: string[]
}

export class TaxCalculationEngine {
  private taxJurisdictions: Map<string, TaxJurisdiction> = new Map()
  private taxConfigs: Map<string, TaxConfig> = new Map()

  constructor() {
    this.initializeDefaultTaxConfigs()
  }

  async calculateTaxes(request: TaxCalculationRequest): Promise<TaxCalculationResult> {
    try {
      auditLogger.log({
        action: 'tax_calculation_started',
        metadata: {
          lineItemCount: request.lineItems.length,
          customerCountry: request.customerAddress.country,
          invoiceDate: request.invoiceDate
        }
      })

      // Validate request
      this.validateTaxCalculationRequest(request)

      // Determine applicable tax jurisdictions
      const applicableJurisdictions = await this.determineApplicableJurisdictions(request)

      // Check for exemptions
      const exemptionsApplied = await this.checkTaxExemptions(request, applicableJurisdictions)

      // Calculate taxes for each line item
      const calculatedLineItems = await this.calculateLineItemTaxes(
        request.lineItems,
        applicableJurisdictions,
        exemptionsApplied,
        request.invoiceDate
      )

      // Generate tax summary
      const taxSummary = this.generateTaxSummary(calculatedLineItems)

      // Calculate total tax
      const totalTax = taxSummary.reduce((sum, tax) => sum + tax.amount, 0)

      const result: TaxCalculationResult = {
        lineItems: calculatedLineItems,
        totalTax,
        taxSummary,
        exemptionsApplied: exemptionsApplied.map((e: any) => e.exemptionType)
      }

      auditLogger.log({
        action: 'tax_calculation_completed',
        metadata: {
          totalTax,
          jurisdictionCount: applicableJurisdictions.length,
          exemptionCount: exemptionsApplied.length
        }
      })

      return result

    } catch (error: any) {
      auditLogger.log({
        action: 'tax_calculation_failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Tax calculation failed',
        'TAX_CALCULATION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  private validateTaxCalculationRequest(request: TaxCalculationRequest): void {
    if (!request.lineItems || request.lineItems.length === 0) {
      throw new AppError(
        'Line items are required for tax calculation',
        'INVALID_TAX_REQUEST',
        400
      )
    }

    if (!request.customerAddress || !request.businessAddress) {
      throw new AppError(
        'Customer and business addresses are required',
        'INVALID_TAX_REQUEST',
        400
      )
    }

    if (!request.invoiceDate) {
      throw new AppError(
        'Invoice date is required for tax calculation',
        'INVALID_TAX_REQUEST',
        400
      )
    }

    // Validate each line item
    for (const item of request.lineItems) {
      if (item.quantity <= 0) {
        throw new AppError(
          `Invalid quantity for line item: ${item.description}`,
          'INVALID_LINE_ITEM',
          400
        )
      }

      if (item.unitPrice < 0) {
        throw new AppError(
          `Invalid unit price for line item: ${item.description}`,
          'INVALID_LINE_ITEM',
          400
        )
      }
    }
  }

  private async determineApplicableJurisdictions(
    request: TaxCalculationRequest
  ): Promise<TaxJurisdiction[]> {
    const jurisdictions: TaxJurisdiction[] = []

    // Determine tax nexus based on business and customer locations
    const hasPhysicalNexus = this.checkPhysicalNexus(
      request.businessAddress,
      request.customerAddress
    )

    const hasEconomicNexus = await this.checkEconomicNexus(
      request.customerAddress,
      request.invoiceDate
    )

    if (hasPhysicalNexus || hasEconomicNexus) {
      // Add applicable jurisdictions
      const countryJurisdiction = this.getJurisdictionByLocation(
        request.customerAddress.country
      )
      if (countryJurisdiction) {
        jurisdictions.push(countryJurisdiction)
      }

      const stateJurisdiction = this.getJurisdictionByLocation(
        request.customerAddress.country,
        request.customerAddress.state
      )
      if (stateJurisdiction) {
        jurisdictions.push(stateJurisdiction)
      }

      const localJurisdiction = this.getJurisdictionByLocation(
        request.customerAddress.country,
        request.customerAddress.state,
        request.customerAddress.city
      )
      if (localJurisdiction) {
        jurisdictions.push(localJurisdiction)
      }
    }

    return jurisdictions
  }

  private checkPhysicalNexus(
    businessAddress: TaxCalculationRequest['businessAddress'],
    customerAddress: TaxCalculationRequest['customerAddress']
  ): boolean {
    // Physical nexus exists if business and customer are in same jurisdiction
    return businessAddress.country === customerAddress.country &&
           businessAddress.state === customerAddress.state
  }

  private async checkEconomicNexus(
    customerAddress: TaxCalculationRequest['customerAddress'],
    invoiceDate: string
  ): Promise<boolean> {
    // Economic nexus rules vary by jurisdiction
    // This would typically check sales thresholds and transaction counts
    // For now, return false as a placeholder
    return false
  }

  private getJurisdictionByLocation(
    country: string,
    state?: string,
    city?: string
  ): TaxJurisdiction | undefined {
    // This would typically query the database
    // For now, return mock jurisdictions
    const key = `${country}-${state || ''}-${city || ''}`
    return this.taxJurisdictions.get(key)
  }

  private async checkTaxExemptions(
    request: TaxCalculationRequest,
    jurisdictions: TaxJurisdiction[]
  ): Promise<TaxCalculationRequest['exemptions']> {
    if (!request.exemptions) return []

    const validExemptions: TaxCalculationRequest['exemptions'] = []
    const invoiceDate = new Date(request.invoiceDate)

    for (const exemption of request.exemptions) {
      const validFrom = new Date(exemption.validFrom)
      const validTo = exemption.validTo ? new Date(exemption.validTo) : null

      // Check if exemption is valid for the invoice date
      if (invoiceDate >= validFrom && (!validTo || invoiceDate <= validTo)) {
        // Verify exemption certificate (would typically call external service)
        const isValid = await this.verifyExemptionCertificate(exemption)
        if (isValid) {
          validExemptions.push(exemption)
        }
      }
    }

    return validExemptions
  }

  private async verifyExemptionCertificate(
    exemption: NonNullable<TaxCalculationRequest['exemptions']>[0]
  ): Promise<boolean> {
    // This would typically verify with external tax authority
    // For now, return true as a placeholder
    return true
  }

  private async calculateLineItemTaxes(
    lineItems: InvoiceLineItem[],
    jurisdictions: TaxJurisdiction[],
    exemptions: TaxCalculationRequest['exemptions'],
    invoiceDate: string
  ): Promise<TaxCalculationResult['lineItems']> {
    const calculatedItems: TaxCalculationResult['lineItems'] = []

    for (const item of lineItems) {
      const itemWithTaxes = {
        ...item,
        appliedTaxes: [] as TaxCalculationResult['lineItems'][0]['appliedTaxes']
      }

      // Calculate taxable amount (after discounts)
      let taxableAmount = item.quantity * item.unitPrice
      if (item.discountAmount > 0) {
        taxableAmount -= item.discountAmount
      } else if (item.discountPercentage > 0) {
        taxableAmount -= taxableAmount * (item.discountPercentage / 100)
      }

      let totalItemTax = 0

      for (const jurisdiction of jurisdictions) {
        // Check if any exemptions apply
        const isExempt = exemptions.some(exemption =>
          this.isExemptionApplicable(exemption, jurisdiction, item)
        )

        if (!isExempt) {
          for (const taxConfig of jurisdiction.taxConfigs) {
            // Check if tax config is valid for the invoice date
            if (this.isTaxConfigValid(taxConfig, invoiceDate)) {
              const taxAmount = this.calculateTaxAmount(
                taxableAmount,
                taxConfig,
                totalItemTax
              )

              if (taxAmount > 0) {
                itemWithTaxes.appliedTaxes.push({
                  configId: taxConfig.id,
                  name: taxConfig.name,
                  rate: taxConfig.rate,
                  amount: taxAmount,
                  jurisdiction: jurisdiction.name
                })

                totalItemTax += taxAmount
              }
            }
          }
        }
      }

      // Update item with calculated tax
      itemWithTaxes.taxAmount = totalItemTax
      itemWithTaxes.lineTotal = taxableAmount + totalItemTax

      calculatedItems.push(itemWithTaxes)
    }

    return calculatedItems
  }

  private isExemptionApplicable(
    exemption: NonNullable<TaxCalculationRequest['exemptions']>[0],
    jurisdiction: TaxJurisdiction,
    item: InvoiceLineItem
  ): boolean {
    // Exemption rules vary by type and jurisdiction
    switch (exemption.exemptionType) {
      case 'resale':
        // Resale exemptions typically apply to all items
        return true
      case 'nonprofit':
        // Nonprofit exemptions may have restrictions
        return true
      case 'government':
        // Government exemptions typically apply to all items
        return true
      case 'export':
        // Export exemptions apply when shipping outside jurisdiction
        return true
      default:
        return false
    }
  }

  private isTaxConfigValid(taxConfig: TaxConfig, invoiceDate: string): boolean {
    const invoiceDateObj = new Date(invoiceDate)
    const validFrom = new Date(taxConfig.validFrom)
    const validTo = taxConfig.validTo ? new Date(taxConfig.validTo) : null

    return invoiceDateObj >= validFrom && (!validTo || invoiceDateObj <= validTo)
  }

  private calculateTaxAmount(
    taxableAmount: number,
    taxConfig: TaxConfig,
    existingTax: number
  ): number {
    if (taxConfig.isCompound) {
      // Compound tax is calculated on taxable amount plus existing tax
      return (taxableAmount + existingTax) * taxConfig.rate
    } else {
      // Simple tax is calculated only on taxable amount
      return taxableAmount * taxConfig.rate
    }
  }

  private generateTaxSummary(
    lineItems: TaxCalculationResult['lineItems']
  ): TaxCalculationResult['taxSummary'] {
    const summaryMap = new Map<string, TaxCalculationResult['taxSummary'][0]>()

    for (const item of lineItems) {
      for (const tax of item.appliedTaxes) {
        const key = `${tax.jurisdiction}-${tax.name}`
        const existing = summaryMap.get(key)

        if (existing) {
          existing.taxableAmount += (item.quantity * item.unitPrice) -
            (item.discountAmount || (item.quantity * item.unitPrice * (item.discountPercentage || 0) / 100))
          existing.amount += tax.amount
        } else {
          summaryMap.set(key, {
            jurisdiction: tax.jurisdiction,
            taxName: tax.name,
            taxableAmount: (item.quantity * item.unitPrice) -
              (item.discountAmount || (item.quantity * item.unitPrice * (item.discountPercentage || 0) / 100)),
            rate: tax.rate,
            amount: tax.amount
          })
        }
      }
    }

    return Array.from(summaryMap.values())
  }

  private initializeDefaultTaxConfigs(): void {
    // Initialize with common tax configurations
    // This would typically load from database

    // US Sales Tax Examples
    const usSalesTax: TaxConfig = {
      id: '1',
      name: 'Sales Tax',
      rate: 0.0875, // 8.75%
      isCompound: false,
      isInclusive: false,
      applicableCountries: ['US'],
      validFrom: '2023-01-01T00:00:00Z'
    }

    const canadaGST: TaxConfig = {
      id: '2',
      name: 'GST',
      rate: 0.05, // 5%
      isCompound: false,
      isInclusive: false,
      applicableCountries: ['CA'],
      validFrom: '2023-01-01T00:00:00Z'
    }

    const canadaPST: TaxConfig = {
      id: '3',
      name: 'PST',
      rate: 0.07, // 7%
      isCompound: false,
      isInclusive: false,
      applicableCountries: ['CA'],
      validFrom: '2023-01-01T00:00:00Z'
    }

    this.taxConfigs.set('1', usSalesTax)
    this.taxConfigs.set('2', canadaGST)
    this.taxConfigs.set('3', canadaPST)

    // Create mock jurisdictions
    const usJurisdiction: TaxJurisdiction = {
      id: 'us-ca-sf',
      name: 'San Francisco, CA, US',
      country: 'US',
      state: 'CA',
      city: 'San Francisco',
      taxConfigs: [usSalesTax],
      isActive: true
    }

    const canadaJurisdiction: TaxJurisdiction = {
      id: 'ca-bc-vancouver',
      name: 'Vancouver, BC, CA',
      country: 'CA',
      state: 'BC',
      city: 'Vancouver',
      taxConfigs: [canadaGST, canadaPST],
      isActive: true
    }

    this.taxJurisdictions.set('US-CA-San Francisco', usJurisdiction)
    this.taxJurisdictions.set('CA-BC-Vancouver', canadaJurisdiction)
  }

  // Public methods for tax configuration management
  async getTaxConfigs(filters?: {
    country?: string
    state?: string
    isActive?: boolean
  }): Promise<TaxConfig[]> {
    let configs = Array.from(this.taxConfigs.values())

    if (filters) {
      if (filters.country) {
        configs = configs.filter((config: any) =>
          config.applicableCountries?.includes(filters.country!)
        )
      }

      if (filters.isActive !== undefined) {
        // Filter based on validity dates
        const now = new Date()
        configs = configs.filter((config: any) => {
          const validFrom = new Date(config.validFrom)
          const validTo = config.validTo ? new Date(config.validTo) : null
          return now >= validFrom && (!validTo || now <= validTo)
        })
      }
    }

    return configs
  }

  async createTaxConfig(config: Omit<TaxConfig, 'id'>): Promise<TaxConfig> {
    const id = this.generateTaxConfigId()
    const newConfig: TaxConfig = { ...config, id }

    this.taxConfigs.set(id, newConfig)

    auditLogger.log({
      action: 'tax_config_created',
      metadata: { configId: id, name: config.name, rate: config.rate }
    })

    return newConfig
  }

  private generateTaxConfigId(): string {
    return `tax_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
}