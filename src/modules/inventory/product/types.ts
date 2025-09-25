/**
 * Product and SKU Management Types
 * Comprehensive type definitions for inventory and product management
 */

import { z } from 'zod'

// Core Product Types
export enum ProductType {
  PHYSICAL = 'physical',
  DIGITAL = 'digital',
  SERVICE = 'service',
  SUBSCRIPTION = 'subscription',
  BUNDLE = 'bundle',
  VARIANT = 'variant'
}

export enum ProductStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  DRAFT = 'draft',
  ARCHIVED = 'archived',
  DISCONTINUED = 'discontinued'
}

export enum StockStatus {
  IN_STOCK = 'in_stock',
  LOW_STOCK = 'low_stock',
  OUT_OF_STOCK = 'out_of_stock',
  BACKORDER = 'backorder',
  PREORDER = 'preorder',
  DISCONTINUED = 'discontinued'
}

export enum UnitOfMeasure {
  PIECE = 'piece',
  KILOGRAM = 'kg',
  GRAM = 'g',
  POUND = 'lb',
  OUNCE = 'oz',
  LITER = 'l',
  MILLILITER = 'ml',
  GALLON = 'gal',
  METER = 'm',
  CENTIMETER = 'cm',
  INCH = 'in',
  FOOT = 'ft',
  SQUARE_METER = 'sqm',
  SQUARE_FOOT = 'sqft',
  CUBIC_METER = 'cbm',
  CUBIC_FOOT = 'cbft',
  HOUR = 'hour',
  DAY = 'day',
  MONTH = 'month'
}

export enum TaxCategory {
  STANDARD = 'standard',
  REDUCED = 'reduced',
  ZERO_RATED = 'zero_rated',
  EXEMPT = 'exempt',
  DIGITAL_SERVICES = 'digital_services',
  FOOD_BEVERAGE = 'food_beverage',
  MEDICAL = 'medical',
  BOOKS = 'books',
  CLOTHING = 'clothing'
}

// Product Dimension and Weight Schema
export const DimensionsSchema = z.object({
  length: z.number().positive(),
  width: z.number().positive(),
  height: z.number().positive(),
  unit: z.enum(['cm', 'in', 'm', 'ft']).default('cm'),
  weight: z.number().positive(),
  weightUnit: z.enum(['g', 'kg', 'lb', 'oz']).default('kg')
})

// Product Category Schema
export const CategorySchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1, 'Category name is required'),
  description: z.string().optional(),
  parentId: z.string().uuid().optional(),
  path: z.string(), // e.g., "Electronics > Computers > Laptops"
  level: z.number().int().min(0),
  isActive: z.boolean().default(true),
  sortOrder: z.number().int().default(0),
  metadata: z.record(z.unknown()).optional()
})

// Product Attribute Schema
export const AttributeSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  type: z.enum(['text', 'number', 'boolean', 'date', 'enum', 'multi_enum']),
  required: z.boolean().default(false),
  sortOrder: z.number().int().default(0),
  options: z.array(z.object({
    value: z.string(),
    label: z.string(),
    sortOrder: z.number().int().default(0)
  })).optional(),
  validation: z.object({
    min: z.number().optional(),
    max: z.number().optional(),
    pattern: z.string().optional(),
    allowedValues: z.array(z.string()).optional()
  }).optional(),
  metadata: z.record(z.unknown()).optional()
})

// Product Variant Schema
export const VariantSchema = z.object({
  id: z.string().uuid(),
  productId: z.string().uuid(),
  sku: z.string().min(1, 'SKU is required'),
  name: z.string().min(1, 'Variant name is required'),
  description: z.string().optional(),
  attributes: z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.string())])),
  pricing: z.object({
    basePrice: z.number().nonnegative(),
    salePrice: z.number().nonnegative().optional(),
    cost: z.number().nonnegative().optional(),
    currency: z.string().length(3),
    priceAdjustment: z.number().default(0),
    priceAdjustmentType: z.enum(['fixed', 'percentage']).default('fixed')
  }),
  inventory: z.object({
    trackInventory: z.boolean().default(true),
    quantity: z.number().int().nonnegative().default(0),
    reservedQuantity: z.number().int().nonnegative().default(0),
    availableQuantity: z.number().int().nonnegative().default(0),
    reorderPoint: z.number().int().nonnegative().default(10),
    maxStock: z.number().int().nonnegative().optional(),
    locationQuantities: z.record(z.number().int().nonnegative()).optional()
  }),
  dimensions: DimensionsSchema.optional(),
  images: z.array(z.object({
    id: z.string().uuid(),
    url: z.string().url(),
    altText: z.string().optional(),
    isPrimary: z.boolean().default(false),
    sortOrder: z.number().int().default(0)
  })).default([]),
  status: z.nativeEnum(ProductStatus).default(ProductStatus.ACTIVE),
  isActive: z.boolean().default(true),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime().optional(),
  metadata: z.record(z.unknown()).optional()
})

// Main Product Schema
export const ProductSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  name: z.string().min(1, 'Product name is required'),
  description: z.string().optional(),
  shortDescription: z.string().max(255).optional(),
  sku: z.string().min(1, 'SKU is required'),
  barcode: z.string().optional(),
  type: z.nativeEnum(ProductType).default(ProductType.PHYSICAL),
  status: z.nativeEnum(ProductStatus).default(ProductStatus.DRAFT),

  // Category and Classification
  categoryId: z.string().uuid().optional(),
  categoryPath: z.string().optional(),
  tags: z.array(z.string()).default([]),
  brand: z.string().optional(),
  manufacturer: z.string().optional(),
  model: z.string().optional(),

  // Pricing
  pricing: z.object({
    basePrice: z.number().nonnegative('Base price cannot be negative'),
    salePrice: z.number().nonnegative().optional(),
    cost: z.number().nonnegative().optional(),
    currency: z.string().length(3, 'Currency must be 3 characters'),
    taxCategory: z.nativeEnum(TaxCategory).default(TaxCategory.STANDARD),
    taxRate: z.number().min(0).max(1).optional(),
    priceHistory: z.array(z.object({
      price: z.number().nonnegative(),
      effectiveDate: z.string().datetime(),
      reason: z.string().optional()
    })).default([])
  }),

  // Inventory Management
  inventory: z.object({
    trackInventory: z.boolean().default(true),
    quantity: z.number().int().nonnegative().default(0),
    reservedQuantity: z.number().int().nonnegative().default(0),
    availableQuantity: z.number().int().nonnegative().default(0),
    reorderPoint: z.number().int().nonnegative().default(10),
    maxStock: z.number().int().nonnegative().optional(),
    unitOfMeasure: z.nativeEnum(UnitOfMeasure).default(UnitOfMeasure.PIECE),
    stockStatus: z.nativeEnum(StockStatus).default(StockStatus.IN_STOCK),
    backorderAllowed: z.boolean().default(false),
    preorderAllowed: z.boolean().default(false),
    locationQuantities: z.record(z.number().int().nonnegative()).optional()
  }),

  // Physical Properties
  dimensions: DimensionsSchema.optional(),
  shippingInfo: z.object({
    isShippable: z.boolean().default(true),
    freeShipping: z.boolean().default(false),
    shippingClass: z.string().optional(),
    handlingTime: z.number().int().nonnegative().default(1), // days
    fragile: z.boolean().default(false),
    hazardous: z.boolean().default(false),
    requiresSpecialHandling: z.boolean().default(false)
  }).optional(),

  // Digital Properties
  digitalInfo: z.object({
    downloadable: z.boolean().default(false),
    downloadLimit: z.number().int().positive().optional(),
    downloadExpiry: z.number().int().positive().optional(), // days
    fileUrl: z.string().url().optional(),
    fileSize: z.number().positive().optional(), // bytes
    supportedFormats: z.array(z.string()).optional()
  }).optional(),

  // Media and Assets
  images: z.array(z.object({
    id: z.string().uuid(),
    url: z.string().url(),
    altText: z.string().optional(),
    isPrimary: z.boolean().default(false),
    sortOrder: z.number().int().default(0)
  })).default([]),

  documents: z.array(z.object({
    id: z.string().uuid(),
    name: z.string(),
    type: z.enum(['manual', 'specification', 'warranty', 'certificate', 'other']),
    url: z.string().url(),
    size: z.number().positive(), // bytes
    uploadedAt: z.string().datetime()
  })).default([]),

  // Variants and Options
  hasVariants: z.boolean().default(false),
  variants: z.array(VariantSchema).default([]),
  variantAttributes: z.array(z.string().uuid()).default([]), // Attribute IDs used for variants

  // SEO and Marketing
  seo: z.object({
    metaTitle: z.string().max(60).optional(),
    metaDescription: z.string().max(160).optional(),
    keywords: z.array(z.string()).default([]),
    slug: z.string().optional()
  }).optional(),

  // Relationships
  relatedProducts: z.array(z.string().uuid()).default([]),
  bundleProducts: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive(),
    discount: z.number().min(0).max(100).default(0)
  })).default([]),

  // Supplier Information
  suppliers: z.array(z.object({
    supplierId: z.string().uuid(),
    supplierSku: z.string().optional(),
    cost: z.number().nonnegative(),
    currency: z.string().length(3),
    leadTime: z.number().int().nonnegative(), // days
    minimumOrderQuantity: z.number().int().positive().default(1),
    isPrimary: z.boolean().default(false)
  })).default([]),

  // Custom Attributes
  customAttributes: z.record(z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.string())
  ])).default({}),

  // Audit fields
  createdBy: z.string().uuid(),
  updatedBy: z.string().uuid().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime().optional(),
  version: z.number().positive().default(1),

  // Metadata
  metadata: z.record(z.unknown()).optional()
})

// Create Product Request Schema
export const CreateProductRequestSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  sku: z.string().min(1),
  type: z.nativeEnum(ProductType).optional(),
  categoryId: z.string().uuid().optional(),
  pricing: z.object({
    basePrice: z.number().nonnegative(),
    currency: z.string().length(3),
    taxCategory: z.nativeEnum(TaxCategory).optional()
  }),
  inventory: z.object({
    trackInventory: z.boolean().optional(),
    quantity: z.number().int().nonnegative().optional(),
    reorderPoint: z.number().int().nonnegative().optional(),
    unitOfMeasure: z.nativeEnum(UnitOfMeasure).optional()
  }).optional(),
  dimensions: DimensionsSchema.optional(),
  images: z.array(z.object({
    url: z.string().url(),
    altText: z.string().optional(),
    isPrimary: z.boolean().optional()
  })).optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional()
})

// Update Product Request Schema
export const UpdateProductRequestSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  status: z.nativeEnum(ProductStatus).optional(),
  categoryId: z.string().uuid().optional(),
  pricing: z.object({
    basePrice: z.number().nonnegative().optional(),
    salePrice: z.number().nonnegative().optional(),
    cost: z.number().nonnegative().optional(),
    taxCategory: z.nativeEnum(TaxCategory).optional()
  }).optional(),
  inventory: z.object({
    quantity: z.number().int().nonnegative().optional(),
    reorderPoint: z.number().int().nonnegative().optional(),
    maxStock: z.number().int().nonnegative().optional(),
    backorderAllowed: z.boolean().optional(),
    preorderAllowed: z.boolean().optional()
  }).optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional()
})

// Product Search Parameters
export interface ProductSearchParams {
  page?: number
  limit?: number
  search?: string
  categoryId?: string
  status?: ProductStatus
  type?: ProductType
  stockStatus?: StockStatus
  minPrice?: number
  maxPrice?: number
  tags?: string[]
  brand?: string
  sortBy?: 'name' | 'sku' | 'price' | 'quantity' | 'createdAt' | 'updatedAt'
  sortOrder?: 'asc' | 'desc'
  includeVariants?: boolean
  includeInactive?: boolean
}

// Product List Response
export interface ProductListResponse {
  products: Product[]
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
    hasNext: boolean
    hasPrev: boolean
  }
  aggregations: {
    totalValue: number
    totalQuantity: number
    lowStockCount: number
    outOfStockCount: number
    byCategory: Record<string, number>
    byStatus: Record<string, number>
  }
}

// Inventory Movement Types
export enum MovementType {
  PURCHASE = 'purchase',
  SALE = 'sale',
  ADJUSTMENT = 'adjustment',
  TRANSFER = 'transfer',
  RETURN = 'return',
  DAMAGE = 'damage',
  THEFT = 'theft',
  PRODUCTION = 'production',
  CONSUMPTION = 'consumption'
}

export interface InventoryMovement {
  id: string
  productId: string
  variantId?: string
  locationId?: string
  type: MovementType
  quantity: number
  unitCost?: number
  totalCost?: number
  reason: string
  reference?: string
  orderId?: string
  userId: string
  timestamp: string
  metadata?: Record<string, unknown>
}

// Stock Adjustment Schema
export const StockAdjustmentSchema = z.object({
  productId: z.string().uuid(),
  variantId: z.string().uuid().optional(),
  locationId: z.string().uuid().optional(),
  quantity: z.number().int(),
  reason: z.string().min(1),
  reference: z.string().optional(),
  unitCost: z.number().nonnegative().optional(),
  notes: z.string().optional()
})

// Bundle Configuration
export interface BundleItem {
  productId: string
  variantId?: string
  quantity: number
  discount: number
  required: boolean
}

export interface ProductBundle {
  id: string
  name: string
  description?: string
  items: BundleItem[]
  totalPrice: number
  bundlePrice: number
  savings: number
  isActive: boolean
  validFrom?: string
  validTo?: string
}

// Export TypeScript types
export type Dimensions = z.infer<typeof DimensionsSchema>
export type Category = z.infer<typeof CategorySchema>
export type Attribute = z.infer<typeof AttributeSchema>
export type Variant = z.infer<typeof VariantSchema>
export type Product = z.infer<typeof ProductSchema>
export type CreateProductRequest = z.infer<typeof CreateProductRequestSchema>
export type UpdateProductRequest = z.infer<typeof UpdateProductRequestSchema>
export type StockAdjustment = z.infer<typeof StockAdjustmentSchema>

// Product Analytics Types
export interface ProductAnalytics {
  productId: string
  period: {
    start: string
    end: string
  }
  sales: {
    quantity: number
    revenue: number
    orders: number
    averageOrderValue: number
  }
  inventory: {
    turnoverRate: number
    daysOnHand: number
    stockouts: number
    averageStockLevel: number
  }
  profitability: {
    grossProfit: number
    grossMargin: number
    profitPerUnit: number
  }
  trends: {
    salesTrend: 'increasing' | 'decreasing' | 'stable'
    demandForecast: number[]
    seasonality: Record<string, number>
  }
}

// Import/Export Types
export interface ProductImportMapping {
  name: string
  description?: string
  sku: string
  price: string
  quantity?: string
  category?: string
  brand?: string
  weight?: string
  dimensions?: string
}

export interface ProductExportOptions {
  format: 'csv' | 'xlsx' | 'json'
  includeVariants: boolean
  includeImages: boolean
  includeInventory: boolean
  includePricing: boolean
  categoryIds?: string[]
  status?: ProductStatus[]
}

// Barcode Types
export interface BarcodeInfo {
  type: 'UPC' | 'EAN' | 'ISBN' | 'CODE128' | 'CODE39' | 'QR'
  value: string
  checksum?: string
  isValid: boolean
}

// Product Recommendations
export interface ProductRecommendation {
  type: 'related' | 'upsell' | 'cross_sell' | 'frequently_bought_together'
  products: {
    productId: string
    score: number
    reason: string
  }[]
  algorithm: string
  confidence: number
}