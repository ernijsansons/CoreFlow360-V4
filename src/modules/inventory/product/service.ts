/**
 * Product Management Service
 * Comprehensive product and SKU management with advanced inventory features
 */

import { z } from 'zod'
import type {
  Product,
  Variant,
  Category,
  CreateProductRequest,
  UpdateProductRequest,
  ProductSearchParams,
  ProductListResponse,
  InventoryMovement,
  StockAdjustment,
  ProductAnalytics,
  BarcodeInfo,
  ProductType,
  ProductStatus,
  StockStatus,
  MovementType
} from './types'
import {
  ProductSchema,
  CreateProductRequestSchema,
  UpdateProductRequestSchema,
  StockAdjustmentSchema
} from './types'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export // TODO: Consider splitting ProductService into smaller, focused classes
class ProductService {
  constructor(
    private readonly db: D1Database,
    private readonly imageService?: any, // Image processing service
    private readonly barcodeService?: any, // Barcode generation/validation service
    private readonly analyticsService?: any // Analytics service
  ) {}

  async createProduct(request: CreateProductRequest, userId: string): Promise<Product> {
    try {
      auditLogger.log({
        action: 'product_creation_started',
        userId,
        metadata: {
          name: request.name,
          sku: request.sku,
          type: request.type
        }
      })

      // Validate request
      CreateProductRequestSchema.parse(request)

      // Check for duplicate SKU
      await this.validateUniqueSku(request.sku)

      // Generate product ID
      const productId = this.generateProductId()

      // Process images if provided
      const processedImages = request.images ? await this.processProductImages(request.images) : []

      // Calculate available quantity
      const quantity = request.inventory?.quantity || 0
      const availableQuantity = quantity

      // Determine stock status
      const stockStatus = this.calculateStockStatus(quantity, request.inventory?.reorderPoint || 10)

      // Create product object
      const product: Product = {
        id: productId,
        businessId: '', // Will be set from auth context
        name: request.name,
        description: request.description,
        sku: request.sku,
        type: request.type || ProductType.PHYSICAL,
        status: ProductStatus.DRAFT,
        categoryId: request.categoryId,
        tags: request.tags || [],
        pricing: {
          basePrice: request.pricing.basePrice,
          currency: request.pricing.currency,
          taxCategory: request.pricing.taxCategory || 'standard' as any,
          priceHistory: [{
            price: request.pricing.basePrice,
            effectiveDate: new Date().toISOString(),
            reason: 'Initial price'
          }]
        },
        inventory: {
          trackInventory: request.inventory?.trackInventory ?? true,
          quantity,
          reservedQuantity: 0,
          availableQuantity,
          reorderPoint: request.inventory?.reorderPoint || 10,
          unitOfMeasure: request.inventory?.unitOfMeasure || 'piece' as any,
          stockStatus,
          backorderAllowed: false,
          preorderAllowed: false
        },
        dimensions: request.dimensions,
        images: processedImages,
        hasVariants: false,
        variants: [],
        variantAttributes: [],
        relatedProducts: [],
        bundleProducts: [],
        suppliers: [],
        customAttributes: {},
        createdBy: userId,
        createdAt: new Date().toISOString(),
        version: 1,
        metadata: request.metadata
      }

      // Validate complete product
      ProductSchema.parse(product)

      // Save to database
      await this.saveProduct(product)

      // Create initial inventory movement
      if (quantity > 0) {
        await this.createInventoryMovement({
          productId,
          type: MovementType.ADJUSTMENT,
          quantity,
          reason: 'Initial stock',
          userId
        })
      }

      auditLogger.log({
        action: 'product_created',
        productId,
        userId,
        metadata: {
          name: product.name,
          sku: product.sku,
          initialQuantity: quantity
        }
      })

      return product

    } catch (error) {
      auditLogger.log({
        action: 'product_creation_failed',
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: request
      })

      if (error instanceof z.ZodError) {
        throw new AppError(
          'Product validation failed',
          'PRODUCT_VALIDATION_ERROR',
          400,
          { validationErrors: error.errors }
        )
      }

      throw new AppError(
        'Product creation failed',
        'PRODUCT_CREATION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async updateProduct(productId: string, request: UpdateProductRequest, userId: string): Promise<Product> {
    try {
      auditLogger.log({
        action: 'product_update_started',
        productId,
        userId,
        metadata: request
      })

      // Validate request
      UpdateProductRequestSchema.parse(request)

      // Get existing product
      const existingProduct = await this.getProduct(productId)
      if (!existingProduct) {
        throw new AppError('Product not found', 'PRODUCT_NOT_FOUND', 404)
      }

      // Create updated product
      const updatedProduct: Product = {
        ...existingProduct,
        ...request,
        pricing: request.pricing ? {
          ...existingProduct.pricing,
          ...request.pricing
        } : existingProduct.pricing,
        inventory: request.inventory ? {
          ...existingProduct.inventory,
          ...request.inventory
        } : existingProduct.inventory,
        updatedBy: userId,
        updatedAt: new Date().toISOString(),
        version: existingProduct.version + 1
      }

      // Handle price changes
      if (request.pricing?.basePrice && request.pricing.basePrice !== existingProduct.pricing.basePrice) {
        updatedProduct.pricing.priceHistory.push({
          price: request.pricing.basePrice,
          effectiveDate: new Date().toISOString(),
          reason: 'Price update'
        })
      }

      // Update stock status if quantity changed
      if (request.inventory?.quantity !== undefined) {
        const newQuantity = request.inventory.quantity
        const reorderPoint = request.inventory.reorderPoint || existingProduct.inventory.reorderPoint
        updatedProduct.inventory.stockStatus = this.calculateStockStatus(newQuantity, reorderPoint)
        updatedProduct.inventory.availableQuantity = newQuantity - existingProduct.inventory.reservedQuantity

        // Create inventory movement for quantity change
        const quantityDifference = newQuantity - existingProduct.inventory.quantity
        if (quantityDifference !== 0) {
          await this.createInventoryMovement({
            productId,
            type: MovementType.ADJUSTMENT,
            quantity: quantityDifference,
            reason: 'Quantity adjustment',
            userId
          })
        }
      }

      // Validate updated product
      ProductSchema.parse(updatedProduct)

      // Save to database
      await this.saveProduct(updatedProduct)

      auditLogger.log({
        action: 'product_updated',
        productId,
        userId,
        metadata: {
          changedFields: Object.keys(request),
          version: updatedProduct.version
        }
      })

      return updatedProduct

    } catch (error) {
      auditLogger.log({
        action: 'product_update_failed',
        productId,
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Product update failed',
        'PRODUCT_UPDATE_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getProduct(productId: string, includeVariants = false): Promise<Product | null> {
    try {
      // Database query implementation would go here
      // For now, return mock data
      return null

    } catch (error) {
      throw new AppError(
        'Failed to retrieve product',
        'PRODUCT_RETRIEVAL_ERROR',
        500,
        { originalError: error, productId }
      )
    }
  }

  async searchProducts(params: ProductSearchParams): Promise<ProductListResponse> {
    try {
      auditLogger.log({
        action: 'product_search_started',
        metadata: params
      })

      // Validate and normalize parameters
      const normalizedParams = this.normalizeSearchParams(params)

      // Execute search query
      const products = await this.executeProductSearch(normalizedParams)

      // Calculate aggregations
      const aggregations = await this.calculateSearchAggregations(products, normalizedParams)

      // Calculate pagination
      const pagination = this.calculatePagination(
        products.length,
        normalizedParams.page || 1,
        normalizedParams.limit || 50
      )

      const response: ProductListResponse = {
        products: products.slice(
          (pagination.page - 1) * pagination.limit,
          pagination.page * pagination.limit
        ),
        pagination,
        aggregations
      }

      auditLogger.log({
        action: 'product_search_completed',
        metadata: {
          resultCount: response.products.length,
          totalCount: pagination.total
        }
      })

      return response

    } catch (error) {
      auditLogger.log({
        action: 'product_search_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: params
      })

      throw new AppError(
        'Product search failed',
        'PRODUCT_SEARCH_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async adjustStock(adjustment: StockAdjustment, userId: string): Promise<Product> {
    try {
      auditLogger.log({
        action: 'stock_adjustment_started',
        productId: adjustment.productId,
        quantity: adjustment.quantity,
        userId
      })

      // Validate adjustment
      StockAdjustmentSchema.parse(adjustment)

      // Get product
      const product = await this.getProduct(adjustment.productId)
      if (!product) {
        throw new AppError('Product not found', 'PRODUCT_NOT_FOUND', 404)
      }

      // Check if inventory tracking is enabled
      if (!product.inventory.trackInventory) {
        throw new AppError(
          'Inventory tracking is not enabled for this product',
          'INVENTORY_TRACKING_DISABLED',
          400
        )
      }

      // Calculate new quantity
      const currentQuantity = adjustment.variantId
        ? this.getVariantQuantity(product, adjustment.variantId)
        : product.inventory.quantity

      const newQuantity = currentQuantity + adjustment.quantity

      if (newQuantity < 0) {
        throw new AppError(
          'Adjustment would result in negative stock',
          'NEGATIVE_STOCK_ERROR',
          400
        )
      }

      // Update product quantity
      if (adjustment.variantId) {
        await this.updateVariantQuantity(product, adjustment.variantId, newQuantity)
      } else {
        product.inventory.quantity = newQuantity
        product.inventory.availableQuantity = newQuantity - product.inventory.reservedQuantity
        product.inventory.stockStatus = this.calculateStockStatus(newQuantity, product.inventory.reorderPoint)
      }

      // Save updated product
      await this.saveProduct(product)

      // Create inventory movement
      await this.createInventoryMovement({
        productId: adjustment.productId,
        variantId: adjustment.variantId,
        locationId: adjustment.locationId,
        type: MovementType.ADJUSTMENT,
        quantity: adjustment.quantity,
        unitCost: adjustment.unitCost,
        totalCost: adjustment.unitCost ? adjustment.unitCost * Math.abs(adjustment.quantity) : undefined,
        reason: adjustment.reason,
        reference: adjustment.reference,
        userId
      })

      auditLogger.log({
        action: 'stock_adjusted',
        productId: adjustment.productId,
        oldQuantity: currentQuantity,
        newQuantity,
        adjustment: adjustment.quantity,
        userId
      })

      return product

    } catch (error) {
      auditLogger.log({
        action: 'stock_adjustment_failed',
        productId: adjustment.productId,
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      })

      throw new AppError(
        'Stock adjustment failed',
        'STOCK_ADJUSTMENT_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async reserveStock(productId: string, quantity: number, reason: string, userId: string): Promise<void> {
    try {
      auditLogger.log({
        action: 'stock_reservation_started',
        productId,
        quantity,
        userId
      })

      const product = await this.getProduct(productId)
      if (!product) {
        throw new AppError('Product not found', 'PRODUCT_NOT_FOUND', 404)
      }

      if (quantity > product.inventory.availableQuantity) {
        throw new AppError(
          'Insufficient available stock',
          'INSUFFICIENT_STOCK',
          400,
          {
            requested: quantity,
            available: product.inventory.availableQuantity
          }
        )
      }

      // Update reservations
      product.inventory.reservedQuantity += quantity
      product.inventory.availableQuantity -= quantity
      product.inventory.stockStatus = this.calculateStockStatus(
        product.inventory.availableQuantity,
        product.inventory.reorderPoint
      )

      await this.saveProduct(product)

      auditLogger.log({
        action: 'stock_reserved',
        productId,
        quantity,
        newReservedQuantity: product.inventory.reservedQuantity,
        userId
      })

    } catch (error) {
      auditLogger.log({
        action: 'stock_reservation_failed',
        productId,
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      })

      throw new AppError(
        'Stock reservation failed',
        'STOCK_RESERVATION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async releaseStock(productId: string, quantity: number, reason: string, userId: string): Promise<void> {
    try {
      const product = await this.getProduct(productId)
      if (!product) {
        throw new AppError('Product not found', 'PRODUCT_NOT_FOUND', 404)
      }

      if (quantity > product.inventory.reservedQuantity) {
        throw new AppError(
          'Cannot release more stock than reserved',
          'INVALID_RELEASE_QUANTITY',
          400
        )
      }

      // Update reservations
      product.inventory.reservedQuantity -= quantity
      product.inventory.availableQuantity += quantity
      product.inventory.stockStatus = this.calculateStockStatus(
        product.inventory.availableQuantity,
        product.inventory.reorderPoint
      )

      await this.saveProduct(product)

      auditLogger.log({
        action: 'stock_released',
        productId,
        quantity,
        newReservedQuantity: product.inventory.reservedQuantity,
        userId
      })

    } catch (error) {
      throw new AppError(
        'Stock release failed',
        'STOCK_RELEASE_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async generateBarcode(productId: string, type: 'UPC' | 'EAN' | 'CODE128' = 'CODE128'): Promise<BarcodeInfo> {
    try {
      if (!this.barcodeService) {
        throw new AppError('Barcode service not available', 'SERVICE_UNAVAILABLE', 503)
      }

      const product = await this.getProduct(productId)
      if (!product) {
        throw new AppError('Product not found', 'PRODUCT_NOT_FOUND', 404)
      }

      const barcodeInfo = await this.barcodeService.generate(type, product.sku)

      // Update product with barcode
      product.barcode = barcodeInfo.value
      await this.saveProduct(product)

      auditLogger.log({
        action: 'barcode_generated',
        productId,
        barcodeType: type,
        barcodeValue: barcodeInfo.value
      })

      return barcodeInfo

    } catch (error) {
      throw new AppError(
        'Barcode generation failed',
        'BARCODE_GENERATION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getProductAnalytics(productId: string, periodStart: string, periodEnd: string): Promise<ProductAnalytics> {
    try {
      if (!this.analyticsService) {
        throw new AppError('Analytics service not available', 'SERVICE_UNAVAILABLE', 503)
      }

      const analytics = await this.analyticsService.getProductAnalytics(productId, periodStart, periodEnd)

      auditLogger.log({
        action: 'product_analytics_retrieved',
        productId,
        period: { start: periodStart, end: periodEnd }
      })

      return analytics

    } catch (error) {
      throw new AppError(
        'Failed to retrieve product analytics',
        'ANALYTICS_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getInventoryMovements(
    productId: string,
    filters?: {
      startDate?: string
      endDate?: string
      type?: MovementType
      limit?: number
    }
  ): Promise<InventoryMovement[]> {
    try {
      // Database query implementation
      return []

    } catch (error) {
      throw new AppError(
        'Failed to retrieve inventory movements',
        'MOVEMENT_RETRIEVAL_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getLowStockProducts(threshold?: number): Promise<Product[]> {
    try {
      // Query products where available quantity <= reorder point
      // Database implementation would go here
      return []

    } catch (error) {
      throw new AppError(
        'Failed to retrieve low stock products',
        'LOW_STOCK_QUERY_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async bulkUpdatePrices(updates: { productId: string; newPrice:
  number; reason?: string }[], userId: string): Promise<void> {
    try {
      auditLogger.log({
        action: 'bulk_price_update_started',
        updateCount: updates.length,
        userId
      })

      for (const update of updates) {
        const product = await this.getProduct(update.productId)
        if (product) {
          product.pricing.basePrice = update.newPrice
          product.pricing.priceHistory.push({
            price: update.newPrice,
            effectiveDate: new Date().toISOString(),
            reason: update.reason || 'Bulk price update'
          })
          product.updatedBy = userId
          product.updatedAt = new Date().toISOString()
          product.version += 1

          await this.saveProduct(product)
        }
      }

      auditLogger.log({
        action: 'bulk_price_update_completed',
        updateCount: updates.length,
        userId
      })

    } catch (error) {
      auditLogger.log({
        action: 'bulk_price_update_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      })

      throw new AppError(
        'Bulk price update failed',
        'BULK_UPDATE_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  // Private helper methods
  private async validateUniqueSku(sku: string, excludeProductId?: string): Promise<void> {
    // Database query to check SKU uniqueness
    // Throw error if SKU already exists
  }

  private generateProductId(): string {
    return `prod_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private async processProductImages(images: any[]): Promise<any[]> {
    if (!this.imageService) return images

    const processedImages = []
    for (const image of images) {
      const processed = await this.imageService.process(image.url, {
        resize: { width: 800, height: 800 },
        quality: 80,
        format: 'webp'
      })
      processedImages.push({
        ...image,
        id: this.generateImageId(),
        url: processed.url
      })
    }
    return processedImages
  }

  private generateImageId(): string {
    return `img_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private calculateStockStatus(quantity: number, reorderPoint: number): StockStatus {
    if (quantity <= 0) return StockStatus.OUT_OF_STOCK
    if (quantity <= reorderPoint) return StockStatus.LOW_STOCK
    return StockStatus.IN_STOCK
  }

  private async createInventoryMovement(movement: Omit<InventoryMovement, 'id' | 'timestamp'>): Promise<void> {
    const movementRecord: InventoryMovement = {
      id: this.generateMovementId(),
      timestamp: new Date().toISOString(),
      ...movement
    }

    // Save to database
    auditLogger.log({
      action: 'inventory_movement_created',
      movementId: movementRecord.id,
      productId: movement.productId,
      type: movement.type,
      quantity: movement.quantity
    })
  }

  private generateMovementId(): string {
    return `mov_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private getVariantQuantity(product: Product, variantId: string): number {
    const variant = product.variants.find(v => v.id === variantId)
    return variant?.inventory.quantity || 0
  }

  private async updateVariantQuantity(product: Product, variantId: string, newQuantity: number): Promise<void> {
    const variant = product.variants.find(v => v.id === variantId)
    if (variant) {
      variant.inventory.quantity = newQuantity
      variant.inventory.availableQuantity = newQuantity - variant.inventory.reservedQuantity
    }
  }

  private normalizeSearchParams(params: ProductSearchParams): ProductSearchParams {
    return {
      page: Math.max(1, params.page || 1),
      limit: Math.min(100, Math.max(1, params.limit || 50)),
      sortBy: params.sortBy || 'createdAt',
      sortOrder: params.sortOrder || 'desc',
      includeVariants: params.includeVariants || false,
      includeInactive: params.includeInactive || false,
      ...params
    }
  }

  private async executeProductSearch(params: ProductSearchParams): Promise<Product[]> {
    // Database query implementation
    return []
  }

  private async calculateSearchAggregations(products: Product[], params: ProductSearchParams): Promise<ProductListResponse['aggregations']> {
    return {
      totalValue: 0,
      totalQuantity: 0,
      lowStockCount: 0,
      outOfStockCount: 0,
      byCategory: {},
      byStatus: {}
    }
  }

  private calculatePagination(total: number, page: number, limit: number) {
    const pages = Math.ceil(total / limit)
    return {
      page,
      limit,
      total,
      pages,
      hasNext: page < pages,
      hasPrev: page > 1
    }
  }

  private async saveProduct(product: Product): Promise<void> {
    // Database save implementation
    auditLogger.log({
      action: 'product_saved',
      productId: product.id,
      version: product.version
    })
  }
}