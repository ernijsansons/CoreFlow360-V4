/**
 * Advanced Stock Tracking System
 * Real-time inventory tracking with multi-location support and predictive analytics
 */

import { z } from 'zod'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'
import { MovementType, StockStatus } from '../product/types'

export enum LocationType {
  WAREHOUSE = 'warehouse',
  STORE = 'store',
  DISTRIBUTION_CENTER = 'distribution_center',
  SUPPLIER = 'supplier',
  CUSTOMER = 'customer',
  VIRTUAL = 'virtual',
  CONSIGNMENT = 'consignment',
  TRANSIT = 'transit'
}

export enum StockTrackingMethod {
  FIFO = 'fifo', // First In, First Out
  LIFO = 'lifo', // Last In, First Out
  WEIGHTED_AVERAGE = 'weighted_average',
  SPECIFIC_IDENTIFICATION = 'specific_identification',
  STANDARD_COST = 'standard_cost'
}

export enum AlertType {
  LOW_STOCK = 'low_stock',
  OUT_OF_STOCK = 'out_of_stock',
  OVERSTOCK = 'overstock',
  EXPIRY_WARNING = 'expiry_warning',
  SLOW_MOVING = 'slow_moving',
  FAST_MOVING = 'fast_moving',
  NEGATIVE_STOCK = 'negative_stock',
  VARIANCE_DETECTED = 'variance_detected'
}

export enum StockTransferStatus {
  PENDING = 'pending',
  IN_TRANSIT = 'in_transit',
  RECEIVED = 'received',
  CANCELLED = 'cancelled',
  REJECTED = 'rejected'
}

export interface StockLocation {
  id: string
  businessId: string
  name: string
  code: string
  type: LocationType
  address: {
    street: string
    city: string
    state: string
    postalCode: string
    country: string
  }
  isActive: boolean
  parentLocationId?: string
  managerUserId?: string
  capacity?: {
    totalVolume: number
    totalWeight: number
    maxSku: number
  }
  settings: {
    allowNegativeStock: boolean
    autoReorderEnabled: boolean
    trackingMethod: StockTrackingMethod
    requiresApproval: boolean
  }
  metadata?: Record<string, unknown>
}

export interface StockItem {
  id: string
  productId: string
  variantId?: string
  locationId: string
  quantity: number
  reservedQuantity: number
  availableQuantity: number
  unitCost: number
  totalValue: number
  batchNumber?: string
  serialNumbers?: string[]
  expiryDate?: string
  supplierLotNumber?: string
  receivedDate: string
  lastMovementDate: string
  lastCountDate?: string
  adjustmentReason?: string
  metadata?: Record<string, unknown>
}

export interface StockMovement {
  id: string
  businessId: string
  productId: string
  variantId?: string
  fromLocationId?: string
  toLocationId?: string
  movementType: MovementType
  quantity: number
  unitCost: number
  totalCost: number
  batchNumber?: string
  serialNumbers?: string[]
  reference: string
  orderId?: string
  transferId?: string
  reason: string
  notes?: string
  userId: string
  approvedBy?: string
  approvedAt?: string
  timestamp: string
  metadata?: Record<string, unknown>
}

export interface StockTransfer {
  id: string
  businessId: string
  fromLocationId: string
  toLocationId: string
  status: StockTransferStatus
  items: {
    productId: string
    variantId?: string
    quantity: number
    unitCost: number
    batchNumber?: string
    serialNumbers?: string[]
  }[]
  requestedBy: string
  requestedAt: string
  approvedBy?: string
  approvedAt?: string
  shippedBy?: string
  shippedAt?: string
  receivedBy?: string
  receivedAt?: string
  trackingNumber?: string
  notes?: string
  metadata?: Record<string, unknown>
}

export interface StockAlert {
  id: string
  businessId: string
  type: AlertType
  severity: 'low' | 'medium' | 'high' | 'critical'
  productId: string
  variantId?: string
  locationId?: string
  message: string
  threshold?: number
  currentValue: number
  isActive: boolean
  acknowledgedBy?: string
  acknowledgedAt?: string
  resolvedAt?: string
  createdAt: string
  metadata?: Record<string, unknown>
}

export interface StockForecast {
  id: string
  productId: string
  variantId?: string
  locationId?: string
  period: {
    start: string
    end: string
  }
  forecast: {
    date: string
    demandForecast: number
    stockForecast: number
    reorderSuggestion?: number
  }[]
  confidence: number
  algorithm: string
  factors: {
    seasonality: number
    trend: number
    promotions: number
    historical: number
  }
  createdAt: string
}

export interface CycleCount {
  id: string
  businessId: string
  locationId: string
  name: string
  description?: string
  status: 'scheduled' | 'in_progress' | 'completed' | 'cancelled'
  type: 'full' | 'partial' | 'abc_analysis' | 'random'
  scheduledDate: string
  startedAt?: string
  completedAt?: string
  assignedTo: string[]
  items: {
    productId: string
    variantId?: string
    expectedQuantity: number
    countedQuantity?: number
    variance?: number
    countedBy?: string
    countedAt?: string
    notes?: string
  }[]
  summary?: {
    totalItems: number
    countedItems: number
    varianceItems: number
    totalVarianceValue: number
    accuracy: number
  }
  metadata?: Record<string, unknown>
}

const StockLocationSchema = z.object({
  id: z.string().uuid(),
  businessId: z.string().uuid(),
  name: z.string().min(1),
  code: z.string().min(1),
  type: z.nativeEnum(LocationType),
  address: z.object({
    street: z.string(),
    city: z.string(),
    state: z.string(),
    postalCode: z.string(),
    country: z.string()
  }),
  isActive: z.boolean().default(true),
  parentLocationId: z.string().uuid().optional(),
  managerUserId: z.string().uuid().optional(),
  capacity: z.object({
    totalVolume: z.number().positive(),
    totalWeight: z.number().positive(),
    maxSku: z.number().int().positive()
  }).optional(),
  settings: z.object({
    allowNegativeStock: z.boolean().default(false),
    autoReorderEnabled: z.boolean().default(false),
    trackingMethod: z.nativeEnum(StockTrackingMethod).default(StockTrackingMethod.FIFO),
    requiresApproval: z.boolean().default(false)
  }),
  metadata: z.record(z.unknown()).optional()
})

export // TODO: Consider splitting StockTrackingService into smaller, focused classes
class StockTrackingService {
  private stockItems: Map<string, Map<string, StockItem>> = new Map() // locationId -> productId -> StockItem
  private stockMovements: Map<string, StockMovement> = new Map()
  private stockTransfers: Map<string, StockTransfer> = new Map()
  private stockAlerts: Map<string, StockAlert> = new Map()
  private locations: Map<string, StockLocation> = new Map()
  private cycleCounts: Map<string, CycleCount> = new Map()

  constructor(
    private readonly db: D1Database,
    private readonly alertService?: any,
    private readonly forecastingService?: any
  ) {
    this.initializeDefaultLocations()
    this.startAlertMonitoring()
  }

  async createLocation(location: Omit<StockLocation, 'id'>): Promise<StockLocation> {
    try {
      auditLogger.log({
        action: 'stock_location_creation_started',
        metadata: {
          name: location.name,
          type: location.type,
          code: location.code
        }
      })

      // Validate location
      const newLocation: StockLocation = {
        id: this.generateLocationId(),
        ...location
      }

      StockLocationSchema.parse(newLocation)

      // Check for duplicate location code
      await this.validateUniqueLocationCode(newLocation.code)

      // Save location
      this.locations.set(newLocation.id, newLocation)

      auditLogger.log({
        action: 'stock_location_created',
        locationId: newLocation.id,
        name: newLocation.name,
        type: newLocation.type
      })

      return newLocation

    } catch (error) {
      auditLogger.log({
        action: 'stock_location_creation_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: location
      })

      throw new AppError(
        'Stock location creation failed',
        'LOCATION_CREATION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getStockLevel(productId: string, locationId?: string, variantId?: string): Promise<StockItem[]> {
    try {
      const stockItems: StockItem[] = []

      if (locationId) {
        const locationStock = this.stockItems.get(locationId)
        const key = variantId ? `${productId}:${variantId}` : productId
        const item = locationStock?.get(key)
        if (item) {
          stockItems.push(item)
        }
      } else {
        // Get stock from all locations
        for (const [locId, locationStock] of this.stockItems) {
          const key = variantId ? `${productId}:${variantId}` : productId
          const item = locationStock.get(key)
          if (item) {
            stockItems.push(item)
          }
        }
      }

      return stockItems

    } catch (error) {
      throw new AppError(
        'Failed to retrieve stock level',
        'STOCK_LEVEL_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async updateStock(
    productId: string,
    locationId: string,
    quantity: number,
    movementType: MovementType,
    reason: string,
    userId: string,
    options?: {
      variantId?: string
      unitCost?: number
      batchNumber?: string
      serialNumbers?: string[]
      reference?: string
      orderId?: string
    }
  ): Promise<StockItem> {
    try {
      auditLogger.log({
        action: 'stock_update_started',
        productId,
        locationId,
        quantity,
        movementType,
        userId
      })

      // Validate location exists
      const location = this.locations.get(locationId)
      if (!location) {
        throw new AppError('Location not found', 'LOCATION_NOT_FOUND', 404)
      }

      // Get or create stock item
      const stockItem = await this.getOrCreateStockItem(productId, locationId, options?.variantId)

      // Calculate new quantity
      const oldQuantity = stockItem.quantity
      let newQuantity: number

      switch (movementType) {
        case MovementType.PURCHASE:
        case MovementType.ADJUSTMENT:
        case MovementType.RETURN:
        case MovementType.PRODUCTION:
          newQuantity = oldQuantity + Math.abs(quantity)
          break
        case MovementType.SALE:
        case MovementType.DAMAGE:
        case MovementType.THEFT:
        case MovementType.CONSUMPTION:
          newQuantity = oldQuantity - Math.abs(quantity)
          break
        case MovementType.TRANSFER:
          // Transfer movements are handled separately
          newQuantity = oldQuantity + quantity // quantity can be positive or negative for transfers
          break
        default:
          newQuantity = oldQuantity + quantity
      }

      // Check for negative stock
      if (newQuantity < 0 && !location.settings.allowNegativeStock) {
        throw new AppError(
          'Insufficient stock for this operation',
          'INSUFFICIENT_STOCK',
          400,
          {
            available: oldQuantity,
            requested: Math.abs(quantity),
            operation: movementType
          }
        )
      }

      // Update stock item
      stockItem.quantity = newQuantity
      stockItem.availableQuantity = newQuantity - stockItem.reservedQuantity
      stockItem.lastMovementDate = new Date().toISOString()

      if (options?.unitCost) {
        // Update cost using specified tracking method
        stockItem.unitCost = this.calculateNewUnitCost(
          stockItem,
          quantity,
          options.unitCost,
          location.settings.trackingMethod
        )
      }

      stockItem.totalValue = stockItem.quantity * stockItem.unitCost

      // Create stock movement record
      const movement: StockMovement = {
        id: this.generateMovementId(),
        businessId: location.businessId,
        productId,
        variantId: options?.variantId,
        toLocationId: movementType === MovementType.SALE ? undefined : locationId,
        fromLocationId: movementType === MovementType.PURCHASE ? undefined : locationId,
        movementType,
        quantity: Math.abs(quantity),
        unitCost: options?.unitCost || stockItem.unitCost,
        totalCost: Math.abs(quantity) * (options?.unitCost || stockItem.unitCost),
        batchNumber: options?.batchNumber,
        serialNumbers: options?.serialNumbers,
        reference: options?.reference || '',
        orderId: options?.orderId,
        reason,
        userId,
        timestamp: new Date().toISOString()
      }

      this.stockMovements.set(movement.id, movement)

      // Check for alerts
      await this.checkStockAlerts(stockItem, location)

      auditLogger.log({
        action: 'stock_updated',
        productId,
        locationId,
        oldQuantity,
        newQuantity,
        movementId: movement.id,
        userId
      })

      return stockItem

    } catch (error) {
      auditLogger.log({
        action: 'stock_update_failed',
        productId,
        locationId,
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      })

      throw new AppError(
        'Stock update failed',
        'STOCK_UPDATE_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async transferStock(transfer: Omit<StockTransfer, 'id' | 'status' | 'requestedAt'>): Promise<StockTransfer> {
    try {
      auditLogger.log({
        action: 'stock_transfer_started',
        fromLocationId: transfer.fromLocationId,
        toLocationId: transfer.toLocationId,
        itemCount: transfer.items.length,
        requestedBy: transfer.requestedBy
      })

      // Validate locations
      const fromLocation = this.locations.get(transfer.fromLocationId)
      const toLocation = this.locations.get(transfer.toLocationId)

      if (!fromLocation || !toLocation) {
        throw new AppError('Invalid location(s) for transfer', 'INVALID_LOCATIONS', 400)
      }

      // Create transfer record
      const stockTransfer: StockTransfer = {
        id: this.generateTransferId(),
        status: StockTransferStatus.PENDING,
        requestedAt: new Date().toISOString(),
        ...transfer
      }

      // Validate stock availability
      for (const item of transfer.items) {
        const stockItem = await this.getStockItem(item.productId, transfer.fromLocationId, item.variantId)
        if (!stockItem || stockItem.availableQuantity < item.quantity) {
          throw new AppError(
            `Insufficient stock for product ${item.productId}`,
            'INSUFFICIENT_STOCK',
            400,
            {
              productId: item.productId,
              requested: item.quantity,
              available: stockItem?.availableQuantity || 0
            }
          )
        }
      }

      // Reserve stock at source location
      for (const item of transfer.items) {
        await this.reserveStock(item.productId, transfer.fromLocationId, item.quantity, item.variantId)
      }

      this.stockTransfers.set(stockTransfer.id, stockTransfer)

      auditLogger.log({
        action: 'stock_transfer_created',
        transferId: stockTransfer.id,
        fromLocationId: transfer.fromLocationId,
        toLocationId: transfer.toLocationId
      })

      return stockTransfer

    } catch (error) {
      auditLogger.log({
        action: 'stock_transfer_failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        metadata: transfer
      })

      throw new AppError(
        'Stock transfer failed',
        'STOCK_TRANSFER_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async completeTransfer(transferId: string, receivedBy: string, receivedItems?: {
    productId: string
    variantId?: string
    quantityReceived: number
    condition?: 'good' | 'damaged' | 'expired'
    notes?: string
  }[]): Promise<StockTransfer> {
    try {
      const transfer = this.stockTransfers.get(transferId)
      if (!transfer) {
        throw new AppError('Transfer not found', 'TRANSFER_NOT_FOUND', 404)
      }

      if (transfer.status !== StockTransferStatus.IN_TRANSIT) {
        throw new AppError('Transfer is not in transit', 'INVALID_TRANSFER_STATUS', 400)
      }

      // Process received items
      const itemsToProcess = receivedItems || transfer.items.map(item => ({
        productId: item.productId,
        variantId: item.variantId,
        quantityReceived: item.quantity,
        condition: 'good' as const
      }))

      for (const receivedItem of itemsToProcess) {
        const originalItem = transfer.items.find(i =>
          i.productId === receivedItem.productId &&
          i.variantId === receivedItem.variantId
        )

        if (!originalItem) continue

        // Remove stock from source location
        await this.updateStock(
          receivedItem.productId,
          transfer.fromLocationId,
          -originalItem.quantity,
          MovementType.TRANSFER,
          `Transfer to ${transfer.toLocationId}`,
          receivedBy,
          {
            variantId: receivedItem.variantId,
            reference: transferId,
            unitCost: originalItem.unitCost
          }
        )

        // Release reserved stock
        await this.releaseReservedStock(
          receivedItem.productId,
          transfer.fromLocationId,
          originalItem.quantity,
          receivedItem.variantId
        )

        // Add stock to destination location
        if (receivedItem.condition === 'good') {
          await this.updateStock(
            receivedItem.productId,
            transfer.toLocationId,
            receivedItem.quantityReceived,
            MovementType.TRANSFER,
            `Transfer from ${transfer.fromLocationId}`,
            receivedBy,
            {
              variantId: receivedItem.variantId,
              reference: transferId,
              unitCost: originalItem.unitCost
            }
          )
        } else {
          // Handle damaged or expired items
          await this.handleDamagedTransferItem(
            receivedItem,
            originalItem,
            transfer,
            receivedBy
          )
        }
      }

      // Update transfer status
      transfer.status = StockTransferStatus.RECEIVED
      transfer.receivedBy = receivedBy
      transfer.receivedAt = new Date().toISOString()

      auditLogger.log({
        action: 'stock_transfer_completed',
        transferId,
        receivedBy,
        itemCount: itemsToProcess.length
      })

      return transfer

    } catch (error) {
      auditLogger.log({
        action: 'stock_transfer_completion_failed',
        transferId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'Transfer completion failed',
        'TRANSFER_COMPLETION_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async startCycleCount(count: Omit<CycleCount, 'id' | 'status' | 'startedAt'>): Promise<CycleCount> {
    try {
      auditLogger.log({
        action: 'cycle_count_started',
        locationId: count.locationId,
        type: count.type,
        itemCount: count.items.length
      })

      const cycleCount: CycleCount = {
        id: this.generateCycleCountId(),
        status: 'in_progress',
        startedAt: new Date().toISOString(),
        ...count
      }

      this.cycleCounts.set(cycleCount.id, cycleCount)

      auditLogger.log({
        action: 'cycle_count_created',
        cycleCountId: cycleCount.id,
        locationId: count.locationId
      })

      return cycleCount

    } catch (error) {
      throw new AppError(
        'Cycle count creation failed',
        'CYCLE_COUNT_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async updateCycleCountItem(
    cycleCountId: string,
    productId: string,
    countedQuantity: number,
    countedBy: string,
    variantId?: string,
    notes?: string
  ): Promise<CycleCount> {
    try {
      const cycleCount = this.cycleCounts.get(cycleCountId)
      if (!cycleCount) {
        throw new AppError('Cycle count not found', 'CYCLE_COUNT_NOT_FOUND', 404)
      }

      const item = cycleCount.items.find(i =>
        i.productId === productId && i.variantId === variantId
      )

      if (!item) {
        throw new AppError('Item not found in cycle count', 'ITEM_NOT_FOUND', 404)
      }

      // Update item
      item.countedQuantity = countedQuantity
      item.variance = countedQuantity - item.expectedQuantity
      item.countedBy = countedBy
      item.countedAt = new Date().toISOString()
      item.notes = notes

      // Check if all items are counted
      const allCounted = cycleCount.items.every(i => i.countedQuantity !== undefined)
      if (allCounted) {
        await this.completeCycleCount(cycleCountId)
      }

      auditLogger.log({
        action: 'cycle_count_item_updated',
        cycleCountId,
        productId,
        countedQuantity,
        variance: item.variance,
        countedBy
      })

      return cycleCount

    } catch (error) {
      throw new AppError(
        'Cycle count item update failed',
        'CYCLE_COUNT_UPDATE_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  async getStockAlerts(filters?: {
    locationId?: string
    type?: AlertType
    severity?: string
    isActive?: boolean
  }): Promise<StockAlert[]> {
    let alerts = Array.from(this.stockAlerts.values())

    if (filters) {
      if (filters.locationId) {
        alerts = alerts.filter(a => a.locationId === filters.locationId)
      }
      if (filters.type) {
        alerts = alerts.filter(a => a.type === filters.type)
      }
      if (filters.severity) {
        alerts = alerts.filter(a => a.severity === filters.severity)
      }
      if (filters.isActive !== undefined) {
        alerts = alerts.filter(a => a.isActive === filters.isActive)
      }
    }

    return alerts.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
  }

  async generateStockForecast(
    productId: string,
    locationId: string,
    periodDays: number,
    variantId?: string
  ): Promise<StockForecast> {
    try {
      if (!this.forecastingService) {
        throw new AppError('Forecasting service not available', 'SERVICE_UNAVAILABLE', 503)
      }

      const forecast = await this.forecastingService.generateForecast({
        productId,
        variantId,
        locationId,
        periodDays
      })

      auditLogger.log({
        action: 'stock_forecast_generated',
        productId,
        locationId,
        periodDays,
        confidence: forecast.confidence
      })

      return forecast

    } catch (error) {
      throw new AppError(
        'Stock forecast generation failed',
        'FORECAST_ERROR',
        500,
        { originalError: error }
      )
    }
  }

  // Private helper methods
  private async getOrCreateStockItem(productId: string, locationId: string, variantId?: string): Promise<StockItem> {
    const key = variantId ? `${productId}:${variantId}` : productId

    if (!this.stockItems.has(locationId)) {
      this.stockItems.set(locationId, new Map())
    }

    const locationStock = this.stockItems.get(locationId)!
    let stockItem = locationStock.get(key)

    if (!stockItem) {
      stockItem = {
        id: this.generateStockItemId(),
        productId,
        variantId,
        locationId,
        quantity: 0,
        reservedQuantity: 0,
        availableQuantity: 0,
        unitCost: 0,
        totalValue: 0,
        receivedDate: new Date().toISOString(),
        lastMovementDate: new Date().toISOString()
      }
      locationStock.set(key, stockItem)
    }

    return stockItem
  }

  private async getStockItem(productId: string, locationId: string, variantId?: string): Promise<StockItem | null> {
    const key = variantId ? `${productId}:${variantId}` : productId
    const locationStock = this.stockItems.get(locationId)
    return locationStock?.get(key) || null
  }

  private calculateNewUnitCost(
    stockItem: StockItem,
    quantity: number,
    newUnitCost: number,
    trackingMethod: StockTrackingMethod
  ): number {
    switch (trackingMethod) {
      case StockTrackingMethod.WEIGHTED_AVERAGE:
        const totalValue = (stockItem.quantity * stockItem.unitCost) + (quantity * newUnitCost)
        const totalQuantity = stockItem.quantity + quantity
        return totalQuantity > 0 ? totalValue / totalQuantity : newUnitCost

      case StockTrackingMethod.FIFO:
      case StockTrackingMethod.LIFO:
        // For FIFO/LIFO, maintain layers (simplified here)
        return newUnitCost

      case StockTrackingMethod.STANDARD_COST:
        return stockItem.unitCost // Keep existing standard cost

      default:
        return newUnitCost
    }
  }

  private async reserveStock(productId: string, locationId:
  string, quantity: number, variantId?: string): Promise<void> {
    const stockItem = await this.getStockItem(productId, locationId, variantId)
    if (stockItem) {
      stockItem.reservedQuantity += quantity
      stockItem.availableQuantity -= quantity
    }
  }

  private async releaseReservedStock(productId: string, locationId:
  string, quantity: number, variantId?: string): Promise<void> {
    const stockItem = await this.getStockItem(productId, locationId, variantId)
    if (stockItem) {
      stockItem.reservedQuantity = Math.max(0, stockItem.reservedQuantity - quantity)
      stockItem.availableQuantity = stockItem.quantity - stockItem.reservedQuantity
    }
  }

  private async checkStockAlerts(stockItem: StockItem, location: StockLocation): Promise<void> {
    const alerts: StockAlert[] = []

    // Check for low stock
    if (stockItem.availableQuantity <= 5) { // Simplified reorder point
      alerts.push({
        id: this.generateAlertId(),
        businessId: location.businessId,
        type: AlertType.LOW_STOCK,
        severity: stockItem.availableQuantity === 0 ? 'critical' : 'medium',
        productId: stockItem.productId,
        variantId: stockItem.variantId,
        locationId: stockItem.locationId,
        message: `Low stock alert: ${stockItem.availableQuantity} units remaining`,
        currentValue: stockItem.availableQuantity,
        isActive: true,
        createdAt: new Date().toISOString()
      })
    }

    // Check for negative stock
    if (stockItem.quantity < 0) {
      alerts.push({
        id: this.generateAlertId(),
        businessId: location.businessId,
        type: AlertType.NEGATIVE_STOCK,
        severity: 'critical',
        productId: stockItem.productId,
        variantId: stockItem.variantId,
        locationId: stockItem.locationId,
        message: `Negative stock detected: ${stockItem.quantity} units`,
        currentValue: stockItem.quantity,
        isActive: true,
        createdAt: new Date().toISOString()
      })
    }

    // Save alerts
    for (const alert of alerts) {
      this.stockAlerts.set(alert.id, alert)
      if (this.alertService) {
        await this.alertService.sendAlert(alert)
      }
    }
  }

  private async handleDamagedTransferItem(
    receivedItem: any,
    originalItem: any,
    transfer: StockTransfer,
    receivedBy: string
  ): Promise<void> {
    // Create damage movement
    await this.updateStock(
      receivedItem.productId,
      transfer.toLocationId,
      receivedItem.quantityReceived,
      MovementType.DAMAGE,
      `Damaged in transfer ${transfer.id}`,
      receivedBy,
      {
        variantId: receivedItem.variantId,
        reference: transfer.id,
        unitCost: originalItem.unitCost
      }
    )
  }

  private async completeCycleCount(cycleCountId: string): Promise<void> {
    const cycleCount = this.cycleCounts.get(cycleCountId)
    if (!cycleCount) return

    // Calculate summary
    const totalItems = cycleCount.items.length
    const countedItems = cycleCount.items.filter(i => i.countedQuantity !== undefined).length
    const varianceItems = cycleCount.items.filter(i => i.variance !== 0).length
    const totalVarianceValue = cycleCount.items.reduce((sum, item) => {
      return sum + (item.variance || 0) * (item.expectedQuantity || 0) // Simplified value calculation
    }, 0)
    const accuracy = countedItems > 0 ? ((countedItems - varianceItems) / countedItems) * 100 : 0

    cycleCount.summary = {
      totalItems,
      countedItems,
      varianceItems,
      totalVarianceValue,
      accuracy
    }

    cycleCount.status = 'completed'
    cycleCount.completedAt = new Date().toISOString()

    // Apply adjustments for variances
    for (const item of cycleCount.items) {
      if (item.variance && item.variance !== 0) {
        await this.updateStock(
          item.productId,
          cycleCount.locationId,
          item.variance,
          MovementType.ADJUSTMENT,
          `Cycle count adjustment - ${cycleCount.name}`,
          'system',
          {
            variantId: item.variantId,
            reference: cycleCountId
          }
        )
      }
    }

    auditLogger.log({
      action: 'cycle_count_completed',
      cycleCountId,
      accuracy,
      varianceItems,
      totalVarianceValue
    })
  }

  private startAlertMonitoring(): void {
    // Start background monitoring for alerts
    setInterval(async () => {
      // Monitor expiry dates, slow-moving items, etc.
      // This would be implemented based on business requirements
    }, 3600000) // Check hourly
  }

  private async validateUniqueLocationCode(code: string): Promise<void> {
    for (const location of this.locations.values()) {
      if (location.code === code) {
        throw new AppError('Location code already exists', 'DUPLICATE_LOCATION_CODE', 400)
      }
    }
  }

  private initializeDefaultLocations(): void {
    const defaultLocation: StockLocation = {
      id: 'main-warehouse',
      businessId: 'default',
      name: 'Main Warehouse',
      code: 'MAIN',
      type: LocationType.WAREHOUSE,
      address: {
        street: '123 Warehouse St',
        city: 'Business City',
        state: 'BC',
        postalCode: '12345',
        country: 'US'
      },
      isActive: true,
      settings: {
        allowNegativeStock: false,
        autoReorderEnabled: true,
        trackingMethod: StockTrackingMethod.FIFO,
        requiresApproval: false
      }
    }

    this.locations.set(defaultLocation.id, defaultLocation)
  }

  // ID generators
  private generateLocationId(): string {
    return `loc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateStockItemId(): string {
    return `stock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateMovementId(): string {
    return `mov_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateTransferId(): string {
    return `xfer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateCycleCountId(): string {
    return `count_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
}