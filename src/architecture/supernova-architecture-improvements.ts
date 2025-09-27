/**
 * SUPERNOVA Architecture Improvements
 * Critical architectural enhancements for CoreFlow360 V4
 */

import { Logger } from '../shared/logger';

const logger = new Logger({ component: 'supernova-architecture' });

// ============================================================================
// DEPENDENCY INJECTION CONTAINER
// ============================================================================

export interface ServiceDefinition<T = any> {
  implementation: new (...args: any[]) => T;
  dependencies: string[];
  singleton: boolean;
  instance?: T;
}

export class SupernovaDIContainer {
  private services = new Map<string, ServiceDefinition>();
  private instances = new Map<string, any>();

  /**
   * SUPERNOVA Enhanced: Register service with dependency injection
   */
  register<T>(name: string, definition: ServiceDefinition<T>): void {
    this.services.set(name, definition);
  }

  /**
   * SUPERNOVA Enhanced: Resolve service with automatic dependency injection
   */
  resolve<T>(name: string): T {
    if (this.instances.has(name)) {
      return this.instances.get(name) as T;
    }

    const definition = this.services.get(name);
    if (!definition) {
      throw new Error(`Service '${name}' not found`);
    }

    // Resolve dependencies
    const dependencies = definition.dependencies.map((dep: any) => this.resolve(dep));
    
    // Create instance
    const instance = new definition.implementation(...dependencies);
    
    // Cache if singleton
    if (definition.singleton) {
      this.instances.set(name, instance);
    }

    return instance;
  }

  /**
   * SUPERNOVA Enhanced: Clear all instances (useful for testing)
   */
  clear(): void {
    this.instances.clear();
  }
}

// ============================================================================
// OBSERVER PATTERN IMPLEMENTATION
// ============================================================================

export interface Observer<T = any> {
  update(data: T): void;
}

export interface Subject<T = any> {
  subscribe(observer: Observer<T>): void;
  unsubscribe(observer: Observer<T>): void;
  notify(data: T): void;
}

export class SupernovaEventBus<T = any> implements Subject<T> {
  private observers: Set<Observer<T>> = new Set();
  private eventHistory: T[] = [];
  private maxHistorySize = 100;

  /**
   * SUPERNOVA Enhanced: Subscribe observer with error handling
   */
  subscribe(observer: Observer<T>): void {
    this.observers.add(observer);
  }

  /**
   * SUPERNOVA Enhanced: Unsubscribe observer
   */
  unsubscribe(observer: Observer<T>): void {
    this.observers.delete(observer);
  }

  /**
   * SUPERNOVA Enhanced: Notify all observers with error handling
   */
  notify(data: T): void {
    this.eventHistory.push(data);
    
    // Maintain history size
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }

    for (const observer of this.observers) {
      try {
        observer.update(data);
      } catch (error: any) {
        logger.error('Observer notification failed:', error);
      }
    }
  }

  /**
   * SUPERNOVA Enhanced: Get event history
   */
  getHistory(): T[] {
    return [...this.eventHistory];
  }

  /**
   * SUPERNOVA Enhanced: Clear event history
   */
  clearHistory(): void {
    this.eventHistory = [];
  }
}

// ============================================================================
// THREAD-SAFE SINGLETON PATTERN
// ============================================================================

export class SupernovaSingleton<T> {
  private static instances = new Map<string, any>();
  private static locks = new Map<string, Promise<any>>();

  /**
   * SUPERNOVA Enhanced: Thread-safe singleton with lazy initialization
   */
  static getInstance<T>(
    key: string,
    factory: () => T,
    options: { maxInstances?: number; ttl?: number } = {}
  ): T {
    const { maxInstances = 1, ttl = 0 } = options;

    // Check if instance exists
    if (this.instances.has(key)) {
      return this.instances.get(key) as T;
    }

    // Check if creation is in progress
    if (this.locks.has(key)) {
      return this.locks.get(key) as T;
    }

    // Create new instance with lock
    const creationPromise = this.createInstance(key, factory, maxInstances, ttl);
    this.locks.set(key, creationPromise);

    return creationPromise as T;
  }

  private static async createInstance<T>(
    key: string,
    factory: () => T,
    maxInstances: number,
    ttl: number
  ): Promise<T> {
    try {
      const instance = factory();
      
      // Store instance
      this.instances.set(key, instance);
      
      // Set TTL if specified
      if (ttl > 0) {
        setTimeout(() => {
          this.instances.delete(key);
        }, ttl);
      }

      // Clean up lock
      this.locks.delete(key);

      return instance;
    } catch (error: any) {
      this.locks.delete(key);
      throw error;
    }
  }

  /**
   * SUPERNOVA Enhanced: Clear singleton instance
   */
  static clearInstance(key: string): void {
    this.instances.delete(key);
    this.locks.delete(key);
  }

  /**
   * SUPERNOVA Enhanced: Clear all instances
   */
  static clearAll(): void {
    this.instances.clear();
    this.locks.clear();
  }
}

// ============================================================================
// REPOSITORY PATTERN WITH CACHING
// ============================================================================

export interface Repository<T, ID = string> {
  findById(id: ID): Promise<T | null>;
  findAll(): Promise<T[]>;
  save(entity: T): Promise<T>;
  delete(id: ID): Promise<boolean>;
  findBy(criteria: Partial<T>): Promise<T[]>;
}

export class SupernovaRepository<T, ID = string> implements Repository<T, ID> {
  private cache = new Map<ID, T>();
  private cacheTimestamps = new Map<ID, number>();
  private ttl: number;

  constructor(
    private dataSource: Repository<T, ID>,
    ttl: number = 300000 // 5 minutes
  ) {
    this.ttl = ttl;
  }

  /**
   * SUPERNOVA Enhanced: Cached find by ID
   */
  async findById(id: ID): Promise<T | null> {
    // Check cache first
    if (this.cache.has(id)) {
      const timestamp = this.cacheTimestamps.get(id)!;
      if (Date.now() - timestamp < this.ttl) {
        return this.cache.get(id)!;
      }
    }

    // Fetch from data source
    const entity = await this.dataSource.findById(id);
    
    if (entity) {
      this.cache.set(id, entity);
      this.cacheTimestamps.set(id, Date.now());
    }

    return entity;
  }

  /**
   * SUPERNOVA Enhanced: Cached find all
   */
  async findAll(): Promise<T[]> {
    const entities = await this.dataSource.findAll();
    
    // Update cache
    entities.forEach((entity: any) => {
      const id = (entity as any).id;
      if (id) {
        this.cache.set(id, entity);
        this.cacheTimestamps.set(id, Date.now());
      }
    });

    return entities;
  }

  /**
   * SUPERNOVA Enhanced: Save with cache invalidation
   */
  async save(entity: T): Promise<T> {
    const savedEntity = await this.dataSource.save(entity);
    const id = (savedEntity as any).id;
    
    if (id) {
      this.cache.set(id, savedEntity);
      this.cacheTimestamps.set(id, Date.now());
    }

    return savedEntity;
  }

  /**
   * SUPERNOVA Enhanced: Delete with cache invalidation
   */
  async delete(id: ID): Promise<boolean> {
    const result = await this.dataSource.delete(id);
    
    if (result) {
      this.cache.delete(id);
      this.cacheTimestamps.delete(id);
    }

    return result;
  }

  /**
   * SUPERNOVA Enhanced: Find by criteria with caching
   */
  async findBy(criteria: Partial<T>): Promise<T[]> {
    // For complex criteria, we can't use cache effectively
    // So we delegate to data source
    return this.dataSource.findBy(criteria);
  }

  /**
   * SUPERNOVA Enhanced: Clear cache
   */
  clearCache(): void {
    this.cache.clear();
    this.cacheTimestamps.clear();
  }

  /**
   * SUPERNOVA Enhanced: Get cache statistics
   */
  getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size,
      hitRate: 0 // Would be calculated in real implementation
    };
  }
}

// ============================================================================
// COMMAND PATTERN WITH UNDO/REDO
// ============================================================================

export interface Command {
  execute(): Promise<void>;
  undo(): Promise<void>;
  canUndo(): boolean;
  getDescription(): string;
}

export // TODO: Consider splitting SupernovaCommandManager into smaller, focused classes
class SupernovaCommandManager {
  private history: Command[] = [];
  private currentIndex = -1;
  private maxHistorySize = 100;

  /**
   * SUPERNOVA Enhanced: Execute command with history tracking
   */
  async execute(command: Command): Promise<void> {
    try {
      await command.execute();
      
      // Remove any commands after current index
      this.history = this.history.slice(0, this.currentIndex + 1);
      
      // Add new command
      this.history.push(command);
      this.currentIndex++;
      
      // Maintain history size
      if (this.history.length > this.maxHistorySize) {
        this.history.shift();
        this.currentIndex--;
      }
      
    } catch (error: any) {
      logger.error('Command execution failed:', error);
      throw error;
    }
  }

  /**
   * SUPERNOVA Enhanced: Undo last command
   */
  async undo(): Promise<boolean> {
    if (this.currentIndex < 0 || !this.history[this.currentIndex].canUndo()) {
      return false;
    }

    try {
      await this.history[this.currentIndex].undo();
      this.currentIndex--;
      return true;
    } catch (error: any) {
      logger.error('Command undo failed:', error);
      return false;
    }
  }

  /**
   * SUPERNOVA Enhanced: Redo last undone command
   */
  async redo(): Promise<boolean> {
    if (this.currentIndex >= this.history.length - 1) {
      return false;
    }

    try {
      this.currentIndex++;
      await this.history[this.currentIndex].execute();
      return true;
    } catch (error: any) {
      logger.error('Command redo failed:', error);
      this.currentIndex--; // Rollback index
      return false;
    }
  }

  /**
   * SUPERNOVA Enhanced: Get command history
   */
  getHistory(): Command[] {
    return [...this.history];
  }

  /**
   * SUPERNOVA Enhanced: Clear history
   */
  clearHistory(): void {
    this.history = [];
    this.currentIndex = -1;
  }

  /**
   * SUPERNOVA Enhanced: Can undo/redo
   */
  canUndo(): boolean {
    return this.currentIndex >= 0 && this.history[this.currentIndex].canUndo();
  }

  canRedo(): boolean {
    return this.currentIndex < this.history.length - 1;
  }
}

// ============================================================================
// FACTORY PATTERN WITH REGISTRY
// ============================================================================

export interface Factory<T> {
  create(config: any): T;
  getType(): string;
}

export class SupernovaFactoryRegistry<T> {
  private factories = new Map<string, Factory<T>>();
  private defaultFactory?: Factory<T>;

  /**
   * SUPERNOVA Enhanced: Register factory
   */
  register(type: string, factory: Factory<T>): void {
    this.factories.set(type, factory);
  }

  /**
   * SUPERNOVA Enhanced: Set default factory
   */
  setDefault(factory: Factory<T>): void {
    this.defaultFactory = factory;
  }

  /**
   * SUPERNOVA Enhanced: Create instance with type resolution
   */
  create(type: string, config: any): T {
    const factory = this.factories.get(type) || this.defaultFactory;
    
    if (!factory) {
      throw new Error(`No factory found for type '${type}'`);
    }

    return factory.create(config);
  }

  /**
   * SUPERNOVA Enhanced: Get available types
   */
  getAvailableTypes(): string[] {
    return Array.from(this.factories.keys());
  }

  /**
   * SUPERNOVA Enhanced: Check if type is supported
   */
  isSupported(type: string): boolean {
    return this.factories.has(type);
  }
}

// ============================================================================
// ADAPTER PATTERN FOR EXTERNAL SERVICES
// ============================================================================

export interface ExternalService {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
}

export class SupernovaServiceAdapter<T extends ExternalService> {
  private service: T;
  private isConnected = false;
  private connectionRetries = 0;
  private maxRetries = 3;

  constructor(service: T) {
    this.service = service;
  }

  /**
   * SUPERNOVA Enhanced: Connect with retry logic
   */
  async connect(): Promise<void> {
    try {
      await this.service.connect();
      this.isConnected = true;
      this.connectionRetries = 0;
    } catch (error: any) {
      this.connectionRetries++;
      
      if (this.connectionRetries < this.maxRetries) {
        logger.warn(`Connection attempt ${this.connectionRetries} failed, retrying...`);
        await this.delay(1000 * this.connectionRetries);
        return this.connect();
      }
      
      throw error;
    }
  }

  /**
   * SUPERNOVA Enhanced: Disconnect gracefully
   */
  async disconnect(): Promise<void> {
    try {
      await this.service.disconnect();
      this.isConnected = false;
    } catch (error: any) {
      logger.error('Disconnect failed:', error);
    }
  }

  /**
   * SUPERNOVA Enhanced: Execute with connection check
   */
  async execute<R>(operation: (service: T) => Promise<R>): Promise<R> {
    if (!this.isConnected) {
      await this.connect();
    }

    try {
      return await operation(this.service);
    } catch (error: any) {
      // If connection lost, try to reconnect
      if (!this.service.isConnected()) {
        this.isConnected = false;
        await this.connect();
        return await operation(this.service);
      }
      
      throw error;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// SUPERNOVA ARCHITECTURE UTILITIES
// ============================================================================

export class SupernovaArchitectureUtils {
  private static diContainer = new SupernovaDIContainer();
  private static eventBus = new SupernovaEventBus();
  private static commandManager = new SupernovaCommandManager();

  /**
   * SUPERNOVA Enhanced: Get dependency injection container
   */
  static getDIContainer(): SupernovaDIContainer {
    return this.diContainer;
  }

  /**
   * SUPERNOVA Enhanced: Get event bus
   */
  static getEventBus(): SupernovaEventBus {
    return this.eventBus;
  }

  /**
   * SUPERNOVA Enhanced: Get command manager
   */
  static getCommandManager(): SupernovaCommandManager {
    return this.commandManager;
  }

  /**
   * SUPERNOVA Enhanced: Initialize architecture components
   */
  static initialize(): void {
    // Register core services
    this.diContainer.register('logger', {
      implementation: Logger,
      dependencies: [],
      singleton: true
    });

    this.diContainer.register('eventBus', {
      implementation: SupernovaEventBus,
      dependencies: [],
      singleton: true
    });

    logger.info('SUPERNOVA Architecture initialized');
  }
}
