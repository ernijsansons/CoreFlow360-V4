/**
 * Bounded Collections Utility
 * Prevents unbounded growth of arrays and collections that could cause memory issues
 */

import { Logger } from './logger';

export interface BoundedArrayOptions {
  maxSize: number;
  evictionPolicy?: 'fifo' | 'lifo' | 'lru';
  onEviction?: (evictedItem: any) => void;
  onCapacityReached?: (currentSize: number, maxSize: number) => void;
}

export class BoundedArray<T> {
  private items: T[] = [];
  private accessOrder: Map<number, number> = new Map(); // For LRU tracking
  private accessCounter = 0;
  private logger: Logger;

  constructor(private options: BoundedArrayOptions) {
    this.logger = new Logger();

    if (options.maxSize <= 0) {
      throw new Error('BoundedArray maxSize must be greater than 0');
    }
  }

  /**
   * Add item to the bounded array
   */
  push(item: T): void {
    // Check if we need to evict items first
    if (this.items.length >= this.options.maxSize) {
      this.options.onCapacityReached?.(this.items.length, this.options.maxSize);
      this.evictItems(1);
    }

    this.items.push(item);

    // Track access for LRU if needed
    if (this.options.evictionPolicy === 'lru') {
      this.accessOrder.set(this.items.length - 1, ++this.accessCounter);
    }

    this.logger.debug('Item added to bounded array', {
      currentSize: this.items.length,
      maxSize: this.options.maxSize,
      evictionPolicy: this.options.evictionPolicy
    });
  }

  /**
   * Add multiple items, respecting bounds
   */
  pushMany(items: T[]): void {
    for (const item of items) {
      this.push(item);
    }
  }

  /**
   * Get item by index
   */
  get(index: number): T | undefined {
    if (index < 0 || index >= this.items.length) {
      return undefined;
    }

    // Update access order for LRU
    if (this.options.evictionPolicy === 'lru') {
      this.accessOrder.set(index, ++this.accessCounter);
    }

    return this.items[index];
  }

  /**
   * Remove and return the last item
   */
  pop(): T | undefined {
    const item = this.items.pop();
    if (item !== undefined && this.options.evictionPolicy === 'lru') {
      this.accessOrder.delete(this.items.length);
    }
    return item;
  }

  /**
   * Remove and return the first item
   */
  shift(): T | undefined {
    const item = this.items.shift();
    if (item !== undefined && this.options.evictionPolicy === 'lru') {
      // Reindex access order after shift
      const newAccessOrder = new Map<number, number>();
      for (const [index, access] of this.accessOrder.entries()) {
        if (index > 0) {
          newAccessOrder.set(index - 1, access);
        }
      }
      this.accessOrder = newAccessOrder;
    }
    return item;
  }

  /**
   * Get current length
   */
  get length(): number {
    return this.items.length;
  }

  /**
   * Check if array is full
   */
  get isFull(): boolean {
    return this.items.length >= this.options.maxSize;
  }

  /**
   * Get remaining capacity
   */
  get remainingCapacity(): number {
    return Math.max(0, this.options.maxSize - this.items.length);
  }

  /**
   * Get all items (returns copy)
   */
  toArray(): T[] {
    return [...this.items];
  }

  /**
   * Clear all items
   */
  clear(): void {
    this.items = [];
    this.accessOrder.clear();
    this.accessCounter = 0;
  }

  /**
   * Filter items and maintain bounds
   */
  filter(predicate: (item: T, index: number) => boolean): void {
    const filteredItems = this.items.filter(predicate);
    this.items = filteredItems;

    // Update access order tracking
    if (this.options.evictionPolicy === 'lru') {
      this.accessOrder.clear();
      this.accessCounter = 0;
    }
  }

  /**
   * Find item by predicate
   */
  find(predicate: (item: T, index: number) => boolean): T | undefined {
    const index = this.items.findIndex(predicate);
    return index !== -1 ? this.get(index) : undefined;
  }

  /**
   * Check if item exists
   */
  includes(item: T): boolean {
    return this.items.includes(item);
  }

  /**
   * Iterate over items
   */
  forEach(callback: (item: T, index: number) => void): void {
    this.items.forEach((item, index) => {
      callback(item, index);
      // Update access for LRU
      if (this.options.evictionPolicy === 'lru') {
        this.accessOrder.set(index, ++this.accessCounter);
      }
    });
  }

  /**
   * Map over items
   */
  map<U>(callback: (item: T, index: number) => U): U[] {
    return this.items.map(callback);
  }

  /**
   * Evict items based on policy
   */
  private evictItems(count: number): void {
    for (let i = 0; i < count && this.items.length > 0; i++) {
      let evictedItem: T;

      switch (this.options.evictionPolicy) {
        case 'lifo':
          evictedItem = this.items.pop()!;
          break;

        case 'lru':
          const lruIndex = this.findLRUIndex();
          evictedItem = this.items.splice(lruIndex, 1)[0];
          this.updateAccessOrderAfterRemoval(lruIndex);
          break;

        case 'fifo':
        default:
          evictedItem = this.items.shift()!;
          break;
      }

      this.options.onEviction?.(evictedItem);

      this.logger.debug('Item evicted from bounded array', {
        evictionPolicy: this.options.evictionPolicy,
        remainingSize: this.items.length
      });
    }
  }

  /**
   * Find the least recently used item index
   */
  private findLRUIndex(): number {
    if (this.accessOrder.size === 0) {
      return 0; // Default to first item
    }

    let lruIndex = 0;
    let lruAccess = Number.MAX_SAFE_INTEGER;

    for (const [index, access] of this.accessOrder.entries()) {
      if (access < lruAccess) {
        lruAccess = access;
        lruIndex = index;
      }
    }

    return lruIndex;
  }

  /**
   * Update access order after item removal
   */
  private updateAccessOrderAfterRemoval(removedIndex: number): void {
    const newAccessOrder = new Map<number, number>();

    for (const [index, access] of this.accessOrder.entries()) {
      if (index < removedIndex) {
        newAccessOrder.set(index, access);
      } else if (index > removedIndex) {
        newAccessOrder.set(index - 1, access);
      }
      // Skip the removed index
    }

    this.accessOrder = newAccessOrder;
  }

  /**
   * Update access order after shift operation
   */
  private updateAccessOrderAfterShift(): void {
    const newAccessOrder = new Map<number, number>();

    for (const [index, access] of this.accessOrder.entries()) {
      if (index > 0) {
        newAccessOrder.set(index - 1, access);
      }
    }

    this.accessOrder = newAccessOrder;
  }

  /**
   * Get statistics about the bounded array
   */
  getStatistics(): {
    currentSize: number;
    maxSize: number;
    utilizationPercentage: number;
    evictionPolicy: string;
    totalAccesses: number;
  } {
    return {
      currentSize: this.items.length,
      maxSize: this.options.maxSize,
      utilizationPercentage: (this.items.length / this.options.maxSize) * 100,
      evictionPolicy: this.options.evictionPolicy || 'fifo',
      totalAccesses: this.accessCounter
    };
  }
}

/**
 * Bounded Set with maximum size limit
 */
export class BoundedSet<T> {
  private items: Set<T> = new Set();
  private insertionOrder: T[] = [];
  private logger: Logger;

  constructor(private maxSize: number, private onEviction?: (evictedItem: T) => void) {
    this.logger = new Logger();

    if (maxSize <= 0) {
      throw new Error('BoundedSet maxSize must be greater than 0');
    }
  }

  /**
   * Add item to the bounded set
   */
  add(item: T): boolean {
    // If item already exists, update its position
    if (this.items.has(item)) {
      this.updateInsertionOrder(item);
      return false;
    }

    // Check if we need to evict items first
    if (this.items.size >= this.maxSize) {
      this.evictOldestItem();
    }

    this.items.add(item);
    this.insertionOrder.push(item);

    this.logger.debug('Item added to bounded set', {
      currentSize: this.items.size,
      maxSize: this.maxSize
    });

    return true;
  }

  /**
   * Check if item exists in set
   */
  has(item: T): boolean {
    return this.items.has(item);
  }

  /**
   * Remove item from set
   */
  delete(item: T): boolean {
    if (this.items.delete(item)) {
      this.insertionOrder = this.insertionOrder.filter((i: any) => i !== item);
      return true;
    }
    return false;
  }

  /**
   * Get current size
   */
  get size(): number {
    return this.items.size;
  }

  /**
   * Check if set is full
   */
  get isFull(): boolean {
    return this.items.size >= this.maxSize;
  }

  /**
   * Clear all items
   */
  clear(): void {
    this.items.clear();
    this.insertionOrder = [];
  }

  /**
   * Convert to array
   */
  toArray(): T[] {
    return [...this.insertionOrder];
  }

  /**
   * Iterate over items
   */
  forEach(callback: (item: T) => void): void {
    this.items.forEach(callback);
  }

  /**
   * Update insertion order for existing item
   */
  private updateInsertionOrder(item: T): void {
    this.insertionOrder = this.insertionOrder.filter((i: any) => i !== item);
    this.insertionOrder.push(item);
  }

  /**
   * Evict the oldest item
   */
  private evictOldestItem(): void {
    if (this.insertionOrder.length > 0) {
      const oldestItem = this.insertionOrder.shift()!;
      this.items.delete(oldestItem);
      this.onEviction?.(oldestItem);

      this.logger.debug('Item evicted from bounded set', {
        remainingSize: this.items.size
      });
    }
  }
}

/**
 * Bounded Map with maximum size limit
 */
export class BoundedMap<K, V> {
  private items: Map<K, V> = new Map();
  private insertionOrder: K[] = [];
  private logger: Logger;

  constructor(private maxSize: number, private onEviction?: (key: K, value: V) => void) {
    this.logger = new Logger();

    if (maxSize <= 0) {
      throw new Error('BoundedMap maxSize must be greater than 0');
    }
  }

  /**
   * Set key-value pair
   */
  set(key: K, value: V): void {
    // If key already exists, update its position
    if (this.items.has(key)) {
      this.items.set(key, value);
      this.updateInsertionOrder(key);
      return;
    }

    // Check if we need to evict items first
    if (this.items.size >= this.maxSize) {
      this.evictOldestItem();
    }

    this.items.set(key, value);
    this.insertionOrder.push(key);

    this.logger.debug('Item added to bounded map', {
      currentSize: this.items.size,
      maxSize: this.maxSize
    });
  }

  /**
   * Get value by key
   */
  get(key: K): V | undefined {
    return this.items.get(key);
  }

  /**
   * Check if key exists
   */
  has(key: K): boolean {
    return this.items.has(key);
  }

  /**
   * Delete key-value pair
   */
  delete(key: K): boolean {
    if (this.items.delete(key)) {
      this.insertionOrder = this.insertionOrder.filter((k: any) => k !== key);
      return true;
    }
    return false;
  }

  /**
   * Get current size
   */
  get size(): number {
    return this.items.size;
  }

  /**
   * Check if map is full
   */
  get isFull(): boolean {
    return this.items.size >= this.maxSize;
  }

  /**
   * Clear all items
   */
  clear(): void {
    this.items.clear();
    this.insertionOrder = [];
  }

  /**
   * Get all keys
   */
  keys(): K[] {
    return [...this.insertionOrder];
  }

  /**
   * Get all values
   */
  values(): V[] {
    return this.insertionOrder.map((key: any) => this.items.get(key)!);
  }

  /**
   * Get all entries
   */
  entries(): [K, V][] {
    return this.insertionOrder.map((key: any) => [key, this.items.get(key)!]);
  }

  /**
   * Iterate over entries
   */
  forEach(callback: (value: V, key: K) => void): void {
    this.insertionOrder.forEach((key: any) => {
      const value = this.items.get(key)!;
      callback(value, key);
    });
  }

  /**
   * Update insertion order for existing key
   */
  private updateInsertionOrder(key: K): void {
    this.insertionOrder = this.insertionOrder.filter((k: any) => k !== key);
    this.insertionOrder.push(key);
  }

  /**
   * Evict the oldest item
   */
  private evictOldestItem(): void {
    if (this.insertionOrder.length > 0) {
      const oldestKey = this.insertionOrder.shift()!;
      const oldestValue = this.items.get(oldestKey)!;
      this.items.delete(oldestKey);
      this.onEviction?.(oldestKey, oldestValue);

      this.logger.debug('Item evicted from bounded map', {
        remainingSize: this.items.size
      });
    }
  }
}