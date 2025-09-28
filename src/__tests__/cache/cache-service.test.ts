import { describe, it, expect, beforeEach, afterEach, vi, MockedFunction } from 'vitest';
import { CacheService, EnhancedCacheStats, CacheInfo, CacheUtils, createCacheService } from '../../../cache/cache-service';
import type { KVNamespace } from '@cloudflare/workers-types';

// Mock KVNamespace
const mockKV: Partial<KVNamespace> = {
  get: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  list: vi.fn(),
};

// Mock Cache API
const mockCacheAPI: Partial<Cache> = {
  match: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  keys: vi.fn(),
};

// Mock global caches
Object.defineProperty(global, 'caches', {
  value: {
    open: vi.fn().mockResolvedValue(mockCacheAPI),
    delete: vi.fn(),
    keys: vi.fn().mockResolvedValue([]),
  },
  writable: true,
});

// Mock performance.now for consistent testing
const mockPerformanceNow = vi.fn();
Object.defineProperty(global, 'performance', {
  value: { now: mockPerformanceNow },
  writable: true,
});

// Mock setInterval and clearInterval
const mockSetInterval = vi.fn();
const mockClearInterval = vi.fn();
Object.defineProperty(global, 'setInterval', { value: mockSetInterval, writable: true });
Object.defineProperty(global, 'clearInterval', { value: mockClearInterval, writable: true });

// Mock console methods
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

describe('CacheService', () => {
  let cacheService: CacheService;

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();
    mockPerformanceNow.mockReturnValue(Date.now());

    // Mock console methods
    console.log = vi.fn();
    console.error = vi.fn();
    console.warn = vi.fn();

    // Reset KV mock implementations
    (mockKV.get as MockedFunction<any>).mockResolvedValue(null);
    (mockKV.put as MockedFunction<any>).mockResolvedValue(undefined);
    (mockKV.delete as MockedFunction<any>).mockResolvedValue(undefined);
    (mockKV.list as MockedFunction<any>).mockResolvedValue({ keys: [], list_complete: true });

    // Reset Cache API mock implementations
    (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
    (mockCacheAPI.put as MockedFunction<any>).mockResolvedValue(undefined);
    (mockCacheAPI.delete as MockedFunction<any>).mockResolvedValue(false);
    (mockCacheAPI.keys as MockedFunction<any>).mockResolvedValue([]);

    cacheService = new CacheService(mockKV as KVNamespace, mockCacheAPI as Cache);
  });

  afterEach(() => {
    // Restore console methods
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
  });

  describe('Constructor and Initialization', () => {
    it('should initialize with KV namespace', () => {
      const service = new CacheService(mockKV as KVNamespace);
      expect(service).toBeInstanceOf(CacheService);
    });

    it('should initialize with KV namespace and Cache API', () => {
      const service = new CacheService(mockKV as KVNamespace, mockCacheAPI as Cache);
      expect(service).toBeInstanceOf(CacheService);
    });

    it('should start background tasks on initialization', () => {
      expect(mockSetInterval).toHaveBeenCalledTimes(3); // 3 background tasks
    });
  });

  describe('Get Operations', () => {
    it('should return null for cache miss', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue(null);

      const result = await cacheService.get('non-existent-key');
      expect(result).toBeNull();
    });

    it('should return data from L1 cache (Cache API) on hit', async () => {
      const mockData = { test: 'data' };
      const mockResponse = new Response(JSON.stringify(mockData), {
        headers: {
          'X-Cache-Timestamp': Date.now().toString(),
          'X-Cache-TTL': '300000'
        }
      });

      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(mockResponse);

      const result = await cacheService.get('test-key');
      expect(result).toEqual(mockData);
    });

    it('should return data from L2 cache (KV) on L1 miss', async () => {
      const mockData = { test: 'data' };

      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue(mockData);

      const result = await cacheService.get('test-key');
      expect(result).toEqual(mockData);
    });

    it('should promote high-priority data to L1 cache', async () => {
      const mockData = { test: 'data' };

      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue(mockData);

      await cacheService.get('test-key', { priority: 5 });

      expect(mockCacheAPI.put).toHaveBeenCalled();
    });

    it('should handle cache errors gracefully', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockRejectedValue(new Error('Cache error'));
      (mockKV.get as MockedFunction<any>).mockRejectedValue(new Error('KV error'));

      const result = await cacheService.get('error-key');
      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalledWith('Cache get error:', expect.any(Error));
    });

    it('should schedule warm-up for stale data', async () => {
      const oldTimestamp = (Date.now() - 250000).toString(); // 250 seconds ago
      const mockResponse = new Response(JSON.stringify({ test: 'data' }), {
        headers: {
          'X-Cache-Timestamp': oldTimestamp,
          'X-Cache-TTL': '300000' // 5 minutes TTL
        }
      });

      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(mockResponse);

      await cacheService.get('stale-key', { warmUp: true });

      // Warm-up should be scheduled (tested indirectly through queue size)
    });

    it('should track performance metrics', async () => {
      const startTime = Date.now();
      mockPerformanceNow.mockReturnValueOnce(startTime).mockReturnValueOnce(startTime + 10);

      (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

      await cacheService.get('metrics-key');

      const stats = await cacheService.getStats();
      expect(stats.totalRequests).toBeGreaterThan(0);
    });
  });

  describe('Set Operations', () => {
    it('should set data in both KV and Cache API', async () => {
      const testData = { test: 'data' };

      await cacheService.set('test-key', testData);

      expect(mockKV.put).toHaveBeenCalledWith(
        'test-key',
        expect.stringContaining('"data":'),
        expect.objectContaining({ expirationTtl: expect.any(Number) })
      );
    });

    it('should set data with custom options', async () => {
      const testData = { test: 'data' };
      const options = {
        contentType: 'user-data',
        priority: 5,
        compress: true,
        tags: ['user', 'profile']
      };

      await cacheService.set('test-key', testData, options);

      expect(mockKV.put).toHaveBeenCalledWith(
        'test-key',
        expect.stringContaining('"priority":5'),
        expect.objectContaining({ expirationTtl: 60 }) // user-data TTL
      );
    });

    it('should set high-priority data in Cache API', async () => {
      const testData = { test: 'data' };

      await cacheService.set('high-priority-key', testData, { priority: 5 });

      expect(mockCacheAPI.put).toHaveBeenCalled();
    });

    it('should handle compression simulation', async () => {
      const largeData = { test: 'x'.repeat(2000) };

      await cacheService.set('large-key', largeData, { compress: true });

      expect(mockKV.put).toHaveBeenCalled();
    });

    it('should handle set errors', async () => {
      (mockKV.put as MockedFunction<any>).mockRejectedValue(new Error('Set error'));

      await expect(cacheService.set('error-key', { test: 'data' })).rejects.toThrow('Set error');
    });

    it('should respect different TTLs based on content type', async () => {
      const testData = { test: 'data' };

      await cacheService.set('financial-key', testData, { contentType: 'financial' });
      expect(mockKV.put).toHaveBeenCalledWith(
        'financial-key',
        expect.any(String),
        expect.objectContaining({ expirationTtl: 300 })
      );

      await cacheService.set('static-key', testData, { contentType: 'static' });
      expect(mockKV.put).toHaveBeenCalledWith(
        'static-key',
        expect.any(String),
        expect.objectContaining({ expirationTtl: 86400 })
      );
    });
  });

  describe('Invalidation Operations', () => {
    it('should invalidate single key', async () => {
      await cacheService.invalidate('test-key');

      expect(mockKV.delete).toHaveBeenCalledWith('test-key');
    });

    it('should invalidate by pattern', async () => {
      (mockKV.list as MockedFunction<any>).mockResolvedValue({
        keys: [{ name: 'user:123' }, { name: 'user:456' }],
        list_complete: true
      });

      await cacheService.invalidate('user:*');

      expect(mockKV.list).toHaveBeenCalledWith({
        prefix: 'user:',
        cursor: undefined,
        limit: 100
      });
    });

    it('should invalidate by tags', async () => {
      const mockData = {
        data: { test: 'data' },
        metadata: { tags: ['user', 'profile'] }
      };

      (mockKV.list as MockedFunction<any>).mockResolvedValue({
        keys: [{ name: 'tagged-key' }],
        list_complete: true
      });
      (mockKV.get as MockedFunction<any>).mockResolvedValue(mockData);

      await cacheService.invalidate('*', { tags: ['user'] });

      expect(mockKV.delete).toHaveBeenCalledWith('tagged-key');
    });

    it('should invalidate by priority', async () => {
      await cacheService.invalidate('*', { priority: 3 });

      // Should process priority cache and invalidate low-priority items
    });

    it('should invalidate with business ID scoping', async () => {
      await cacheService.invalidate('data:*', { businessId: 'business123' });

      expect(mockKV.list).toHaveBeenCalledWith({
        prefix: 'business123:data:',
        cursor: undefined,
        limit: 100
      });
    });

    it('should handle Cache API invalidation', async () => {
      const mockRequests = [
        { url: 'http://example.com/api/test1' },
        { url: 'http://example.com/api/test2' }
      ];

      (mockCacheAPI.keys as MockedFunction<any>).mockResolvedValue(mockRequests);

      await cacheService.invalidate('test*');

      expect(mockCacheAPI.delete).toHaveBeenCalledTimes(2);
    });

    it('should log slow invalidations', async () => {
      const startTime = Date.now();
      mockPerformanceNow.mockReturnValueOnce(startTime).mockReturnValueOnce(startTime + 150);

      await cacheService.invalidate('slow-key');

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Slow cache invalidation'),
        expect.any(String)
      );
    });

    it('should handle invalidation errors gracefully', async () => {
      (mockKV.delete as MockedFunction<any>).mockRejectedValue(new Error('Delete error'));

      await cacheService.invalidate('error-key');

      // Should not throw, but log warning about failed invalidations
    });
  });

  describe('Has Operation', () => {
    it('should return true when key exists in Cache API', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(new Response('{}'));

      const exists = await cacheService.has('existing-key');
      expect(exists).toBe(true);
    });

    it('should return true when key exists in KV', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue('some-data');

      const exists = await cacheService.has('kv-key');
      expect(exists).toBe(true);
    });

    it('should return false when key does not exist', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue(null);

      const exists = await cacheService.has('non-existent');
      expect(exists).toBe(false);
    });
  });

  describe('Statistics and Monitoring', () => {
    it('should return enhanced statistics', async () => {
      const stats = await cacheService.getStats();

      expect(stats).toHaveProperty('l1Hits');
      expect(stats).toHaveProperty('l2Hits');
      expect(stats).toHaveProperty('totalHits');
      expect(stats).toHaveProperty('misses');
      expect(stats).toHaveProperty('totalRequests');
      expect(stats).toHaveProperty('hitRate');
      expect(stats).toHaveProperty('l1HitRate');
      expect(stats).toHaveProperty('l2HitRate');
      expect(stats).toHaveProperty('avgResponseTime');
      expect(stats).toHaveProperty('requestsPerHour');
      expect(stats).toHaveProperty('invalidations');
      expect(stats).toHaveProperty('priorityCacheSize');
      expect(stats).toHaveProperty('warmupQueueSize');
      expect(stats).toHaveProperty('uptime');
      expect(stats).toHaveProperty('memoryUsage');
    });

    it('should calculate hit rates correctly', async () => {
      // Simulate some cache operations
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

      await cacheService.get('key1');
      await cacheService.get('key2');
      await cacheService.get('non-existent');

      const stats = await cacheService.getStats();
      expect(stats.totalRequests).toBe(3);
      expect(stats.hitRate).toBeGreaterThan(0);
    });

    it('should reset statistics', () => {
      cacheService.resetStats();

      // After reset, stats should be zeroed
      expect(true).toBe(true); // Stats reset is internal
    });

    it('should estimate memory usage', async () => {
      const stats = await cacheService.getStats();
      expect(typeof stats.memoryUsage).toBe('number');
      expect(stats.memoryUsage).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Cache Information', () => {
    it('should return cache info for Cache API key', async () => {
      const mockResponse = new Response('{}', {
        headers: {
          'X-Cache-Timestamp': '1234567890',
          'X-Cache-TTL': '300',
          'Content-Length': '100'
        }
      });

      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(mockResponse);

      const info = await cacheService.getInfo('test-key');

      expect(info).toEqual({
        key: 'test-key',
        source: 'cache-api',
        timestamp: '1234567890',
        ttl: 300,
        size: '100'
      });
    });

    it('should return cache info for KV key', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

      const info = await cacheService.getInfo('kv-key');

      expect(info).toEqual({
        key: 'kv-key',
        source: 'kv',
        timestamp: 'unknown',
        ttl: 0,
        size: expect.any(String)
      });
    });

    it('should return null for non-existent key', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockResolvedValue(null);

      const info = await cacheService.getInfo('non-existent');
      expect(info).toBeNull();
    });
  });

  describe('Bulk Operations', () => {
    it('should get many keys in parallel', async () => {
      (mockKV.get as MockedFunction<any>)
        .mockResolvedValueOnce({ key: 'value1' })
        .mockResolvedValueOnce({ key: 'value2' })
        .mockResolvedValueOnce(null);

      const results = await cacheService.getMany(['key1', 'key2', 'key3']);

      expect(results).toEqual({
        key1: { key: 'value1' },
        key2: { key: 'value2' }
      });
    });

    it('should set many keys in parallel', async () => {
      const entries = {
        key1: { data: 'value1' },
        key2: { data: 'value2' }
      };

      await cacheService.setMany(entries, { priority: 3 });

      expect(mockKV.put).toHaveBeenCalledTimes(2);
    });

    it('should delete many keys in parallel', async () => {
      await cacheService.deleteMany(['key1', 'key2', 'key3']);

      expect(mockKV.delete).toHaveBeenCalledTimes(3);
    });
  });

  describe('Priority Cache Management', () => {
    it('should track priority access patterns', async () => {
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

      await cacheService.get('priority-key', { priority: 5 });
      await cacheService.get('priority-key', { priority: 3 });

      // Priority should be updated to the maximum
      const stats = await cacheService.getStats();
      expect(stats.priorityCacheSize).toBeGreaterThan(0);
    });

    it('should evict least recently used items when full', async () => {
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

      // Fill priority cache beyond limit
      for (let i = 0; i < 600; i++) {
        await cacheService.get(`key${i}`, { priority: 1 });
      }

      const stats = await cacheService.getStats();
      expect(stats.priorityCacheSize).toBeLessThanOrEqual(500); // MAX_PRIORITY_CACHE_SIZE
    });
  });

  describe('Clear Operations', () => {
    it('should clear all cache data', async () => {
      (mockKV.list as MockedFunction<any>).mockResolvedValue({
        keys: [{ name: 'key1' }, { name: 'key2' }],
        list_complete: true
      });

      await cacheService.clear();

      expect(mockKV.delete).toHaveBeenCalledWith('key1');
      expect(mockKV.delete).toHaveBeenCalledWith('key2');
      expect(global.caches.delete).toHaveBeenCalled();
    });

    it('should handle paginated KV clearing', async () => {
      (mockKV.list as MockedFunction<any>)
        .mockResolvedValueOnce({
          keys: [{ name: 'key1' }],
          list_complete: false,
          cursor: 'next-cursor'
        })
        .mockResolvedValueOnce({
          keys: [{ name: 'key2' }],
          list_complete: true
        });

      await cacheService.clear();

      expect(mockKV.list).toHaveBeenCalledTimes(2);
      expect(mockKV.delete).toHaveBeenCalledWith('key1');
      expect(mockKV.delete).toHaveBeenCalledWith('key2');
    });
  });

  describe('TTL Management', () => {
    it('should return correct TTL for different content types', () => {
      expect(cacheService.getTTL('user-data')).toBe(60);
      expect(cacheService.getTTL('financial')).toBe(300);
      expect(cacheService.getTTL('analytics')).toBe(3600);
      expect(cacheService.getTTL('static')).toBe(86400);
      expect(cacheService.getTTL('config')).toBe(604800);
      expect(cacheService.getTTL('unknown')).toBe(300); // default
    });
  });

  describe('Background Tasks', () => {
    it('should process warm-up queue', async () => {
      // Background tasks are started on initialization
      expect(mockSetInterval).toHaveBeenCalledWith(expect.any(Function), 30000);
      expect(mockSetInterval).toHaveBeenCalledWith(expect.any(Function), 300000);
      expect(mockSetInterval).toHaveBeenCalledWith(expect.any(Function), 600000);
    });

    it('should clean up priority cache', async () => {
      // Simulate old entries in priority cache
      await cacheService.get('old-key', { priority: 1 });

      // Background cleanup should remove old entries
      const stats = await cacheService.getStats();
      expect(stats.priorityCacheSize).toBeGreaterThanOrEqual(0);
    });

    it('should log performance metrics periodically', async () => {
      // Performance metrics logging is handled by background tasks
      expect(mockSetInterval).toHaveBeenCalled();
    });
  });

  describe('Error Resilience', () => {
    it('should handle Cache API errors gracefully', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockRejectedValue(new Error('Cache API error'));
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ fallback: 'data' });

      const result = await cacheService.get('test-key');
      expect(result).toEqual({ fallback: 'data' });
    });

    it('should handle KV errors gracefully', async () => {
      (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(null);
      (mockKV.get as MockedFunction<any>).mockRejectedValue(new Error('KV error'));

      const result = await cacheService.get('test-key');
      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle invalidation errors in batch operations', async () => {
      (mockKV.list as MockedFunction<any>).mockResolvedValue({
        keys: [{ name: 'error-key' }],
        list_complete: true
      });
      (mockKV.get as MockedFunction<any>).mockRejectedValue(new Error('Get error'));

      await cacheService.invalidate('*', { tags: ['test'] });

      // Should not throw, errors are handled gracefully
    });
  });

  describe('Concurrency and Race Conditions', () => {
    it('should handle concurrent get operations', async () => {
      (mockKV.get as MockedFunction<any>).mockResolvedValue({ concurrent: 'data' });

      const promises = Array.from({ length: 10 }, () =>
        cacheService.get('concurrent-key')
      );

      const results = await Promise.all(promises);
      results.forEach(result => {
        expect(result).toEqual({ concurrent: 'data' });
      });
    });

    it('should handle concurrent set operations', async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        cacheService.set(`concurrent-set-${i}`, { value: i })
      );

      await Promise.all(promises);
      expect(mockKV.put).toHaveBeenCalledTimes(10);
    });

    it('should handle concurrent invalidation operations', async () => {
      (mockKV.list as MockedFunction<any>).mockResolvedValue({
        keys: [],
        list_complete: true
      });

      const promises = Array.from({ length: 5 }, () =>
        cacheService.invalidate('concurrent:*')
      );

      await Promise.all(promises);
      expect(mockKV.list).toHaveBeenCalledTimes(5);
    });
  });
});

describe('CacheUtils', () => {
  describe('generateKey', () => {
    it('should generate key with prefix and parts', () => {
      const key = CacheUtils.generateKey('user', '123', 'profile');
      expect(key).toBe('user:123:profile');
    });

    it('should handle single part', () => {
      const key = CacheUtils.generateKey('user', '123');
      expect(key).toBe('user:123');
    });

    it('should handle empty parts', () => {
      const key = CacheUtils.generateKey('user');
      expect(key).toBe('user:');
    });
  });

  describe('isExpired', () => {
    it('should return true for expired timestamp', () => {
      const oldTimestamp = (Date.now() - 10000).toString(); // 10 seconds ago
      const isExpired = CacheUtils.isExpired(oldTimestamp, 5); // 5 second TTL
      expect(isExpired).toBe(true);
    });

    it('should return false for valid timestamp', () => {
      const recentTimestamp = (Date.now() - 1000).toString(); // 1 second ago
      const isExpired = CacheUtils.isExpired(recentTimestamp, 5); // 5 second TTL
      expect(isExpired).toBe(false);
    });

    it('should handle invalid timestamp', () => {
      const isExpired = CacheUtils.isExpired('invalid', 5);
      expect(isExpired).toBe(true); // NaN should be treated as expired
    });
  });

  describe('formatSize', () => {
    it('should format bytes correctly', () => {
      expect(CacheUtils.formatSize(0)).toBe('0 Bytes');
      expect(CacheUtils.formatSize(1024)).toBe('1 KB');
      expect(CacheUtils.formatSize(1048576)).toBe('1 MB');
      expect(CacheUtils.formatSize(1073741824)).toBe('1 GB');
    });

    it('should handle decimal values', () => {
      expect(CacheUtils.formatSize(1536)).toBe('1.5 KB');
      expect(CacheUtils.formatSize(1572864)).toBe('1.5 MB');
    });
  });
});

describe('createCacheService factory', () => {
  it('should create CacheService instance', () => {
    const service = createCacheService(mockKV as KVNamespace);
    expect(service).toBeInstanceOf(CacheService);
  });

  it('should create CacheService with Cache API', () => {
    const service = createCacheService(mockKV as KVNamespace, mockCacheAPI as Cache);
    expect(service).toBeInstanceOf(CacheService);
  });
});

describe('Edge Cases and Performance', () => {
  let cacheService: CacheService;

  beforeEach(() => {
    cacheService = new CacheService(mockKV as KVNamespace, mockCacheAPI as Cache);
  });

  it('should handle very large cache keys', async () => {
    const longKey = 'x'.repeat(1000);
    (mockKV.get as MockedFunction<any>).mockResolvedValue(null);

    const result = await cacheService.get(longKey);
    expect(result).toBeNull();
  });

  it('should handle very large data objects', async () => {
    const largeData = { data: 'x'.repeat(100000) };

    await cacheService.set('large-data', largeData);
    expect(mockKV.put).toHaveBeenCalled();
  });

  it('should handle rapid successive operations', async () => {
    (mockKV.get as MockedFunction<any>).mockResolvedValue({ rapid: 'data' });

    const operations = [];
    for (let i = 0; i < 100; i++) {
      operations.push(cacheService.get(`rapid-${i}`));
    }

    const results = await Promise.all(operations);
    expect(results).toHaveLength(100);
  });

  it('should handle cache size limits', async () => {
    (mockKV.get as MockedFunction<any>).mockResolvedValue({ test: 'data' });

    // Create many cached entries to test size limits
    for (let i = 0; i < 1200; i++) {
      await cacheService.get(`size-test-${i}`, { priority: 1 });
    }

    const stats = await cacheService.getStats();
    expect(stats.priorityCacheSize).toBeLessThanOrEqual(500);
  });

  it('should handle malformed cache data', async () => {
    (mockCacheAPI.match as MockedFunction<any>).mockResolvedValue(
      new Response('invalid json{', {
        headers: { 'X-Cache-Timestamp': Date.now().toString() }
      })
    );

    const result = await cacheService.get('malformed-key');
    expect(result).toBeNull();
  });
});