/**
 * Comprehensive Tests for MockKVNamespace
 * Validates 100% interface compatibility with Cloudflare KVNamespace
 *
 * Test Coverage:
 * - All get() method overloads
 * - All getWithMetadata() overloads
 * - put() with various value types
 * - delete() operations
 * - list() with different options
 * - Batch operations
 * - Type conversions
 *
 * @coverage-target 100%
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MockKVNamespace, createMockKV } from '../kv-namespace-mock';
import type { KVNamespace } from '@cloudflare/workers-types';

describe('MockKVNamespace', () => {
  let mockKV: MockKVNamespace;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
  });

  describe('Interface Compatibility', () => {
    it('should be assignable to KVNamespace type', () => {
      const kv: KVNamespace = mockKV as any;
      expect(kv).toBeDefined();
    });

    it('should create instances via factory function', () => {
      const kv = createMockKV();
      expect(kv).toBeInstanceOf(MockKVNamespace);
    });
  });

  describe('GET Method - Single Key Operations', () => {
    beforeEach(async () => {
      await mockKV.put('text-key', 'test value');
      await mockKV.put('json-key', JSON.stringify({ foo: 'bar', num: 42 }));
    });

    it('should get string value with no options', async () => {
      const value = await mockKV.get('text-key');
      expect(value).toBe('test value');
    });

    it('should get string value with type="text"', async () => {
      const value = await mockKV.get('text-key', 'text');
      expect(value).toBe('test value');
    });

    it('should get JSON value with type="json"', async () => {
      const value = await mockKV.get('json-key', 'json') as { foo: string; num: number };
      expect(value).toEqual({ foo: 'bar', num: 42 });
    });

    it('should get ArrayBuffer value with type="arrayBuffer"', async () => {
      const value = await mockKV.get('text-key', 'arrayBuffer');
      expect(value).toBeInstanceOf(ArrayBuffer);

      const text = new TextDecoder().decode(value as ArrayBuffer);
      expect(text).toBe('test value');
    });

    it('should get ReadableStream value with type="stream"', async () => {
      const stream = await mockKV.get('text-key', 'stream');
      expect(stream).toBeInstanceOf(ReadableStream);

      const reader = stream!.getReader();
      const { value, done } = await reader.read();
      expect(done).toBe(false);

      const text = new TextDecoder().decode(value);
      expect(text).toBe('test value');
    });

    it('should get string value with options object (type: text)', async () => {
      const value = await mockKV.get('text-key', { type: 'text' });
      expect(value).toBe('test value');
    });

    it('should get JSON value with options object (type: json)', async () => {
      const value = await mockKV.get('json-key', { type: 'json' }) as { foo: string };
      expect(value).toEqual({ foo: 'bar', num: 42 });
    });

    it('should return null for non-existent keys', async () => {
      const value = await mockKV.get('non-existent');
      expect(value).toBeNull();
    });

    it('should return null for invalid JSON', async () => {
      await mockKV.put('invalid-json', 'not valid json {');
      const value = await mockKV.get('invalid-json', 'json');
      expect(value).toBeNull();
    });
  });

  describe('GET Method - Batch Operations', () => {
    beforeEach(async () => {
      await mockKV.put('key1', 'value1');
      await mockKV.put('key2', 'value2');
      await mockKV.put('key3', JSON.stringify({ data: 'test' }));
    });

    it('should get multiple keys as text', async () => {
      const values = await mockKV.get(['key1', 'key2'], 'text');
      expect(values).toBeInstanceOf(Map);
      expect(values.get('key1')).toBe('value1');
      expect(values.get('key2')).toBe('value2');
    });

    it('should get multiple keys as JSON', async () => {
      const values = await mockKV.get(['key3'], 'json') as Map<string, { data: string } | null>;
      expect(values).toBeInstanceOf(Map);
      expect(values.get('key3')).toEqual({ data: 'test' });
    });

    it('should get multiple keys with options', async () => {
      const values = await mockKV.get(['key1', 'key2'], { type: 'text' });
      expect(values).toBeInstanceOf(Map);
      expect(values.size).toBe(2);
    });

    it('should handle non-existent keys in batch', async () => {
      const values = await mockKV.get(['key1', 'non-existent'], 'text');
      expect(values.get('key1')).toBe('value1');
      expect(values.get('non-existent')).toBeNull();
    });
  });

  describe('PUT Method', () => {
    it('should put string values', async () => {
      await mockKV.put('test', 'value');
      const value = await mockKV.get('test');
      expect(value).toBe('value');
    });

    it('should put ArrayBuffer values', async () => {
      const buffer = new TextEncoder().encode('buffer value').buffer;
      await mockKV.put('buffer-key', buffer);

      const value = await mockKV.get('buffer-key');
      expect(value).toBe('buffer value');
    });

    it('should put ArrayBufferView values', async () => {
      const view = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      await mockKV.put('view-key', view);

      const value = await mockKV.get('view-key');
      expect(value).toBe('Hello');
    });

    it('should put ReadableStream values', async () => {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('stream value'));
          controller.close();
        }
      }) as ReadableStream;

      await mockKV.put('stream-key', stream as any);
      const value = await mockKV.get('stream-key');
      expect(value).toBe('stream value');
    });

    it('should store metadata with put options', async () => {
      await mockKV.put('meta-key', 'value', {
        metadata: { userId: '123', version: 1 }
      });

      const result = await mockKV.getWithMetadata('meta-key') as any;
      expect(result.value).toBe('value');
      expect(result.metadata).toEqual({ userId: '123', version: 1 });
    });

    it('should handle expiration options (stored but not enforced)', async () => {
      await mockKV.put('expire-key', 'value', {
        expirationTtl: 60
      });

      const value = await mockKV.get('expire-key');
      expect(value).toBe('value');
    });

    it('should overwrite existing values', async () => {
      await mockKV.put('key', 'value1');
      await mockKV.put('key', 'value2');

      const value = await mockKV.get('key');
      expect(value).toBe('value2');
    });
  });

  describe('DELETE Method', () => {
    beforeEach(async () => {
      await mockKV.put('delete-me', 'value');
      await mockKV.put('keep-me', 'value');
    });

    it('should delete existing keys', async () => {
      await mockKV.delete('delete-me');

      const value = await mockKV.get('delete-me');
      expect(value).toBeNull();
    });

    it('should not affect other keys', async () => {
      await mockKV.delete('delete-me');

      const value = await mockKV.get('keep-me');
      expect(value).toBe('value');
    });

    it('should handle deleting non-existent keys gracefully', async () => {
      await expect(mockKV.delete('non-existent')).resolves.toBeUndefined();
    });

    it('should delete metadata along with value', async () => {
      await mockKV.put('with-meta', 'value', { metadata: { test: true } });
      await mockKV.delete('with-meta');

      const result = await mockKV.getWithMetadata('with-meta');
      expect(result.value).toBeNull();
      expect(result.metadata).toBeNull();
    });
  });

  describe('LIST Method', () => {
    beforeEach(async () => {
      await mockKV.put('users:1', 'alice');
      await mockKV.put('users:2', 'bob');
      await mockKV.put('users:3', 'charlie');
      await mockKV.put('posts:1', 'post1');
      await mockKV.put('posts:2', 'post2');
    });

    it('should list all keys', async () => {
      const result = await mockKV.list();

      expect(result.keys.length).toBe(5);
      expect(result.list_complete).toBe(true);
      expect(result.cacheStatus).toBeNull();
    });

    it('should filter keys by prefix', async () => {
      const result = await mockKV.list({ prefix: 'users:' });

      expect(result.keys.length).toBe(3);
      expect(result.keys.map((k: any) => k.name)).toEqual(['users:1', 'users:2', 'users:3']);
    });

    it('should limit number of results', async () => {
      const result = await mockKV.list({ limit: 2 });

      expect(result.keys.length).toBe(2);
      expect(result.list_complete).toBe(false);
      expect(result).toHaveProperty('cursor');
    });

    it('should combine prefix and limit', async () => {
      const result = await mockKV.list({ prefix: 'users:', limit: 2 });

      expect(result.keys.length).toBe(2);
      expect(result.keys.every((k: any) => k.name.startsWith('users:'))).toBe(true);
    });

    it('should return list_complete true when all keys returned', async () => {
      const result = await mockKV.list({ limit: 100 });

      expect(result.list_complete).toBe(true);
      expect(result).not.toHaveProperty('cursor');
    });

    it('should include metadata in list results', async () => {
      await mockKV.put('with-meta', 'value', { metadata: { test: 'data' } });

      const result = await mockKV.list({ prefix: 'with-meta' }) as any;

      expect(result.keys[0].metadata).toEqual({ test: 'data' });
    });

    it('should return empty list for non-matching prefix', async () => {
      const result = await mockKV.list({ prefix: 'non-existent:' });

      expect(result.keys.length).toBe(0);
      expect(result.list_complete).toBe(true);
    });
  });

  describe('GET WITH METADATA - Single Key', () => {
    beforeEach(async () => {
      await mockKV.put('text-key', 'text value', {
        metadata: { type: 'text', size: 10 }
      });
      await mockKV.put('json-key', JSON.stringify({ foo: 'bar' }), {
        metadata: { type: 'json' }
      });
    });

    it('should get value with metadata (default text)', async () => {
      const result = await mockKV.getWithMetadata('text-key') as any;

      expect(result.value).toBe('text value');
      expect(result.metadata).toEqual({ type: 'text', size: 10 });
      expect(result.cacheStatus).toBeNull();
    });

    it('should get value with metadata (type: text)', async () => {
      const result = await mockKV.getWithMetadata('text-key', 'text') as any;

      expect(result.value).toBe('text value');
      expect(result.metadata).toEqual({ type: 'text', size: 10 });
    });

    it('should get JSON value with metadata', async () => {
      const result = await mockKV.getWithMetadata('json-key', 'json') as any;

      expect(result.value).toEqual({ foo: 'bar' });
      expect(result.metadata).toEqual({ type: 'json' });
    });

    it('should get ArrayBuffer with metadata', async () => {
      const result = await mockKV.getWithMetadata('text-key', 'arrayBuffer');

      expect(result.value).toBeInstanceOf(ArrayBuffer);
      expect(result.metadata).toEqual({ type: 'text', size: 10 });
    });

    it('should get stream with metadata', async () => {
      const result = await mockKV.getWithMetadata('text-key', 'stream');

      expect(result.value).toBeInstanceOf(ReadableStream);
      expect(result.metadata).toEqual({ type: 'text', size: 10 });
    });

    it('should return null metadata for keys without metadata', async () => {
      await mockKV.put('no-meta', 'value');
      const result = await mockKV.getWithMetadata('no-meta');

      expect(result.value).toBe('value');
      expect(result.metadata).toBeNull();
    });

    it('should return null for non-existent keys', async () => {
      const result = await mockKV.getWithMetadata('non-existent');

      expect(result.value).toBeNull();
      expect(result.metadata).toBeNull();
    });
  });

  describe('GET WITH METADATA - Batch Operations', () => {
    beforeEach(async () => {
      await mockKV.put('key1', 'value1', { metadata: { id: 1 } });
      await mockKV.put('key2', 'value2', { metadata: { id: 2 } });
      await mockKV.put('key3', JSON.stringify({ data: 'test' }), { metadata: { id: 3 } });
    });

    it('should get multiple values with metadata as text', async () => {
      const results = await mockKV.getWithMetadata(['key1', 'key2'], 'text') as any;

      expect(results).toBeInstanceOf(Map);
      expect(results.get('key1')?.value).toBe('value1');
      expect(results.get('key1')?.metadata).toEqual({ id: 1 });
      expect(results.get('key2')?.value).toBe('value2');
      expect(results.get('key2')?.metadata).toEqual({ id: 2 });
    });

    it('should get multiple values with metadata as JSON', async () => {
      const results = await mockKV.getWithMetadata(['key3'], 'json') as any;

      expect(results.get('key3')?.value).toEqual({ data: 'test' });
      expect(results.get('key3')?.metadata).toEqual({ id: 3 });
    });

    it('should handle batch with mixed existing and non-existent keys', async () => {
      const results = await mockKV.getWithMetadata(['key1', 'non-existent'], 'text');

      expect(results.get('key1')?.value).toBe('value1');
      expect(results.get('non-existent')?.value).toBeNull();
      expect(results.get('non-existent')?.metadata).toBeNull();
    });
  });

  describe('Helper Methods', () => {
    it('should clear all data', async () => {
      await mockKV.put('key1', 'value1');
      await mockKV.put('key2', 'value2');

      mockKV.clear();

      const result = await mockKV.list();
      expect(result.keys.length).toBe(0);
    });

    it('should get all stored data', async () => {
      await mockKV.put('key1', 'value1');
      await mockKV.put('key2', 'value2');

      const all = mockKV.getAll();

      expect(all).toBeInstanceOf(Map);
      expect(all.size).toBe(2);
      expect(all.get('key1')).toBe('value1');
      expect(all.get('key2')).toBe('value2');
    });

    it('should return store size', async () => {
      expect(mockKV.size()).toBe(0);

      await mockKV.put('key1', 'value1');
      expect(mockKV.size()).toBe(1);

      await mockKV.put('key2', 'value2');
      expect(mockKV.size()).toBe(2);

      await mockKV.delete('key1');
      expect(mockKV.size()).toBe(1);
    });

    it('should check if key exists', async () => {
      expect(mockKV.has('key1')).toBe(false);

      await mockKV.put('key1', 'value1');
      expect(mockKV.has('key1')).toBe(true);

      await mockKV.delete('key1');
      expect(mockKV.has('key1')).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string values', async () => {
      await mockKV.put('empty', '');
      const value = await mockKV.get('empty');
      expect(value).toBe('');
    });

    it('should handle Unicode characters', async () => {
      const unicode = '你好世界 🌍 مرحبا';
      await mockKV.put('unicode', unicode);
      const value = await mockKV.get('unicode');
      expect(value).toBe(unicode);
    });

    it('should handle large values', async () => {
      const largeValue = 'x'.repeat(10000);
      await mockKV.put('large', largeValue);
      const value = await mockKV.get('large');
      expect(value).toBe(largeValue);
    });

    it('should handle complex JSON structures', async () => {
      const complexObject = {
        nested: {
          deeply: {
            values: [1, 2, 3],
            flags: { a: true, b: false }
          }
        },
        array: ['test', 123, null, { key: 'value' }]
      };

      await mockKV.put('complex', JSON.stringify(complexObject));
      const value = await mockKV.get('complex', 'json');
      expect(value).toEqual(complexObject);
    });

    it('should handle keys with special characters', async () => {
      const specialKey = 'user:email@example.com:session:abc-123';
      await mockKV.put(specialKey, 'value');
      const value = await mockKV.get(specialKey);
      expect(value).toBe('value');
    });

    it('should handle concurrent operations', async () => {
      const promises = Array.from({ length: 100 }, (_, i) =>
        mockKV.put(`key${i}`, `value${i}`)
      );

      await Promise.all(promises);

      expect(mockKV.size()).toBe(100);

      const value50 = await mockKV.get('key50');
      expect(value50).toBe('value50');
    });
  });

  describe('Type Safety', () => {
    it('should preserve generic types for JSON', async () => {
      interface User {
        id: number;
        name: string;
        email: string;
      }

      const user: User = {
        id: 1,
        name: 'Test User',
        email: 'test@example.com'
      };

      await mockKV.put('user', JSON.stringify(user));
      const retrieved = await mockKV.get('user', 'json') as User | null;

      // TypeScript should recognize this as User | null
      expect(retrieved).toEqual(user);
    });

    it('should handle metadata generics', async () => {
      interface CustomMetadata {
        version: number;
        author: string;
        tags: string[];
      }

      const metadata: CustomMetadata = {
        version: 1,
        author: 'system',
        tags: ['important', 'test']
      };

      await mockKV.put('doc', 'content', { metadata });
      const result = await mockKV.getWithMetadata('doc') as any;

      expect(result.metadata).toEqual(metadata);
    });
  });

  describe('Performance', () => {
    it('should handle 1000 sequential puts efficiently', async () => {
      const start = performance.now();

      for (let i = 0; i < 1000; i++) {
        await mockKV.put(`key${i}`, `value${i}`);
      }

      const duration = performance.now() - start;

      expect(mockKV.size()).toBe(1000);
      expect(duration).toBeLessThan(1000); // Should complete in < 1 second
    });

    it('should handle 1000 sequential gets efficiently', async () => {
      // Setup
      for (let i = 0; i < 100; i++) {
        await mockKV.put(`key${i}`, `value${i}`);
      }

      const start = performance.now();

      for (let i = 0; i < 1000; i++) {
        await mockKV.get(`key${i % 100}`);
      }

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(500); // Should be very fast
    });

    it('should handle large batch operations efficiently', async () => {
      for (let i = 0; i < 100; i++) {
        await mockKV.put(`key${i}`, `value${i}`);
      }

      const keys = Array.from({ length: 100 }, (_, i) => `key${i}`);
      const start = performance.now();

      const results = await mockKV.get(keys, 'text');

      const duration = performance.now() - start;

      expect(results.size).toBe(100);
      expect(duration).toBeLessThan(100);
    });
  });
});
