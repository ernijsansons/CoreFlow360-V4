/**
 * Step Handlers Tests
 * Comprehensive test coverage for all workflow step handlers
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  HttpRequestStepHandler,
  DatabaseStepHandler,
  EmailStepHandler,
  FileProcessingStepHandler,
  DelayStepHandler,
  StepHandlerRegistry,
} from '../step-handlers';
import { WorkflowStep } from '../types';

describe('HttpRequestStepHandler', () => {
  let handler: HttpRequestStepHandler;
  let mockStep: WorkflowStep;
  let mockContext: any;

  beforeEach(() => {
    handler = new HttpRequestStepHandler();
    mockContext = {
      workflowId: 'wf_123',
      executionId: 'exec_123',
      stepId: 'step_123',
      correlationId: 'corr_123',
      businessId: 'biz_123',
      userId: 'user_123',
      variables: {},
    };
    mockStep = {
      id: 'step_123',
      name: 'Test HTTP Request',
      type: 'action',
      executionMode: 'sequential',
      dependsOn: [],
      handler: 'http_request',
      parameters: {
        url: 'https://api.example.com/test',
        method: 'GET',
      },
      canRollback: true,
    };
  });

  describe('execute', () => {
    it('should successfully execute HTTP GET request', async () => {
      // Mock fetch globally
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: vi.fn().mockResolvedValue('{"success":true}'),
        headers: new Headers({ 'content-type': 'application/json' }),
      });

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.status).toBe(200);
      expect(result.output.data).toEqual({ success: true });
      expect(result.cost).toBeDefined();
      expect(result.cost.networkCalls).toBe(1);
    });

    it('should handle HTTP POST with body', async () => {
      mockStep.parameters = {
        url: 'https://api.example.com/create',
        method: 'POST',
        body: { name: 'Test Item' },
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        statusText: 'Created',
        text: vi.fn().mockResolvedValue('{"id":"123"}'),
        headers: new Headers(),
      });

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.status).toBe(201);
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/create',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ name: 'Test Item' }),
        })
      );
    });

    it('should handle invalid URL error', async () => {
      mockStep.parameters = { url: 'not-a-valid-url' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle HTTP error responses', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: vi.fn().mockResolvedValue('Not Found'),
        headers: new Headers(),
      });

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('404');
    });

    it('should handle network timeout', async () => {
      mockStep.parameters = {
        url: 'https://api.example.com/slow',
        timeout: 100,
      };

      global.fetch = vi.fn().mockImplementation(() =>
        new Promise((resolve) => setTimeout(resolve, 200))
      );

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
    });

    it('should validate missing URL parameter', async () => {
      mockStep.parameters = {};

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('URL');
    });
  });

  describe('rollback', () => {
    it('should skip rollback if no rollback URL provided', async () => {
      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });

    it('should execute rollback request', async () => {
      mockStep.rollbackParameters = {
        rollbackUrl: 'https://api.example.com/undo',
        rollbackMethod: 'DELETE',
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
      });

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/undo',
        expect.objectContaining({ method: 'DELETE' })
      );
    });
  });
});

describe('DatabaseStepHandler', () => {
  let handler: DatabaseStepHandler;
  let mockStep: WorkflowStep;
  let mockContext: any;

  beforeEach(() => {
    handler = new DatabaseStepHandler();
    mockContext = {
      workflowId: 'wf_123',
      executionId: 'exec_123',
      stepId: 'step_db',
      correlationId: 'corr_123',
      businessId: 'biz_123',
      userId: 'user_123',
      variables: {},
    };
    mockStep = {
      id: 'step_db',
      name: 'Test Database Operation',
      type: 'action',
      executionMode: 'sequential',
      dependsOn: [],
      handler: 'database',
      parameters: {
        operation: 'insert',
        table: 'users',
        data: { name: 'John Doe', email: 'john@example.com' },
      },
      canRollback: true,
    };
  });

  describe('execute', () => {
    it('should execute insert operation', async () => {
      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.operation).toBe('insert');
      expect(result.output.table).toBe('users');
      expect(result.output.affectedRows).toBe(1);
      expect(result.cost).toBeDefined();
    });

    it('should execute update operation', async () => {
      mockStep.parameters = {
        operation: 'update',
        table: 'users',
        data: { name: 'Jane Doe' },
        where: { id: '123' },
      };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.operation).toBe('update');
    });

    it('should execute delete operation', async () => {
      mockStep.parameters = {
        operation: 'delete',
        table: 'users',
        where: { id: '123' },
      };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.operation).toBe('delete');
    });

    it('should validate missing operation parameter', async () => {
      mockStep.parameters = { table: 'users' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('operation');
    });

    it('should validate missing table parameter', async () => {
      mockStep.parameters = { operation: 'insert' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('table');
    });

    it('should track transaction ID when transaction enabled', async () => {
      mockStep.parameters = {
        operation: 'insert',
        table: 'users',
        data: { name: 'Test' },
        transaction: true,
      };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.transactionId).toBeDefined();
    });
  });

  describe('rollback', () => {
    it('should rollback insert with delete', async () => {
      mockContext.originalOutput = {
        operation: 'insert',
        table: 'users',
        affectedRows: 1,
      };

      const result = await handler.rollback(mockStep, mockContext);

      // Log error if any for debugging
      if (!result.success) {
        console.log('Rollback error:', result.error);
      }

      expect(result.success).toBe(true);
    });

    it('should rollback update with restore', async () => {
      mockStep.parameters = {
        operation: 'update',
        table: 'users',
        data: { name: 'Updated' },
        where: { id: '123' },
      };
      mockContext.originalOutput = {
        operation: 'update',
        table: 'users',
        affectedRows: 1,
      };

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });

    it('should rollback delete with restore', async () => {
      mockStep.parameters = {
        operation: 'delete',
        table: 'users',
        where: { id: '123' },
      };
      mockContext.originalOutput = {
        operation: 'delete',
        table: 'users',
        affectedRows: 1,
      };

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });
  });
});

describe('EmailStepHandler', () => {
  let handler: EmailStepHandler;
  let mockStep: WorkflowStep;
  let mockContext: any;

  beforeEach(() => {
    handler = new EmailStepHandler();
    mockContext = {
      workflowId: 'wf_123',
      executionId: 'exec_123',
      stepId: 'step_email',
      correlationId: 'corr_123',
      businessId: 'biz_123',
      userId: 'user_123',
      variables: {},
    };
    mockStep = {
      id: 'step_email',
      name: 'Test Email',
      type: 'action',
      executionMode: 'sequential',
      dependsOn: [],
      handler: 'email',
      parameters: {
        to: 'test@example.com',
        subject: 'Test Subject',
        template: 'welcome',
        templateData: { name: 'John' },
      },
      canRollback: true,
    };
  });

  describe('execute', () => {
    it('should send email successfully', async () => {
      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.messageId).toBeDefined();
      expect(result.output.recipients).toBe(1);
      expect(result.output.subject).toBe('Test Subject');
      expect(result.cost).toBeDefined();
      expect(result.cost.customCosts?.emails).toBe(1);
    });

    it('should send to multiple recipients', async () => {
      mockStep.parameters = {
        to: ['test1@example.com', 'test2@example.com'],
        subject: 'Bulk Email',
      };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.recipients).toBe(2);
    });

    it('should validate missing to parameter', async () => {
      mockStep.parameters = { subject: 'Test' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('to');
    });

    it('should validate missing subject parameter', async () => {
      mockStep.parameters = { to: 'test@example.com' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('subject');
    });
  });

  describe('rollback', () => {
    it('should skip rollback if no template provided', async () => {
      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });

    it('should send correction email', async () => {
      mockStep.rollbackParameters = {
        rollbackTemplate: 'correction',
        rollbackSubject: 'Correction Notice',
      };
      mockContext.originalOutput = {
        messageId: 'msg_123',
        subject: 'Original Subject',
      };

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });
  });
});

describe('FileProcessingStepHandler', () => {
  let handler: FileProcessingStepHandler;
  let mockStep: WorkflowStep;
  let mockContext: any;

  beforeEach(() => {
    handler = new FileProcessingStepHandler();
    mockContext = {
      workflowId: 'wf_123',
      executionId: 'exec_123',
      stepId: 'step_file',
      correlationId: 'corr_123',
      businessId: 'biz_123',
      userId: 'user_123',
      variables: {},
    };
    mockStep = {
      id: 'step_file',
      name: 'Test File Processing',
      type: 'action',
      executionMode: 'sequential',
      dependsOn: [],
      handler: 'file_processing',
      parameters: {
        operation: 'compress',
        inputPath: '/data/input.pdf',
        outputPath: '/data/output.pdf.gz',
      },
      canRollback: true,
    };
  });

  describe('execute', () => {
    it('should compress file', async () => {
      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.operation).toBe('compress');
      expect(result.output.inputSize).toBeGreaterThan(0);
      expect(result.output.outputSize).toBeLessThan(result.output.inputSize);
    });

    it('should convert file format', async () => {
      mockStep.parameters = {
        operation: 'convert',
        inputPath: '/data/file.docx',
        outputPath: '/data/file.pdf',
        options: { format: 'pdf' },
      };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.operation).toBe('convert');
    });

    it('should validate missing operation', async () => {
      mockStep.parameters = { inputPath: '/data/file.txt' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('operation');
    });

    it('should validate missing inputPath', async () => {
      mockStep.parameters = { operation: 'compress' };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('inputPath');
    });
  });

  describe('rollback', () => {
    it('should delete processed file on compress rollback', async () => {
      mockContext.originalOutput = {
        operation: 'compress',
        outputPath: '/data/output.pdf.gz',
      };

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });

    it('should warn on delete operation rollback', async () => {
      mockStep.parameters = { operation: 'delete', inputPath: '/data/file.txt' };
      mockContext.originalOutput = { operation: 'delete' };

      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });
  });
});

describe('DelayStepHandler', () => {
  let handler: DelayStepHandler;
  let mockStep: WorkflowStep;
  let mockContext: any;

  beforeEach(() => {
    handler = new DelayStepHandler();
    mockContext = {
      workflowId: 'wf_123',
      executionId: 'exec_123',
      stepId: 'step_delay',
      correlationId: 'corr_123',
      businessId: 'biz_123',
      userId: 'user_123',
      variables: {},
    };
    mockStep = {
      id: 'step_delay',
      name: 'Test Delay',
      type: 'action',
      executionMode: 'sequential',
      dependsOn: [],
      handler: 'delay',
      parameters: {
        delayMs: 100,
      },
      canRollback: true,
    };
  });

  describe('execute', () => {
    it('should delay for specified milliseconds', async () => {
      const startTime = Date.now();
      const result = await handler.execute(mockStep, mockContext);
      const elapsed = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(elapsed).toBeGreaterThanOrEqual(100);
      expect(result.output.plannedDelayMs).toBe(100);
      expect(result.output.actualDelayMs).toBeGreaterThanOrEqual(100);
    });

    it('should delay until specific time', async () => {
      const futureTime = new Date(Date.now() + 100).toISOString();
      mockStep.parameters = { delayUntil: futureTime };

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(true);
      expect(result.output.plannedDelayMs).toBeGreaterThanOrEqual(0);
    });

    it('should validate missing delay parameters', async () => {
      mockStep.parameters = {};

      const result = await handler.execute(mockStep, mockContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('delayMs or delayUntil');
    });
  });

  describe('rollback', () => {
    it('should not require rollback', async () => {
      const result = await handler.rollback(mockStep, mockContext);

      expect(result.success).toBe(true);
    });
  });
});

describe('StepHandlerRegistry', () => {
  let registry: StepHandlerRegistry;

  beforeEach(() => {
    registry = new StepHandlerRegistry();
  });

  it('should register built-in handlers on initialization', () => {
    const handlers = registry.getRegisteredHandlers();

    expect(handlers).toContain('http_request');
    expect(handlers).toContain('database');
    expect(handlers).toContain('email');
    expect(handlers).toContain('file_processing');
    expect(handlers).toContain('delay');
  });

  it('should register custom handler', () => {
    const customHandler = new HttpRequestStepHandler();
    registry.register('custom_handler', customHandler);

    expect(registry.has('custom_handler')).toBe(true);
    expect(registry.get('custom_handler')).toBe(customHandler);
  });

  it('should get handler by name', () => {
    const handler = registry.get('http_request');

    expect(handler).toBeInstanceOf(HttpRequestStepHandler);
  });

  it('should check if handler exists', () => {
    expect(registry.has('http_request')).toBe(true);
    expect(registry.has('nonexistent')).toBe(false);
  });

  it('should list all registered handler names', () => {
    const handlers = registry.getRegisteredHandlers();

    expect(handlers.length).toBeGreaterThan(0);
    expect(Array.isArray(handlers)).toBe(true);
  });
});
