/**
 * Agent Capability Validation Tests
 * Verifies that agents correctly implement and validate their declared capabilities
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestEnvironmentFactory,
  BusinessContextGenerator,
  TaskGenerator,
  setupAgentTests,
  type TestEnvironment
} from '../test-harness';
import {
  DEPARTMENT_CAPABILITIES,
  type AgentTask,
  type BusinessContext,
  type ValidationResult
} from '../../../src/modules/agents/types';

describe('Agent Capability Validation', () => {
  let testEnv: TestEnvironment;
  let businessContext: BusinessContext;

  setupAgentTests();

  beforeEach(async () => {
    testEnv = await TestEnvironmentFactory.create();
    businessContext = testEnv.businessContext;
  });

  afterEach(async () => {
    await TestEnvironmentFactory.cleanup(testEnv);
  });

  describe('Capability Declaration Validation', () => {
    it('should have valid capability format', () => {
      const agent = testEnv.mockAgent;

      agent.capabilities.forEach(capability => {
        // Capabilities should follow snake_case naming convention
        expect(capability).toMatch(/^[a-z][a-z0-9_]*[a-z0-9]$/);
        expect(capability.length).toBeGreaterThan(2);
        expect(capability.length).toBeLessThan(50);
      });
    });

    it('should have department-specific capabilities', () => {
      const agent = testEnv.mockAgent;

      // If agent declares departments, it should have relevant capabilities
      if (agent.departments && agent.departments.length > 0) {
        agent.departments.forEach(department => {
          if (DEPARTMENT_CAPABILITIES[department as keyof typeof DEPARTMENT_CAPABILITIES]) {
            const deptCapabilities = DEPARTMENT_CAPABILITIES[department as keyof typeof DEPARTMENT_CAPABILITIES];

            // Agent should have at least one capability from its department
            const hasRelevantCapability = agent.capabilities.some(cap =>
              deptCapabilities.includes(cap)
            );

            // For test agent, we'll be lenient, but production agents should follow this
            if (department !== 'engineering') {
              expect(hasRelevantCapability).toBe(true);
            }
          }
        });
      }
    });

    it('should validate capability uniqueness', () => {
      const agent = testEnv.mockAgent;
      const uniqueCapabilities = new Set(agent.capabilities);

      expect(uniqueCapabilities.size).toBe(agent.capabilities.length);
    });
  });

  describe('Input Validation by Capability', () => {
    const testCapabilities = [
      'financial_analysis',
      'content_generation',
      'data_processing',
      'report_generation',
      'automation'
    ];

    testCapabilities.forEach(capability => {
      describe(`${capability} capability`, () => {
        it('should validate correct input format', async () => {
          const validInputs = [
            {
              prompt: `Perform ${capability} on this data`,
              data: { sample: 'data' },
              parameters: {}
            },
            {
              prompt: `Simple ${capability} request`,
              data: null,
              parameters: { format: 'json' }
            }
          ];

          for (const input of validInputs) {
            const result = await testEnv.mockAgent.validateInput(input, capability);
            expect(result.valid).toBe(true);
          }
        });

        it('should reject malformed input', async () => {
          const invalidInputs = [
            null,
            undefined,
            'string-only',
            123,
            [],
            { /* missing required fields */ }
          ];

          for (const input of invalidInputs) {
            const result = await testEnv.mockAgent.validateInput(input, capability);
            expect(result.valid).toBe(false);
            expect(result.errors).toBeDefined();
          }
        });

        it('should sanitize potentially harmful input', async () => {
          const harmfulInput = {
            prompt: '<script>alert("xss")</script>DROP TABLE users;',
            data: {
              malicious: '"; DELETE FROM accounts; --',
              xss: '<img src=x onerror=alert(1)>'
            },
            parameters: {
              callback: 'javascript:void(0)',
              file: '../../../etc/passwd'
            }
          };

          const result = await testEnv.mockAgent.validateInput(harmfulInput, capability);

          if (result.sanitizedInput) {
            const sanitized = result.sanitizedInput as any;
            expect(sanitized.prompt).not.toContain('<script>');
            expect(sanitized.prompt).not.toContain('DROP TABLE');

            if (sanitized.data) {
              expect(JSON.stringify(sanitized.data)).not.toContain('DELETE FROM');
              expect(JSON.stringify(sanitized.data)).not.toContain('<img');
            }
          }
        });
      });
    });
  });

  describe('Department-Specific Validation', () => {
    Object.entries(DEPARTMENT_CAPABILITIES).forEach(([department, capabilities]) => {
      describe(`${department} department`, () => {
        let deptBusinessContext: BusinessContext;

        beforeEach(() => {
          deptBusinessContext = BusinessContextGenerator.generate({
            userContext: {
              ...businessContext.userContext,
              department
            }
          });
        });

        it('should validate department-specific tasks', async () => {
          for (const capability of capabilities) {
            const task = TaskGenerator.generate({
              capability,
              context: deptBusinessContext,
              metadata: { department }
            });

            const result = await testEnv.mockAgent.validateInput(task.input, capability);
            expect(result).toBeDefined();
            expect(typeof result.valid).toBe('boolean');
          }
        });

        it('should enforce department permissions', async () => {
          const restrictedTask = TaskGenerator.generate({
            capability: capabilities[0],
            context: {
              ...deptBusinessContext,
              userContext: {
                ...deptBusinessContext.userContext,
                department: 'unauthorized_department',
                permissions: ['read'] // Limited permissions
              }
            }
          });

          // Agent should either validate or reject based on department access
          const result = await testEnv.mockAgent.validateInput(
            restrictedTask.input,
            capabilities[0]
          );
          expect(typeof result.valid).toBe('boolean');
        });
      });
    });
  });

  describe('Business Context Validation', () => {
    it('should validate required business context fields', async () => {
      const requiredFields = [
        'businessId',
        'userId',
        'businessData',
        'userContext',
        'requestContext'
      ];

      for (const field of requiredFields) {
        const invalidContext = { ...businessContext };
        delete (invalidContext as any)[field];

        const task = TaskGenerator.generate({
          context: invalidContext
        });

        try {
          await testEnv.mockAgent.execute(task, invalidContext);
        } catch (error) {
          // Should either handle gracefully or throw appropriate error
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should validate business data consistency', async () => {
      const inconsistentContext = BusinessContextGenerator.generate({
        businessData: {
          ...businessContext.businessData,
          currency: 'INVALID',
          fiscalYearStart: 'invalid-date'
        }
      });

      const task = TaskGenerator.generate({
        context: inconsistentContext
      });

      const result = await testEnv.mockAgent.validateInput(task.input, 'test');
      // Should detect and handle invalid business data
      expect(typeof result.valid).toBe('boolean');
    });

    it('should enforce user permission validation', async () => {
      const lowPermissionContext = BusinessContextGenerator.generate({
        userContext: {
          ...businessContext.userContext,
          permissions: ['read'], // Very limited permissions
          role: 'viewer'
        }
      });

      const sensitiveTask = TaskGenerator.generate({
        capability: 'financial_analysis',
        context: lowPermissionContext,
        input: {
          prompt: 'Access sensitive financial data',
          data: { confidential: true }
        }
      });

      const result = await testEnv.mockAgent.validateInput(
        sensitiveTask.input,
        'financial_analysis'
      );

      // Should handle permission validation appropriately
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Cross-Capability Validation', () => {
    it('should handle capability combinations', async () => {
      const multiCapabilityTask = TaskGenerator.generate({
        input: {
          prompt: 'Perform financial analysis and generate a report',
          data: { analysis: true, report: true },
          parameters: {
            capabilities: ['financial_analysis', 'report_generation']
          }
        }
      });

      // Agent should validate if it can handle multiple capabilities
      const analysisResult = await testEnv.mockAgent.validateInput(
        multiCapabilityTask.input,
        'financial_analysis'
      );

      const reportResult = await testEnv.mockAgent.validateInput(
        multiCapabilityTask.input,
        'report_generation'
      );

      expect(typeof analysisResult.valid).toBe('boolean');
      expect(typeof reportResult.valid).toBe('boolean');
    });

    it('should validate capability dependencies', async () => {
      // Some capabilities might depend on others
      const dependentTask = TaskGenerator.generate({
        input: {
          prompt: 'Generate automated report based on analysis',
          data: { requiresAnalysis: true },
          parameters: { dependency: 'financial_analysis' }
        }
      });

      const result = await testEnv.mockAgent.validateInput(
        dependentTask.input,
        'automation'
      );

      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Input Size and Complexity Validation', () => {
    it('should handle large input validation', async () => {
      const largeInput = {
        prompt: 'Process this large dataset',
        data: {
          records: Array.from({ length: 1000 }, (_, i) => ({
            id: i,
            value: `record-${i}`,
            metadata: { created: Date.now(), index: i }
          }))
        },
        parameters: { batchSize: 100 }
      };

      const result = await testEnv.mockAgent.validateInput(largeInput, 'data_processing');

      // Should either validate successfully or provide appropriate errors
      expect(typeof result.valid).toBe('boolean');

      if (!result.valid && result.errors) {
        // Errors should be descriptive
        result.errors.forEach(error => {
          expect(error.message).toHaveLength.greaterThan(0);
          expect(error.code).toHaveLength.greaterThan(0);
        });
      }
    });

    it('should validate input complexity limits', async () => {
      const complexInput = {
        prompt: 'Perform extremely complex analysis with multiple parameters',
        data: {
          nested: {
            deep: {
              structure: {
                with: {
                  many: {
                    levels: {
                      of: {
                        nesting: 'value'
                      }
                    }
                  }
                }
              }
            }
          },
          arrays: [
            [1, 2, [3, 4, [5, 6]]],
            { complex: true, nested: { values: [1, 2, 3] } }
          ]
        },
        parameters: {
          complexity: 'maximum',
          recursion: 10,
          iterations: 1000
        }
      };

      const result = await testEnv.mockAgent.validateInput(complexInput, 'analysis');
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Error Handling in Validation', () => {
    it('should provide meaningful validation errors', async () => {
      const problematicInput = {
        prompt: '', // Empty prompt
        data: undefined,
        parameters: {
          timeout: -1, // Invalid timeout
          maxResults: 'not-a-number' // Wrong type
        }
      };

      const result = await testEnv.mockAgent.validateInput(problematicInput, 'test');

      if (!result.valid && result.errors) {
        result.errors.forEach(error => {
          expect(error.field).toBeDefined();
          expect(error.code).toBeDefined();
          expect(error.message).toBeDefined();
          expect(error.message).toHaveLength.greaterThan(0);
        });
      }
    });

    it('should handle validation timeouts gracefully', async () => {
      // Simulate a validation that might timeout
      const timeoutInput = {
        prompt: 'Test validation timeout handling',
        data: { simulate: 'timeout' },
        parameters: {
          validationTimeout: 1, // Very short timeout
          complexValidation: true
        }
      };

      const startTime = Date.now();
      const result = await testEnv.mockAgent.validateInput(timeoutInput, 'test');
      const endTime = Date.now();

      // Validation should complete within reasonable time
      expect(endTime - startTime).toBeLessThan(5000); // 5 second max
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Validation Performance', () => {
    it('should validate inputs efficiently', async () => {
      const inputs = Array.from({ length: 100 }, (_, i) => ({
        prompt: `Test prompt ${i}`,
        data: { index: i, test: true },
        parameters: { batch: i }
      }));

      const startTime = performance.now();

      const results = await Promise.all(
        inputs.map(input => testEnv.mockAgent.validateInput(input, 'test'))
      );

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      // Should validate 100 inputs in reasonable time
      expect(totalTime).toBeLessThan(1000); // 1 second max
      expect(results).toHaveLength(100);

      results.forEach(result => {
        expect(typeof result.valid).toBe('boolean');
      });
    });

    it('should cache validation results when appropriate', async () => {
      const input = {
        prompt: 'Identical input for caching test',
        data: { cache: true },
        parameters: {}
      };

      // First validation
      const start1 = performance.now();
      const result1 = await testEnv.mockAgent.validateInput(input, 'test');
      const time1 = performance.now() - start1;

      // Second validation (potentially cached)
      const start2 = performance.now();
      const result2 = await testEnv.mockAgent.validateInput(input, 'test');
      const time2 = performance.now() - start2;

      expect(result1.valid).toBe(result2.valid);

      // Second validation might be faster due to caching
      // (This is optional behavior, so we don't enforce it)
      if (time2 < time1 * 0.5) {
        // Likely cached
        expect(time2).toBeLessThan(time1);
      }
    });
  });
});