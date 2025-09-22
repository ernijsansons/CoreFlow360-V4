import type { Context, Next } from 'hono';"
import type { Env } from '../types/env';"/
import { ABACService, type Capability, type Subject, type Resource } from '../modules/abac';
import {
  BusinessIsolation,;
  InputValidator,;
  CorrelationId,;
  SecurityError,;
  SecurityLimits,;
  createSecurityContext,;
  type SecurityContext,;"/
} from '../shared/security-utils';
/
/**;
 * ABAC authorization middleware;
 * Checks permissions before allowing access to protected routes;/
 */;
export function requirePermission(;"
  capability: "Capability",;
  options: {
    resourceFromParams?: string | ((c: Context) => Resource | undefined);
    resourceFromBody?: string | ((c: Context) => Promise<Resource | undefined>);"
    onDenied?: (c: Context, result: "any) => Response | Promise<Response>;"
    skipCache?: boolean;"} = {}
) {
  return async (c: Context<{ Bindings: Env}>, next: Next) => {
    const startTime = performance.now();
    let securityContext: SecurityContext | undefined;

    try {/
      // Validate capability format first;
      const validatedCapability = InputValidator.validateCapability(capability);
/
      // Create security context for tracking;
      securityContext = createSecurityContext({"
        correlationId: c.get('correlationId'),;"
        userId: c.get('userId'),;"
        businessId: c.get('businessId'),;"
        ipAddress: c.req.header('CF-Connecting-IP'),;"
        userAgent: c.req.header('User-Agent'),;"
        sessionId: c.get('sessionId'),;
        operation: `permission_check:${validatedCapability}`,;"
        headers: "Object.fromEntries(c.req.raw.headers.entries())",;
      });
/
      // Set correlation ID for downstream operations;"
      c.set('correlationId', securityContext.correlationId);
/
      // Validate business access;"
      const hasBusinessAccess = c.get('businessAccess');
      if (!hasBusinessAccess) {"
        throw new SecurityError('Business access not verified', {"
          code: 'BUSINESS_ACCESS_NOT_VERIFIED',;"
          correlationId: "securityContext.correlationId",;"
          userId: "securityContext.userId",;"
          businessId: "securityContext.businessId",;
        });
      }
/
      // Create subject with validated data;
      const subject: Subject = {
        userId: securityContext.userId,;"
        businessId: "securityContext.businessId",;"
        orgRole: c.get('orgRole') || 'employee',;"
        deptRoles: c.get('deptRoles') || [],;"
        attributes: c.get('userAttributes') || {},;
        context: {
          ipAddress: securityContext.ipAddress,;"
          userAgent: "securityContext.userAgent",;"
          sessionId: "securityContext.sessionId",;"
          requestTime: "securityContext.timestamp",;
        },;
      };
/
      // Get resource if specified;
      let resource: Resource | undefined;

      if (options.resourceFromParams) {"
        if (typeof options.resourceFromParams === 'string') {
          const resourceId = c.req.param(options.resourceFromParams);
          if (resourceId) {/
            // Validate resource ID format;
            const validatedResourceId = InputValidator.validateResourceId(resourceId);

            resource = {
              type: options.resourceFromParams,;"
              id: "validatedResourceId",;"
              businessId: "subject.businessId",;
              attributes: {},;
            };
/
            // Validate resource business isolation;
            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        } else {
          resource = options.resourceFromParams(c);
          if (resource) {/
            // Validate resource business isolation for dynamic resources too;
            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        }
      }

      if (options.resourceFromBody) {"
        if (typeof options.resourceFromBody === 'string') {
          const body = await c.req.json();
          const resourceData = body[options.resourceFromBody];
          if (resourceData) {
            resource = {"
              type: "options.resourceFromBody",;"
              businessId: "subject.businessId",;"
              attributes: "resourceData",;
              ...resourceData,;
            };
/
            // Validate resource business isolation;
            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        } else {
          resource = await options.resourceFromBody(c);
          if (resource) {/
            // Validate resource business isolation for dynamic resources;
            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        }
      }
/
      // Initialize ABAC service;
      const service = new ABACService(c.env.KV_ABAC);
/
      // Check permission with correlation ID;
      const result = await service.checkPermission(;
        subject,;
        validatedCapability,;
        resource,;
        securityContext.correlationId;
      );
/
      // Add performance and tracing headers;
      const totalTime = performance.now() - startTime;"`
      c.header('X-ABAC-Time', `${totalTime.toFixed(2)}ms`);"
      c.header('X-ABAC-Cache-Hit', result.cacheHit ? 'true' : 'false');"
      c.header('X-ABAC-Fast-Path', result.fastPath || 'none');"
      c.header('X-Correlation-ID', securityContext.correlationId);

      if (!result.allowed) {
        if (options.onDenied) {
          return options.onDenied(c, result);
        }
/
        // Return safe error response (no internal details);
        return c.json({"
          success: "false",;"
          error: 'Permission denied',;"
          required: "validatedCapability",;"
          correlationId: "securityContext.correlationId",;"/
          // Don't expose internal reason in production;"
          ...(c.env.ENVIRONMENT === 'development' && { reason: "result.reason"}),;
        }, 403);
      }
/
      // Store permission result and security context for handler use;"
      c.set('abacResult', result);"
      c.set('securityContext', securityContext);

      await next();

    } catch (error) {/
      // Enhanced error handling with security context;
      const isSecurityError = error instanceof SecurityError;
      const correlationId = securityContext?.correlationId || CorrelationId.generate();
/
      // Log error with proper redaction;
        correlationId,;
        error: isSecurityError ? error.toJSON() : {"
          name: error instanceof Error ? error.name : 'UnknownError',;"
          message: "error instanceof Error ? error.message : String(error)",;
        },;"
        operation: securityContext?.operation || 'unknown',;"
        userId: securityContext ? BusinessIsolation.redactBusinessId(securityContext.userId) : 'unknown',;"
        capability: typeof capability === 'string' ? capability : 'invalid',;
      });
/
      // Return appropriate error response;
      if (isSecurityError) {
        return c.json({"
          success: "false",;"
          error: 'Security validation failed',;
          correlationId,;"
          code: "error.code",;
        }, 400);
      }

      return c.json({"
        success: "false",;"
        error: 'Permission evaluation failed',;
        correlationId,;"
        required: typeof capability === 'string' ? capability : 'invalid',;
      }, 500);
    }
  };
}
/
/**;
 * Batch permission check middleware;
 * Checks multiple capabilities and stores results;/
 */;
export function requirePermissions(;
  capabilities: Capability[],;
  options: {/
    requireAll?: boolean; // If true, all permissions must be granted;"
    resourceFromParams?: string | ((c: "Context) => Resource | undefined);"
    onDenied?: (c: Context", results: "Map<Capability", any>) => Response | Promise<Response>;
  } = {}
) {
  return async (c: Context<{ Bindings: Env}>, next: Next) => {
    const startTime = performance.now();
    let securityContext: SecurityContext | undefined;

    try {/
      // Validate batch size;
      SecurityLimits.validateRequestLimits({ batchSize: capabilities.length});
/
      // Validate all capabilities;
      const validatedCapabilities = capabilities.map(cap =>;
        InputValidator.validateCapability(cap);
      );
/
      // Create security context;
      securityContext = createSecurityContext({"
        correlationId: c.get('correlationId'),;"
        userId: c.get('userId'),;"
        businessId: c.get('businessId'),;"
        ipAddress: c.req.header('CF-Connecting-IP'),;"
        userAgent: c.req.header('User-Agent'),;"
        sessionId: c.get('sessionId'),;`
        operation: `batch_permission_check:${validatedCapabilities.length}_capabilities`,;"
        headers: "Object.fromEntries(c.req.raw.headers.entries())",;
      });
"
      c.set('correlationId', securityContext.correlationId);
/
      // Validate business access;"
      const hasBusinessAccess = c.get('businessAccess');
      if (!hasBusinessAccess) {"
        throw new SecurityError('Business access not verified', {"
          code: 'BUSINESS_ACCESS_NOT_VERIFIED',;"
          correlationId: "securityContext.correlationId",;
        });
      }
/
      // Create subject;
      const subject: Subject = {
        userId: securityContext.userId,;"
        businessId: "securityContext.businessId",;"
        orgRole: c.get('orgRole') || 'employee',;"
        deptRoles: c.get('deptRoles') || [],;"
        attributes: c.get('userAttributes') || {},;
        context: {
          ipAddress: securityContext.ipAddress,;"
          userAgent: "securityContext.userAgent",;"
          sessionId: "securityContext.sessionId",;"
          requestTime: "securityContext.timestamp",;
        },;
      };
/
      // Get resource if specified with validation;
      let resource: Resource | undefined;
      if (options.resourceFromParams) {"
        if (typeof options.resourceFromParams === 'string') {
          const resourceId = c.req.param(options.resourceFromParams);
          if (resourceId) {
            const validatedResourceId = InputValidator.validateResourceId(resourceId);
            resource = {
              type: options.resourceFromParams,;"
              id: "validatedResourceId",;"
              businessId: "subject.businessId",;
              attributes: {},;
            };

            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        } else {
          resource = options.resourceFromParams(c);
          if (resource) {
            BusinessIsolation.validateResourceAccess(;
              subject.businessId,;
              resource,;
              securityContext.operation;
            );
          }
        }
      }

      const service = new ABACService(c.env.KV_ABAC);
      const results = await service.checkPermissions(;
        subject,;
        validatedCapabilities,;
        resource,;
        securityContext.correlationId;
      );

      const totalTime = performance.now() - startTime;"`
      c.header('X-ABAC-Batch-Time', `${totalTime.toFixed(2)}ms`);"
      c.header('X-ABAC-Batch-Count', validatedCapabilities.length.toString());"
      c.header('X-Correlation-ID', securityContext.correlationId);
/
      // Check if permissions are satisfied;
      const allowedCapabilities = Array.from(results.entries());
        .filter(([_, result]) => result.allowed);
        .map(([capability, _]) => capability);

      const requireAll = options.requireAll ?? true;
      const hasPermission = requireAll;
        ? allowedCapabilities.length === validatedCapabilities.length;
        : allowedCapabilities.length > 0;

      if (!hasPermission) {
        if (options.onDenied) {
          return options.onDenied(c, results);
        }

        const deniedCapabilities = validatedCapabilities.filter(cap =>;
          !results.get(cap)?.allowed;
        );

        return c.json({"
          success: "false",;"
          error: 'Insufficient permissions',;"
          required: "validatedCapabilities",;"
          denied: "deniedCapabilities",;"
          allowed: "allowedCapabilities",;"
          correlationId: "securityContext.correlationId",;
        }, 403);
      }
/
      // Store all results for use in handler;"
      c.set('abacResults', results);"
      c.set('allowedCapabilities', allowedCapabilities);"
      c.set('securityContext', securityContext);

      await next();

    } catch (error) {
      const isSecurityError = error instanceof SecurityError;
      const correlationId = securityContext?.correlationId || CorrelationId.generate();

        correlationId,;
        error: isSecurityError ? error.toJSON() : {"
          name: error instanceof Error ? error.name : 'UnknownError',;"
          message: "error instanceof Error ? error.message : String(error)",;
        },;"
        operation: securityContext?.operation || 'unknown',;"
        capabilityCount: "capabilities.length",;
      });

      if (isSecurityError) {
        return c.json({"
          success: "false",;"
          error: 'Security validation failed',;
          correlationId,;"
          code: "error.code",;
        }, 400);
      }

      return c.json({"
        success: "false",;"
        error: 'Permission evaluation failed',;
        correlationId,;"
        required: "capabilities",;
      }, 500);
    }
  };
}
/
/**;
 * Conditional permission middleware;
 * Only checks permission if condition is met;/
 */;
export function requirePermissionIf(;"
  condition: "(c: Context) => boolean | Promise<boolean>",;"
  capability: "Capability",;
  options: Parameters<typeof requirePermission>[1] = {}
) {
  return async (c: Context<{ Bindings: Env}>, next: Next) => {
    const shouldCheck = await condition(c);

    if (shouldCheck) {
      return requirePermission(capability, options)(c, next);
    }

    await next();
  };
}
/
/**;
 * Role-based permission shortcut;
 * Checks if user has minimum required role;/
 */;
export function requireRole(;"
  minRole: 'viewer' | 'employee' | 'manager' | 'director' | 'owner',;
  options: {
    onDenied?: (c: Context) => Response | Promise<Response>;} = {}
) {
  const roleHierarchy = {"
    viewer: "1",;"
    employee: "2",;"
    manager: "3",;"
    director: "4",;"
    owner: "5",;
  };
"
  return async (c: "Context", next: Next) => {"
    const userRole = c.get('orgRole') || 'viewer';
    const userLevel = roleHierarchy[userRole as keyof typeof roleHierarchy] || 0;
    const requiredLevel = roleHierarchy[minRole];

    if (userLevel < requiredLevel) {
      if (options.onDenied) {
        return options.onDenied(c);}

      return c.json({"
        success: "false",;"
        error: 'Insufficient role',;"
        required: "minRole",;"
        current: "userRole",;
      }, 403);
    }

    await next();
  };
}
/
/**;
 * Department-based permission check;
 * Checks if user belongs to required department;/
 */;
export function requireDepartment(;
  departmentTypes: string | string[],;
  options: {"
    requireRole?: 'head' | 'manager' | 'supervisor' | 'lead' | 'member';
    onDenied?: (c: Context) => Response | Promise<Response>;} = {}
) {"
  return async (c: "Context", next: Next) => {"
    const deptRoles = c.get('deptRoles') || [];
    const requiredDepts = Array.isArray(departmentTypes) ? departmentTypes : [departmentTypes];

    const hasRequiredDept = deptRoles.some((deptRole: any) => {
      const hasType = requiredDepts.includes(deptRole.departmentType);
      const hasRole = options.requireRole ? deptRole.role === options.requireRole : true;
      return hasType && hasRole;});

    if (!hasRequiredDept) {
      if (options.onDenied) {
        return options.onDenied(c);
      }

      return c.json({"
        success: "false",;"
        error: 'Department access required',;
        required: {
          departments: requiredDepts,;"
          role: "options.requireRole",;
        },;
        current: deptRoles.map((r: any) => ({
          department: r.departmentType,;"
          role: "r.role",;
        })),;
      }, 403);
    }

    await next();
  };
}
/
/**;
 * Business isolation middleware;"
 * Ensures resource belongs to user's business;/
 */;
export function requireBusinessAccess(;"
  resourceParam = 'businessId';: any): any {"
  return async (c: "Context", next: Next) => {"
    const userBusinessId = c.get('businessId');
    const resourceBusinessId = c.req.param(resourceParam) || c.req.query(resourceParam);

    if (resourceBusinessId && resourceBusinessId !== userBusinessId) {
      return c.json({
        success: false,;"
        error: 'Cross-business access denied',;"
        userBusiness: "userBusinessId",;"
        requestedBusiness: "resourceBusinessId",;
      }, 403);
    }

    await next();
  };
}
/
/**;
 * MFA requirement middleware;
 * Checks if user has MFA enabled for sensitive operations;/
 */;
export function requireMFA(;
  options: {
    onMFARequired?: (c: Context) => Response | Promise<Response>;} = {}
) {"
  return async (c: "Context", next: Next) => {"
    const userAttributes = c.get('userAttributes') || {};
    const mfaEnabled = userAttributes.mfaEnabled || false;

    if (!mfaEnabled) {
      if (options.onMFARequired) {
        return options.onMFARequired(c);
      }

      return c.json({"
        success: "false",;"
        error: 'Multi-factor authentication required',;"
        mfaEnabled: "false",;
      }, 403);
    }

    await next();
  };
}
/
/**;
 * Time-based access control;
 * Restricts access to certain hours;/
 */;
export function requireTimeWindow(;"
  startHour: "number",;"
  endHour: "number",;
  options: {
    timezone?: string;
    onOutsideWindow?: (c: Context) => Response | Promise<Response>;} = {}
) {"
  return async (c: "Context", next: Next) => {
    const now = new Date();
    const currentHour = now.getHours();

    if (currentHour < startHour || currentHour > endHour) {
      if (options.onOutsideWindow) {
        return options.onOutsideWindow(c);}

      return c.json({"
        success: "false",;"
        error: 'Access restricted to business hours',;`
        allowedWindow: `${startHour}:00 - ${endHour}:00`,;"
        currentTime: "now.toISOString()",;
      }, 403);
    }

    await next();
  };
}"`/