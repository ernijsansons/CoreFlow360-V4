/**
 * Artillery Helper Functions for Dynamic Test Data Generation
 * Provides utilities for performance testing scenarios
 */

const crypto = require('crypto');

// Generate random string of specified length
function randomString(length = 8) {
  return crypto.randomBytes(length).toString('hex').substring(0, length);
}

// Generate random email
function randomEmail() {
  return `test${randomString(8)}@example.com`;
}

// Generate random phone number
function randomPhone() {
  return `+1${Math.floor(Math.random() * 9000000000) + 1000000000}`;
}

// Generate random amount with 2 decimal places
function randomAmount(min = 10, max = 10000) {
  return Math.round((Math.random() * (max - min) + min) * 100) / 100;
}

// Generate realistic company names
function randomCompanyName() {
  const prefixes = ['Tech', 'Global', 'Smart', 'Digital', 'Advanced', 'Innovative', 'Premier', 'Elite'];
  const suffixes = ['Solutions', 'Systems', 'Corp', 'Industries', 'Technologies', 'Group', 'Enterprises', 'Inc'];

  return `${prefixes[Math.floor(Math.random() * prefixes.length)]} ${suffixes[Math.floor(Math.random() * suffixes.length)]}`;
}

// Generate random invoice line items
function generateInvoiceLines(count = 3) {
  const products = [
    'Software License',
    'Consulting Services',
    'Hardware Installation',
    'Training Session',
    'Support Package',
    'Development Services',
    'Maintenance Contract',
    'Custom Integration'
  ];

  return Array.from({ length: count }, (_, i) => ({
    description: `${products[Math.floor(Math.random() * products.length)]} - Item ${i + 1}`,
    quantity: Math.floor(Math.random() * 10) + 1,
    unit_price: randomAmount(50, 500),
    account_id: `acc_revenue_${Math.floor(Math.random() * 5) + 1}`,
    tax_rate_id: `tax_rate_${Math.floor(Math.random() * 3) + 1}`
  }));
}

// Generate JWT token for testing (mock)
function generateJWT() {
  const header = Buffer.from(JSON.stringify({
    alg: 'HS256',
    typ: 'JWT'
  })).toString('base64url');

  const payload = Buffer.from(JSON.stringify({
    sub: `user_${randomString(8)}`,
    business_id: `business_${Math.floor(Math.random() * 1000)}`,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
  })).toString('base64url');

  const signature = crypto
    .createHmac('sha256', 'test-secret')
    .update(`${header}.${payload}`)
    .digest('base64url');

  return `${header}.${payload}.${signature}`;
}

// Generate timestamp in various formats
function generateTimestamp(format = 'iso') {
  const now = new Date();

  switch (format) {
    case 'iso':
      return now.toISOString();
    case 'unix':
      return Math.floor(now.getTime() / 1000);
    case 'milliseconds':
      return now.getTime();
    case 'date-only':
      return now.toISOString().split('T')[0];
    default:
      return now.toISOString();
  }
}

// Generate realistic address
function generateAddress() {
  const streets = ['Main St', 'Oak Ave', 'Pine Rd', 'Cedar Ln', 'Elm Dr', 'Maple Way'];
  const cities = ['Springfield', 'Madison', 'Franklin', 'Georgetown', 'Arlington'];
  const states = ['CA', 'NY', 'TX', 'FL', 'IL', 'PA', 'OH', 'GA', 'NC', 'MI'];

  return {
    street: `${Math.floor(Math.random() * 9999) + 1} ${streets[Math.floor(Math.random() * streets.length)]}`,
    city: cities[Math.floor(Math.random() * cities.length)],
    state: states[Math.floor(Math.random() * states.length)],
    zip_code: String(Math.floor(Math.random() * 90000) + 10000),
    country: 'US'
  };
}

// Generate performance test data
function generatePerformanceTestData() {
  return {
    timestamp: Date.now(),
    test_id: randomString(16),
    user_id: `user_${randomString(8)}`,
    session_id: `session_${randomString(12)}`,
    business_id: `business_${Math.floor(Math.random() * 100)}`,
    metadata: {
      user_agent: 'Artillery Performance Test',
      ip_address: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      request_id: randomString(20)
    }
  };
}

// Load simulation functions
function simulateDatabaseLoad() {
  // Simulate database-heavy operations
  const operations = [
    'SELECT',
    'INSERT',
    'UPDATE',
    'DELETE',
    'JOIN',
    'AGGREGATE'
  ];

  return {
    operation: operations[Math.floor(Math.random() * operations.length)],
    table_name: `table_${Math.floor(Math.random() * 20)}`,
    rows_affected: Math.floor(Math.random() * 1000),
    execution_time_ms: Math.floor(Math.random() * 100)
  };
}

function simulateCacheLoad() {
  const operations = ['GET', 'SET', 'DELETE', 'INVALIDATE'];
  const cache_levels = ['L1', 'L2', 'L3'];

  return {
    operation: operations[Math.floor(Math.random() * operations.length)],
    cache_level: cache_levels[Math.floor(Math.random() * cache_levels.length)],
    key: `cache_key_${randomString(12)}`,
    hit_rate: Math.random(),
    size_bytes: Math.floor(Math.random() * 1024 * 1024) // Up to 1MB
  };
}

// Error simulation functions
function simulateError(type = 'random') {
  const errorTypes = {
    validation: {
      status: 400,
      message: 'Validation failed',
      code: 'VALIDATION_ERROR'
    },
    authentication: {
      status: 401,
      message: 'Authentication required',
      code: 'AUTH_ERROR'
    },
    authorization: {
      status: 403,
      message: 'Insufficient permissions',
      code: 'AUTHZ_ERROR'
    },
    not_found: {
      status: 404,
      message: 'Resource not found',
      code: 'NOT_FOUND'
    },
    rate_limit: {
      status: 429,
      message: 'Rate limit exceeded',
      code: 'RATE_LIMIT'
    },
    server_error: {
      status: 500,
      message: 'Internal server error',
      code: 'SERVER_ERROR'
    }
  };

  if (type === 'random') {
    const types = Object.keys(errorTypes);
    type = types[Math.floor(Math.random() * types.length)];
  }

  return errorTypes[type] || errorTypes.server_error;
}

// Business logic generators
function generateBusinessMetrics() {
  return {
    revenue: randomAmount(10000, 1000000),
    expenses: randomAmount(5000, 800000),
    profit_margin: Math.round(Math.random() * 30 * 100) / 100,
    customer_count: Math.floor(Math.random() * 10000),
    invoice_count: Math.floor(Math.random() * 1000),
    average_deal_size: randomAmount(1000, 50000),
    conversion_rate: Math.round(Math.random() * 0.5 * 10000) / 10000,
    churn_rate: Math.round(Math.random() * 0.1 * 10000) / 10000
  };
}

function generateCustomerData() {
  const customer = {
    id: `customer_${randomString(8)}`,
    name: randomCompanyName(),
    email: randomEmail(),
    phone: randomPhone(),
    website: `https://${randomString(8)}.com`,
    industry: ['Technology', 'Healthcare', 'Finance', 'Manufacturing', 'Retail'][Math.floor(Math.random() * 5)],
    size: ['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+'][Math.floor(Math.random() * 6)],
    revenue_range: ['0-1M', '1M-5M', '5M-10M', '10M-50M', '50M-100M', '100M+'][Math.floor(Math.random() * 6)],
    billing_address: generateAddress(),
    shipping_address: generateAddress(),
    payment_terms: {
      type: ['net', 'cod', 'prepaid'][Math.floor(Math.random() * 3)],
      days: [15, 30, 45, 60][Math.floor(Math.random() * 4)]
    },
    credit_limit: randomAmount(10000, 100000),
    created_at: generateTimestamp(),
    is_active: Math.random() > 0.1 // 90% active
  };

  return customer;
}

// Export functions for Artillery
module.exports = {
  // String generators
  randomString,
  randomEmail,
  randomPhone,
  randomCompanyName,

  // Numeric generators
  randomAmount,

  // Complex data generators
  generateInvoiceLines,
  generateJWT,
  generateTimestamp,
  generateAddress,
  generatePerformanceTestData,
  generateBusinessMetrics,
  generateCustomerData,

  // Load simulation
  simulateDatabaseLoad,
  simulateCacheLoad,
  simulateError,

  // Artillery context helpers
  setRandomBusinessId: function(context, events, done) {
    const businessIds = ['business123', 'business456', 'business789'];
    context.vars.businessId = businessIds[Math.floor(Math.random() * businessIds.length)];
    return done();
  },

  setRandomCustomer: function(context, events, done) {
    context.vars.customer = generateCustomerData();
    return done();
  },

  setRandomInvoiceData: function(context, events, done) {
    context.vars.invoiceData = {
      lines: generateInvoiceLines(Math.floor(Math.random() * 5) + 1),
      currency: ['USD', 'EUR', 'GBP'][Math.floor(Math.random() * 3)],
      issue_date: generateTimestamp(),
      due_date: generateTimestamp()
    };
    return done();
  },

  setPerformanceMetrics: function(context, events, done) {
    context.vars.performanceData = generatePerformanceTestData();
    return done();
  },

  // Load testing helpers
  simulateUserWorkflow: function(context, events, done) {
    const workflows = [
      'create_customer_invoice_workflow',
      'lead_to_customer_workflow',
      'financial_reporting_workflow',
      'crm_data_entry_workflow'
    ];

    context.vars.workflow = workflows[Math.floor(Math.random() * workflows.length)];
    context.vars.workflowSteps = Math.floor(Math.random() * 10) + 3; // 3-12 steps
    return done();
  },

  // Concurrency testing
  simulateConcurrentAccess: function(context, events, done) {
    context.vars.concurrentUser = {
      id: randomString(8),
      session: randomString(16),
      requests: Math.floor(Math.random() * 50) + 10
    };
    return done();
  },

  // Error injection for resilience testing
  injectRandomError: function(context, events, done) {
    if (Math.random() < 0.05) { // 5% error rate
      const error = simulateError();
      context.vars.shouldError = true;
      context.vars.errorType = error;
    } else {
      context.vars.shouldError = false;
    }
    return done();
  },

  // Performance measurement helpers
  startTimer: function(context, events, done) {
    context.vars.startTime = Date.now();
    return done();
  },

  endTimer: function(context, events, done) {
    if (context.vars.startTime) {
      const duration = Date.now() - context.vars.startTime;
      context.vars.requestDuration = duration;

      // Log slow requests
      if (duration > 150) {
        console.warn(`Slow request detected: ${duration}ms`);
      }
    }
    return done();
  },

  // Memory and resource simulation
  simulateMemoryUsage: function(context, events, done) {
    context.vars.memoryUsage = {
      heap_used: Math.floor(Math.random() * 1024 * 1024 * 100), // Up to 100MB
      heap_total: Math.floor(Math.random() * 1024 * 1024 * 200), // Up to 200MB
      external: Math.floor(Math.random() * 1024 * 1024 * 50), // Up to 50MB
      rss: Math.floor(Math.random() * 1024 * 1024 * 300) // Up to 300MB
    };
    return done();
  }
};