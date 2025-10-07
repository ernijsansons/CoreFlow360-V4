# CoreFlow360 V4 API Documentation

## Base URL
```
Production: https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1
Staging: https://coreflow360-v4-staging.ernijs-ansons.workers.dev/api/v1
```

## Authentication

CoreFlow360 uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header for all authenticated requests.

### Obtaining a Token

**POST** `/auth/login`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "usr_abc123",
      "email": "user@example.com",
      "businessId": "biz_def456",
      "role": "owner"
    },
    "expiresIn": 86400
  }
}
```

### Using the Token

Include the token in all subsequent requests:

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/businesses \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Refreshing Tokens

**POST** `/auth/refresh`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

## Rate Limiting

API requests are rate-limited to ensure fair usage:

- **Default**: 60 requests per minute per IP
- **Authenticated**: 1000 requests per minute per user
- **Enterprise**: Custom limits available

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1698432000
```

When rate limited, you'll receive:

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Please retry after 1698432000",
  "retryAfter": 60
}
```

## Error Handling

All errors follow a consistent format:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": {
      "email": "Invalid email format",
      "password": "Password must be at least 12 characters"
    }
  },
  "requestId": "req_xyz789"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid or missing authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid input parameters |
| `RATE_LIMITED` | 429 | Too many requests |
| `SERVER_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## Core Endpoints

### Authentication

#### Register New User
**POST** `/auth/register`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePassword123!",
    "businessName": "Acme Corp",
    "fullName": "John Doe"
  }'
```

#### Login
**POST** `/auth/login`

See [Authentication](#authentication) section above.

#### Logout
**POST** `/auth/logout`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Reset Password
**POST** `/auth/reset-password`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### Businesses

#### List Businesses
**GET** `/businesses`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/businesses \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "biz_abc123",
      "name": "Acme Corp",
      "industry": "Technology",
      "createdAt": "2024-01-15T10:30:00Z",
      "settings": {
        "currency": "USD",
        "timezone": "America/New_York",
        "fiscalYearStart": "01-01"
      }
    }
  ],
  "pagination": {
    "total": 1,
    "page": 1,
    "pageSize": 20
  }
}
```

#### Create Business
**POST** `/businesses`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/businesses \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Business",
    "industry": "Retail",
    "settings": {
      "currency": "USD",
      "timezone": "America/Los_Angeles"
    }
  }'
```

#### Get Business Details
**GET** `/businesses/{businessId}`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/businesses/biz_abc123 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Update Business
**PATCH** `/businesses/{businessId}`

```bash
curl -X PATCH https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/businesses/biz_abc123 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Business Name",
    "settings": {
      "currency": "EUR"
    }
  }'
```

### CRM (Customer Relationship Management)

#### List Customers
**GET** `/crm/customers`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Query Parameters:**
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 20, max: 100)
- `search` (string): Search by name or email
- `status` (string): Filter by status (active, inactive, lead)

#### Create Customer
**POST** `/crm/customers`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Smith",
    "email": "john@example.com",
    "phone": "+1-555-123-4567",
    "company": "Smith Industries",
    "type": "lead",
    "customFields": {
      "source": "Website",
      "industry": "Manufacturing"
    }
  }'
```

#### Get Customer
**GET** `/crm/customers/{customerId}`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers/cust_xyz789 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Update Customer
**PATCH** `/crm/customers/{customerId}`

```bash
curl -X PATCH https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers/cust_xyz789 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "customer",
    "customFields": {
      "lastPurchase": "2024-10-01"
    }
  }'
```

### Finance

#### List Invoices
**GET** `/finance/invoices`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/finance/invoices \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Query Parameters:**
- `status` (string): draft, sent, paid, overdue, cancelled
- `customerId` (string): Filter by customer
- `dateFrom` (string): Start date (YYYY-MM-DD)
- `dateTo` (string): End date (YYYY-MM-DD)

#### Create Invoice
**POST** `/finance/invoices`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/finance/invoices \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "customerId": "cust_xyz789",
    "dueDate": "2024-11-01",
    "items": [
      {
        "description": "Consulting Services",
        "quantity": 10,
        "unitPrice": 150.00,
        "taxRate": 0.10
      }
    ],
    "notes": "Thank you for your business"
  }'
```

#### Send Invoice
**POST** `/finance/invoices/{invoiceId}/send`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/finance/invoices/inv_abc123/send \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "emailTo": "customer@example.com",
    "emailCc": "accounts@example.com",
    "message": "Please find attached your invoice."
  }'
```

#### Record Payment
**POST** `/finance/invoices/{invoiceId}/payments`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/finance/invoices/inv_abc123/payments \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1650.00,
    "paymentDate": "2024-10-15",
    "paymentMethod": "bank_transfer",
    "reference": "TXN-12345"
  }'
```

### AI Agents

#### List AI Agents
**GET** `/agents`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/agents \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "agent_finance",
      "name": "Finance Agent",
      "status": "active",
      "tasksCompleted": 1247,
      "efficiency": 98.5,
      "lastActive": "2024-10-06T14:30:00Z"
    },
    {
      "id": "agent_crm",
      "name": "CRM Agent",
      "status": "active",
      "tasksCompleted": 892,
      "efficiency": 97.2,
      "lastActive": "2024-10-06T14:29:45Z"
    }
  ]
}
```

#### Execute Agent Task
**POST** `/agents/{agentId}/execute`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/agents/agent_finance/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "reconcile_transactions",
    "parameters": {
      "accountId": "acc_123",
      "dateRange": "last_30_days"
    }
  }'
```

#### Get Agent Recommendations
**GET** `/agents/recommendations`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/agents/recommendations \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Analytics

#### Get Dashboard Metrics
**GET** `/analytics/dashboard`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/analytics/dashboard \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Revenue Analytics
**GET** `/analytics/revenue`

```bash
curl -X GET "https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/analytics/revenue?period=month&groupBy=day" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Query Parameters:**
- `period` (string): day, week, month, quarter, year
- `groupBy` (string): day, week, month
- `compareWith` (string): previous_period, last_year

#### Customer Analytics
**GET** `/analytics/customers`

```bash
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/analytics/customers \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## WebSocket API (Real-time Updates)

Connect to receive real-time updates:

```javascript
const ws = new WebSocket('wss://coreflow360-v4-prod.ernijs-ansons.workers.dev/ws');

ws.onopen = () => {
  // Authenticate
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'YOUR_JWT_TOKEN'
  }));

  // Subscribe to events
  ws.send(JSON.stringify({
    type: 'subscribe',
    channels: ['invoices', 'customers', 'agents']
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);

  // Handle different event types
  switch(data.type) {
    case 'invoice.created':
      console.log('New invoice:', data.payload);
      break;
    case 'customer.updated':
      console.log('Customer updated:', data.payload);
      break;
    case 'agent.task_completed':
      console.log('Agent completed task:', data.payload);
      break;
  }
};
```

### Event Types

| Event | Description |
|-------|-------------|
| `invoice.created` | New invoice created |
| `invoice.paid` | Invoice payment received |
| `customer.created` | New customer added |
| `customer.updated` | Customer information updated |
| `agent.task_started` | AI agent started a task |
| `agent.task_completed` | AI agent completed a task |
| `alert.triggered` | System alert triggered |

## Code Examples

### JavaScript/Node.js

```javascript
// Install: npm install axios
const axios = require('axios');

class CoreFlow360Client {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseURL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1';
  }

  async request(method, endpoint, data = null) {
    try {
      const response = await axios({
        method,
        url: `${this.baseURL}${endpoint}`,
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        data
      });
      return response.data;
    } catch (error) {
      console.error('API Error:', error.response?.data || error.message);
      throw error;
    }
  }

  // Get all customers
  async getCustomers() {
    return this.request('GET', '/crm/customers');
  }

  // Create invoice
  async createInvoice(invoiceData) {
    return this.request('POST', '/finance/invoices', invoiceData);
  }

  // Execute AI agent task
  async executeAgentTask(agentId, task, parameters) {
    return this.request('POST', `/agents/${agentId}/execute`, {
      task,
      parameters
    });
  }
}

// Usage
const client = new CoreFlow360Client('YOUR_API_TOKEN');

// Get customers
const customers = await client.getCustomers();
console.log('Customers:', customers);

// Create invoice
const invoice = await client.createInvoice({
  customerId: 'cust_123',
  dueDate: '2024-11-01',
  items: [{
    description: 'Service',
    quantity: 1,
    unitPrice: 100
  }]
});
console.log('Invoice created:', invoice);
```

### Python

```python
# Install: pip install requests
import requests
import json

class CoreFlow360Client:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1'
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

    def request(self, method, endpoint, data=None):
        url = f'{self.base_url}{endpoint}'
        response = requests.request(
            method=method,
            url=url,
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()

    def get_customers(self):
        return self.request('GET', '/crm/customers')

    def create_invoice(self, invoice_data):
        return self.request('POST', '/finance/invoices', invoice_data)

    def execute_agent_task(self, agent_id, task, parameters):
        return self.request('POST', f'/agents/{agent_id}/execute', {
            'task': task,
            'parameters': parameters
        })

# Usage
client = CoreFlow360Client('YOUR_API_TOKEN')

# Get customers
customers = client.get_customers()
print('Customers:', customers)

# Create invoice
invoice = client.create_invoice({
    'customerId': 'cust_123',
    'dueDate': '2024-11-01',
    'items': [{
        'description': 'Service',
        'quantity': 1,
        'unitPrice': 100
    }]
})
print('Invoice created:', invoice)

# Execute AI agent task
result = client.execute_agent_task(
    'agent_finance',
    'reconcile_transactions',
    {'accountId': 'acc_123', 'dateRange': 'last_30_days'}
)
print('Agent result:', result)
```

### cURL Examples

```bash
# Get authentication token
TOKEN=$(curl -s -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' \
  | jq -r '.data.token')

# List customers
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'

# Create customer
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/crm/customers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Customer",
    "email": "new@example.com"
  }' | jq '.'

# Get analytics
curl -X GET https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/analytics/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Setting Up Webhooks

**POST** `/webhooks/configure`

```bash
curl -X POST https://coreflow360-v4-prod.ernijs-ansons.workers.dev/api/v1/webhooks/configure \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/webhook",
    "events": ["invoice.paid", "customer.created"],
    "secret": "your_webhook_secret"
  }'
```

### Webhook Payload

```json
{
  "id": "evt_123",
  "type": "invoice.paid",
  "timestamp": "2024-10-06T10:30:00Z",
  "data": {
    "invoiceId": "inv_abc123",
    "amount": 1500.00,
    "customerId": "cust_xyz789"
  },
  "signature": "sha256=..."
}
```

### Verifying Webhook Signatures

```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}
```

## Postman Collection

Download our Postman collection for easy API testing:

[Download Postman Collection](https://api.coreflow360.com/postman/collection.json)

Import instructions:
1. Open Postman
2. Click "Import"
3. Select the downloaded JSON file
4. Set your API token in the collection variables

## SDK Libraries

Official SDKs coming soon:
- **JavaScript/TypeScript**: npm install @coreflow360/sdk
- **Python**: pip install coreflow360
- **PHP**: composer require coreflow360/sdk
- **Ruby**: gem install coreflow360
- **Go**: go get github.com/coreflow360/go-sdk

## API Changelog

### Version 1.0.0 (October 2024)
- Initial API release
- Core endpoints for auth, businesses, CRM, finance
- AI agent integration
- WebSocket support
- Webhook system

### Coming Soon (v1.1.0)
- GraphQL endpoint
- Batch operations
- Advanced filtering
- Custom fields API
- Workflow automation API

## Support

**API Status Page**: https://status.coreflow360.com

**Developer Forum**: https://developers.coreflow360.com/forum

**API Support**: api-support@coreflow360.com

**Response Times**:
- Critical issues: < 1 hour
- Major issues: < 4 hours
- Minor issues: < 24 hours

---

**API Version**: 1.0.0
**Last Updated**: October 2024
**Status**: Production Ready

For the latest updates and announcements, follow [@CoreFlow360Dev](https://twitter.com/CoreFlow360Dev)