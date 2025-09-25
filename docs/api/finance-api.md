# Finance API Documentation

## Overview

The CoreFlow360 V4 Finance API provides comprehensive financial management capabilities including:
- Double-entry bookkeeping
- Invoice management
- Payment processing (Stripe & PayPal)
- Financial reporting
- Multi-currency support

Base URL: `https://api.coreflow360.com/api/v1`

## Authentication

All requests require authentication headers:
- `X-Business-ID`: Your business identifier
- `X-User-ID`: User making the request
- `Authorization`: Bearer token (for protected endpoints)

## Finance Endpoints

### Chart of Accounts

#### List Accounts
```
GET /finance/accounts
```

Returns all accounts in the chart of accounts.

#### Create Account
```
POST /finance/accounts
```

Body:
```json
{
  "code": "ACC-001",
  "name": "Cash on Hand",
  "type": "ASSET",
  "category": "CURRENT_ASSET",
  "description": "Petty cash",
  "currency": "USD",
  "isActive": true
}
```

Types: `ASSET`, `LIABILITY`, `EQUITY`, `REVENUE`, `EXPENSE`

Categories:
- Assets: `CURRENT_ASSET`, `FIXED_ASSET`
- Liabilities: `CURRENT_LIABILITY`, `LONG_TERM_LIABILITY`
- Equity: `OWNERS_EQUITY`
- Revenue: `OPERATING_REVENUE`
- Expenses: `OPERATING_EXPENSE`, `COST_OF_GOODS_SOLD`

#### Get Account
```
GET /finance/accounts/:id
```

### Journal Entries

#### Create Journal Entry
```
POST /finance/journal-entries
```

Body:
```json
{
  "date": 1704067200000,
  "description": "Monthly rent payment",
  "type": "STANDARD",
  "reference": "INV-2024-001",
  "lines": [
    {
      "accountId": "acc-1",
      "debit": 1000,
      "description": "Rent expense"
    },
    {
      "accountId": "acc-2",
      "credit": 1000,
      "description": "Cash payment"
    }
  ]
}
```

Types: `STANDARD`, `ADJUSTING`, `CLOSING`, `REVERSING`

**Important**: Journal entries must balance (total debits = total credits)

#### List Journal Entries
```
GET /finance/journal-entries?page=1&limit=20&sortBy=date&sortOrder=desc
```

#### Post Journal Entry
```
POST /finance/journal-entries/:id/post
```

Posts a draft journal entry to the general ledger.

### Financial Reports

#### Trial Balance
```
GET /finance/reports/trial-balance?startDate=1704067200000&endDate=1735689600000
```

#### Profit & Loss Statement
```
GET /finance/reports/profit-loss?startDate=1704067200000&endDate=1735689600000
```

#### Balance Sheet
```
GET /finance/reports/balance-sheet?startDate=1704067200000&endDate=1735689600000
```

#### Cash Flow Statement
```
GET /finance/reports/cash-flow?startDate=1704067200000&endDate=1735689600000
```

### Period Management

#### List Periods
```
GET /finance/periods
```

#### Close Period
```
POST /finance/periods/:id/close
```

Closes an accounting period, preventing further entries.

## Invoice Endpoints

### Invoice Management

#### Create Invoice
```
POST /invoices
```

Body:
```json
{
  "customerId": "cust-123",
  "type": "standard",
  "paymentTerms": "net_30",
  "currency": "USD",
  "lineItems": [
    {
      "description": "Consulting Services",
      "quantity": 10,
      "unitPrice": 150.00,
      "taxRate": 10,
      "discountPercent": 5
    }
  ],
  "notes": "Thank you for your business",
  "purchaseOrderNumber": "PO-456"
}
```

Types: `standard`, `recurring`, `credit_note`, `proforma`

Payment Terms: `net_15`, `net_30`, `net_45`, `net_60`, `due_on_receipt`, `custom`

#### List Invoices
```
GET /invoices?status=paid&startDate=2024-01-01&page=1&limit=20
```

Filters:
- `status`: draft, sent, viewed, partially_paid, paid, overdue, cancelled
- `customerId`: Filter by customer
- `startDate`/`endDate`: Date range
- `minAmount`/`maxAmount`: Amount range
- `search`: Search term

#### Get Invoice
```
GET /invoices/:id
```

#### Update Invoice
```
PUT /invoices/:id
```

#### Delete Invoice
```
DELETE /invoices/:id
```

### Invoice Actions

#### Send Invoice
```
POST /invoices/:id/send
```

Body:
```json
{
  "to": ["customer@example.com"],
  "cc": ["accounting@company.com"],
  "subject": "Invoice #INV-2024-001",
  "message": "Please find attached your invoice.",
  "attachPdf": true,
  "sendReminder": true,
  "reminderDays": [7, 14, 30]
}
```

#### Record Payment
```
POST /invoices/:id/payments
```

Body:
```json
{
  "amount": 500.00,
  "paymentDate": "2024-01-15",
  "paymentMethod": "bank_transfer",
  "reference": "TXN-001",
  "notes": "Partial payment received",
  "sendReceipt": true
}
```

Payment Methods: `cash`, `check`, `credit_card`, `bank_transfer`, `ach`, `paypal`, `stripe`, `other`

#### Generate PDF
```
GET /invoices/:id/pdf
```

Returns invoice as PDF document.

#### Approve Invoice
```
POST /invoices/:id/approve
```

#### Void Invoice
```
POST /invoices/:id/void?reason=Customer%20cancelled
```

### Invoice Analytics

#### Summary Statistics
```
GET /invoices/analytics/summary?startDate=2024-01-01&endDate=2024-12-31
```

#### Aging Report
```
GET /invoices/analytics/aging
```

## Payment Endpoints

### Stripe Integration

#### Create Payment Intent
```
POST /payments/stripe/payment-intent
```

Body:
```json
{
  "amount": 10000,
  "currency": "USD",
  "customerId": "cust_123",
  "invoiceId": "inv_456",
  "description": "Payment for Invoice #INV-2024-001",
  "paymentMethodTypes": ["card"],
  "captureMethod": "automatic",
  "metadata": {
    "orderId": "order_789"
  }
}
```

#### Create Customer
```
POST /payments/stripe/customer
```

Body:
```json
{
  "email": "customer@example.com",
  "name": "John Doe",
  "phone": "+1234567890",
  "address": {
    "line1": "123 Main St",
    "city": "New York",
    "state": "NY",
    "postalCode": "10001",
    "country": "US"
  }
}
```

#### Create Subscription
```
POST /payments/stripe/subscription
```

Body:
```json
{
  "customerId": "cust_123",
  "priceId": "price_456",
  "quantity": 1,
  "trialPeriodDays": 14,
  "metadata": {
    "plan": "premium"
  }
}
```

#### Process Refund
```
POST /payments/stripe/refund
```

Body:
```json
{
  "paymentIntentId": "pi_123",
  "amount": 5000,
  "reason": "requested_by_customer",
  "metadata": {
    "ticketId": "support_789"
  }
}
```

Refund Reasons: `duplicate`, `fraudulent`, `requested_by_customer`

#### Webhook Handler
```
POST /payments/stripe/webhook
```

Handles Stripe webhook events. Requires `stripe-signature` header.

### PayPal Integration

#### Create Order
```
POST /payments/paypal/order
```

Body:
```json
{
  "amount": 100.00,
  "currency": "USD",
  "description": "Product purchase",
  "invoiceId": "inv_123",
  "customerId": "cust_456",
  "returnUrl": "https://app.coreflow360.com/success",
  "cancelUrl": "https://app.coreflow360.com/cancel"
}
```

#### Capture Order
```
POST /payments/paypal/order/:id/capture
```

Captures a PayPal order after customer approval.

#### Webhook Handler
```
POST /payments/paypal/webhook
```

Handles PayPal webhook events.

### Bank Transfers

#### Initiate Transfer
```
POST /payments/bank-transfer
```

Body:
```json
{
  "amount": 1000.00,
  "currency": "USD",
  "accountNumber": "123456789",
  "routingNumber": "987654321",
  "accountType": "checking",
  "customerId": "cust_123",
  "invoiceId": "inv_456",
  "description": "Invoice payment"
}
```

Account Types: `checking`, `savings`

### Payment Status

#### Get Payment Status
```
GET /payments/status/:id?provider=stripe
```

Providers: `stripe`, `paypal`

#### Payment History
```
GET /payments/history?customerId=cust_123&startDate=2024-01-01&limit=20
```

## Error Responses

All endpoints return errors in the following format:

```json
{
  "success": false,
  "error": "Error message description",
  "requestId": "req_abc123",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

Common HTTP Status Codes:
- `200`: Success
- `400`: Bad Request (validation error)
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `429`: Rate Limited
- `500`: Internal Server Error

## Rate Limiting

API requests are rate limited to:
- 100 requests per minute for standard endpoints
- 10 requests per minute for report generation
- 1000 requests per minute for webhook endpoints

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Time when limit resets

## Webhooks

Configure webhook endpoints to receive real-time updates:

### Event Types
- `invoice.created`
- `invoice.sent`
- `invoice.paid`
- `invoice.overdue`
- `payment.succeeded`
- `payment.failed`
- `subscription.created`
- `subscription.cancelled`

### Webhook Security
All webhooks include signature verification:
- Stripe: `stripe-signature` header
- PayPal: Signature verification via API
- Custom: HMAC-SHA256 signature in `X-Webhook-Signature` header

## Testing

Test environment base URL: `https://test-api.coreflow360.com/api/v1`

Use test API keys:
- Stripe: Keys starting with `sk_test_` and `pk_test_`
- PayPal: Sandbox credentials

Test card numbers:
- Success: `4242 4242 4242 4242`
- Decline: `4000 0000 0000 0002`
- 3D Secure: `4000 0025 0000 3155`

## Support

For API support:
- Email: api-support@coreflow360.com
- Documentation: https://docs.coreflow360.com/api
- Status: https://status.coreflow360.com