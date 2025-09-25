import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  CreditCard,
  ArrowUpRight,
  ArrowDownLeft,
  Search,
  Filter,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  AlertCircle
} from 'lucide-react'

interface Payment {
  id: string
  transactionId: string
  customer: string
  amount: number
  type: 'payment' | 'refund' | 'chargeback'
  status: 'successful' | 'failed' | 'pending' | 'processing'
  method: 'card' | 'bank' | 'paypal' | 'stripe'
  date: string
  description: string
}

export function PaymentsHistory() {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [typeFilter, setTypeFilter] = React.useState('all')
  const [statusFilter, setStatusFilter] = React.useState('all')

  const payments: Payment[] = [
    {
      id: '1',
      transactionId: 'TXN-2024-001',
      customer: 'Acme Corporation',
      amount: 2450.00,
      type: 'payment',
      status: 'successful',
      method: 'card',
      date: '2024-02-01T10:30:00',
      description: 'Invoice #INV-2024-001 payment'
    },
    {
      id: '2',
      transactionId: 'TXN-2024-002',
      customer: 'TechStart Inc',
      amount: 99.00,
      type: 'refund',
      status: 'successful',
      method: 'stripe',
      date: '2024-02-01T09:15:00',
      description: 'Partial refund for invoice #INV-2024-002'
    },
    {
      id: '3',
      transactionId: 'TXN-2024-003',
      customer: 'Global Solutions Ltd',
      amount: 1299.00,
      type: 'payment',
      status: 'pending',
      method: 'bank',
      date: '2024-01-31T14:20:00',
      description: 'Monthly subscription payment'
    },
    {
      id: '4',
      transactionId: 'TXN-2024-004',
      customer: 'StartupHub',
      amount: 3750.00,
      type: 'payment',
      status: 'failed',
      method: 'card',
      date: '2024-01-31T11:45:00',
      description: 'Payment failed - insufficient funds'
    },
    {
      id: '5',
      transactionId: 'TXN-2024-005',
      customer: 'Digital Agency Pro',
      amount: 5200.00,
      type: 'payment',
      status: 'successful',
      method: 'paypal',
      date: '2024-01-30T16:00:00',
      description: 'Annual plan payment'
    },
    {
      id: '6',
      transactionId: 'TXN-2024-006',
      customer: 'Cloud Services Co',
      amount: 450.00,
      type: 'chargeback',
      status: 'processing',
      method: 'card',
      date: '2024-01-30T13:30:00',
      description: 'Chargeback dispute in progress'
    }
  ]

  const filteredPayments = payments.filter((payment) => {
    const matchesSearch = 
      payment.transactionId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      payment.customer.toLowerCase().includes(searchQuery.toLowerCase()) ||
      payment.description.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesType = typeFilter === 'all' || payment.type === typeFilter
    const matchesStatus = statusFilter === 'all' || payment.status === statusFilter
    
    return matchesSearch && matchesType && matchesStatus
  })

  const getStatusIcon = (status: Payment['status']) => {
    switch (status) {
      case 'successful':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-500" />
      case 'processing':
        return <AlertCircle className="h-4 w-4 text-blue-500" />
      default:
        return null
    }
  }

  const getStatusBadge = (status: Payment['status']) => {
    switch (status) {
      case 'successful':
        return <Badge variant="success">Successful</Badge>
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>
      case 'pending':
        return <Badge variant="secondary">Pending</Badge>
      case 'processing':
        return <Badge variant="outline">Processing</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const getMethodIcon = (method: Payment['method']) => {
    switch (method) {
      case 'card':
        return '💳'
      case 'bank':
        return '🏦'
      case 'paypal':
        return '🅿️'
      case 'stripe':
        return '💵'
      default:
        return '💰'
    }
  }

  const calculateTotals = () => {
    return filteredPayments.reduce((acc, payment) => {
      if (payment.type === 'payment' && payment.status === 'successful') {
        acc.received += payment.amount
      } else if (payment.type === 'refund' && payment.status === 'successful') {
        acc.refunded += payment.amount
      } else if (payment.status === 'pending' || payment.status === 'processing') {
        acc.pending += payment.amount
      }
      return acc
    }, { received: 0, refunded: 0, pending: 0 })
  }

  const totals = calculateTotals()

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Received</CardDescription>
            <CardTitle className="text-2xl text-green-600">
              ${totals.received.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Refunded</CardDescription>
            <CardTitle className="text-2xl text-red-600">
              ${totals.refunded.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Pending</CardDescription>
            <CardTitle className="text-2xl text-yellow-600">
              ${totals.pending.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>Payment History</CardTitle>
              <CardDescription>View all payment transactions and refunds</CardDescription>
            </div>
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search transactions..."
                className="pl-10"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-40">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="payment">Payments</SelectItem>
                <SelectItem value="refund">Refunds</SelectItem>
                <SelectItem value="chargeback">Chargebacks</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="successful">Successful</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="processing">Processing</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-4">
            {filteredPayments.map((payment) => (
              <div key={payment.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-full ${
                    payment.type === 'payment' ? 'bg-green-100 dark:bg-green-900/20' : 
                    payment.type === 'refund' ? 'bg-red-100 dark:bg-red-900/20' : 
                    'bg-yellow-100 dark:bg-yellow-900/20'
                  }`}>
                    {payment.type === 'payment' ? (
                      <ArrowDownLeft className="h-4 w-4 text-green-600 dark:text-green-400" />
                    ) : payment.type === 'refund' ? (
                      <ArrowUpRight className="h-4 w-4 text-red-600 dark:text-red-400" />
                    ) : (
                      <AlertCircle className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <p className="font-medium">{payment.customer}</p>
                      {getStatusIcon(payment.status)}
                    </div>
                    <p className="text-sm text-gray-500">{payment.transactionId}</p>
                    <p className="text-xs text-gray-400">{payment.description}</p>
                  </div>
                </div>

                <div className="text-right">
                  <div className="flex items-center space-x-2 justify-end">
                    <span className={`text-lg font-bold ${
                      payment.type === 'payment' ? 'text-green-600' : 
                      payment.type === 'refund' ? 'text-red-600' : 
                      'text-yellow-600'
                    }`}>
                      {payment.type === 'refund' || payment.type === 'chargeback' ? '-' : '+'}
                      ${payment.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                    </span>
                    <span className="text-lg">{getMethodIcon(payment.method)}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    {new Date(payment.date).toLocaleString('en-US', {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </p>
                  <div className="mt-1">
                    {getStatusBadge(payment.status)}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {filteredPayments.length === 0 && (
            <div className="text-center py-12">
              <CreditCard className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No payments found</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}