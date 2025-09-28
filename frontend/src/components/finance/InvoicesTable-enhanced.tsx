import * as React from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DollarSign,
  FileText,
  Send,
  Download,
  MoreHorizontal,
  Search,
  Filter,
  Plus,
  Calendar,
  AlertCircle,
  CheckCircle,
  Clock,
  XCircle,
  Mail,
  Printer,
  RefreshCw,
  Loader2,
  TrendingUp,
  TrendingDown,
  CreditCard,
  Receipt
} from 'lucide-react'
import {
  useInvoices,
  useUpdateInvoice,
  useSendInvoice,
  useVoidInvoice,
  useRecordPayment,
  useBulkSendInvoices,
  useExportInvoices,
  useFinancialMetrics
} from '@/hooks/api/use-finance'
import { useToast } from '@/hooks/use-toast'
import { formatDistanceToNow, format } from 'date-fns'

interface Invoice {
  id: string
  number: string
  customerId: string
  customerName: string
  customerEmail: string
  status: 'draft' | 'sent' | 'viewed' | 'paid' | 'overdue' | 'void'
  issueDate: string
  dueDate: string
  subtotal: number
  tax: number
  total: number
  currency: string
  items: any[]
  paymentStatus: 'pending' | 'partial' | 'paid'
  amountPaid: number
  balance: number
  lastViewedAt?: string
  sentAt?: string
  paidAt?: string
}

export function InvoicesTableEnhanced() {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [statusFilter, setStatusFilter] = React.useState('all')
  const [selectedInvoices, setSelectedInvoices] = React.useState<string[]>([])
  const [showPaymentModal, setShowPaymentModal] = React.useState(false)
  const [selectedInvoice, setSelectedInvoice] = React.useState<Invoice | null>(null)
  const { toast } = useToast()

  // Fetch invoices using React Query
  const {
    data: invoicesResponse,
    isLoading,
    isError,
    error,
    refetch,
    isFetching
  } = useInvoices({
    status: statusFilter !== 'all' ? statusFilter : undefined,
    search: searchQuery || undefined,
  })

  // Fetch financial metrics
  const { data: metricsResponse } = useFinancialMetrics()

  // Mutations
  const updateInvoice = useUpdateInvoice()
  const sendInvoice = useSendInvoice()
  const voidInvoice = useVoidInvoice()
  const recordPayment = useRecordPayment()
  const bulkSendInvoices = useBulkSendInvoices()
  const exportInvoices = useExportInvoices()

  // Use API data or fallback to mock data
  const apiInvoices = invoicesResponse?.data || []
  const metrics = metricsResponse?.data || {
    totalInvoiced: 0,
    totalPaid: 0,
    totalOutstanding: 0,
    overdueAmount: 0,
    averagePaymentTime: 0,
  }

  // Mock data for development
  const mockInvoices: Invoice[] = [
    {
      id: '1',
      number: 'INV-2024-001',
      customerId: 'cust-1',
      customerName: 'Acme Corporation',
      customerEmail: 'billing@acmecorp.com',
      status: 'sent',
      issueDate: '2024-01-15',
      dueDate: '2024-02-15',
      subtotal: 5000,
      tax: 500,
      total: 5500,
      currency: 'USD',
      items: [],
      paymentStatus: 'pending',
      amountPaid: 0,
      balance: 5500,
      sentAt: '2024-01-15T10:00:00Z',
    },
    {
      id: '2',
      number: 'INV-2024-002',
      customerId: 'cust-2',
      customerName: 'TechStart Inc',
      customerEmail: 'finance@techstart.com',
      status: 'paid',
      issueDate: '2024-01-20',
      dueDate: '2024-02-20',
      subtotal: 12000,
      tax: 1200,
      total: 13200,
      currency: 'USD',
      items: [],
      paymentStatus: 'paid',
      amountPaid: 13200,
      balance: 0,
      sentAt: '2024-01-20T10:00:00Z',
      paidAt: '2024-01-25T10:00:00Z',
    },
  ]

  const invoices = apiInvoices.length > 0 ? apiInvoices : (isError ? mockInvoices : [])

  const filteredInvoices = invoices.filter(invoice => {
    if (statusFilter !== 'all' && invoice.status !== statusFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        invoice.number.toLowerCase().includes(query) ||
        invoice.customerName.toLowerCase().includes(query) ||
        invoice.customerEmail.toLowerCase().includes(query)
      )
    }
    return true
  })

  const handleSendInvoice = async (invoiceId: string) => {
    try {
      await sendInvoice.mutateAsync(invoiceId)
    } catch (error) {
      console.error('Failed to send invoice:', error)
    }
  }

  const handleVoidInvoice = async (invoiceId: string) => {
    const reason = prompt('Please provide a reason for voiding this invoice:')
    if (reason) {
      try {
        await voidInvoice.mutateAsync({ id: invoiceId, reason })
      } catch (error) {
        console.error('Failed to void invoice:', error)
      }
    }
  }

  const handleRecordPayment = async (invoice: Invoice) => {
    setSelectedInvoice(invoice)
    setShowPaymentModal(true)
  }

  const handleBulkAction = async (action: string) => {
    if (selectedInvoices.length === 0) {
      toast({
        title: 'No invoices selected',
        description: 'Please select at least one invoice to perform this action.',
        variant: 'warning',
      })
      return
    }

    try {
      switch (action) {
        case 'send':
          await bulkSendInvoices.mutateAsync(selectedInvoices)
          setSelectedInvoices([])
          break
        case 'export':
          await exportInvoices.mutateAsync({
            format: 'pdf',
            filters: { ids: selectedInvoices }
          })
          break
        case 'mark-paid':
          // TODO: Implement bulk mark as paid
          toast({
            title: 'Feature coming soon',
            description: 'Bulk payment recording will be available in the next update.',
          })
          break
      }
    } catch (error) {
      console.error(`Failed to perform bulk action: ${action}`, error)
    }
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedInvoices(filteredInvoices.map(invoice => invoice.id))
    } else {
      setSelectedInvoices([])
    }
  }

  const handleSelectInvoice = (invoiceId: string, checked: boolean) => {
    if (checked) {
      setSelectedInvoices(prev => [...prev, invoiceId])
    } else {
      setSelectedInvoices(prev => prev.filter(id => id !== invoiceId))
    }
  }

  const getStatusColor = (status: Invoice['status']) => {
    const colors = {
      draft: 'bg-gray-100 text-gray-800',
      sent: 'bg-blue-100 text-blue-800',
      viewed: 'bg-yellow-100 text-yellow-800',
      paid: 'bg-green-100 text-green-800',
      overdue: 'bg-red-100 text-red-800',
      void: 'bg-gray-100 text-gray-500',
    }
    return colors[status] || 'bg-gray-100 text-gray-800'
  }

  const getStatusIcon = (status: Invoice['status']) => {
    switch (status) {
      case 'draft':
        return <FileText className="h-4 w-4" />
      case 'sent':
        return <Send className="h-4 w-4" />
      case 'viewed':
        return <Mail className="h-4 w-4" />
      case 'paid':
        return <CheckCircle className="h-4 w-4" />
      case 'overdue':
        return <AlertCircle className="h-4 w-4" />
      case 'void':
        return <XCircle className="h-4 w-4" />
      default:
        return <Clock className="h-4 w-4" />
    }
  }

  const formatCurrency = (amount: number, currency = 'USD') => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: 2,
    }).format(amount)
  }

  const isOverdue = (dueDate: string, status: string) => {
    return status !== 'paid' && status !== 'void' && new Date(dueDate) < new Date()
  }

  return (
    <div className="space-y-4">
      {/* Metrics Cards */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Invoiced</p>
                <p className="text-2xl font-bold">{formatCurrency(metrics.totalInvoiced)}</p>
              </div>
              <Receipt className="h-8 w-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Paid</p>
                <p className="text-2xl font-bold">{formatCurrency(metrics.totalPaid)}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Outstanding</p>
                <p className="text-2xl font-bold">{formatCurrency(metrics.totalOutstanding)}</p>
              </div>
              <Clock className="h-8 w-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Overdue</p>
                <p className="text-2xl font-bold text-red-600">
                  {formatCurrency(metrics.overdueAmount)}
                </p>
              </div>
              <AlertCircle className="h-8 w-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Invoices Table */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="text-2xl">Invoices</CardTitle>
              <CardDescription>
                {isLoading ? (
                  'Loading invoices...'
                ) : (
                  <>
                    {filteredInvoices.length} invoices
                    {selectedInvoices.length > 0 && ` • ${selectedInvoices.length} selected`}
                  </>
                )}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="icon"
                onClick={() => refetch()}
                disabled={isFetching}
              >
                {isFetching ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
              </Button>

              {selectedInvoices.length > 0 && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline">
                      Bulk Actions ({selectedInvoices.length})
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent>
                    <DropdownMenuItem onClick={() => handleBulkAction('send')}>
                      <Send className="h-4 w-4 mr-2" />
                      Send Invoices
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleBulkAction('export')}>
                      <Download className="h-4 w-4 mr-2" />
                      Export Selected
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleBulkAction('mark-paid')}>
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Mark as Paid
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}

              <Button className="gap-2">
                <Plus className="h-4 w-4" />
                New Invoice
              </Button>
            </div>
          </div>

          <div className="flex gap-2 mt-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="Search invoices..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="draft">Draft</SelectItem>
                <SelectItem value="sent">Sent</SelectItem>
                <SelectItem value="viewed">Viewed</SelectItem>
                <SelectItem value="paid">Paid</SelectItem>
                <SelectItem value="overdue">Overdue</SelectItem>
                <SelectItem value="void">Void</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>

        <CardContent>
          {isError && !invoices.length && (
            <div className="flex items-center gap-2 p-4 mb-4 bg-red-50 text-red-800 rounded-lg">
              <AlertCircle className="h-5 w-5" />
              <span>Failed to load invoices. Error: {error?.message}</span>
            </div>
          )}

          {isLoading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : filteredInvoices.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 mx-auto text-gray-400 mb-4" />
              <h3 className="text-lg font-semibold mb-2">No invoices found</h3>
              <p className="text-gray-600 mb-4">
                {searchQuery || statusFilter !== 'all'
                  ? 'Try adjusting your filters'
                  : 'Start by creating your first invoice'}
              </p>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Create Your First Invoice
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectedInvoices.length === filteredInvoices.length && filteredInvoices.length > 0}
                      onCheckedChange={handleSelectAll}
                    />
                  </TableHead>
                  <TableHead>Invoice</TableHead>
                  <TableHead>Customer</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Due Date</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Balance</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredInvoices.map((invoice) => {
                  const overdue = isOverdue(invoice.dueDate, invoice.status)
                  return (
                    <TableRow key={invoice.id}>
                      <TableCell>
                        <Checkbox
                          checked={selectedInvoices.includes(invoice.id)}
                          onCheckedChange={(checked) => handleSelectInvoice(invoice.id, checked as boolean)}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{invoice.number}</div>
                        <div className="text-sm text-gray-500">
                          {format(new Date(invoice.issueDate), 'MMM d, yyyy')}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>{invoice.customerName}</div>
                        <div className="text-sm text-gray-500">{invoice.customerEmail}</div>
                      </TableCell>
                      <TableCell>
                        <Badge className={`${getStatusColor(overdue ? 'overdue' : invoice.status)} gap-1`}>
                          {getStatusIcon(overdue ? 'overdue' : invoice.status)}
                          {overdue ? 'Overdue' : invoice.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className={overdue ? 'text-red-600 font-medium' : ''}>
                          {format(new Date(invoice.dueDate), 'MMM d, yyyy')}
                        </div>
                        {overdue && (
                          <div className="text-sm text-red-600">
                            {formatDistanceToNow(new Date(invoice.dueDate), { addSuffix: true })}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="font-medium">
                        {formatCurrency(invoice.total, invoice.currency)}
                      </TableCell>
                      <TableCell>
                        {invoice.balance > 0 ? (
                          <div className="font-medium text-orange-600">
                            {formatCurrency(invoice.balance, invoice.currency)}
                          </div>
                        ) : (
                          <Badge className="bg-green-100 text-green-800">
                            Paid
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              disabled={sendInvoice.isPending || voidInvoice.isPending}
                            >
                              {(sendInvoice.isPending || voidInvoice.isPending) ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <MoreHorizontal className="h-4 w-4" />
                              )}
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuItem>
                              <FileText className="h-4 w-4 mr-2" />
                              View Invoice
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <Printer className="h-4 w-4 mr-2" />
                              Print
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <Download className="h-4 w-4 mr-2" />
                              Download PDF
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            {invoice.status === 'draft' && (
                              <DropdownMenuItem onClick={() => handleSendInvoice(invoice.id)}>
                                <Send className="h-4 w-4 mr-2" />
                                Send Invoice
                              </DropdownMenuItem>
                            )}
                            {invoice.balance > 0 && (
                              <DropdownMenuItem onClick={() => handleRecordPayment(invoice)}>
                                <CreditCard className="h-4 w-4 mr-2" />
                                Record Payment
                              </DropdownMenuItem>
                            )}
                            {invoice.status !== 'void' && (
                              <DropdownMenuItem
                                onClick={() => handleVoidInvoice(invoice.id)}
                                className="text-red-600"
                              >
                                <XCircle className="h-4 w-4 mr-2" />
                                Void Invoice
                              </DropdownMenuItem>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}