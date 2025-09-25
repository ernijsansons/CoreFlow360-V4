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
import {
  FileText,
  Download,
  Send,
  MoreHorizontal,
  Search,
  Filter,
  Plus
} from 'lucide-react'

interface Invoice {
  id: string
  number: string
  customer: string
  email: string
  amount: number
  status: 'paid' | 'pending' | 'overdue' | 'draft' | 'cancelled'
  dueDate: string
  issuedDate: string
}

export function InvoicesTable() {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [statusFilter, setStatusFilter] = React.useState('all')

  const invoices: Invoice[] = [
    {
      id: '1',
      number: 'INV-2024-001',
      customer: 'Acme Corporation',
      email: 'billing@acme.com',
      amount: 2450.00,
      status: 'paid',
      dueDate: '2024-02-15',
      issuedDate: '2024-01-15'
    },
    {
      id: '2',
      number: 'INV-2024-002',
      customer: 'TechStart Inc',
      email: 'accounts@techstart.com',
      amount: 899.00,
      status: 'pending',
      dueDate: '2024-02-28',
      issuedDate: '2024-01-28'
    },
    {
      id: '3',
      number: 'INV-2024-003',
      customer: 'Global Solutions Ltd',
      email: 'finance@globalsolutions.com',
      amount: 1299.00,
      status: 'overdue',
      dueDate: '2024-01-31',
      issuedDate: '2024-01-01'
    },
    {
      id: '4',
      number: 'INV-2024-004',
      customer: 'StartupHub',
      email: 'pay@startuphub.io',
      amount: 3750.00,
      status: 'draft',
      dueDate: '2024-03-15',
      issuedDate: '2024-02-01'
    },
    {
      id: '5',
      number: 'INV-2024-005',
      customer: 'Digital Agency Pro',
      email: 'billing@digitalagency.com',
      amount: 5200.00,
      status: 'paid',
      dueDate: '2024-01-20',
      issuedDate: '2023-12-20'
    },
    {
      id: '6',
      number: 'INV-2024-006',
      customer: 'Cloud Services Co',
      email: 'accounts@cloudservices.co',
      amount: 1850.00,
      status: 'pending',
      dueDate: '2024-03-01',
      issuedDate: '2024-02-01'
    },
    {
      id: '7',
      number: 'INV-2024-007',
      customer: 'Marketing Masters',
      email: 'finance@marketingmasters.com',
      amount: 990.00,
      status: 'cancelled',
      dueDate: '2024-02-10',
      issuedDate: '2024-01-10'
    },
    {
      id: '8',
      number: 'INV-2024-008',
      customer: 'Data Analytics Inc',
      email: 'billing@dataanalytics.com',
      amount: 4500.00,
      status: 'paid',
      dueDate: '2024-02-05',
      issuedDate: '2024-01-05'
    }
  ]

  const filteredInvoices = invoices.filter((invoice) => {
    const matchesSearch = 
      invoice.number.toLowerCase().includes(searchQuery.toLowerCase()) ||
      invoice.customer.toLowerCase().includes(searchQuery.toLowerCase()) ||
      invoice.email.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesStatus = statusFilter === 'all' || invoice.status === statusFilter
    
    return matchesSearch && matchesStatus
  })

  const getStatusBadge = (status: Invoice['status']) => {
    switch (status) {
      case 'paid':
        return <Badge variant="success">Paid</Badge>
      case 'pending':
        return <Badge variant="secondary">Pending</Badge>
      case 'overdue':
        return <Badge variant="destructive">Overdue</Badge>
      case 'draft':
        return <Badge variant="outline">Draft</Badge>
      case 'cancelled':
        return <Badge variant="default">Cancelled</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const calculateTotals = () => {
    const totals = filteredInvoices.reduce((acc, invoice) => {
      if (invoice.status === 'paid') {
        acc.paid += invoice.amount
      } else if (invoice.status === 'pending' || invoice.status === 'overdue') {
        acc.outstanding += invoice.amount
      }
      acc.total += invoice.amount
      return acc
    }, { paid: 0, outstanding: 0, total: 0 })

    return totals
  }

  const totals = calculateTotals()

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Invoiced</CardDescription>
            <CardTitle className="text-2xl">
              ${totals.total.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Paid</CardDescription>
            <CardTitle className="text-2xl text-green-600">
              ${totals.paid.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Outstanding</CardDescription>
            <CardTitle className="text-2xl text-orange-600">
              ${totals.outstanding.toLocaleString('en-US', { minimumFractionDigits: 2 })}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>Invoices</CardTitle>
              <CardDescription>Manage and track all your invoices</CardDescription>
            </div>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Create Invoice
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search invoices..."
                className="pl-10"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-40">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="paid">Paid</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="overdue">Overdue</SelectItem>
                <SelectItem value="draft">Draft</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline">
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Invoice</TableHead>
                  <TableHead>Customer</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Due Date</TableHead>
                  <TableHead>Issued</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredInvoices.map((invoice) => (
                  <TableRow key={invoice.id}>
                    <TableCell className="font-medium">
                      <div className="flex items-center space-x-2">
                        <FileText className="h-4 w-4 text-gray-400" />
                        <span>{invoice.number}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <p className="font-medium">{invoice.customer}</p>
                        <p className="text-xs text-gray-500">{invoice.email}</p>
                      </div>
                    </TableCell>
                    <TableCell className="font-medium">
                      ${invoice.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                    </TableCell>
                    <TableCell>{getStatusBadge(invoice.status)}</TableCell>
                    <TableCell>
                      {new Date(invoice.dueDate).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric'
                      })}
                    </TableCell>
                    <TableCell>
                      {new Date(invoice.issuedDate).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric'
                      })}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" className="h-8 w-8 p-0">
                            <span className="sr-only">Open menu</span>
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem>
                            <FileText className="h-4 w-4 mr-2" />
                            View Invoice
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Download className="h-4 w-4 mr-2" />
                            Download PDF
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Send className="h-4 w-4 mr-2" />
                            Send Reminder
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600">
                            Cancel Invoice
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {filteredInvoices.length === 0 && (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No invoices found</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}