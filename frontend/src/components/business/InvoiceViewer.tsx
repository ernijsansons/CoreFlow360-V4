/**
 * Invoice Viewer Component
 * Professional invoice display with actions and status management
 */

import React, { useState } from 'react'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader } from '../ui/card'
import { Button } from '../ui/button'
import { Badge } from '../ui/Badge'
import { Modal, ConfirmModal } from '../ui/Modal'
import {
  Download,
  Send,
  Edit,
  Trash2,
  Eye,
  DollarSign,
  Calendar,
  Building,
  Mail,
  Phone,
  MapPin
} from 'lucide-react'

export interface InvoiceLineItem {
  id: string
  description: string
  quantity: number
  unitPrice: number
  lineTotal: number
  taxAmount?: number
}

export interface InvoiceData {
  id: string
  invoiceNumber: string
  status: 'draft' | 'sent' | 'viewed' | 'paid' | 'overdue' | 'cancelled'
  issueDate: string
  dueDate: string
  currency: string

  // Customer information
  customer: {
    name: string
    email?: string
    phone?: string
    address: {
      street: string
      city: string
      state: string
      postalCode: string
      country: string
    }
  }

  // Business information
  business: {
    name: string
    email?: string
    phone?: string
    address: {
      street: string
      city: string
      state: string
      postalCode: string
      country: string
    }
    logo?: string
  }

  // Financial details
  lineItems: InvoiceLineItem[]
  subtotal: number
  totalTax: number
  totalDiscount?: number
  totalAmount: number
  amountPaid?: number
  amountDue: number

  // Additional information
  notes?: string
  terms?: string
  paymentInstructions?: string
}

export interface InvoiceViewerProps {
  invoice: InvoiceData
  onEdit?: () => void
  onDelete?: () => void
  onSend?: () => void
  onDownload?: () => void
  onMarkAsPaid?: () => void
  onDuplicate?: () => void
  className?: string
  showActions?: boolean
  compact?: boolean
}

const statusColors = {
  draft: 'bg-gray-100 text-gray-800',
  sent: 'bg-blue-100 text-blue-800',
  viewed: 'bg-purple-100 text-purple-800',
  paid: 'bg-green-100 text-green-800',
  overdue: 'bg-red-100 text-red-800',
  cancelled: 'bg-gray-100 text-gray-600'
}

const statusIcons = {
  draft: Edit,
  sent: Send,
  viewed: Eye,
  paid: DollarSign,
  overdue: Calendar,
  cancelled: Trash2
}

export const InvoiceViewer: React.FC<InvoiceViewerProps> = ({
  invoice,
  onEdit,
  onDelete,
  onSend,
  onDownload,
  onMarkAsPaid,
  onDuplicate,
  className,
  showActions = true,
  compact = false,
}) => {
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [showPaymentModal, setShowPaymentModal] = useState(false)

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: invoice.currency,
    }).format(amount)
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
  }

  const StatusIcon = statusIcons[invoice.status]

  const handleDelete = () => {
    setShowDeleteConfirm(false)
    onDelete?.()
  }

  const handleMarkAsPaid = () => {
    setShowPaymentModal(false)
    onMarkAsPaid?.()
  }

  if (compact) {
    return (
      <Card className={cn('w-full', className)}>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div>
                <div className="font-semibold">{invoice.invoiceNumber}</div>
                <div className="text-sm text-muted-foreground">{invoice.customer.name}</div>
              </div>
              <Badge className={statusColors[invoice.status]}>
                <StatusIcon className="h-3 w-3 mr-1" />
                {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
              </Badge>
            </div>
            <div className="text-right">
              <div className="font-semibold">{formatCurrency(invoice.totalAmount)}</div>
              <div className="text-sm text-muted-foreground">Due {formatDate(invoice.dueDate)}</div>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <>
      <Card className={cn('w-full max-w-4xl mx-auto', className)}>
        {/* Header */}
        <CardHeader className="pb-6">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h1 className="text-2xl font-bold">Invoice {invoice.invoiceNumber}</h1>
              <div className="flex items-center space-x-4">
                <Badge className={statusColors[invoice.status]}>
                  <StatusIcon className="h-3 w-3 mr-1" />
                  {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                </Badge>
                <span className="text-sm text-muted-foreground">
                  Issued {formatDate(invoice.issueDate)}
                </span>
              </div>
            </div>

            {showActions && (
              <div className="flex space-x-2">
                {onDownload && (
                  <Button variant="outline" size="sm" onClick={onDownload}>
                    <Download className="h-4 w-4 mr-2" />
                    Download
                  </Button>
                )}
                {onSend && invoice.status === 'draft' && (
                  <Button variant="outline" size="sm" onClick={onSend}>
                    <Send className="h-4 w-4 mr-2" />
                    Send
                  </Button>
                )}
                {onEdit && (
                  <Button variant="outline" size="sm" onClick={onEdit}>
                    <Edit className="h-4 w-4 mr-2" />
                    Edit
                  </Button>
                )}
                {onMarkAsPaid && invoice.status !== 'paid' && (
                  <Button size="sm" onClick={() => setShowPaymentModal(true)}>
                    <DollarSign className="h-4 w-4 mr-2" />
                    Mark Paid
                  </Button>
                )}
              </div>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-8">
          {/* Business and Customer Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Business Info */}
            <div>
              <h3 className="font-semibold mb-3 flex items-center">
                <Building className="h-4 w-4 mr-2" />
                From
              </h3>
              <div className="space-y-1 text-sm">
                <div className="font-medium">{invoice.business.name}</div>
                <div>{invoice.business.address.street}</div>
                <div>
                  {invoice.business.address.city}, {invoice.business.address.state} {invoice.business.address.postalCode}
                </div>
                <div>{invoice.business.address.country}</div>
                {invoice.business.email && (
                  <div className="flex items-center mt-2">
                    <Mail className="h-3 w-3 mr-1" />
                    {invoice.business.email}
                  </div>
                )}
                {invoice.business.phone && (
                  <div className="flex items-center">
                    <Phone className="h-3 w-3 mr-1" />
                    {invoice.business.phone}
                  </div>
                )}
              </div>
            </div>

            {/* Customer Info */}
            <div>
              <h3 className="font-semibold mb-3 flex items-center">
                <MapPin className="h-4 w-4 mr-2" />
                Bill To
              </h3>
              <div className="space-y-1 text-sm">
                <div className="font-medium">{invoice.customer.name}</div>
                <div>{invoice.customer.address.street}</div>
                <div>
                  {invoice.customer.address.city}, {invoice.customer.address.state} {invoice.customer.address.postalCode}
                </div>
                <div>{invoice.customer.address.country}</div>
                {invoice.customer.email && (
                  <div className="flex items-center mt-2">
                    <Mail className="h-3 w-3 mr-1" />
                    {invoice.customer.email}
                  </div>
                )}
                {invoice.customer.phone && (
                  <div className="flex items-center">
                    <Phone className="h-3 w-3 mr-1" />
                    {invoice.customer.phone}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Invoice Details */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-muted rounded-lg">
            <div>
              <div className="text-sm text-muted-foreground">Invoice Date</div>
              <div className="font-medium">{formatDate(invoice.issueDate)}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Due Date</div>
              <div className="font-medium">{formatDate(invoice.dueDate)}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Total Amount</div>
              <div className="font-medium">{formatCurrency(invoice.totalAmount)}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Amount Due</div>
              <div className="font-medium text-primary">{formatCurrency(invoice.amountDue)}</div>
            </div>
          </div>

          {/* Line Items */}
          <div>
            <h3 className="font-semibold mb-4">Items</h3>
            <div className="border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm font-medium">Description</th>
                    <th className="px-4 py-3 text-right text-sm font-medium">Qty</th>
                    <th className="px-4 py-3 text-right text-sm font-medium">Price</th>
                    <th className="px-4 py-3 text-right text-sm font-medium">Total</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {invoice.lineItems.map((item) => (
                    <tr key={item.id}>
                      <td className="px-4 py-3">{item.description}</td>
                      <td className="px-4 py-3 text-right">{item.quantity}</td>
                      <td className="px-4 py-3 text-right">{formatCurrency(item.unitPrice)}</td>
                      <td className="px-4 py-3 text-right font-medium">{formatCurrency(item.lineTotal)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Totals */}
          <div className="flex justify-end">
            <div className="w-64 space-y-2">
              <div className="flex justify-between">
                <span>Subtotal:</span>
                <span>{formatCurrency(invoice.subtotal)}</span>
              </div>
              {invoice.totalDiscount && invoice.totalDiscount > 0 && (
                <div className="flex justify-between text-green-600">
                  <span>Discount:</span>
                  <span>-{formatCurrency(invoice.totalDiscount)}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span>Tax:</span>
                <span>{formatCurrency(invoice.totalTax)}</span>
              </div>
              <div className="flex justify-between font-semibold text-lg border-t pt-2">
                <span>Total:</span>
                <span>{formatCurrency(invoice.totalAmount)}</span>
              </div>
              {invoice.amountPaid && invoice.amountPaid > 0 && (
                <>
                  <div className="flex justify-between text-green-600">
                    <span>Amount Paid:</span>
                    <span>-{formatCurrency(invoice.amountPaid)}</span>
                  </div>
                  <div className="flex justify-between font-semibold text-primary border-t pt-2">
                    <span>Amount Due:</span>
                    <span>{formatCurrency(invoice.amountDue)}</span>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Notes and Terms */}
          {(invoice.notes || invoice.terms || invoice.paymentInstructions) && (
            <div className="space-y-4 pt-4 border-t">
              {invoice.notes && (
                <div>
                  <h4 className="font-medium mb-2">Notes</h4>
                  <p className="text-sm text-muted-foreground">{invoice.notes}</p>
                </div>
              )}
              {invoice.terms && (
                <div>
                  <h4 className="font-medium mb-2">Terms & Conditions</h4>
                  <p className="text-sm text-muted-foreground">{invoice.terms}</p>
                </div>
              )}
              {invoice.paymentInstructions && (
                <div>
                  <h4 className="font-medium mb-2">Payment Instructions</h4>
                  <p className="text-sm text-muted-foreground">{invoice.paymentInstructions}</p>
                </div>
              )}
            </div>
          )}

          {/* Actions Footer */}
          {showActions && (
            <div className="flex justify-between items-center pt-6 border-t">
              <div className="flex space-x-2">
                {onDuplicate && (
                  <Button variant="outline" size="sm" onClick={onDuplicate}>
                    Duplicate
                  </Button>
                )}
                {onDelete && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowDeleteConfirm(true)}
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </Button>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={showDeleteConfirm}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={handleDelete}
        title="Delete Invoice"
        message={`Are you sure you want to delete invoice ${invoice.invoiceNumber}? This action cannot be undone.`}
        confirmText="Delete"
        variant="destructive"
      />

      {/* Mark as Paid Modal */}
      <ConfirmModal
        isOpen={showPaymentModal}
        onClose={() => setShowPaymentModal(false)}
        onConfirm={handleMarkAsPaid}
        title="Mark as Paid"
        message={`Mark invoice ${invoice.invoiceNumber} as paid for ${formatCurrency(invoice.amountDue)}?`}
        confirmText="Mark Paid"
      />
    </>
  )
}

export type { InvoiceViewerProps, InvoiceData, InvoiceLineItem }