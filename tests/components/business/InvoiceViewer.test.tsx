/**
 * InvoiceViewer Component Tests
 * Test suite for invoice display component
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { InvoiceViewer, type InvoiceData } from '@/components/business/InvoiceViewer'

const mockInvoice: InvoiceData = {
  id: 'inv-1',
  invoiceNumber: 'INV-2024-001',
  status: 'sent',
  issueDate: '2024-01-15T00:00:00Z',
  dueDate: '2024-02-15T00:00:00Z',
  currency: 'USD',
  customer: {
    name: 'Acme Corp',
    email: 'billing@acme.com',
    phone: '+1 (555) 123-4567',
    address: {
      street: '123 Business St',
      city: 'New York',
      state: 'NY',
      postalCode: '10001',
      country: 'US'
    }
  },
  business: {
    name: 'CoreFlow360',
    email: 'billing@coreflow360.com',
    phone: '+1 (555) 987-6543',
    address: {
      street: '456 Enterprise Ave',
      city: 'San Francisco',
      state: 'CA',
      postalCode: '94102',
      country: 'US'
    }
  },
  lineItems: [
    {
      id: 'item-1',
      description: 'Professional Services',
      quantity: 10,
      unitPrice: 100.00,
      lineTotal: 1000.00
    },
    {
      id: 'item-2',
      description: 'Software License',
      quantity: 1,
      unitPrice: 200.00,
      lineTotal: 200.00
    }
  ],
  subtotal: 1200.00,
  totalTax: 50.00,
  totalAmount: 1250.00,
  amountDue: 1250.00,
  notes: 'Thank you for your business!',
  terms: 'Payment due within 30 days'
}

describe('InvoiceViewer Component', () => {
  it('renders invoice details correctly', () => {
    render(<InvoiceViewer invoice={mockInvoice} />)

    // Check invoice number and status
    expect(screen.getByText('Invoice INV-2024-001')).toBeInTheDocument()
    expect(screen.getByText('Sent')).toBeInTheDocument()

    // Check customer information
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('billing@acme.com')).toBeInTheDocument()

    // Check business information
    expect(screen.getByText('CoreFlow360')).toBeInTheDocument()
    expect(screen.getByText('billing@coreflow360.com')).toBeInTheDocument()

    // Check line items
    expect(screen.getByText('Professional Services')).toBeInTheDocument()
    expect(screen.getByText('Software License')).toBeInTheDocument()

    // Check totals
    expect(screen.getByText('$1,200.00')).toBeInTheDocument() // Subtotal
    expect(screen.getByText('$50.00')).toBeInTheDocument() // Tax
    expect(screen.getByText('$1,250.00')).toBeInTheDocument() // Total
  })

  it('renders in compact mode', () => {
    render(<InvoiceViewer invoice={mockInvoice} compact />)

    // Should show minimal information
    expect(screen.getByText('INV-2024-001')).toBeInTheDocument()
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('$1,250.00')).toBeInTheDocument()

    // Should not show detailed sections
    expect(screen.queryByText('From')).not.toBeInTheDocument()
    expect(screen.queryByText('Bill To')).not.toBeInTheDocument()
  })

  it('handles action callbacks', () => {
    const mockOnEdit = vi.fn()
    const mockOnDelete = vi.fn()
    const mockOnSend = vi.fn()
    const mockOnDownload = vi.fn()
    const mockOnMarkAsPaid = vi.fn()

    render(
      <InvoiceViewer
        invoice={mockInvoice}
        onEdit={mockOnEdit}
        onDelete={mockOnDelete}
        onSend={mockOnSend}
        onDownload={mockOnDownload}
        onMarkAsPaid={mockOnMarkAsPaid}
      />
    )

    // Test download button
    fireEvent.click(screen.getByRole('button', { name: /download/i }))
    expect(mockOnDownload).toHaveBeenCalledTimes(1)

    // Test edit button
    fireEvent.click(screen.getByRole('button', { name: /edit/i }))
    expect(mockOnEdit).toHaveBeenCalledTimes(1)

    // Test mark as paid button
    fireEvent.click(screen.getByRole('button', { name: /mark paid/i }))

    // Should open confirmation modal
    expect(screen.getByText('Mark as Paid')).toBeInTheDocument()

    // Confirm the action
    fireEvent.click(screen.getByRole('button', { name: /mark paid/i }))
    expect(mockOnMarkAsPaid).toHaveBeenCalledTimes(1)
  })

  it('shows delete confirmation modal', async () => {
    const mockOnDelete = vi.fn()

    render(
      <InvoiceViewer
        invoice={mockInvoice}
        onDelete={mockOnDelete}
      />
    )

    // Click delete button
    fireEvent.click(screen.getByRole('button', { name: /delete/i }))

    // Should show confirmation modal
    expect(screen.getByText('Delete Invoice')).toBeInTheDocument()
    expect(screen.getByText(/are you sure you want to delete invoice/i)).toBeInTheDocument()

    // Confirm deletion
    fireEvent.click(screen.getByRole('button', { name: /delete/i }))

    await waitFor(() => {
      expect(mockOnDelete).toHaveBeenCalledTimes(1)
    })
  })

  it('hides actions when showActions is false', () => {
    render(
      <InvoiceViewer
        invoice={mockInvoice}
        showActions={false}
        onEdit={vi.fn()}
        onDelete={vi.fn()}
      />
    )

    expect(screen.queryByRole('button', { name: /edit/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /download/i })).not.toBeInTheDocument()
  })

  it('formats currency correctly', () => {
    const euroInvoice: InvoiceData = {
      ...mockInvoice,
      currency: 'EUR',
      totalAmount: 1000.50
    }

    render(<InvoiceViewer invoice={euroInvoice} />)

    // Should format as Euro currency
    expect(screen.getByText('€1,000.50')).toBeInTheDocument()
  })

  it('displays correct status styling', () => {
    const { rerender } = render(<InvoiceViewer invoice={mockInvoice} />)

    // Test different statuses
    const statuses: Array<InvoiceData['status']> = ['draft', 'paid', 'overdue', 'cancelled']

    statuses.forEach(status => {
      const testInvoice = { ...mockInvoice, status }
      rerender(<InvoiceViewer invoice={testInvoice} />)

      const statusBadge = screen.getByText(status.charAt(0).toUpperCase() + status.slice(1))
      expect(statusBadge).toBeInTheDocument()
    })
  })

  it('handles missing optional fields gracefully', () => {
    const minimalInvoice: InvoiceData = {
      ...mockInvoice,
      customer: {
        ...mockInvoice.customer,
        email: undefined,
        phone: undefined
      },
      notes: undefined,
      terms: undefined,
      paymentInstructions: undefined
    }

    render(<InvoiceViewer invoice={minimalInvoice} />)

    // Should still render without errors
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('$1,250.00')).toBeInTheDocument()

    // Should not show sections for missing data
    expect(screen.queryByText('Notes')).not.toBeInTheDocument()
    expect(screen.queryByText('Terms & Conditions')).not.toBeInTheDocument()
  })

  it('displays payment information when partially paid', () => {
    const partiallyPaidInvoice: InvoiceData = {
      ...mockInvoice,
      amountPaid: 500.00,
      amountDue: 750.00
    }

    render(<InvoiceViewer invoice={partiallyPaidInvoice} />)

    expect(screen.getByText('-$500.00')).toBeInTheDocument() // Amount paid
    expect(screen.getByText('$750.00')).toBeInTheDocument() // Amount due
  })

  it('shows send button only for draft invoices', () => {
    const mockOnSend = vi.fn()

    // Test with draft status
    const draftInvoice = { ...mockInvoice, status: 'draft' as const }
    const { rerender } = render(
      <InvoiceViewer invoice={draftInvoice} onSend={mockOnSend} />
    )

    expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument()

    // Test with sent status
    const sentInvoice = { ...mockInvoice, status: 'sent' as const }
    rerender(<InvoiceViewer invoice={sentInvoice} onSend={mockOnSend} />)

    expect(screen.queryByRole('button', { name: /send/i })).not.toBeInTheDocument()
  })

  it('accessibility features work correctly', () => {
    render(<InvoiceViewer invoice={mockInvoice} />)

    // Check for proper headings structure
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Invoice INV-2024-001')
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(3) // From, Bill To, Items

    // Check for table structure
    const table = screen.getByRole('table')
    expect(table).toBeInTheDocument()

    const columnHeaders = screen.getAllByRole('columnheader')
    expect(columnHeaders).toHaveLength(4) // Description, Qty, Price, Total

    // Check for proper button labeling
    const buttons = screen.getAllByRole('button')
    buttons.forEach(button => {
      expect(button).toHaveAccessibleName()
    })
  })
})