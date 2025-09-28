import * as React from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { CalendarIcon, CreditCard, DollarSign, FileText } from 'lucide-react'
import { useRecordPayment } from '@/hooks/api/use-finance'
import { useToast } from '@/hooks/use-toast'
import { format } from 'date-fns'

const paymentFormSchema = z.object({
  amount: z.coerce.number().min(0.01, 'Amount must be greater than 0'),
  method: z.enum(['cash', 'check', 'bank_transfer', 'credit_card', 'debit_card', 'paypal', 'stripe', 'other']),
  reference: z.string().optional(),
  notes: z.string().optional(),
  processedAt: z.string().optional(),
})

type PaymentFormData = z.infer<typeof paymentFormSchema>

interface Invoice {
  id: string
  number: string
  customerName: string
  total: number
  balance: number
  currency: string
  dueDate: string
  status: string
}

interface PaymentRecordModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  invoice: Invoice | null
}

export function PaymentRecordModal({ open, onOpenChange, invoice }: PaymentRecordModalProps) {
  const { toast } = useToast()
  const recordPayment = useRecordPayment()

  const form = useForm<PaymentFormData>({
    resolver: zodResolver(paymentFormSchema),
    defaultValues: {
      amount: 0,
      method: 'bank_transfer',
      reference: '',
      notes: '',
      processedAt: new Date().toISOString().split('T')[0],
    },
  })

  // Reset form when invoice changes
  React.useEffect(() => {
    if (invoice) {
      form.reset({
        amount: invoice.balance,
        method: 'bank_transfer',
        reference: '',
        notes: '',
        processedAt: new Date().toISOString().split('T')[0],
      })
    }
  }, [invoice, form])

  const onSubmit = async (data: PaymentFormData) => {
    if (!invoice) return

    try {
      await recordPayment.mutateAsync({
        invoiceId: invoice.id,
        amount: data.amount,
        method: data.method,
        reference: data.reference,
        notes: data.notes,
        processedAt: data.processedAt,
      })

      onOpenChange(false)
      form.reset()

      toast({
        title: 'Payment recorded',
        description: `Payment of ${formatCurrency(data.amount, invoice.currency)} has been recorded for invoice #${invoice.number}`,
        variant: 'success',
      })
    } catch (error) {
      toast({
        title: 'Failed to record payment',
        description: error instanceof Error ? error.message : 'An unexpected error occurred',
        variant: 'destructive',
      })
    }
  }

  const formatCurrency = (amount: number, currency = 'USD') => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: 2,
    }).format(amount)
  }

  const getPaymentMethodIcon = (method: string) => {
    switch (method) {
      case 'credit_card':
      case 'debit_card':
        return <CreditCard className="h-4 w-4" />
      case 'cash':
        return <DollarSign className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  const getPaymentMethodLabel = (method: string) => {
    const labels = {
      cash: 'Cash',
      check: 'Check',
      bank_transfer: 'Bank Transfer',
      credit_card: 'Credit Card',
      debit_card: 'Debit Card',
      paypal: 'PayPal',
      stripe: 'Stripe',
      other: 'Other',
    }
    return labels[method as keyof typeof labels] || method
  }

  if (!invoice) return null

  const remainingBalance = invoice.balance - form.watch('amount', 0)
  const isPartialPayment = remainingBalance > 0
  const isOverpayment = remainingBalance < 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            Record Payment
          </DialogTitle>
          <DialogDescription>
            Record a payment for invoice #{invoice.number}
          </DialogDescription>
        </DialogHeader>

        {/* Invoice Summary */}
        <div className="border rounded-lg p-4 bg-gray-50 dark:bg-gray-900">
          <div className="flex justify-between items-start mb-2">
            <div>
              <h4 className="font-semibold">{invoice.customerName}</h4>
              <p className="text-sm text-gray-600">Invoice #{invoice.number}</p>
            </div>
            <Badge variant="outline">
              Due {format(new Date(invoice.dueDate), 'MMM d, yyyy')}
            </Badge>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-600">Total Amount:</span>
              <p className="font-medium">{formatCurrency(invoice.total, invoice.currency)}</p>
            </div>
            <div>
              <span className="text-gray-600">Outstanding:</span>
              <p className="font-medium text-orange-600">
                {formatCurrency(invoice.balance, invoice.currency)}
              </p>
            </div>
          </div>
        </div>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            {/* Payment Amount */}
            <FormField
              control={form.control}
              name="amount"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Payment Amount *</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <DollarSign className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                      <Input
                        type="number"
                        step="0.01"
                        min="0"
                        placeholder="0.00"
                        className="pl-10"
                        {...field}
                      />
                    </div>
                  </FormControl>
                  {remainingBalance !== invoice.balance && (
                    <FormDescription>
                      {isOverpayment ? (
                        <span className="text-orange-600">
                          Overpayment: {formatCurrency(Math.abs(remainingBalance), invoice.currency)}
                        </span>
                      ) : isPartialPayment ? (
                        <span className="text-blue-600">
                          Remaining balance: {formatCurrency(remainingBalance, invoice.currency)}
                        </span>
                      ) : (
                        <span className="text-green-600">
                          Invoice will be fully paid
                        </span>
                      )}
                    </FormDescription>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Payment Method */}
            <FormField
              control={form.control}
              name="method"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Payment Method *</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select payment method" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {['bank_transfer', 'credit_card', 'debit_card', 'cash', 'check', 'paypal', 'stripe', 'other'].map((method) => (
                        <SelectItem key={method} value={method}>
                          <div className="flex items-center gap-2">
                            {getPaymentMethodIcon(method)}
                            {getPaymentMethodLabel(method)}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Reference Number */}
            <FormField
              control={form.control}
              name="reference"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Reference Number</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Transaction ID, check number, etc."
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Optional reference for tracking purposes
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Payment Date */}
            <FormField
              control={form.control}
              name="processedAt"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Payment Date</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <CalendarIcon className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                      <Input
                        type="date"
                        className="pl-10"
                        {...field}
                      />
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Notes */}
            <FormField
              control={form.control}
              name="notes"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Notes</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="Additional notes about this payment..."
                      className="min-h-[80px]"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={recordPayment.isPending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={recordPayment.isPending || !form.formState.isValid}
              >
                {recordPayment.isPending ? 'Recording...' : 'Record Payment'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}