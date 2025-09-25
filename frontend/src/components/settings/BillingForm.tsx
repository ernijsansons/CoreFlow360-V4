import * as React from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import {
  CreditCard,
  Loader2,
  CheckCircle2,
  AlertCircle
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { cn } from '@/lib/utils'

const billingSchema = z.object({
  cardNumber: z.string()
    .min(16, 'Card number must be 16 digits')
    .max(16, 'Card number must be 16 digits')
    .regex(/^\d+$/, 'Card number must contain only digits'),
  cardHolder: z.string().min(1, 'Cardholder name is required'),
  expiryMonth: z.string().min(1, 'Expiry month is required'),
  expiryYear: z.string().min(1, 'Expiry year is required'),
  cvv: z.string()
    .min(3, 'CVV must be 3 or 4 digits')
    .max(4, 'CVV must be 3 or 4 digits')
    .regex(/^\d+$/, 'CVV must contain only digits'),
  billingAddress: z.string().min(1, 'Billing address is required'),
  city: z.string().min(1, 'City is required'),
  state: z.string().min(1, 'State is required'),
  zipCode: z.string()
    .min(5, 'ZIP code must be at least 5 digits')
    .regex(/^\d+(-\d+)?$/, 'Invalid ZIP code format'),
  country: z.string().min(1, 'Country is required'),
  setAsDefault: z.boolean().optional(),
})

type BillingFormData = z.infer<typeof billingSchema>

export function BillingForm() {
  const [isLoading, setIsLoading] = React.useState(false)
  const [success, setSuccess] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    watch,
    reset,
  } = useForm<BillingFormData>({
    resolver: zodResolver(billingSchema),
    defaultValues: {
      country: 'US',
      setAsDefault: true,
    }
  })

  const formatCardNumber = (value: string) => {
    const digits = value.replace(/\D/g, '')
    const groups = digits.match(/.{1,4}/g) || []
    return groups.join(' ')
  }

  const handleCardNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\s/g, '')
    if (value.length <= 16 && /^\d*$/.test(value)) {
      setValue('cardNumber', value)
    }
  }

  const onSubmit = async (data: BillingFormData) => {
    setIsLoading(true)
    setError(null)
    setSuccess(false)

    try {
      await new Promise(resolve => setTimeout(resolve, 2000))

      if (Math.random() > 0.8) {
        throw new Error('Card validation failed. Please check your details and try again.')
      }

      setSuccess(true)
      setTimeout(() => {
        setSuccess(false)
        reset()
      }, 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const cardNumber = watch('cardNumber')
  const displayCardNumber = cardNumber ? formatCardNumber(cardNumber) : ''

  const currentYear = new Date().getFullYear()
  const years = Array.from({ length: 10 }, (_, i) => currentYear + i)

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {success && (
        <Alert className="bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800">
          <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
          <AlertTitle className="text-green-900 dark:text-green-100">
            Payment method added successfully
          </AlertTitle>
          <AlertDescription className="text-green-700 dark:text-green-300">
            Your payment method has been saved and can be used for future transactions.
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="cardNumber">Card Number</Label>
          <div className="relative">
            <CreditCard className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="cardNumber"
              placeholder="1234 5678 9012 3456"
              className="pl-10"
              value={displayCardNumber}
              onChange={handleCardNumberChange}
              maxLength={19}
              aria-invalid={!!errors.cardNumber}
              aria-describedby={errors.cardNumber ? 'cardNumber-error' : undefined}
            />
          </div>
          {errors.cardNumber && (
            <p id="cardNumber-error" className="text-xs text-red-500">
              {errors.cardNumber.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="cardHolder">Cardholder Name</Label>
          <Input
            id="cardHolder"
            placeholder="John Doe"
            {...register('cardHolder')}
            aria-invalid={!!errors.cardHolder}
            aria-describedby={errors.cardHolder ? 'cardHolder-error' : undefined}
          />
          {errors.cardHolder && (
            <p id="cardHolder-error" className="text-xs text-red-500">
              {errors.cardHolder.message}
            </p>
          )}
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-2">
            <Label htmlFor="expiryMonth">Expiry Month</Label>
            <Select onValueChange={(value) => setValue('expiryMonth', value)}>
              <SelectTrigger id="expiryMonth">
                <SelectValue placeholder="MM" />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: 12 }, (_, i) => i + 1).map((month) => (
                  <SelectItem key={month} value={month.toString().padStart(2, '0')}>
                    {month.toString().padStart(2, '0')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.expiryMonth && (
              <p className="text-xs text-red-500">
                {errors.expiryMonth.message}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="expiryYear">Expiry Year</Label>
            <Select onValueChange={(value) => setValue('expiryYear', value)}>
              <SelectTrigger id="expiryYear">
                <SelectValue placeholder="YYYY" />
              </SelectTrigger>
              <SelectContent>
                {years.map((year) => (
                  <SelectItem key={year} value={year.toString()}>
                    {year}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.expiryYear && (
              <p className="text-xs text-red-500">
                {errors.expiryYear.message}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="cvv">CVV</Label>
            <Input
              id="cvv"
              type="text"
              placeholder="123"
              maxLength={4}
              {...register('cvv')}
              aria-invalid={!!errors.cvv}
              aria-describedby={errors.cvv ? 'cvv-error' : undefined}
            />
            {errors.cvv && (
              <p id="cvv-error" className="text-xs text-red-500">
                {errors.cvv.message}
              </p>
            )}
          </div>
        </div>

        <div className="border-t pt-4">
          <h3 className="font-medium mb-4">Billing Address</h3>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="billingAddress">Street Address</Label>
              <Input
                id="billingAddress"
                placeholder="123 Main St"
                {...register('billingAddress')}
                aria-invalid={!!errors.billingAddress}
                aria-describedby={errors.billingAddress ? 'billingAddress-error' : undefined}
              />
              {errors.billingAddress && (
                <p id="billingAddress-error" className="text-xs text-red-500">
                  {errors.billingAddress.message}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="city">City</Label>
                <Input
                  id="city"
                  placeholder="San Francisco"
                  {...register('city')}
                  aria-invalid={!!errors.city}
                  aria-describedby={errors.city ? 'city-error' : undefined}
                />
                {errors.city && (
                  <p id="city-error" className="text-xs text-red-500">
                    {errors.city.message}
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="state">State</Label>
                <Input
                  id="state"
                  placeholder="CA"
                  {...register('state')}
                  aria-invalid={!!errors.state}
                  aria-describedby={errors.state ? 'state-error' : undefined}
                />
                {errors.state && (
                  <p id="state-error" className="text-xs text-red-500">
                    {errors.state.message}
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="zipCode">ZIP Code</Label>
                <Input
                  id="zipCode"
                  placeholder="94105"
                  {...register('zipCode')}
                  aria-invalid={!!errors.zipCode}
                  aria-describedby={errors.zipCode ? 'zipCode-error' : undefined}
                />
                {errors.zipCode && (
                  <p id="zipCode-error" className="text-xs text-red-500">
                    {errors.zipCode.message}
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="country">Country</Label>
                <Select defaultValue="US" onValueChange={(value) => setValue('country', value)}>
                  <SelectTrigger id="country">
                    <SelectValue placeholder="Select country" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="US">United States</SelectItem>
                    <SelectItem value="CA">Canada</SelectItem>
                    <SelectItem value="UK">United Kingdom</SelectItem>
                    <SelectItem value="AU">Australia</SelectItem>
                    <SelectItem value="DE">Germany</SelectItem>
                    <SelectItem value="FR">France</SelectItem>
                  </SelectContent>
                </Select>
                {errors.country && (
                  <p className="text-xs text-red-500">
                    {errors.country.message}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="checkbox"
            id="setAsDefault"
            className="rounded border-gray-300"
            {...register('setAsDefault')}
          />
          <Label htmlFor="setAsDefault" className="text-sm font-normal">
            Set as default payment method
          </Label>
        </div>
      </div>

      <div className="flex justify-between">
        <Button type="button" variant="outline">
          Cancel
        </Button>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Processing...
            </>
          ) : (
            'Add Payment Method'
          )}
        </Button>
      </div>

      <div className="pt-4 border-t">
        <div className="flex items-center justify-center space-x-4 text-xs text-gray-500">
          <span>Secured by</span>
          <div className="flex items-center space-x-2">
            <span className="font-medium">Stripe</span>
            <span>•</span>
            <span>256-bit SSL encryption</span>
          </div>
        </div>
      </div>
    </form>
  )
}