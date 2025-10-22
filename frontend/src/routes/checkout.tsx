import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'

export const Route = createFileRoute('/checkout')({
  component: CheckoutPage,
  validateSearch: (search: Record<string, unknown>) => {
    return {
      plan: (search.plan as string) || 'professional',
      billing: (search.billing as 'monthly' | 'annual') || 'monthly',
    }
  },
})

interface PlanDetails {
  name: string
  price: {
    monthly: number
    annual: number
  }
  features: string[]
}

const plans: Record<string, PlanDetails> = {
  starter: {
    name: 'Starter',
    price: { monthly: 0, annual: 0 },
    features: ['1 business', '2 AI agents', '1,000 tasks/month', 'Basic analytics'],
  },
  professional: {
    name: 'Professional',
    price: { monthly: 99, annual: 950 },
    features: ['5 businesses', 'Unlimited AI agents', '10,000 tasks/month', 'Advanced analytics', 'Priority support'],
  },
  premium: {
    name: 'Premium',
    price: { monthly: 299, annual: 2870 },
    features: ['Unlimited businesses', 'Unlimited agents & tasks', 'ML-powered analytics', 'White-label', 'Dedicated success manager'],
  },
}

function CheckoutPage() {
  const navigate = useNavigate()
  const { plan: selectedPlan, billing } = Route.useSearch()
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>(billing)
  const [paymentMethod, setPaymentMethod] = useState<'card' | 'paypal'>('card')
  const [isProcessing, setIsProcessing] = useState(false)

  const [formData, setFormData] = useState({
    email: '',
    cardName: '',
    cardNumber: '',
    expiry: '',
    cvc: '',
    country: 'US',
    postalCode: '',
  })

  const planDetails = plans[selectedPlan] || plans.professional
  const price = planDetails.price[billingCycle]
  const savingsPercent = billingCycle === 'annual' ? 20 : 0
  const monthlySavings = billingCycle === 'annual' ? (planDetails.price.monthly * 12 - planDetails.price.annual) : 0

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsProcessing(true)

    try {
      // TODO: Integrate with Stripe/PayPal payment processing
      await new Promise(resolve => setTimeout(resolve, 2000)) // Simulate payment processing

      // Redirect to success page
      navigate({ to: '/checkout/success', search: { plan: selectedPlan } })
    } catch (error) {
      console.error('Payment failed:', error)
      alert('Payment processing failed. Please try again.')
    } finally {
      setIsProcessing(false)
    }
  }

  if (selectedPlan === 'starter') {
    navigate({ to: '/auth/register' })
    return null
  }

  return (
    <div className="min-h-screen bg-background py-12 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Complete Your Subscription</h1>
          <p className="text-lg text-muted-foreground">
            Start your 14-day free trial today. Cancel anytime.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Order Summary */}
          <div className="lg:col-span-1">
            <div className="bg-card rounded-xl p-6 border border-border sticky top-4">
              <h2 className="text-xl font-bold mb-6">Order Summary</h2>

              {/* Plan Selection */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold">{planDetails.name} Plan</span>
                  <button
                    onClick={() => navigate({ to: '/pricing' })}
                    className="text-sm text-brand-primary hover:underline"
                  >
                    Change
                  </button>
                </div>
                <ul className="space-y-1 text-sm text-muted-foreground">
                  {planDetails.features.map((feature, index) => (
                    <li key={index}>✓ {feature}</li>
                  ))}
                </ul>
              </div>

              {/* Billing Cycle Toggle */}
              <div className="mb-6 p-4 bg-muted/30 rounded-lg">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-semibold">Billing Cycle</span>
                  {savingsPercent > 0 && (
                    <span className="text-xs bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded-full font-semibold">
                      Save {savingsPercent}%
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => setBillingCycle('monthly')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      billingCycle === 'monthly'
                        ? 'bg-brand-primary text-white'
                        : 'bg-background hover:bg-muted'
                    }`}
                  >
                    Monthly
                  </button>
                  <button
                    onClick={() => setBillingCycle('annual')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      billingCycle === 'annual'
                        ? 'bg-brand-primary text-white'
                        : 'bg-background hover:bg-muted'
                    }`}
                  >
                    Annual
                  </button>
                </div>
              </div>

              {/* Price Breakdown */}
              <div className="space-y-3 mb-6 pb-6 border-b">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Subtotal</span>
                  <span className="font-semibold">${price}</span>
                </div>
                {monthlySavings > 0 && (
                  <div className="flex items-center justify-between text-green-600 dark:text-green-400">
                    <span>Annual savings</span>
                    <span className="font-semibold">-${monthlySavings}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">14-day free trial</span>
                  <span className="font-semibold text-brand-primary">$0</span>
                </div>
              </div>

              {/* Total */}
              <div className="flex items-center justify-between text-xl font-bold mb-4">
                <span>Due Today</span>
                <span className="text-brand-primary">$0</span>
              </div>

              <p className="text-xs text-muted-foreground mb-4">
                Your trial starts today. You'll be charged ${price} on{' '}
                {new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toLocaleDateString('en-US', {
                  month: 'long',
                  day: 'numeric',
                  year: 'numeric',
                })}
                {billingCycle === 'annual' && ' for the first year'}.
              </p>

              {/* Security Badge */}
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span>Secure 256-bit SSL encryption</span>
              </div>
            </div>
          </div>

          {/* Payment Form */}
          <div className="lg:col-span-2">
            <form onSubmit={handleSubmit} className="bg-card rounded-xl p-8 border border-border">
              {/* Email */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold mb-4">Account Information</h3>
                <div>
                  <label htmlFor="email" className="block text-sm font-medium mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    required
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                    placeholder="you@example.com"
                  />
                  <p className="text-xs text-muted-foreground mt-2">
                    We'll send your receipt and account details to this email
                  </p>
                </div>
              </div>

              {/* Payment Method Selection */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold mb-4">Payment Method</h3>
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <button
                    type="button"
                    onClick={() => setPaymentMethod('card')}
                    className={`p-4 border-2 rounded-lg flex items-center justify-center gap-2 transition-colors ${
                      paymentMethod === 'card'
                        ? 'border-brand-primary bg-brand-primary/5'
                        : 'border-border hover:border-brand-primary/50'
                    }`}
                  >
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                    </svg>
                    <span className="font-semibold">Credit Card</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setPaymentMethod('paypal')}
                    className={`p-4 border-2 rounded-lg flex items-center justify-center gap-2 transition-colors ${
                      paymentMethod === 'paypal'
                        ? 'border-brand-primary bg-brand-primary/5'
                        : 'border-border hover:border-brand-primary/50'
                    }`}
                  >
                    <span className="text-2xl">💳</span>
                    <span className="font-semibold">PayPal</span>
                  </button>
                </div>

                {paymentMethod === 'card' ? (
                  <div className="space-y-4">
                    <div>
                      <label htmlFor="cardName" className="block text-sm font-medium mb-2">
                        Cardholder Name
                      </label>
                      <input
                        type="text"
                        id="cardName"
                        required
                        value={formData.cardName}
                        onChange={(e) => setFormData({ ...formData, cardName: e.target.value })}
                        className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                        placeholder="John Doe"
                      />
                    </div>

                    <div>
                      <label htmlFor="cardNumber" className="block text-sm font-medium mb-2">
                        Card Number
                      </label>
                      <input
                        type="text"
                        id="cardNumber"
                        required
                        value={formData.cardNumber}
                        onChange={(e) => setFormData({ ...formData, cardNumber: e.target.value })}
                        className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                        placeholder="4242 4242 4242 4242"
                        maxLength={19}
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label htmlFor="expiry" className="block text-sm font-medium mb-2">
                          Expiry Date
                        </label>
                        <input
                          type="text"
                          id="expiry"
                          required
                          value={formData.expiry}
                          onChange={(e) => setFormData({ ...formData, expiry: e.target.value })}
                          className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                          placeholder="MM / YY"
                          maxLength={7}
                        />
                      </div>

                      <div>
                        <label htmlFor="cvc" className="block text-sm font-medium mb-2">
                          CVC
                        </label>
                        <input
                          type="text"
                          id="cvc"
                          required
                          value={formData.cvc}
                          onChange={(e) => setFormData({ ...formData, cvc: e.target.value })}
                          className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                          placeholder="123"
                          maxLength={4}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-8 bg-muted/30 rounded-lg text-center">
                    <div className="text-4xl mb-4">💳</div>
                    <p className="text-muted-foreground mb-4">
                      You'll be redirected to PayPal to complete your payment securely.
                    </p>
                  </div>
                )}
              </div>

              {/* Billing Address */}
              <div className="mb-8">
                <h3 className="text-lg font-semibold mb-4">Billing Address</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="country" className="block text-sm font-medium mb-2">
                      Country
                    </label>
                    <select
                      id="country"
                      value={formData.country}
                      onChange={(e) => setFormData({ ...formData, country: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                    >
                      <option value="US">United States</option>
                      <option value="CA">Canada</option>
                      <option value="GB">United Kingdom</option>
                      <option value="AU">Australia</option>
                      <option value="DE">Germany</option>
                      <option value="FR">France</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="postalCode" className="block text-sm font-medium mb-2">
                      Postal Code
                    </label>
                    <input
                      type="text"
                      id="postalCode"
                      required
                      value={formData.postalCode}
                      onChange={(e) => setFormData({ ...formData, postalCode: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                      placeholder="10001"
                    />
                  </div>
                </div>
              </div>

              {/* Terms */}
              <div className="mb-6 p-4 bg-muted/30 rounded-lg">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    required
                    className="mt-1 w-4 h-4 text-brand-primary border-border rounded focus:ring-brand-primary"
                  />
                  <span className="text-sm text-muted-foreground">
                    I agree to the{' '}
                    <a href="/terms" className="text-brand-primary hover:underline">
                      Terms of Service
                    </a>{' '}
                    and{' '}
                    <a href="/privacy" className="text-brand-primary hover:underline">
                      Privacy Policy
                    </a>
                    . I understand that my trial starts today and I'll be charged after 14 days unless I cancel.
                  </span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isProcessing}
                className="w-full px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              >
                {isProcessing ? (
                  <span className="flex items-center justify-center gap-2">
                    <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Processing...
                  </span>
                ) : (
                  'Start Free Trial'
                )}
              </button>

              <p className="text-xs text-center text-muted-foreground mt-4">
                🔒 Your payment information is encrypted and secure. We never store your full card details.
              </p>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}
