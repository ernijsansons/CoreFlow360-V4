import React, { useState } from 'react'
import { motion } from 'framer-motion'
import type { PricingTier } from '@/utils/mockData'

interface PricingProps {
  tiers: PricingTier[]
  onSelectTier: (tier: PricingTier) => void
}

export const Pricing: React.FC<PricingProps> = ({ tiers, onSelectTier }) => {
  const [billingPeriod, setBillingPeriod] = useState<'monthly' | 'yearly'>('monthly')

  return (
    <section className="bg-white py-24 dark:bg-gray-900 sm:py-32" id="pricing">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          <h2 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
            Simple, Transparent Pricing
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-lg text-gray-600 dark:text-gray-300">
            Choose the plan that fits your entrepreneurial journey
          </p>

          <div className="mt-8 flex items-center justify-center gap-4">
            <button
              onClick={() => setBillingPeriod('monthly')}
              className={`rounded-lg px-4 py-2 font-medium transition-colors ${
                billingPeriod === 'monthly'
                  ? 'bg-brand-primary-600 text-white'
                  : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'
              }`}
            >
              Monthly
            </button>
            <button
              onClick={() => setBillingPeriod('yearly')}
              className={`rounded-lg px-4 py-2 font-medium transition-colors ${
                billingPeriod === 'yearly'
                  ? 'bg-brand-primary-600 text-white'
                  : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'
              }`}
            >
              Yearly <span className="text-sm text-green-500">(Save 20%)</span>
            </button>
          </div>
        </motion.div>

        <div className="mt-16 grid gap-8 lg:grid-cols-3">
          {tiers.map((tier, index) => {
            const rawPrice = billingPeriod === 'yearly' ? tier.price * 12 * 0.8 : tier.price
            const priceValue =
              Number.isFinite(rawPrice) && rawPrice > 0 ? Math.round(rawPrice) : Math.max(0, rawPrice)
            const periodLabel = billingPeriod === 'yearly' ? 'year' : tier.period
            return (
              <motion.div
                key={tier.name}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
                className={`relative flex flex-col rounded-2xl border p-8 shadow-sm ${
                  tier.highlighted
                    ? 'border-brand-primary-500 bg-brand-primary-50 dark:bg-brand-primary-900/10 ring-2 ring-brand-primary-500'
                    : 'border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800'
                }`}
              >
                {tier.highlighted && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 rounded-full bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 px-4 py-1 text-sm font-semibold text-white">
                    Most Popular
                  </div>
                )}
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">{tier.name}</h3>
                <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">{tier.description}</p>
                <div className="mt-6">
                  <span className="text-4xl font-extrabold text-gray-900 dark:text-white">
                    ${priceValue}
                  </span>
                  <span className="text-gray-600 dark:text-gray-400">
                    /{periodLabel}
                  </span>
                </div>
                <ul className="mt-8 flex-1 space-y-4">
                  {tier.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-3">
                      <svg className="h-5 w-5 flex-shrink-0 text-brand-primary-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                      </svg>
                      <span className="text-gray-700 dark:text-gray-300">{feature}</span>
                    </li>
                  ))}
                </ul>
                <button
                  onClick={() => onSelectTier(tier)}
                  className={`mt-8 w-full rounded-lg px-6 py-3 font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-brand-primary-500 focus:ring-offset-2 ${
                    tier.highlighted
                      ? 'bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 text-white hover:from-brand-primary-700 hover:to-brand-accent-700'
                      : 'bg-gray-100 text-gray-900 hover:bg-gray-200 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600'
                  }`}
                >
                  {tier.cta}
                </button>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
