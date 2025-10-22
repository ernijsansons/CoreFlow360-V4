import React from 'react'
import { motion } from 'framer-motion'
import type { Feature } from '@/utils/mockData'
import { FeatureIcon } from './FeatureIcon'

interface FeaturesProps {
  features: Feature[]
}

export const Features: React.FC<FeaturesProps> = ({ features }) => {
  return (
    <section className="bg-white py-24 dark:bg-gray-900 sm:py-32" id="features">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          <h2 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
            Autonomous AI Agents for Every Business Function
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-lg text-gray-600 dark:text-gray-300">
            Deploy intelligent agents that work 24/7 to run your business operations
          </p>
        </motion.div>

        <div className="mt-16 grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
                className="group relative overflow-hidden rounded-2xl border border-gray-200 bg-white p-8 shadow-sm transition-all hover:shadow-xl dark:border-gray-700 dark:bg-gray-800"
              >
                <div className="absolute inset-0 bg-gradient-to-br from-brand-primary-500/5 to-brand-accent-500/5 opacity-0 transition-opacity group-hover:opacity-100" />
                <div className="relative">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br from-brand-primary-500 to-brand-accent-500">
                    <FeatureIcon name={feature.icon} className="h-6 w-6 text-white" />
                  </div>
                  <h3 className="mt-6 text-xl font-semibold text-gray-900 dark:text-white">
                    {feature.title}
                  </h3>
                  <p className="mt-2 text-gray-600 dark:text-gray-300">{feature.description}</p>
                  {feature.stat && (
                    <div className="mt-4 inline-flex items-center rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900/20 dark:text-green-400">
                      {feature.stat}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
        </div>
      </div>
    </section>
  )
}
