import React from 'react'
import { motion } from 'framer-motion'
import type { Testimonial } from '@/utils/mockData'

interface TestimonialsProps {
  testimonials: Testimonial[]
}

export const Testimonials: React.FC<TestimonialsProps> = ({ testimonials }) => {
  return (
    <section className="bg-gray-50 py-24 dark:bg-gray-800 sm:py-32" id="testimonials">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          <h2 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
            Trusted by Serial Entrepreneurs Worldwide
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-lg text-gray-600 dark:text-gray-300">
            See how founders are scaling multiple businesses with AI agents
          </p>
        </motion.div>

        <div className="mt-16 grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          {testimonials.map((testimonial, index) => (
            <motion.div
              key={testimonial.name}
              data-test-id={`testimonial-${index}`}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className="flex flex-col rounded-2xl bg-white p-8 shadow-md dark:bg-gray-900"
            >
              <div className="flex gap-1">
                {Array.from({
                  length: Math.max(1, Math.round(Number.isFinite(testimonial.rating) ? testimonial.rating : 5)),
                }).map((_, i) => (
                  <svg
                    key={i}
                    className="h-5 w-5 fill-yellow-400"
                    viewBox="0 0 20 20"
                    aria-hidden="true"
                  >
                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                  </svg>
                ))}
              </div>
              <blockquote className="mt-6 flex-1 text-gray-700 dark:text-gray-300">
                "{testimonial.quote}"
              </blockquote>
              <div className="mt-6 flex items-center gap-4">
                <div className="h-12 w-12 overflow-hidden rounded-full bg-gradient-to-br from-brand-primary-400 to-brand-accent-400">
                  <div className="flex h-full w-full items-center justify-center text-lg font-bold text-white">
                    {testimonial.name.charAt(0)}
                  </div>
                </div>
                <div>
                  <div className="font-semibold text-gray-900 dark:text-white">
                    {testimonial.name}
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    {testimonial.role} at {testimonial.company}
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
