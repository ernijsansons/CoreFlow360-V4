import * as React from 'react'
import { cn } from '@/lib/utils'
import { Link } from '@tanstack/react-router'

interface AuthLayoutProps {
  children: React.ReactNode
  title: string
  subtitle?: string
  showBranding?: boolean
}

export function AuthLayout({
  children,
  title,
  subtitle,
  showBranding = true
}: AuthLayoutProps) {
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-950">
      {/* Header with Branding */}
      {showBranding && (
        <header className="w-full py-8 px-8">
          <div className="max-w-7xl mx-auto flex items-center justify-between">
            <Link to="/" className="flex items-center space-x-2 group">
              <div className="h-10 w-10 bg-gradient-to-r from-brand-600 to-brand-700 rounded-lg flex items-center justify-center group-hover:scale-105 transition-transform">
                <span className="text-white font-bold text-xl">CF</span>
              </div>
              <span className="text-2xl font-bold text-gray-900 dark:text-white">
                CoreFlow360
              </span>
            </Link>
            <nav className="hidden md:flex items-center space-x-8">
              <Link
                to="/help"
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                Help
              </Link>
              <Link
                to="/contact"
                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                Contact Sales
              </Link>
            </nav>
          </div>
        </header>
      )}

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center px-8 py-16">
        <div className="w-full max-w-md">
          {/* Title Section */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              {title}
            </h1>
            {subtitle && (
              <p className="mt-2 text-gray-600 dark:text-gray-400">
                {subtitle}
              </p>
            )}
          </div>

          {/* Form Container */}
          <div className="bg-white dark:bg-gray-800 shadow-xl rounded-2xl p-8">
            {children}
          </div>

          {/* Security Notice */}
          <div className="mt-8 text-center">
            <p className="text-xs text-gray-500 dark:text-gray-500">
              Protected by enterprise-grade security. Your data is encrypted in transit and at rest.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full py-8 px-8 border-t border-gray-200 dark:border-gray-800">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
          <div className="flex items-center space-x-6">
            <Link
              to="/privacy"
              className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            >
              Privacy Policy
            </Link>
            <Link
              to="/terms"
              className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            >
              Terms of Service
            </Link>
            <Link
              to="/security"
              className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            >
              Security
            </Link>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            © 2024 CoreFlow360. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  )
}