import * as React from 'react'
import { createFileRoute, Link, useRouter } from '@tanstack/react-router'
import { Home, ArrowLeft, Search, HelpCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'

export const Route = createFileRoute('/error/404')({
  component: NotFoundPage,
})

function NotFoundPage() {
  const router = useRouter()
  const [searchQuery, setSearchQuery] = React.useState('')

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      // Navigate to search results or help page
      router.navigate({ to: '/help', search: { q: searchQuery } })
    }
  }

  const suggestedLinks = [
    { label: 'Dashboard', href: '/', icon: Home },
    { label: 'Settings', href: '/settings' },
    { label: 'Help Center', href: '/help', icon: HelpCircle },
    { label: 'Contact Support', href: '/help/contact' },
  ]

  return (
    <div className="min-h-screen flex items-center justify-center px-8 py-16 bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-950">
      <div className="max-w-2xl w-full text-center space-y-8">
        {/* 404 Illustration */}
        <div className="relative">
          <div className="text-[200px] font-bold text-gray-200 dark:text-gray-800 leading-none select-none">
            404
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl p-8">
              <div className="h-16 w-16 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <Search className="h-8 w-8 text-red-600 dark:text-red-400" />
              </div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                Page not found
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                The page you're looking for doesn't exist or has been moved.
              </p>
            </div>
          </div>
        </div>

        {/* Search Section */}
        <div className="space-y-4 mt-32">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Try searching for what you need:
          </h2>
          <form onSubmit={handleSearch} className="flex gap-2 max-w-md mx-auto">
            <Input
              type="search"
              placeholder="Search for pages, features, or help..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1"
              aria-label="Search"
            />
            <Button type="submit">
              <Search className="h-4 w-4 mr-2" />
              Search
            </Button>
          </form>
        </div>

        {/* Suggested Links */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Helpful links:
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {suggestedLinks.map((link) => (
              <Button
                key={link.href}
                variant="outline"
                asChild
                className="justify-start"
              >
                <Link to={link.href}>
                  {link.icon && <link.icon className="h-4 w-4 mr-2" />}
                  {link.label}
                </Link>
              </Button>
            ))}
          </div>
        </div>

        {/* Additional Help */}
        <Alert className="max-w-md mx-auto">
          <HelpCircle className="h-4 w-4" />
          <AlertTitle>Need assistance?</AlertTitle>
          <AlertDescription>
            If you believe this is an error or need immediate help,{' '}
            <Link
              to="/help/contact"
              className="font-medium text-brand-600 hover:underline"
            >
              contact our support team
            </Link>
            .
          </AlertDescription>
        </Alert>

        {/* Back Navigation */}
        <div className="flex justify-center gap-4">
          <Button
            variant="ghost"
            onClick={() => window.history.back()}
            className="gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Go back
          </Button>
          <Button asChild>
            <Link to="/">
              <Home className="h-4 w-4 mr-2" />
              Go to dashboard
            </Link>
          </Button>
        </div>

        {/* Error Details (for debugging in development) */}
        {import.meta.env.DEV && (
          <details className="mt-8 p-4 bg-gray-100 dark:bg-gray-900 rounded-lg text-left max-w-md mx-auto">
            <summary className="cursor-pointer text-sm font-medium text-gray-600 dark:text-gray-400">
              Technical details
            </summary>
            <div className="mt-2 text-xs text-gray-500 dark:text-gray-500 space-y-1">
              <p>Path: {window.location.pathname}</p>
              <p>Timestamp: {new Date().toISOString()}</p>
              <p>User Agent: {navigator.userAgent}</p>
            </div>
          </details>
        )}
      </div>
    </div>
  )
}