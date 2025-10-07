/**
 * Command Palette Integration Example
 *
 * This file demonstrates how to integrate the command palette
 * into your CoreFlow360 V4 application
 */

import React from 'react'
import { CommandPalette, useCommandPalette } from './command-palette'

/**
 * Example 1: Basic Integration in App Layout
 */
export function AppLayoutWithCommandPalette() {
  // Mock business data - replace with real data from your store/API
  const businesses = [
    { id: "1", name: "TechFlow SaaS", type: "SaaS", revenue: "$127K MRR", status: "active" as const },
    { id: "2", name: "E-Commerce Store", type: "E-commerce", revenue: "$89K/mo", status: "active" as const }
  ]

  // Mock recent items - track user's recent actions
  const recentItems = [
    {
      id: "recent-1",
      title: "Invoice #INV-2024-001",
      description: "Created 5 minutes ago",
      icon: () => <span>📄</span>,
      action: () => console.log("Open invoice"),
      category: "recent" as const
    }
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Command Palette - Always rendered, hidden by default */}
      <CommandPalette
        businesses={businesses}
        recentItems={recentItems}
        onClose={() => console.log("Command palette closed")}
      />

      {/* Your app content */}
      <div className="p-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          CoreFlow360 Dashboard
        </h1>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Press <kbd className="rounded bg-gray-200 px-2 py-1 text-sm dark:bg-gray-700">⌘K</kbd> to open command palette
        </p>
      </div>
    </div>
  )
}

/**
 * Example 2: Using the Command Palette Hook
 */
export function ComponentWithCommandPaletteHook() {
  const { open, close, toggle, CommandPalette } = useCommandPalette()

  return (
    <div>
      {/* Render command palette with hook */}
      <CommandPalette />

      {/* Custom trigger button */}
      <button
        onClick={toggle}
        className="flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
      >
        <span>Quick Actions</span>
        <kbd className="rounded bg-blue-600 px-1.5 py-0.5 text-xs">⌘K</kbd>
      </button>

      {/* Programmatic control */}
      <div className="mt-4 flex gap-2">
        <button onClick={open}>Open</button>
        <button onClick={close}>Close</button>
        <button onClick={toggle}>Toggle</button>
      </div>
    </div>
  )
}

/**
 * Example 3: Global Command Palette Provider
 * Use this at your app root level
 */
export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [businesses, setBusinesses] = React.useState([])
  const [recentItems] = React.useState([])

  // Fetch businesses on mount
  React.useEffect(() => {
    // Replace with actual API call
    fetch('/api/businesses')
      .then(res => res.json())
      .then(data => setBusinesses(data))
      .catch(console.error)
  }, [])


  return (
    <>
      <CommandPalette
        businesses={businesses}
        recentItems={recentItems}
      />
      {children}
    </>
  )
}

/**
 * Example 4: Custom Command Items
 */
export function CustomCommandPaletteExample() {
  // Add custom commands dynamically
  const customCommands = React.useMemo(() => [
    {
      id: "custom-1",
      title: "Deploy to Production",
      description: "Deploy current branch to production",
      icon: () => <span>🚀</span>,
      shortcut: ["⌘", "D", "P"],
      action: async () => {
        console.log("Deploying to production...")
        // Your deployment logic
      },
      keywords: ["deploy", "production", "release"],
      category: "actions" as const,
      badge: "NEW"
    },
    {
      id: "custom-2",
      title: "Run AI Analysis",
      description: "Analyze business performance with AI",
      icon: () => <span>🤖</span>,
      action: async () => {
        console.log("Running AI analysis...")
        // Your AI analysis logic
      },
      keywords: ["ai", "analysis", "performance"],
      category: "ai" as const,
      badge: "AI"
    }
  ], [])

  return (
    <CommandPalette
      recentItems={customCommands}
    />
  )
}

/**
 * Example 5: Search Bar Integration
 * Trigger command palette from a search input
 */
export function SearchBarWithCommandPalette() {
  const { open, CommandPalette } = useCommandPalette()

  return (
    <div className="relative">
      <CommandPalette />

      {/* Search input that opens command palette on focus */}
      <div className="relative">
        <input
          type="text"
          placeholder="Search or press ⌘K..."
          onFocus={open}
          readOnly
          className="w-full rounded-lg border border-gray-300 bg-white px-4 py-2 pl-10 pr-20 text-sm placeholder-gray-500 focus:border-blue-500 focus:outline-none dark:border-gray-600 dark:bg-gray-800 dark:text-white dark:placeholder-gray-400"
        />
        <svg
          className="absolute left-3 top-2.5 h-5 w-5 text-gray-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
        <div className="absolute right-2 top-2 flex items-center gap-0.5">
          <kbd className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500 dark:bg-gray-700 dark:text-gray-400">
            ⌘
          </kbd>
          <kbd className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500 dark:bg-gray-700 dark:text-gray-400">
            K
          </kbd>
        </div>
      </div>
    </div>
  )
}

/**
 * Example 6: Navbar Integration
 */
export function NavbarWithCommandPalette() {
  return (
    <nav className="flex items-center justify-between border-b border-gray-200 bg-white px-6 py-3 dark:border-gray-700 dark:bg-gray-900">
      {/* Logo/Brand */}
      <div className="flex items-center gap-4">
        <h1 className="text-xl font-bold">CoreFlow360</h1>
      </div>

      {/* Center Search (triggers command palette) */}
      <div className="flex-1 max-w-md mx-8">
        <SearchBarWithCommandPalette />
      </div>

      {/* Right side actions */}
      <div className="flex items-center gap-4">
        <button className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white">
          Settings
        </button>
      </div>

      {/* Command Palette (global) */}
      <CommandPalette />
    </nav>
  )
}

/**
 * Usage Instructions:
 *
 * 1. Import the CommandPalette component in your main App or Layout component
 * 2. Add it at the root level (it's hidden by default)
 * 3. It will automatically listen for ⌘K (Mac) or Ctrl+K (Windows)
 * 4. Pass your business data and recent items as props
 * 5. Customize the action handlers to navigate to your routes
 *
 * Performance Tips:
 * - Memoize business and recent items arrays to prevent re-renders
 * - Use React.lazy() if command palette is not immediately needed
 * - Consider virtualizing the list for 100+ items
 *
 * Accessibility:
 * - Full keyboard navigation support (arrow keys, enter, escape)
 * - Screen reader announcements for all actions
 * - ARIA labels and roles properly set
 * - Focus trap when open
 *
 * Customization:
 * - Override styles using Tailwind classes
 * - Add custom command categories
 * - Implement custom search algorithm if needed
 * - Add analytics tracking to action handlers
 */