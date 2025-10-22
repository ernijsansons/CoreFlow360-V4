/* eslint-disable react-refresh/only-export-components */
"use client"

import * as React from "react"
import { useNavigate } from "@tanstack/react-router"
import { Command } from "cmdk"
import {
  Search,
  Home,
  FileText,
  Users,
  Package,
  Settings,
  ChevronRight,
  Calculator,
  Building2,
  ArrowRightLeft,
  Clock,
  Plus,
  UserPlus,
  FileSpreadsheet,
  BarChart3,
  Brain,
  Sparkles,
  Zap,
  Globe,
  Shield,
  Palette,
  Briefcase,
  ShoppingCart,
  Layers
} from "lucide-react"
import { cn } from "@/lib/utils"

// Types
interface CommandItem {
  id: string
  title: string
  description?: string
  icon: React.ComponentType<{ className?: string }>
  shortcut?: string[]
  action: () => void
  keywords?: string[]
  badge?: string
  category: "navigation" | "actions" | "businesses" | "settings" | "recent" | "ai"
}

interface Business {
  id: string
  name: string
  type: string
  revenue?: string
  status: "active" | "paused" | "archived"
}

interface CommandPaletteProps {
  businesses?: Business[]
  recentItems?: CommandItem[]
  onClose?: () => void
}

// Mock data for demonstration
const mockBusinesses: Business[] = [
  { id: "1", name: "TechFlow SaaS", type: "SaaS", revenue: "$127K MRR", status: "active" },
  { id: "2", name: "E-Commerce Store", type: "E-commerce", revenue: "$89K/mo", status: "active" },
  { id: "3", name: "Consulting Pro", type: "Consulting", revenue: "$45K/mo", status: "active" },
  { id: "4", name: "Digital Agency", type: "Agency", revenue: "$210K/mo", status: "active" }
]

export function CommandPalette({
  businesses = mockBusinesses,
  recentItems = [],
  onClose
}: CommandPaletteProps) {
  const [open, setOpen] = React.useState(false)
  const [search, setSearch] = React.useState("")
  const navigate = useNavigate()

  // Keyboard shortcut handler
  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || e.key === "/") {
        e.preventDefault()
        setOpen((open) => !open)
      }
    }

    document.addEventListener("keydown", down)
    return () => document.removeEventListener("keydown", down)
  }, [])

  // Close handler
  const handleClose = () => {
    setOpen(false)
    setSearch("")
    onClose?.()
  }

  // Navigation items
  const navigationItems: CommandItem[] = [
    {
      id: "dashboard",
      title: "Dashboard",
      description: "Multi-business overview",
      icon: Home,
      shortcut: ["⌘", "D"],
      action: () => {
        navigate({ to: "/dashboard" })
        handleClose()
      },
      keywords: ["home", "overview", "main"],
      category: "navigation"
    },
    {
      id: "finance",
      title: "Finance & Accounting",
      description: "Autonomous double-entry bookkeeping",
      icon: Calculator,
      shortcut: ["⌘", "F"],
      action: () => {
        navigate({ to: "/finance" })
        handleClose()
      },
      keywords: ["money", "accounting", "ledger", "invoices"],
      category: "navigation",
      badge: "AI"
    },
    {
      id: "crm",
      title: "CRM & Customers",
      description: "AI-powered customer relationships",
      icon: Users,
      shortcut: ["⌘", "C"],
      action: () => {
        navigate({ to: "/crm" })
        handleClose()
      },
      keywords: ["customers", "contacts", "leads", "deals"],
      category: "navigation",
      badge: "AI"
    },
    {
      id: "inventory",
      title: "Inventory Management",
      description: "Smart inventory & demand forecasting",
      icon: Package,
      shortcut: ["⌘", "I"],
      action: () => {
        navigate({ to: "/inventory" })
        handleClose()
      },
      keywords: ["products", "stock", "warehouse"],
      category: "navigation",
      badge: "AI"
    },
    {
      id: "analytics",
      title: "Analytics & Insights",
      description: "Cross-business intelligence",
      icon: BarChart3,
      shortcut: ["⌘", "A"],
      action: () => {
        navigate({ to: "/analytics" })
        handleClose()
      },
      keywords: ["reports", "metrics", "kpi", "performance"],
      category: "navigation"
    }
  ]

  // Action items
  const actionItems: CommandItem[] = [
    {
      id: "create-invoice",
      title: "Create Invoice",
      description: "Generate new customer invoice",
      icon: FileText,
      shortcut: ["⌘", "N", "I"],
      action: () => {
        navigate({ to: "/finance/invoices/new" })
        handleClose()
      },
      keywords: ["new", "bill", "payment"],
      category: "actions"
    },
    {
      id: "add-customer",
      title: "Add Customer",
      description: "Create new customer profile",
      icon: UserPlus,
      shortcut: ["⌘", "N", "C"],
      action: () => {
        navigate({ to: "/crm/customers/new" })
        handleClose()
      },
      keywords: ["new", "client", "contact"],
      category: "actions"
    },
    {
      id: "create-transaction",
      title: "Record Transaction",
      description: "Add journal entry",
      icon: ArrowRightLeft,
      shortcut: ["⌘", "N", "T"],
      action: () => {
        navigate({ to: "/finance/transactions/new" })
        handleClose()
      },
      keywords: ["journal", "entry", "payment"],
      category: "actions"
    },
    {
      id: "generate-report",
      title: "Generate Report",
      description: "Create financial or business report",
      icon: FileSpreadsheet,
      shortcut: ["⌘", "R"],
      action: () => {
        navigate({ to: "/reports/new" })
        handleClose()
      },
      keywords: ["export", "pdf", "excel"],
      category: "actions"
    }
  ]

  // AI Agent actions
  const aiAgentItems: CommandItem[] = [
    {
      id: "ai-forecast",
      title: "AI Cash Flow Forecast",
      description: "Predict next 90 days cash flow",
      icon: Brain,
      action: () => {
        console.log("Running AI forecast...")
        handleClose()
      },
      keywords: ["predict", "forecast", "ai"],
      category: "ai",
      badge: "AI"
    },
    {
      id: "ai-optimize",
      title: "Optimize Cross-Business Resources",
      description: "AI resource allocation analysis",
      icon: Sparkles,
      action: () => {
        console.log("Optimizing resources...")
        handleClose()
      },
      keywords: ["optimize", "efficiency"],
      category: "ai",
      badge: "AI"
    },
    {
      id: "ai-insights",
      title: "Generate AI Insights",
      description: "Get personalized business recommendations",
      icon: Zap,
      action: () => {
        console.log("Generating insights...")
        handleClose()
      },
      keywords: ["recommendations", "suggestions"],
      category: "ai",
      badge: "AI"
    }
  ]

  // Settings items
  const settingsItems: CommandItem[] = [
    {
      id: "preferences",
      title: "Preferences",
      description: "Application settings",
      icon: Settings,
      shortcut: ["⌘", ","],
      action: () => {
        navigate({ to: "/settings/preferences" })
        handleClose()
      },
      keywords: ["settings", "config"],
      category: "settings"
    },
    {
      id: "security",
      title: "Security & Privacy",
      description: "Manage security settings",
      icon: Shield,
      action: () => {
        navigate({ to: "/settings/security" })
        handleClose()
      },
      keywords: ["password", "2fa", "auth"],
      category: "settings"
    },
    {
      id: "integrations",
      title: "Integrations",
      description: "Connect external services",
      icon: Globe,
      action: () => {
        navigate({ to: "/settings/integrations" })
        handleClose()
      },
      keywords: ["api", "connect", "sync"],
      category: "settings"
    },
    {
      id: "theme",
      title: "Appearance",
      description: "Theme and display settings",
      icon: Palette,
      action: () => {
        navigate({ to: "/settings/appearance" })
        handleClose()
      },
      keywords: ["dark", "light", "theme"],
      category: "settings"
    }
  ]

  // Business switcher
  const businessItems: CommandItem[] = businesses.map(business => ({
    id: `business-${business.id}`,
    title: business.name,
    description: `${business.type} · ${business.revenue}`,
    icon: business.type === "SaaS" ? Layers :
          business.type === "E-commerce" ? ShoppingCart :
          business.type === "Consulting" ? Briefcase : Building2,
    action: () => {
      console.log(`Switching to ${business.name}`)
      handleClose()
    },
    keywords: [business.name.toLowerCase(), business.type.toLowerCase()],
    category: "businesses" as const,
    badge: business.status === "active" ? undefined : business.status
  }))

  // Recent items (last 5 actions)
  const recentActionItems: CommandItem[] = recentItems.slice(0, 5).map(item => ({
    ...item,
    icon: Clock,
    category: "recent" as const
  }))

  return (
    <>
      {/* Trigger button (optional - mainly keyboard activated) */}
      <button
        onClick={() => setOpen(true)}
        className="hidden"
        aria-label="Open command palette"
      />

      {/* Command Palette Dialog */}
      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Command Palette"
        className="command-palette-dialog"
      >
        {/* Glassmorphism backdrop */}
        <div
          className={cn(
            "fixed inset-0 z-50 bg-black/50 backdrop-blur-sm transition-opacity duration-200",
            open ? "opacity-100" : "opacity-0"
          )}
          onClick={handleClose}
          aria-hidden="true"
        />

        {/* Command Palette Container */}
        <div className={cn(
          "fixed left-1/2 top-[15%] z-50 w-full max-w-2xl -translate-x-1/2",
          "animate-in fade-in-0 zoom-in-95 duration-200"
        )}>
          <div className={cn(
            "relative overflow-hidden rounded-2xl",
            "bg-white/95 dark:bg-gray-900/95",
            "backdrop-blur-xl backdrop-saturate-150",
            "border border-gray-200/50 dark:border-gray-700/50",
            "shadow-2xl shadow-black/10 dark:shadow-black/40",
            "ring-1 ring-gray-900/5 dark:ring-white/10"
          )}>
            {/* Search Input */}
            <Command.Input
              value={search}
              onValueChange={setSearch}
              placeholder="Type a command or search..."
              className={cn(
                "w-full border-0 bg-transparent px-6 py-5",
                "text-base placeholder:text-gray-500 dark:placeholder:text-gray-400",
                "focus:outline-none focus:ring-0",
                "font-medium tracking-tight"
              )}
            />

            {/* Divider with gradient */}
            <div className="h-px bg-gradient-to-r from-transparent via-gray-200 dark:via-gray-700 to-transparent" />

            {/* Command List */}
            <Command.List className="max-h-[450px] overflow-y-auto overscroll-contain p-2">
              {/* Empty state */}
              <Command.Empty className="flex flex-col items-center justify-center py-12 text-center">
                <div className="mb-4 rounded-full bg-gray-100 dark:bg-gray-800 p-3">
                  <Search className="h-6 w-6 text-gray-400" />
                </div>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                  No results found
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Try searching for something else
                </p>
              </Command.Empty>

              {/* Recent Items */}
              {recentActionItems.length > 0 && !search && (
                <Command.Group heading="Recent" className="px-2 pb-2">
                  <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                    <Clock className="h-3 w-3" />
                    Recent
                  </div>
                  {recentActionItems.map(item => (
                    <CommandPaletteItem key={item.id} item={item} />
                  ))}
                </Command.Group>
              )}

              {/* Navigation */}
              <Command.Group heading="Navigation" className="px-2 pb-2">
                <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <Home className="h-3 w-3" />
                  Navigation
                </div>
                {navigationItems.map(item => (
                  <CommandPaletteItem key={item.id} item={item} />
                ))}
              </Command.Group>

              {/* Actions */}
              <Command.Group heading="Actions" className="px-2 pb-2">
                <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <Plus className="h-3 w-3" />
                  Actions
                </div>
                {actionItems.map(item => (
                  <CommandPaletteItem key={item.id} item={item} />
                ))}
              </Command.Group>

              {/* AI Features */}
              <Command.Group heading="AI Agents" className="px-2 pb-2">
                <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <Brain className="h-3 w-3" />
                  AI Agents
                </div>
                {aiAgentItems.map(item => (
                  <CommandPaletteItem key={item.id} item={item} />
                ))}
              </Command.Group>

              {/* Business Switcher */}
              <Command.Group heading="Businesses" className="px-2 pb-2">
                <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <Building2 className="h-3 w-3" />
                  Switch Business
                </div>
                {businessItems.map(item => (
                  <CommandPaletteItem key={item.id} item={item} />
                ))}
              </Command.Group>

              {/* Settings */}
              <Command.Group heading="Settings" className="px-2 pb-2">
                <div className="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <Settings className="h-3 w-3" />
                  Settings
                </div>
                {settingsItems.map(item => (
                  <CommandPaletteItem key={item.id} item={item} />
                ))}
              </Command.Group>
            </Command.List>

            {/* Footer with shortcuts hint */}
            <div className="border-t border-gray-200/50 dark:border-gray-700/50 bg-gray-50/50 dark:bg-gray-800/50 px-4 py-3">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-4">
                  <span className="flex items-center gap-1">
                    <kbd className="rounded bg-white dark:bg-gray-700 px-1.5 py-0.5 text-[10px] font-semibold shadow-sm">
                      ↑↓
                    </kbd>
                    <span className="text-gray-500 dark:text-gray-400">Navigate</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="rounded bg-white dark:bg-gray-700 px-1.5 py-0.5 text-[10px] font-semibold shadow-sm">
                      ⏎
                    </kbd>
                    <span className="text-gray-500 dark:text-gray-400">Select</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <kbd className="rounded bg-white dark:bg-gray-700 px-1.5 py-0.5 text-[10px] font-semibold shadow-sm">
                      ESC
                    </kbd>
                    <span className="text-gray-500 dark:text-gray-400">Close</span>
                  </span>
                </div>
                <div className="flex items-center gap-1 text-gray-400 dark:text-gray-500">
                  <Sparkles className="h-3 w-3" />
                  <span>AI-Powered</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Command.Dialog>
    </>
  )
}

// Individual Command Item Component
function CommandPaletteItem({ item }: { item: CommandItem }) {
  const Icon = item.icon

  return (
    <Command.Item
      value={`${item.title} ${item.description} ${item.keywords?.join(" ")}`}
      onSelect={item.action}
      className={cn(
        "relative flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5",
        "transition-all duration-150",
        "hover:bg-gray-100/80 dark:hover:bg-gray-800/80",
        "aria-selected:bg-gradient-to-r aria-selected:from-brand-primary-500/10 aria-selected:to-brand-accent-500/10",
        "aria-selected:text-blue-600 dark:aria-selected:text-blue-400",
        "group"
      )}
    >
      {/* Icon with animation */}
      <div className={cn(
        "flex h-9 w-9 items-center justify-center rounded-lg",
        "bg-gradient-to-br from-gray-100 to-gray-200/50",
        "dark:from-gray-800 dark:to-gray-700/50",
        "transition-all duration-200",
        "group-hover:scale-110 group-hover:rotate-3",
        "group-aria-selected:from-brand-primary-100 group-aria-selected:to-brand-accent-100",
        "dark:group-aria-selected:from-brand-primary-900/30 dark:group-aria-selected:to-brand-accent-900/30"
      )}>
        <Icon className="h-4 w-4 text-gray-600 dark:text-gray-400 group-aria-selected:text-blue-600 dark:group-aria-selected:text-blue-400" />
      </div>

      {/* Content */}
      <div className="flex flex-1 flex-col">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {item.title}
          </span>
          {item.badge && (
            <span className={cn(
              "rounded-full px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
              "bg-gradient-to-r from-brand-primary-500 to-brand-accent-500 text-white",
              "shadow-sm"
            )}>
              {item.badge}
            </span>
          )}
        </div>
        {item.description && (
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {item.description}
          </span>
        )}
      </div>

      {/* Shortcut */}
      {item.shortcut && (
        <div className="ml-auto flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          {item.shortcut.map((key, index) => (
            <kbd
              key={index}
              className={cn(
                "rounded bg-white dark:bg-gray-700",
                "px-1.5 py-0.5 text-[10px] font-semibold",
                "shadow-sm",
                "text-gray-500 dark:text-gray-400"
              )}
            >
              {key}
            </kbd>
          ))}
        </div>
      )}

      {/* Hover arrow indicator */}
      <ChevronRight className="ml-2 h-4 w-4 opacity-0 transition-all group-hover:translate-x-0.5 group-hover:opacity-50" />
    </Command.Item>
  )
}

// Hook for using command palette imperatively
export function useCommandPalette() {
  const [isOpen, setIsOpen] = React.useState(false)

  const open = React.useCallback(() => setIsOpen(true), [])
  const close = React.useCallback(() => setIsOpen(false), [])
  const toggle = React.useCallback(() => setIsOpen(prev => !prev), [])

  return {
    isOpen,
    open,
    close,
    toggle,
    CommandPalette: (props: Partial<CommandPaletteProps>) => (
      <CommandPalette {...props} />
    )
  }
}

// Export everything
export default CommandPalette