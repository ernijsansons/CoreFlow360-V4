import * as React from 'react'
import { Link, useLocation } from '@tanstack/react-router'
import {
  LayoutDashboard,
  Users,
  Building2,
  Phone,
  Mail,
  Calendar,
  DollarSign,
  BarChart3,
  Settings,
  ChevronLeft,
  ChevronDown,
} from 'lucide-react'
import { useUIStore } from '@/stores'
import { useEntityPermissions } from '@/hooks'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui'
import type { SidebarItem } from '@/types'

const sidebarItems: SidebarItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: LayoutDashboard,
    href: '/',
  },
  {
    id: 'crm',
    label: 'CRM',
    icon: Users,
    children: [
      {
        id: 'crm-overview',
        label: 'Overview',
        href: '/crm',
        permissions: ['crm:view'],
      },
      {
        id: 'crm-contacts',
        label: 'Contacts',
        href: '/crm/contacts',
        permissions: ['crm:contacts:view'],
      },
      {
        id: 'crm-companies',
        label: 'Companies',
        href: '/crm/companies',
        permissions: ['crm:companies:view'],
      },
      {
        id: 'crm-deals',
        label: 'Deals',
        href: '/crm/deals',
        permissions: ['crm:deals:view'],
      },
    ],
  },
  {
    id: 'voice',
    label: 'Voice Agent',
    icon: Phone,
    href: '/voice',
    permissions: ['voice:view'],
  },
  {
    id: 'email',
    label: 'Email',
    icon: Mail,
    href: '/email',
    permissions: ['email:view'],
  },
  {
    id: 'calendar',
    label: 'Calendar',
    icon: Calendar,
    href: '/calendar',
    permissions: ['calendar:view'],
  },
  {
    id: 'finance',
    label: 'Finance',
    icon: DollarSign,
    children: [
      {
        id: 'finance-overview',
        label: 'Overview',
        href: '/finance',
        permissions: ['finance:view'],
      },
      {
        id: 'finance-invoices',
        label: 'Invoices',
        href: '/finance/invoices',
        permissions: ['finance:invoices:view'],
      },
      {
        id: 'finance-expenses',
        label: 'Expenses',
        href: '/finance/expenses',
        permissions: ['finance:expenses:view'],
      },
    ],
  },
  {
    id: 'analytics',
    label: 'Analytics',
    icon: BarChart3,
    href: '/analytics',
    permissions: ['analytics:view'],
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: Settings,
    href: '/settings',
    permissions: ['settings:view'],
  },
]

export function Sidebar() {
  const { sidebarOpen, setSidebarOpen } = useUIStore()
  const { hasPermission } = useEntityPermissions()
  const location = useLocation()
  const [expandedItems, setExpandedItems] = React.useState<string[]>(['crm', 'finance'])

  const toggleExpanded = (itemId: string) => {
    setExpandedItems(prev =>
      prev.includes(itemId)
        ? prev.filter(id => id !== itemId)
        : [...prev, itemId]
    )
  }

  const isItemActive = (item: SidebarItem): boolean => {
    if (item.href) {
      return location.pathname === item.href
    }

    if (item.children) {
      return item.children.some(child => child.href === location.pathname)
    }

    return false
  }

  const hasItemPermission = (item: SidebarItem): boolean => {
    if (!item.permissions || item.permissions.length === 0) return true

    return item.permissions.some(permission => hasPermission(permission))
  }

  const renderSidebarItem = (item: SidebarItem, level = 0) => {
    if (!hasItemPermission(item)) return null

    const isActive = isItemActive(item)
    const isExpanded = expandedItems.includes(item.id)
    const hasChildren = item.children && item.children.length > 0

    if (hasChildren) {
      return (
        <div key={item.id}>
          <button
            onClick={() => toggleExpanded(item.id)}
            className={cn(
              "flex items-center w-full px-3 py-2 text-sm font-medium rounded-lg transition-colors",
              "hover:bg-accent hover:text-accent-foreground",
              isActive && "bg-accent text-accent-foreground",
              level > 0 && "ml-4"
            )}
            aria-expanded={isExpanded}
            aria-label={`${item.label} menu`}
          >
            {item.icon && <item.icon className="mr-3 h-4 w-4" aria-hidden="true" />}
            {sidebarOpen && (
              <>
                <span className="flex-1 text-left">{item.label}</span>
                <ChevronDown
                  className={cn(
                    "h-4 w-4 transition-transform",
                    isExpanded && "rotate-180"
                  )}
                />
              </>
            )}
          </button>

          {sidebarOpen && isExpanded && (
            <div className="mt-1 space-y-1">
              {item.children?.map(child => renderSidebarItem(child, level + 1))}
            </div>
          )}
        </div>
      )
    }

    return (
      <Link
        key={item.id}
        to={item.href!}
        className={cn(
          "flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors",
          "hover:bg-accent hover:text-accent-foreground",
          isActive && "bg-accent text-accent-foreground",
          level > 0 && "ml-4"
        )}
        aria-current={isActive ? 'page' : undefined}
        aria-label={item.label}
      >
        {item.icon && <item.icon className="mr-3 h-4 w-4" aria-hidden="true" />}
        {sidebarOpen && (
          <>
            <span className="flex-1">{item.label}</span>
            {item.badge && (
              <span className="ml-2 px-2 py-0.5 text-xs bg-brand-500 text-white rounded-full">
                {item.badge}
              </span>
            )}
          </>
        )}
      </Link>
    )
  }

  return (
    <>
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        id="main-sidebar"
        className={cn(
          "fixed top-16 left-0 z-50 h-[calc(100vh-4rem)] bg-background border-r transition-all duration-200 ease-in-out",
          sidebarOpen ? "w-64" : "w-16",
          "lg:translate-x-0",
          !sidebarOpen && "-translate-x-full lg:translate-x-0"
        )}
        role="navigation"
        aria-label="Main navigation"
        aria-hidden={!sidebarOpen ? "true" : "false"}
      >
        <div className="flex flex-col h-full">
          {/* Sidebar content */}
          <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
            <nav className="space-y-2">
              {sidebarItems.map(item => renderSidebarItem(item))}
            </nav>
          </div>

          {/* Sidebar toggle button */}
          <div className="p-4 border-t">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="w-full justify-center"
              aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
            >
              <ChevronLeft
                className={cn(
                  "h-4 w-4 transition-transform",
                  !sidebarOpen && "rotate-180"
                )}
                aria-hidden="true"
              />
            </Button>
          </div>
        </div>
      </aside>
    </>
  )
}