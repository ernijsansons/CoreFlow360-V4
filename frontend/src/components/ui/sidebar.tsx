import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import {
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  type LucideIcon
} from 'lucide-react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'

export interface SidebarItem {
  id: string
  label: string
  href?: string
  icon?: LucideIcon
  badge?: string | number
  children?: SidebarItem[]
  onClick?: () => void
  disabled?: boolean
}

export interface SidebarProps {
  items: SidebarItem[]
  logo?: React.ReactNode
  footer?: React.ReactNode
  collapsible?: boolean
  collapsed?: boolean
  onCollapsedChange?: (collapsed: boolean) => void
  className?: string
  variant?: 'default' | 'compact' | 'floating'
  showMobileToggle?: boolean
  mobileBreakpoint?: 'sm' | 'md' | 'lg' | 'xl'
}

export function Sidebar({
  items,
  logo,
  footer,
  collapsible = true,
  collapsed: controlledCollapsed,
  onCollapsedChange,
  className,
  variant = 'default',
  showMobileToggle = true,
  mobileBreakpoint = 'lg'
}: SidebarProps) {
  const [collapsed, setCollapsed] = React.useState(controlledCollapsed ?? false)
  const [mobileOpen, setMobileOpen] = React.useState(false)
  const [expandedItems, setExpandedItems] = React.useState<Set<string>>(new Set())
  const pathname = usePathname()

  const isCollapsed = controlledCollapsed ?? collapsed

  const handleCollapse = () => {
    const newCollapsed = !isCollapsed
    setCollapsed(newCollapsed)
    onCollapsedChange?.(newCollapsed)
  }

  const toggleExpanded = (itemId: string) => {
    const newExpanded = new Set(expandedItems)
    if (newExpanded.has(itemId)) {
      newExpanded.delete(itemId)
    } else {
      newExpanded.add(itemId)
    }
    setExpandedItems(newExpanded)
  }

  const mobileBreakpoints = {
    sm: 'sm:hidden',
    md: 'md:hidden',
    lg: 'lg:hidden',
    xl: 'xl:hidden'
  }

  const desktopBreakpoints = {
    sm: 'hidden sm:flex',
    md: 'hidden md:flex',
    lg: 'hidden lg:flex',
    xl: 'hidden xl:flex'
  }

  const variantClasses = {
    default: 'border-r bg-background',
    compact: 'border-r bg-muted/50',
    floating: 'bg-background shadow-lg m-4 rounded-lg'
  }

  const sidebarWidth = isCollapsed ? 'w-16' : 'w-64'

  const renderItem = (item: SidebarItem, depth = 0) => {
    const Icon = item.icon
    const hasChildren = item.children && item.children.length > 0
    const isExpanded = expandedItems.has(item.id)
    const isActive = item.href && pathname === item.href

    const content = (
      <>
        <div className="flex items-center gap-3 flex-1">
          {Icon && (
            <Icon className={cn(
              "shrink-0 transition-all",
              isCollapsed ? "h-5 w-5" : "h-4 w-4",
              isActive && "text-primary"
            )} />
          )}
          {!isCollapsed && (
            <>
              <span className={cn(
                "flex-1 truncate",
                isActive && "font-semibold"
              )}>
                {item.label}
              </span>
              {item.badge !== undefined && (
                <span className="shrink-0 rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
                  {item.badge}
                </span>
              )}
            </>
          )}
        </div>
        {!isCollapsed && hasChildren && (
          <ChevronRight className={cn(
            "h-4 w-4 shrink-0 transition-transform",
            isExpanded && "rotate-90"
          )} />
        )}
      </>
    )

    const itemClasses = cn(
      "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
      "hover:bg-accent hover:text-accent-foreground",
      isActive && "bg-accent text-accent-foreground",
      item.disabled && "opacity-50 cursor-not-allowed",
      depth > 0 && !isCollapsed && "ml-6",
      isCollapsed && "justify-center"
    )

    if (item.href && !hasChildren) {
      return (
        <Link
          key={item.id}
          href={item.href}
          className={itemClasses}
          onClick={() => setMobileOpen(false)}
        >
          {content}
        </Link>
      )
    }

    return (
      <div key={item.id}>
        <button
          className={cn(itemClasses, "w-full")}
          onClick={() => {
            if (hasChildren) {
              toggleExpanded(item.id)
            } else if (item.onClick) {
              item.onClick()
              setMobileOpen(false)
            }
          }}
          disabled={item.disabled}
        >
          {content}
        </button>
        {hasChildren && isExpanded && !isCollapsed && (
          <div className="mt-1 space-y-1">
            {item.children.map(child => renderItem(child, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  const sidebarContent = (
    <>
      {logo && (
        <div className={cn(
          "flex items-center border-b px-4 py-4",
          isCollapsed && "justify-center px-2"
        )}>
          {logo}
        </div>
      )}

      <nav className="flex-1 space-y-1 overflow-y-auto p-4">
        {items.map(item => renderItem(item))}
      </nav>

      {footer && (
        <div className={cn(
          "border-t p-4",
          isCollapsed && "px-2"
        )}>
          {footer}
        </div>
      )}

      {collapsible && (
        <div className="border-t p-2">
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "w-full",
              isCollapsed && "px-2"
            )}
            onClick={handleCollapse}
          >
            {isCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <>
                <ChevronLeft className="h-4 w-4 mr-2" />
                Collapse
              </>
            )}
          </Button>
        </div>
      )}
    </>
  )

  return (
    <>
      {/* Mobile Toggle */}
      {showMobileToggle && (
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "fixed top-4 left-4 z-50",
            mobileBreakpoints[mobileBreakpoint]
          )}
          onClick={() => setMobileOpen(!mobileOpen)}
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      )}

      {/* Mobile Sidebar */}
      {mobileOpen && (
        <>
          <div
            className={cn(
              "fixed inset-0 z-40 bg-black/50",
              mobileBreakpoints[mobileBreakpoint]
            )}
            onClick={() => setMobileOpen(false)}
          />
          <aside
            className={cn(
              "fixed left-0 top-0 z-40 flex h-full w-64 flex-col",
              variantClasses[variant],
              mobileBreakpoints[mobileBreakpoint]
            )}
          >
            {sidebarContent}
          </aside>
        </>
      )}

      {/* Desktop Sidebar */}
      <aside
        className={cn(
          "flex-col transition-all duration-300",
          sidebarWidth,
          variantClasses[variant],
          desktopBreakpoints[mobileBreakpoint],
          variant === 'floating' ? "fixed h-[calc(100vh-2rem)]" : "sticky top-0 h-screen",
          className
        )}
      >
        {sidebarContent}
      </aside>
    </>
  )
}

export interface SidebarSectionProps {
  title?: string
  children: React.ReactNode
  className?: string
  collapsible?: boolean
  defaultExpanded?: boolean
}

export function SidebarSection({
  title,
  children,
  className,
  collapsible = false,
  defaultExpanded = true
}: SidebarSectionProps) {
  const [expanded, setExpanded] = React.useState(defaultExpanded)

  if (!title) {
    return <div className={className}>{children}</div>
  }

  return (
    <div className={className}>
      <button
        className={cn(
          "flex w-full items-center justify-between px-2 py-1.5 text-xs font-semibold text-muted-foreground",
          collapsible && "hover:text-foreground"
        )}
        onClick={() => collapsible && setExpanded(!expanded)}
        disabled={!collapsible}
      >
        <span className="uppercase">{title}</span>
        {collapsible && (
          <ChevronRight className={cn(
            "h-3 w-3 transition-transform",
            expanded && "rotate-90"
          )} />
        )}
      </button>
      {(!collapsible || expanded) && (
        <div className="mt-1 space-y-1">
          {children}
        </div>
      )}
    </div>
  )
}