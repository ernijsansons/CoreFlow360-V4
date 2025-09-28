import * as React from 'react'
import { cn } from '@/lib/utils'
import {
  Home,
  Search,
  Bell,
  User,
  Menu,
  ChevronRight,
  Plus
} from 'lucide-react'

export interface MobileTabItem {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  href?: string
  onClick?: () => void
  badge?: number
  isActive?: boolean
}

export interface MobileTabBarProps {
  items: MobileTabItem[]
  className?: string
  onItemClick?: (item: MobileTabItem) => void
}

export function MobileTabBar({ items, className, onItemClick }: MobileTabBarProps) {
  return (
    <nav
      className={cn(
        'fixed bottom-0 left-0 right-0 z-[var(--z-index-sticky)]',
        'bg-[var(--color-bg-surface)] border-t border-[var(--color-border-subtle)]',
        'backdrop-blur-md bg-opacity-95 shadow-[var(--shadow-lg)]',
        'md:hidden', // Only show on mobile
        className
      )}
      style={{
        paddingBottom: 'var(--mobile-safe-area-bottom)'
      }}
    >
      <div className="flex items-center justify-around px-2 py-2">
        {items.map((item) => {
          const Icon = item.icon
          return (
            <button
              key={item.id}
              onClick={() => {
                item.onClick?.()
                onItemClick?.(item)
              }}
              className={cn(
                'flex flex-col items-center justify-center relative',
                'min-w-[var(--touch-target-comfortable)] min-h-[var(--touch-target-comfortable)]',
                'px-3 py-2 rounded-[var(--radius-lg)]',
                'text-[var(--color-text-tertiary)] transition-all duration-200',
                'hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-hover)]',
                'active:scale-95',
                item.isActive && [
                  'text-[var(--brand-9)] bg-[var(--brand-3)]',
                  'shadow-[var(--shadow-sm)]'
                ]
              )}
            >
              <div className="relative">
                <Icon className="h-5 w-5" />
                {item.badge && item.badge > 0 && (
                  <span className="absolute -top-1 -right-1 h-4 w-4 bg-[var(--error-8)] text-white text-xs font-medium rounded-full flex items-center justify-center">
                    {item.badge > 99 ? '99+' : item.badge}
                  </span>
                )}
              </div>
              <span className="text-xs font-medium mt-1 leading-none">
                {item.label}
              </span>
            </button>
          )
        })}
      </div>
    </nav>
  )
}

export interface MobileMenuProps {
  children: React.ReactNode
  isOpen: boolean
  onClose: () => void
  className?: string
}

export function MobileMenu({ children, isOpen, onClose, className }: MobileMenuProps) {
  React.useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }

    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [isOpen])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-[var(--z-index-modal)] md:hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-in fade-in-0 duration-300"
        onClick={onClose}
      />

      {/* Menu */}
      <div
        className={cn(
          'absolute inset-y-0 left-0 w-80 max-w-[85vw]',
          'bg-[var(--color-bg-surface)] border-r border-[var(--color-border-subtle)]',
          'shadow-[var(--shadow-2xl)] overflow-y-auto',
          'animate-in slide-in-from-left duration-300',
          className
        )}
        style={{
          paddingTop: 'var(--mobile-safe-area-top)',
          paddingBottom: 'var(--mobile-safe-area-bottom)'
        }}
      >
        {children}
      </div>
    </div>
  )
}

export interface MobileListItem {
  id: string
  title: string
  subtitle?: string
  icon?: React.ComponentType<{ className?: string }>
  rightIcon?: React.ComponentType<{ className?: string }>
  href?: string
  onClick?: () => void
  badge?: string | number
  isActive?: boolean
  disabled?: boolean
}

export interface MobileListProps {
  items: MobileListItem[]
  className?: string
  onItemClick?: (item: MobileListItem) => void
  title?: string
}

export function MobileList({ items, className, onItemClick, title }: MobileListProps) {
  return (
    <div className={cn('w-full', className)}>
      {title && (
        <div className="px-4 py-3 border-b border-[var(--color-border-subtle)]">
          <h3 className="text-[var(--font-size-lg)] font-semibold text-[var(--color-text-primary)]">
            {title}
          </h3>
        </div>
      )}

      <div className="divide-y divide-[var(--color-border-subtle)]">
        {items.map((item) => {
          const Icon = item.icon
          const RightIcon = item.rightIcon || ChevronRight

          return (
            <button
              key={item.id}
              onClick={() => {
                if (!item.disabled) {
                  item.onClick?.()
                  onItemClick?.(item)
                }
              }}
              disabled={item.disabled}
              className={cn(
                'w-full flex items-center gap-3 px-4 py-4',
                'text-left transition-all duration-200',
                'hover:bg-[var(--color-bg-hover)] active:bg-[var(--color-bg-component)]',
                'focus:outline-none focus:bg-[var(--color-bg-hover)]',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                item.isActive && 'bg-[var(--brand-3)] border-r-2 border-[var(--brand-8)]'
              )}
            >
              {Icon && (
                <div className={cn(
                  'flex-shrink-0 p-2 rounded-[var(--radius-md)]',
                  'bg-[var(--color-bg-component)]',
                  item.isActive && 'bg-[var(--brand-3)] text-[var(--brand-9)]'
                )}>
                  <Icon className="h-5 w-5" />
                </div>
              )}

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className={cn(
                    'text-[var(--font-size-base)] font-medium truncate',
                    'text-[var(--color-text-primary)]',
                    item.isActive && 'text-[var(--brand-11)]'
                  )}>
                    {item.title}
                  </p>

                  <div className="flex items-center gap-2 ml-2">
                    {item.badge && (
                      <span className={cn(
                        'px-2 py-1 text-xs font-medium rounded-full',
                        'bg-[var(--color-bg-component)] text-[var(--color-text-secondary)]',
                        typeof item.badge === 'number' && item.badge > 0 &&
                        'bg-[var(--error-8)] text-white'
                      )}>
                        {item.badge}
                      </span>
                    )}
                    <RightIcon className="h-4 w-4 text-[var(--color-text-quaternary)]" />
                  </div>
                </div>

                {item.subtitle && (
                  <p className="text-[var(--font-size-sm)] text-[var(--color-text-secondary)] truncate mt-1">
                    {item.subtitle}
                  </p>
                )}
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export interface MobileFABProps {
  onClick: () => void
  icon?: React.ComponentType<{ className?: string }>
  label?: string
  className?: string
  position?: 'bottom-right' | 'bottom-left' | 'bottom-center'
  size?: 'md' | 'lg'
}

export function MobileFAB({
  onClick,
  icon: Icon = Plus,
  label,
  className,
  position = 'bottom-right',
  size = 'md'
}: MobileFABProps) {
  const positionClasses = {
    'bottom-right': 'bottom-20 right-4',
    'bottom-left': 'bottom-20 left-4',
    'bottom-center': 'bottom-20 left-1/2 transform -translate-x-1/2'
  }

  const sizeClasses = {
    md: 'h-14 w-14',
    lg: 'h-16 w-16'
  }

  return (
    <button
      onClick={onClick}
      className={cn(
        'fixed z-[var(--z-index-popover)] md:hidden',
        'bg-[var(--brand-8)] hover:bg-[var(--brand-9)] active:bg-[var(--brand-10)]',
        'text-white shadow-[var(--shadow-lg)] hover:shadow-[var(--shadow-xl)]',
        'rounded-full flex items-center justify-center',
        'transition-all duration-200 hover:scale-105 active:scale-95',
        'focus:outline-none focus:ring-2 focus:ring-[var(--brand-8)] focus:ring-offset-2',
        sizeClasses[size],
        positionClasses[position],
        className
      )}
      style={{
        bottom: position.includes('bottom') ? 'calc(4rem + var(--mobile-safe-area-bottom))' : undefined
      }}
    >
      <Icon className={cn(
        size === 'md' ? 'h-6 w-6' : 'h-7 w-7'
      )} />

      {label && (
        <span className="sr-only">{label}</span>
      )}
    </button>
  )
}

export interface MobileHeaderProps {
  title?: string
  leftAction?: {
    icon: React.ComponentType<{ className?: string }>
    onClick: () => void
    label: string
  }
  rightActions?: Array<{
    icon: React.ComponentType<{ className?: string }>
    onClick: () => void
    label: string
    badge?: number
  }>
  className?: string
  showOnDesktop?: boolean
}

export function MobileHeader({
  title,
  leftAction,
  rightActions = [],
  className,
  showOnDesktop = false
}: MobileHeaderProps) {
  return (
    <header
      className={cn(
        'sticky top-0 z-[var(--z-index-sticky)]',
        'bg-[var(--color-bg-surface)] border-b border-[var(--color-border-subtle)]',
        'backdrop-blur-md bg-opacity-95 shadow-[var(--shadow-sm)]',
        !showOnDesktop && 'md:hidden',
        className
      )}
      style={{
        paddingTop: 'var(--mobile-safe-area-top)'
      }}
    >
      <div className="flex items-center justify-between h-14 px-4">
        {/* Left Action */}
        {leftAction && (
          <button
            onClick={leftAction.onClick}
            className="flex items-center justify-center h-10 w-10 rounded-[var(--radius-md)] hover:bg-[var(--color-bg-hover)] transition-colors"
          >
            <leftAction.icon className="h-5 w-5" />
            <span className="sr-only">{leftAction.label}</span>
          </button>
        )}

        {/* Title */}
        {title && (
          <h1 className="flex-1 text-center text-[var(--font-size-lg)] font-semibold text-[var(--color-text-primary)] truncate mx-4">
            {title}
          </h1>
        )}

        {/* Right Actions */}
        <div className="flex items-center gap-1">
          {rightActions.map((action, index) => (
            <button
              key={index}
              onClick={action.onClick}
              className="relative flex items-center justify-center h-10 w-10 rounded-[var(--radius-md)] hover:bg-[var(--color-bg-hover)] transition-colors"
            >
              <action.icon className="h-5 w-5" />
              {action.badge && action.badge > 0 && (
                <span className="absolute -top-1 -right-1 h-4 w-4 bg-[var(--error-8)] text-white text-xs font-medium rounded-full flex items-center justify-center">
                  {action.badge > 99 ? '99+' : action.badge}
                </span>
              )}
              <span className="sr-only">{action.label}</span>
            </button>
          ))}
        </div>

        {/* Spacer for balance when no left action */}
        {!leftAction && (
          <div className="w-10" />
        )}
      </div>
    </header>
  )
}

// Example usage hook
export function useMobileNavigation() {
  const [isMenuOpen, setIsMenuOpen] = React.useState(false)
  const [activeTab, setActiveTab] = React.useState('home')

  const tabItems: MobileTabItem[] = [
    {
      id: 'home',
      label: 'Home',
      icon: Home,
      isActive: activeTab === 'home'
    },
    {
      id: 'search',
      label: 'Search',
      icon: Search,
      isActive: activeTab === 'search'
    },
    {
      id: 'notifications',
      label: 'Alerts',
      icon: Bell,
      badge: 3,
      isActive: activeTab === 'notifications'
    },
    {
      id: 'profile',
      label: 'Profile',
      icon: User,
      isActive: activeTab === 'profile'
    }
  ]

  return {
    isMenuOpen,
    setIsMenuOpen,
    activeTab,
    setActiveTab,
    tabItems,
    openMenu: () => setIsMenuOpen(true),
    closeMenu: () => setIsMenuOpen(false)
  }
}