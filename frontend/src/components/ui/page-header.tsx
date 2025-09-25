import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { ChevronRight, Home, type LucideIcon } from 'lucide-react'
import Link from 'next/link'

export interface Breadcrumb {
  label: string
  href?: string
  icon?: LucideIcon
}

export interface PageHeaderProps {
  title: string
  description?: string
  breadcrumbs?: Breadcrumb[]
  actions?: React.ReactNode
  children?: React.ReactNode
  className?: string
  variant?: 'default' | 'compact' | 'hero'
  showBackButton?: boolean
  onBack?: () => void
  backButtonText?: string
}

export function PageHeader({
  title,
  description,
  breadcrumbs,
  actions,
  children,
  className,
  variant = 'default',
  showBackButton = false,
  onBack,
  backButtonText = 'Back'
}: PageHeaderProps) {
  const variantClasses = {
    default: 'py-6 px-6',
    compact: 'py-4 px-4',
    hero: 'py-12 px-8 bg-muted/50'
  }

  const titleClasses = {
    default: 'text-3xl font-bold',
    compact: 'text-2xl font-semibold',
    hero: 'text-4xl font-bold'
  }

  const descriptionClasses = {
    default: 'text-muted-foreground',
    compact: 'text-sm text-muted-foreground',
    hero: 'text-lg text-muted-foreground'
  }

  return (
    <div className={cn(
      "border-b",
      variantClasses[variant],
      className
    )}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <Breadcrumbs items={breadcrumbs} className="mb-4" />
      )}

      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 space-y-1">
          <div className="flex items-center gap-2">
            {showBackButton && onBack && (
              <Button
                variant="ghost"
                size="sm"
                onClick={onBack}
                className="mr-2"
              >
                <ChevronRight className="h-4 w-4 rotate-180 mr-1" />
                {backButtonText}
              </Button>
            )}
            <h1 className={titleClasses[variant]}>{title}</h1>
          </div>
          {description && (
            <p className={descriptionClasses[variant]}>
              {description}
            </p>
          )}
        </div>

        {actions && (
          <div className="flex items-center gap-2 shrink-0">
            {actions}
          </div>
        )}
      </div>

      {children && (
        <div className={cn(
          variant === 'hero' ? "mt-8" : "mt-4"
        )}>
          {children}
        </div>
      )}
    </div>
  )
}

interface BreadcrumbsProps {
  items: Breadcrumb[]
  className?: string
  separator?: React.ReactNode
  showHome?: boolean
}

export function Breadcrumbs({
  items,
  className,
  separator = <ChevronRight className="h-4 w-4" />,
  showHome = true
}: BreadcrumbsProps) {
  const allItems = showHome && items[0]?.label !== 'Home'
    ? [{ label: 'Home', href: '/', icon: Home }, ...items]
    : items

  return (
    <nav aria-label="Breadcrumb" className={className}>
      <ol className="flex items-center gap-2 text-sm text-muted-foreground">
        {allItems.map((item, index) => {
          const Icon = item.icon
          const isLast = index === allItems.length - 1

          return (
            <li key={index} className="flex items-center gap-2">
              {index > 0 && (
                <span className="text-muted-foreground/50">
                  {separator}
                </span>
              )}
              {item.href && !isLast ? (
                <Link
                  href={item.href}
                  className="flex items-center gap-1 hover:text-foreground transition-colors"
                >
                  {Icon && <Icon className="h-4 w-4" />}
                  {item.label}
                </Link>
              ) : (
                <span className={cn(
                  "flex items-center gap-1",
                  isLast && "text-foreground font-medium"
                )}>
                  {Icon && <Icon className="h-4 w-4" />}
                  {item.label}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

export interface PageTitleProps {
  title: string
  subtitle?: string
  icon?: LucideIcon
  badge?: React.ReactNode
  className?: string
}

export function PageTitle({
  title,
  subtitle,
  icon: Icon,
  badge,
  className
}: PageTitleProps) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      {Icon && (
        <div className="rounded-lg bg-primary/10 p-2">
          <Icon className="h-6 w-6 text-primary" />
        </div>
      )}
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold">{title}</h1>
          {badge}
        </div>
        {subtitle && (
          <p className="text-sm text-muted-foreground">{subtitle}</p>
        )}
      </div>
    </div>
  )
}

export interface PageSectionProps {
  title?: string
  description?: string
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
  contentClassName?: string
}

export function PageSection({
  title,
  description,
  actions,
  children,
  className,
  contentClassName
}: PageSectionProps) {
  return (
    <section className={cn("space-y-4", className)}>
      {(title || description || actions) && (
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            {title && (
              <h2 className="text-xl font-semibold">{title}</h2>
            )}
            {description && (
              <p className="text-sm text-muted-foreground">
                {description}
              </p>
            )}
          </div>
          {actions && (
            <div className="flex items-center gap-2 shrink-0">
              {actions}
            </div>
          )}
        </div>
      )}
      <div className={contentClassName}>
        {children}
      </div>
    </section>
  )
}