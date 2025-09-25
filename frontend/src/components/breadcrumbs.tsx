import * as React from 'react'
import { ChevronRight, Home } from 'lucide-react'
import { Link } from '@tanstack/react-router'
import { useUIStore } from '@/stores'
import { cn } from '@/lib/utils'

interface BreadcrumbsProps {
  className?: string
}

export function Breadcrumbs({ className }: BreadcrumbsProps) {
  const { breadcrumbs } = useUIStore()

  if (breadcrumbs.length === 0) return null

  return (
    <nav className={cn("flex items-center space-x-1 text-sm", className)}>
      <Link
        to="/"
        className="flex items-center text-muted-foreground hover:text-foreground transition-colors"
      >
        <Home className="h-4 w-4" />
      </Link>

      {breadcrumbs.map((breadcrumb, index) => (
        <React.Fragment key={index}>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />

          {breadcrumb.href ? (
            <Link
              to={breadcrumb.href}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              {breadcrumb.label}
            </Link>
          ) : (
            <span className="text-foreground font-medium">
              {breadcrumb.label}
            </span>
          )}
        </React.Fragment>
      ))}
    </nav>
  )
}