import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import {
  FileX,
  Inbox,
  Search,
  Users,
  FolderOpen,
  Database,
  type LucideIcon
} from 'lucide-react'

export interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: string
  action?: {
    label: string
    onClick: () => void
    variant?: 'default' | 'secondary' | 'outline' | 'ghost'
  }
  secondaryAction?: {
    label: string
    onClick: () => void
  }
  className?: string
  iconClassName?: string
  size?: 'sm' | 'md' | 'lg'
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  secondaryAction,
  className,
  iconClassName,
  size = 'md'
}: EmptyStateProps) {
  const sizeClasses = {
    sm: {
      container: 'py-8',
      icon: 'h-12 w-12',
      title: 'text-lg',
      description: 'text-sm',
      button: 'sm'
    },
    md: {
      container: 'py-12',
      icon: 'h-16 w-16',
      title: 'text-xl',
      description: 'text-base',
      button: 'default'
    },
    lg: {
      container: 'py-16',
      icon: 'h-20 w-20',
      title: 'text-2xl',
      description: 'text-lg',
      button: 'lg'
    }
  }

  const sizes = sizeClasses[size]

  return (
    <div className={cn(
      "flex flex-col items-center justify-center text-center",
      sizes.container,
      className
    )}>
      <div className={cn(
        "rounded-full bg-muted p-4 mb-4",
        size === 'lg' && "p-6"
      )}>
        <Icon className={cn(
          "text-muted-foreground",
          sizes.icon,
          iconClassName
        )} />
      </div>
      
      <h3 className={cn(
        "font-semibold mb-2",
        sizes.title
      )}>
        {title}
      </h3>
      
      {description && (
        <p className={cn(
          "text-muted-foreground max-w-sm mb-6",
          sizes.description
        )}>
          {description}
        </p>
      )}
      
      {(action || secondaryAction) && (
        <div className="flex items-center gap-3">
          {action && (
            <Button
              onClick={action.onClick}
              variant={action.variant || 'default'}
              size={sizes.button as any}
            >
              {action.label}
            </Button>
          )}
          
          {secondaryAction && (
            <Button
              onClick={secondaryAction.onClick}
              variant="ghost"
              size={sizes.button as any}
            >
              {secondaryAction.label}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

// Preset empty states for common use cases
export function NoDataEmptyState(props: Partial<EmptyStateProps>) {
  return (
    <EmptyState
      icon={Database}
      title="No data available"
      description="There's no data to display at the moment."
      {...props}
    />
  )
}

export function NoResultsEmptyState(props: Partial<EmptyStateProps>) {
  return (
    <EmptyState
      icon={Search}
      title="No results found"
      description="Try adjusting your search or filter criteria."
      {...props}
    />
  )
}

export function NoFilesEmptyState(props: Partial<EmptyStateProps>) {
  return (
    <EmptyState
      icon={FileX}
      title="No files yet"
      description="Upload your first file to get started."
      {...props}
    />
  )
}

export function NoUsersEmptyState(props: Partial<EmptyStateProps>) {
  return (
    <EmptyState
      icon={Users}
      title="No users found"
      description="Invite team members to collaborate."
      {...props}
    />
  )
}

export function EmptyFolderState(props: Partial<EmptyStateProps>) {
  return (
    <EmptyState
      icon={FolderOpen}
      title="This folder is empty"
      description="Add files or create subfolders to organize your content."
      {...props}
    />
  )
}