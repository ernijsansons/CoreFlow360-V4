import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { Checkbox } from '@/@/components/ui/checkbox'
import {
  ChevronRight,
  MoreVertical,
  type LucideIcon
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from './dropdown-menu'
import { Badge } from './badge'
import { Avatar } from '@/@/components/ui/avatar'

export interface ListItem {
  id: string
  title: string
  subtitle?: string
  description?: string
  avatar?: string | React.ReactNode
  icon?: LucideIcon
  badge?: string | { label: string; variant?: 'default' | 'secondary' | 'destructive' | 'outline' }
  meta?: React.ReactNode
  actions?: Array<{
    label: string
    onClick: () => void
    icon?: LucideIcon
  }>
}

export interface ListProps {
  items: ListItem[]
  onItemClick?: (item: ListItem) => void
  onSelectionChange?: (selectedItems: ListItem[]) => void
  selectable?: boolean
  className?: string
  variant?: 'default' | 'card' | 'compact'
  divided?: boolean
  hoverable?: boolean
  loading?: boolean
  emptyMessage?: string
  renderItem?: (item: ListItem, index: number) => React.ReactNode
}

export function List({
  items,
  onItemClick,
  onSelectionChange,
  selectable = false,
  className,
  variant = 'default',
  divided = true,
  hoverable = true,
  loading = false,
  emptyMessage = 'No items to display',
  renderItem
}: ListProps) {
  const [selectedItems, setSelectedItems] = React.useState<Set<string>>(new Set())

  const handleSelect = (item: ListItem, checked: boolean) => {
    const newSelection = new Set(selectedItems)
    if (checked) {
      newSelection.add(item.id)
    } else {
      newSelection.delete(item.id)
    }
    setSelectedItems(newSelection)
    
    if (onSelectionChange) {
      const selected = items.filter(i => newSelection.has(i.id))
      onSelectionChange(selected)
    }
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allIds = new Set(items.map(i => i.id))
      setSelectedItems(allIds)
      onSelectionChange?.(items)
    } else {
      setSelectedItems(new Set())
      onSelectionChange?.([])
    }
  }

  if (loading) {
    return (
      <div className={cn("space-y-2", className)}>
        {[1, 2, 3].map(i => (
          <div key={i} className="p-4 space-y-2">
            <div className="h-4 w-1/3 bg-muted animate-pulse rounded" />
            <div className="h-3 w-2/3 bg-muted animate-pulse rounded" />
          </div>
        ))}
      </div>
    )
  }

  if (items.length === 0) {
    return (
      <div className={cn(
        "text-center py-8 text-muted-foreground",
        variant === 'card' && "border rounded-lg",
        className
      )}>
        {emptyMessage}
      </div>
    )
  }

  const listClasses = cn(
    "space-y-1",
    variant === 'card' && "border rounded-lg p-2",
    className
  )

  const itemClasses = (isSelected: boolean) => cn(
    "group relative flex items-center gap-3 p-3 rounded-lg transition-colors",
    variant === 'compact' && "p-2",
    hoverable && "hover:bg-muted/50",
    onItemClick && "cursor-pointer",
    isSelected && "bg-muted",
    divided && variant !== 'card' && "border-b last:border-0"
  )

  return (
    <div className={listClasses}>
      {selectable && items.length > 1 && (
        <div className="flex items-center gap-2 p-2 border-b">
          <Checkbox
            checked={selectedItems.size === items.length}
            onCheckedChange={handleSelectAll}
            aria-label="Select all items"
          />
          <span className="text-sm text-muted-foreground">
            Select all ({items.length})
          </span>
        </div>
      )}

      {items.map((item, index) => {
        if (renderItem) {
          return <div key={item.id}>{renderItem(item, index)}</div>
        }

        const isSelected = selectedItems.has(item.id)
        const Icon = item.icon

        return (
          <div
            key={item.id}
            className={itemClasses(isSelected)}
            onClick={() => onItemClick?.(item)}
          >
            {selectable && (
              <Checkbox
                checked={isSelected}
                onCheckedChange={(checked) => handleSelect(item, checked as boolean)}
                onClick={e => e.stopPropagation()}
                aria-label={`Select ${item.title}`}
              />
            )}

            {(item.avatar || Icon) && (
              <div className="shrink-0">
                {item.avatar ? (
                  typeof item.avatar === 'string' ? (
                    <Avatar className="h-10 w-10">
                      <img src={item.avatar} alt={item.title} />
                    </Avatar>
                  ) : (
                    item.avatar
                  )
                ) : Icon ? (
                  <div className="h-10 w-10 rounded-full bg-muted flex items-center justify-center">
                    <Icon className="h-5 w-5 text-muted-foreground" />
                  </div>
                ) : null}
              </div>
            )}

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <h4 className="font-medium text-sm truncate">{item.title}</h4>
                {item.badge && (
                  typeof item.badge === 'string' ? (
                    <Badge variant="secondary" className="shrink-0">
                      {item.badge}
                    </Badge>
                  ) : (
                    <Badge variant={item.badge.variant} className="shrink-0">
                      {item.badge.label}
                    </Badge>
                  )
                )}
              </div>
              {item.subtitle && (
                <p className="text-sm text-muted-foreground truncate">
                  {item.subtitle}
                </p>
              )}
              {item.description && variant !== 'compact' && (
                <p className="text-xs text-muted-foreground line-clamp-2 mt-1">
                  {item.description}
                </p>
              )}
            </div>

            {item.meta && (
              <div className="shrink-0 text-sm text-muted-foreground">
                {item.meta}
              </div>
            )}

            {item.actions && item.actions.length > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100"
                    onClick={e => e.stopPropagation()}
                  >
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {item.actions.map((action, i) => {
                    const ActionIcon = action.icon
                    return (
                      <DropdownMenuItem
                        key={i}
                        onClick={(e) => {
                          e.stopPropagation()
                          action.onClick()
                        }}
                      >
                        {ActionIcon && <ActionIcon className="h-4 w-4 mr-2" />}
                        {action.label}
                      </DropdownMenuItem>
                    )
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
            )}

            {onItemClick && !item.actions && (
              <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100" />
            )}
          </div>
        )
      })}
    </div>
  )
}

export interface VirtualListProps extends Omit<ListProps, 'items'> {
  items: ListItem[]
  itemHeight: number
  containerHeight: number
}

export function VirtualList({
  items,
  itemHeight,
  containerHeight,
  ...props
}: VirtualListProps) {
  const [scrollTop, setScrollTop] = React.useState(0)
  const scrollElementRef = React.useRef<HTMLDivElement>(null)

  const startIndex = Math.floor(scrollTop / itemHeight)
  const endIndex = Math.min(
    items.length - 1,
    Math.floor((scrollTop + containerHeight) / itemHeight)
  )

  const visibleItems = items.slice(startIndex, endIndex + 1)
  const totalHeight = items.length * itemHeight
  const offsetY = startIndex * itemHeight

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop)
  }

  return (
    <div
      ref={scrollElementRef}
      className="relative overflow-auto"
      style={{ height: containerHeight }}
      onScroll={handleScroll}
    >
      <div style={{ height: totalHeight }}>
        <div
          style={{
            transform: `translateY(${offsetY}px)`
          }}
        >
          <List {...props} items={visibleItems} />
        </div>
      </div>
    </div>
  )
}