import * as React from 'react'
import { Check, ChevronDown, Command, Plus, Search } from 'lucide-react'
import { useEntityStore, useUIStore } from '@/stores'
import type { EntitySwitcherItem } from '@/types'
import { cn, getInitials } from '@/lib/utils'
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Input,
} from '@/components/ui'

interface EntitySwitcherProps {
  className?: string
}

export function EntitySwitcher({ className }: EntitySwitcherProps) {
  const [open, setOpen] = React.useState(false)
  const [search, setSearch] = React.useState('')

  const {
    currentEntity,
    entities,
    recentEntities,
    switchEntity,
    isLoading
  } = useEntityStore()

  const { addToast } = useUIStore()

  const filteredEntities = React.useMemo(() => {
    if (!search) return entities

    const searchLower = search.toLowerCase()
    return entities.filter(entity =>
      entity.name.toLowerCase().includes(searchLower) ||
      entity.type.toLowerCase().includes(searchLower)
    )
  }, [entities, search])

  const handleEntitySwitch = React.useCallback(async (entityId: string) => {
    if (entityId === currentEntity?.id) {
      setOpen(false)
      return
    }

    const success = await switchEntity(entityId)

    if (success) {
      const entity = entities.find(e => e.id === entityId)
      addToast({
        type: 'success',
        message: `Switched to ${entity?.name}`,
        duration: 3000,
      })
      setOpen(false)
      setSearch('')
    } else {
      addToast({
        type: 'error',
        message: 'Failed to switch entity',
        duration: 5000,
      })
    }
  }, [currentEntity?.id, switchEntity, entities, addToast])

  const getEntityBadgeColor = (status: string, plan: string) => {
    if (status !== 'active') return 'bg-gray-500'

    switch (plan) {
      case 'trial':
        return 'bg-warning-500'
      case 'starter':
        return 'bg-brand-500'
      case 'professional':
        return 'bg-success-500'
      case 'enterprise':
        return 'bg-purple-500'
      default:
        return 'bg-gray-500'
    }
  }

  const EntityItem = React.memo(({
    entity,
    isSelected = false
  }: {
    entity: EntitySwitcherItem
    isSelected?: boolean
  }) => (
    <DropdownMenuItem
      className="flex items-center gap-3 p-3 cursor-pointer"
      onClick={() => handleEntitySwitch(entity.id)}
    >
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div className="relative">
          {entity.avatar ? (
            <img
              src={entity.avatar}
              alt={entity.name}
              className="w-8 h-8 rounded-lg object-cover"
            />
          ) : (
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center text-white text-sm font-medium">
              {getInitials(entity.name)}
            </div>
          )}
          <div
            className={cn(
              "absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-background",
              getEntityBadgeColor(entity.status, entity.subscription.plan)
            )}
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm truncate">
              {entity.name}
            </span>
            <span className="text-xs text-muted-foreground capitalize">
              {entity.subscription.plan}
            </span>
          </div>
          <div className="text-xs text-muted-foreground capitalize">
            {entity.type} • {entity.role}
          </div>
        </div>
      </div>

      {isSelected && (
        <Check className="w-4 h-4 text-brand-600" />
      )}
    </DropdownMenuItem>
  ))

  // Keyboard shortcut handler
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(true)
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  if (!currentEntity) {
    return (
      <Button variant="outline" size="sm" className={className}>
        <Plus className="w-4 h-4 mr-2" />
        Add Entity
      </Button>
    )
  }

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn(
            "justify-between min-w-[200px] max-w-[300px]",
            className
          )}
          disabled={isLoading}
        >
          <div className="flex items-center gap-2 min-w-0">
            <div className="relative">
              {currentEntity.avatar ? (
                <img
                  src={currentEntity.avatar}
                  alt={currentEntity.name}
                  className="w-6 h-6 rounded object-cover"
                />
              ) : (
                <div className="w-6 h-6 rounded bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center text-white text-xs font-medium">
                  {getInitials(currentEntity.name)}
                </div>
              )}
              <div
                className={cn(
                  "absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border border-background",
                  getEntityBadgeColor(currentEntity.status, currentEntity.subscription.plan)
                )}
              />
            </div>
            <span className="truncate font-medium">
              {currentEntity.name}
            </span>
          </div>
          <ChevronDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent className="w-80 p-0" align="start">
        <div className="p-3 border-b">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-4 h-4" />
            <Input
              placeholder="Search entities..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
              autoFocus
            />
          </div>
          <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
            <span>Press ⌘K to open</span>
            <span>{entities.length} entities</span>
          </div>
        </div>

        <div className="max-h-80 overflow-y-auto custom-scrollbar">
          {/* Current Entity */}
          <div className="px-2 py-1">
            <DropdownMenuLabel className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Current Entity
            </DropdownMenuLabel>
            <EntityItem
              entity={{
                id: currentEntity.id,
                name: currentEntity.name,
                type: currentEntity.type,
                status: currentEntity.status,
                subscription: currentEntity.subscription,
                role: 'owner', // This would come from the API
              }}
              isSelected={true}
            />
          </div>

          {/* Recent Entities */}
          {recentEntities.length > 0 && (
            <>
              <DropdownMenuSeparator />
              <div className="px-2 py-1">
                <DropdownMenuLabel className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Recent
                </DropdownMenuLabel>
                {recentEntities
                  .filter(entity => entity.id !== currentEntity.id)
                  .slice(0, 3)
                  .map((entity) => (
                    <EntityItem
                      key={entity.id}
                      entity={entity}
                    />
                  ))}
              </div>
            </>
          )}

          {/* All Entities */}
          {filteredEntities.length > 0 && (
            <>
              <DropdownMenuSeparator />
              <div className="px-2 py-1">
                <DropdownMenuLabel className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  {search ? 'Search Results' : 'All Entities'}
                </DropdownMenuLabel>
                {filteredEntities
                  .filter(entity =>
                    entity.id !== currentEntity.id &&
                    !recentEntities.some(recent => recent.id === entity.id)
                  )
                  .map((entity) => (
                    <EntityItem
                      key={entity.id}
                      entity={entity}
                    />
                  ))}
              </div>
            </>
          )}

          {/* No Results */}
          {search && filteredEntities.length === 0 && (
            <div className="p-6 text-center text-sm text-muted-foreground">
              No entities found for "{search}"
            </div>
          )}

          {/* Add New Entity */}
          <DropdownMenuSeparator />
          <DropdownMenuItem className="flex items-center gap-3 p-3 cursor-pointer">
            <div className="w-8 h-8 rounded-lg border-2 border-dashed border-muted-foreground/50 flex items-center justify-center">
              <Plus className="w-4 h-4 text-muted-foreground" />
            </div>
            <div>
              <div className="font-medium text-sm">Create new entity</div>
              <div className="text-xs text-muted-foreground">
                Start a new business or organization
              </div>
            </div>
          </DropdownMenuItem>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}