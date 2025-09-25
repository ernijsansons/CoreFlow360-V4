import * as React from 'react'
import { cn } from '@/lib/utils'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '@/components/ui/Table'
import { Button } from './button'
import { Checkbox } from '@/@/components/ui/checkbox'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from './dropdown-menu'
import {
  MoreHorizontal,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Eye,
  Edit,
  Trash,
  Copy,
  Download
} from 'lucide-react'
import { Badge } from './badge'

export interface DataTableColumn<T> {
  id: string
  header: string | ((props: { column: DataTableColumn<T> }) => React.ReactNode)
  cell?: (props: { row: T; getValue: () => any }) => React.ReactNode
  accessorKey?: keyof T | string
  enableSorting?: boolean
  enableHiding?: boolean
  size?: number
  minSize?: number
  maxSize?: number
}

export interface DataTableProps<T> {
  data: T[]
  columns: DataTableColumn<T>[]
  onRowSelection?: (selectedRows: T[]) => void
  actions?: Array<{
    label: string
    icon?: React.ComponentType<{ className?: string }>
    onClick: (row: T) => void
    variant?: 'default' | 'destructive'
    disabled?: (row: T) => boolean
  }>
  bulkActions?: Array<{
    label: string
    icon?: React.ComponentType<{ className?: string }>
    onClick: (rows: T[]) => void
    variant?: 'default' | 'destructive'
  }>
  getRowId?: (row: T) => string
  className?: string
  showSelection?: boolean
  stickyHeader?: boolean
}

export function DataTable<T extends Record<string, any>>({
  data,
  columns,
  onRowSelection,
  actions,
  bulkActions,
  getRowId,
  className,
  showSelection = false,
  stickyHeader = false
}: DataTableProps<T>) {
  const [selectedRows, setSelectedRows] = React.useState<Set<string>>(new Set())
  const [sortConfig, setSortConfig] = React.useState<{
    column: string
    direction: 'asc' | 'desc'
  } | null>(null)

  const getRowIdValue = (row: T, index: number): string => {
    return getRowId ? getRowId(row) : String(index)
  }

  const getValue = (row: T, accessorKey?: string): any => {
    if (!accessorKey) return null
    const keys = accessorKey.split('.')
    return keys.reduce((obj, key) => obj?.[key], row as any)
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allIds = new Set(data.map((row, i) => getRowIdValue(row, i)))
      setSelectedRows(allIds)
      onRowSelection?.(data)
    } else {
      setSelectedRows(new Set())
      onRowSelection?.([])
    }
  }

  const handleSelectRow = (rowId: string, row: T, checked: boolean) => {
    const newSelection = new Set(selectedRows)
    if (checked) {
      newSelection.add(rowId)
    } else {
      newSelection.delete(rowId)
    }
    setSelectedRows(newSelection)
    
    const selectedData = data.filter((r, i) => 
      newSelection.has(getRowIdValue(r, i))
    )
    onRowSelection?.(selectedData)
  }

  const handleSort = (columnId: string) => {
    setSortConfig(current => {
      if (current?.column !== columnId) {
        return { column: columnId, direction: 'asc' }
      }
      if (current.direction === 'asc') {
        return { column: columnId, direction: 'desc' }
      }
      return null
    })
  }

  const sortedData = React.useMemo(() => {
    if (!sortConfig) return data

    const column = columns.find(c => c.id === sortConfig.column)
    if (!column?.accessorKey) return data

    return [...data].sort((a, b) => {
      const aValue = getValue(a, column.accessorKey as string)
      const bValue = getValue(b, column.accessorKey as string)

      if (aValue === null || aValue === undefined) return 1
      if (bValue === null || bValue === undefined) return -1

      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1
      }
      return 0
    })
  }, [data, sortConfig, columns])

  const selectedRowsArray = React.useMemo(
    () => data.filter((row, i) => selectedRows.has(getRowIdValue(row, i))),
    [data, selectedRows]
  )

  return (
    <div className={cn("space-y-4", className)}>
      {/* Bulk Actions */}
      {bulkActions && selectedRows.size > 0 && (
        <div className="flex items-center gap-2 p-4 bg-muted/50 rounded-lg">
          <span className="text-sm text-muted-foreground">
            {selectedRows.size} row{selectedRows.size !== 1 && 's'} selected
          </span>
          <div className="flex gap-2 ml-auto">
            {bulkActions.map((action, i) => {
              const Icon = action.icon
              return (
                <Button
                  key={i}
                  variant={action.variant || 'outline'}
                  size="sm"
                  onClick={() => action.onClick(selectedRowsArray)}
                >
                  {Icon && <Icon className="h-4 w-4 mr-2" />}
                  {action.label}
                </Button>
              )
            })}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader className={cn(stickyHeader && "sticky top-0 bg-background z-10")}>
            <TableRow>
              {showSelection && (
                <TableHead className="w-[50px]">
                  <Checkbox
                    checked={selectedRows.size === data.length && data.length > 0}
                    onCheckedChange={handleSelectAll}
                    aria-label="Select all"
                  />
                </TableHead>
              )}
              {columns.map(column => (
                <TableHead
                  key={column.id}
                  style={{
                    width: column.size,
                    minWidth: column.minSize,
                    maxWidth: column.maxSize
                  }}
                >
                  {column.enableSorting ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="-ml-3 h-8 data-[state=open]:bg-accent"
                      onClick={() => handleSort(column.id)}
                    >
                      <span>
                        {typeof column.header === 'function'
                          ? column.header({ column })
                          : column.header}
                      </span>
                      {sortConfig?.column === column.id ? (
                        sortConfig.direction === 'asc' ? (
                          <ArrowUp className="ml-2 h-4 w-4" />
                        ) : (
                          <ArrowDown className="ml-2 h-4 w-4" />
                        )
                      ) : (
                        <ArrowUpDown className="ml-2 h-4 w-4" />
                      )}
                    </Button>
                  ) : (
                    <div>
                      {typeof column.header === 'function'
                        ? column.header({ column })
                        : column.header}
                    </div>
                  )}
                </TableHead>
              ))}
              {actions && actions.length > 0 && (
                <TableHead className="w-[80px]">Actions</TableHead>
              )}
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedData.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length + (showSelection ? 1 : 0) + (actions ? 1 : 0)}
                  className="h-24 text-center"
                >
                  No data available
                </TableCell>
              </TableRow>
            ) : (
              sortedData.map((row, rowIndex) => {
                const rowId = getRowIdValue(row, rowIndex)
                const isSelected = selectedRows.has(rowId)

                return (
                  <TableRow key={rowId} data-state={isSelected && "selected"}>
                    {showSelection && (
                      <TableCell>
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={(checked) => 
                            handleSelectRow(rowId, row, checked as boolean)
                          }
                          aria-label={`Select row ${rowIndex + 1}`}
                        />
                      </TableCell>
                    )}
                    {columns.map(column => (
                      <TableCell key={column.id}>
                        {column.cell
                          ? column.cell({
                              row,
                              getValue: () => getValue(row, column.accessorKey as string)
                            })
                          : getValue(row, column.accessorKey as string)}
                      </TableCell>
                    ))}
                    {actions && actions.length > 0 && (
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                              <span className="sr-only">Open menu</span>
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            {actions.map((action, i) => {
                              const Icon = action.icon
                              const isDisabled = action.disabled?.(row)
                              return (
                                <DropdownMenuItem
                                  key={i}
                                  onClick={() => !isDisabled && action.onClick(row)}
                                  disabled={isDisabled}
                                  className={cn(
                                    action.variant === 'destructive' && "text-destructive"
                                  )}
                                >
                                  {Icon && <Icon className="h-4 w-4 mr-2" />}
                                  {action.label}
                                </DropdownMenuItem>
                              )
                            })}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    )}
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

// Example column helper functions
export function createColumns<T>(columns: DataTableColumn<T>[]): DataTableColumn<T>[] {
  return columns
}

export function statusColumn<T>({
  accessorKey,
  header = 'Status',
  statuses
}: {
  accessorKey: keyof T | string
  header?: string
  statuses: Record<string, { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline' }>
}): DataTableColumn<T> {
  return {
    id: accessorKey as string,
    header,
    accessorKey,
    cell: ({ getValue }) => {
      const value = getValue() as string
      const status = statuses[value]
      if (!status) return value
      return <Badge variant={status.variant}>{status.label}</Badge>
    }
  }
}

export function dateColumn<T>({
  accessorKey,
  header = 'Date',
  format = 'PPP'
}: {
  accessorKey: keyof T | string
  header?: string
  format?: string
}): DataTableColumn<T> {
  return {
    id: accessorKey as string,
    header,
    accessorKey,
    enableSorting: true,
    cell: ({ getValue }) => {
      const value = getValue()
      if (!value) return '-'
      const date = new Date(value)
      return date.toLocaleDateString()
    }
  }
}