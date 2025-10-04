/**
 * Table Component
 * Advanced data table with sorting, filtering, and pagination
 */

import React, { useState, useMemo } from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { Input } from './input'
import { ChevronUp, ChevronDown, Search, Filter } from 'lucide-react'

// Basic table components for compatibility
export const Table = React.forwardRef<
  HTMLTableElement,
  React.HTMLAttributes<HTMLTableElement>
>(({ className, ...props }, ref) => (
  <div className="relative w-full overflow-auto">
    <table
      ref={ref}
      className={cn('w-full caption-bottom text-sm', className)}
      {...props}
    />
  </div>
))
Table.displayName = 'Table'

export const TableHeader = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead ref={ref} className={cn('[&_tr]:border-b', className)} {...props} />
))
TableHeader.displayName = 'TableHeader'

export const TableBody = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody
    ref={ref}
    className={cn('[&_tr:last-child]:border-0', className)}
    {...props}
  />
))
TableBody.displayName = 'TableBody'

export const TableRow = React.forwardRef<
  HTMLTableRowElement,
  React.HTMLAttributes<HTMLTableRowElement>
>(({ className, ...props }, ref) => (
  <tr
    ref={ref}
    className={cn(
      'border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted',
      className
    )}
    {...props}
  />
))
TableRow.displayName = 'TableRow'

export const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      'h-12 px-4 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0',
      className
    )}
    {...props}
  />
))
TableHead.displayName = 'TableHead'

export const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <td
    ref={ref}
    className={cn('p-4 align-middle [&:has([role=checkbox])]:pr-0', className)}
    {...props}
  />
))
TableCell.displayName = 'TableCell'

export interface TableColumn<T = any> {
  key: string
  header: string
  accessor?: keyof T | ((row: T) => any)
  sortable?: boolean
  filterable?: boolean
  width?: string | number
  align?: 'left' | 'center' | 'right'
  render?: (value: any, row: T, index: number) => React.ReactNode
}

export interface TableProps<T = any> {
  data: T[]
  columns: TableColumn<T>[]
  loading?: boolean
  pagination?: {
    page: number
    pageSize: number
    total: number
    onPageChange: (page: number) => void
    onPageSizeChange: (pageSize: number) => void
  }
  sorting?: {
    sortBy?: string
    sortOrder?: 'asc' | 'desc'
    onSort: (column: string, order: 'asc' | 'desc') => void
  }
  filtering?: {
    filters: Record<string, string>
    onFilter: (filters: Record<string, string>) => void
  }
  selection?: {
    selectedRows: string[]
    onSelectionChange: (selectedRows: string[]) => void
    getRowId: (row: T) => string
  }
  emptyMessage?: string
  className?: string
  size?: 'sm' | 'md' | 'lg'
  striped?: boolean
  hoverable?: boolean
  bordered?: boolean
}

export const AdvancedTable = <T,>({
  data,
  columns,
  loading = false,
  pagination,
  sorting,
  filtering,
  selection,
  emptyMessage = 'No data available',
  className,
  size = 'md',
  striped = false,
  hoverable = true,
  bordered = true,
  ...props
}: TableProps<T>) => {
  const [localFilters, setLocalFilters] = useState<Record<string, string>>({})
  const [showFilters, setShowFilters] = useState(false)

  // Memoize processed data
  const processedData = useMemo(() => {
    if (!data) return []

    let result = [...data]

    // Apply local filtering if no external filtering
    if (!filtering && Object.keys(localFilters).length > 0) {
      result = result.filter(row => {
        return Object.entries(localFilters).every(([key, filterValue]) => {
          if (!filterValue) return true

          const column = columns.find(col => col.key === key)
          if (!column) return true

          let cellValue: any
          if (typeof column.accessor === 'function') {
            cellValue = column.accessor(row)
          } else if (column.accessor) {
            cellValue = row[column.accessor]
          } else {
            cellValue = (row as any)[key]
          }

          return String(cellValue || '')
            .toLowerCase()
            .includes(filterValue.toLowerCase())
        })
      })
    }

    return result
  }, [data, columns, localFilters, filtering])

  const handleSort = (column: TableColumn<T>) => {
    if (!column.sortable || !sorting) return

    const isCurrentSort = sorting.sortBy === column.key
    const newOrder = isCurrentSort && sorting.sortOrder === 'asc' ? 'desc' : 'asc'

    sorting.onSort(column.key, newOrder)
  }

  const handleFilter = (columnKey: string, value: string) => {
    if (filtering) {
      filtering.onFilter({ ...filtering.filters, [columnKey]: value })
    } else {
      setLocalFilters(prev => ({ ...prev, [columnKey]: value }))
    }
  }

  const handleSelectAll = () => {
    if (!selection) return

    const allRowIds = processedData.map(selection.getRowId)
    const isAllSelected = allRowIds.every(id => selection.selectedRows.includes(id))

    if (isAllSelected) {
      selection.onSelectionChange(
        selection.selectedRows.filter(id => !allRowIds.includes(id))
      )
    } else {
      selection.onSelectionChange([...new Set([...selection.selectedRows, ...allRowIds])])
    }
  }

  const handleRowSelect = (rowId: string) => {
    if (!selection) return

    const isSelected = selection.selectedRows.includes(rowId)

    if (isSelected) {
      selection.onSelectionChange(selection.selectedRows.filter(id => id !== rowId))
    } else {
      selection.onSelectionChange([...selection.selectedRows, rowId])
    }
  }

  const getCellValue = (row: T, column: TableColumn<T>) => {
    if (typeof column.accessor === 'function') {
      return column.accessor(row)
    } else if (column.accessor) {
      return row[column.accessor]
    } else {
      return (row as any)[column.key]
    }
  }

  const tableClasses = cn(
    'w-full border-collapse',
    bordered && 'border border-border',
    className
  )

  const sizeClasses = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg'
  }

  return (
    <div className="w-full">
      {/* Filters */}
      {(filtering || columns.some(col => col.filterable)) && (
        <div className="mb-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
            className="mb-2"
          >
            <Filter className="h-4 w-4 mr-2" />
            Filters
          </Button>

          {showFilters && (
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4 p-4 bg-muted rounded-md">
              {columns
                .filter(col => col.filterable)
                .map(column => (
                  <div key={column.key}>
                    <label className="block text-sm font-medium mb-1">
                      {column.header}
                    </label>
                    <Input
                      placeholder={`Filter ${column.header}...`}
                      value={filtering ? filtering.filters[column.key] || '' : localFilters[column.key] || ''}
                      onChange={(e) => handleFilter(column.key, e.target.value)}
                      className="h-8"
                    />
                  </div>
                ))}
            </div>
          )}
        </div>
      )}

      {/* Table */}
      <div className="relative overflow-auto">
        <table className={cn(tableClasses, sizeClasses[size])} {...props}>
          <thead>
            <tr className="border-b border-border bg-muted/50">
              {selection && (
                <th className="w-12 px-4 py-3 text-left">
                  <input
                    type="checkbox"
                    checked={
                      processedData.length > 0 &&
                      processedData.every(row =>
                        selection.selectedRows.includes(selection.getRowId(row))
                      )
                    }
                    onChange={handleSelectAll}
                    className="rounded border-gray-300"
                  />
                </th>
              )}

              {columns.map((column) => (
                <th
                  key={column.key}
                  className={cn(
                    'px-4 py-3 font-medium text-muted-foreground',
                    column.align === 'center' && 'text-center',
                    column.align === 'right' && 'text-right',
                    column.sortable && 'cursor-pointer hover:text-foreground'
                  )}
                  style={{ width: column.width }}
                  onClick={() => handleSort(column)}
                >
                  <div className="flex items-center gap-2">
                    {column.header}
                    {column.sortable && sorting && (
                      <div className="flex flex-col">
                        <ChevronUp
                          className={cn(
                            'h-3 w-3',
                            sorting.sortBy === column.key && sorting.sortOrder === 'asc'
                              ? 'text-foreground'
                              : 'text-muted-foreground/50'
                          )}
                        />
                        <ChevronDown
                          className={cn(
                            'h-3 w-3 -mt-1',
                            sorting.sortBy === column.key && sorting.sortOrder === 'desc'
                              ? 'text-foreground'
                              : 'text-muted-foreground/50'
                          )}
                        />
                      </div>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan={columns.length + (selection ? 1 : 0)} className="px-4 py-8 text-center text-muted-foreground">
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
                    <span className="ml-2">Loading...</span>
                  </div>
                </td>
              </tr>
            ) : processedData.length === 0 ? (
              <tr>
                <td colSpan={columns.length + (selection ? 1 : 0)} className="px-4 py-8 text-center text-muted-foreground">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              processedData.map((row, index) => {
                const rowId = selection ? selection.getRowId(row) : String(index)
                const isSelected = selection ? selection.selectedRows.includes(rowId) : false

                return (
                  <tr
                    key={rowId}
                    className={cn(
                      'border-b border-border',
                      striped && index % 2 === 1 && 'bg-muted/25',
                      hoverable && 'hover:bg-muted/50',
                      isSelected && 'bg-primary/10'
                    )}
                  >
                    {selection && (
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleRowSelect(rowId)}
                          className="rounded border-gray-300"
                        />
                      </td>
                    )}

                    {columns.map((column) => {
                      const value = getCellValue(row, column)

                      return (
                        <td
                          key={column.key}
                          className={cn(
                            'px-4 py-3',
                            column.align === 'center' && 'text-center',
                            column.align === 'right' && 'text-right'
                          )}
                        >
                          {column.render ? column.render(value, row, index) : String(value || '')}
                        </td>
                      )
                    })}
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination && (
        <div className="flex items-center justify-between mt-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              Showing {((pagination.page - 1) * pagination.pageSize) + 1} to{' '}
              {Math.min(pagination.page * pagination.pageSize, pagination.total)} of{' '}
              {pagination.total} results
            </span>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={pagination.pageSize}
              onChange={(e) => pagination.onPageSizeChange(Number(e.target.value))}
              className="border border-border rounded px-2 py-1 text-sm"
            >
              <option value={10}>10 per page</option>
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
            </select>

            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(pagination.page - 1)}
              disabled={pagination.page <= 1}
            >
              Previous
            </Button>

            <span className="text-sm">
              Page {pagination.page} of {Math.ceil(pagination.total / pagination.pageSize)}
            </span>

            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(pagination.page + 1)}
              disabled={pagination.page >= Math.ceil(pagination.total / pagination.pageSize)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

export type { TableProps, TableColumn }