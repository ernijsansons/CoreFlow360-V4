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
import { Input } from './input'
import {
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  Search,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight
} from 'lucide-react'
import { LoadingSpinner } from './loading-state'
import { EmptyState } from './empty-state'

export interface Column<T> {
  key: keyof T | string
  label: string
  sortable?: boolean
  filterable?: boolean
  width?: string | number
  align?: 'left' | 'center' | 'right'
  render?: (value: any, row: T) => React.ReactNode
  className?: string
}

export interface DataGridProps<T> {
  data: T[]
  columns: Column<T>[]
  loading?: boolean
  error?: string
  onRowClick?: (row: T) => void
  onSort?: (column: string, direction: 'asc' | 'desc') => void
  onFilter?: (filters: Record<string, string>) => void
  onExport?: () => void
  sortColumn?: string
  sortDirection?: 'asc' | 'desc'
  filters?: Record<string, string>
  pagination?: {
    page: number
    pageSize: number
    total: number
    onPageChange: (page: number) => void
    onPageSizeChange: (size: number) => void
  }
  searchable?: boolean
  searchPlaceholder?: string
  onSearch?: (query: string) => void
  className?: string
  striped?: boolean
  hoverable?: boolean
  compact?: boolean
}

export function DataGrid<T extends Record<string, any>>({
  data,
  columns,
  loading = false,
  error,
  onRowClick,
  onSort,
  onFilter,
  onExport,
  sortColumn,
  sortDirection = 'asc',
  filters = {},
  pagination,
  searchable = false,
  searchPlaceholder = 'Search...',
  onSearch,
  className,
  striped = false,
  hoverable = true,
  compact = false
}: DataGridProps<T>) {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [showFilters, setShowFilters] = React.useState(false)
  const [localFilters, setLocalFilters] = React.useState(filters)

  const handleSort = (column: Column<T>) => {
    if (!column.sortable || !onSort) return
    
    const key = column.key as string
    const newDirection = 
      sortColumn === key && sortDirection === 'asc' ? 'desc' : 'asc'
    onSort(key, newDirection)
  }

  const handleFilterChange = (columnKey: string, value: string) => {
    const newFilters = { ...localFilters, [columnKey]: value }
    if (!value) {
      delete newFilters[columnKey]
    }
    setLocalFilters(newFilters)
    onFilter?.(newFilters)
  }

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setSearchQuery(value)
    onSearch?.(value)
  }

  const getValue = (row: T, key: string): any => {
    const keys = key.split('.')
    return keys.reduce((obj, k) => obj?.[k], row as any)
  }

  const renderSortIcon = (column: Column<T>) => {
    if (!column.sortable) return null
    
    const key = column.key as string
    if (sortColumn !== key) {
      return <ChevronsUpDown className="h-4 w-4 opacity-50" />
    }
    
    return sortDirection === 'asc' 
      ? <ChevronUp className="h-4 w-4" />
      : <ChevronDown className="h-4 w-4" />
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <EmptyState
        title="Error loading data"
        description={error}
        icon={XCircle}
        iconClassName="text-destructive"
      />
    )
  }

  if (!data || data.length === 0) {
    return (
      <EmptyState
        title="No data available"
        description="No records found to display."
      />
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Search and Actions Bar */}
      {(searchable || onExport || columns.some(c => c.filterable)) && (
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            {searchable && (
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder={searchPlaceholder}
                  value={searchQuery}
                  onChange={handleSearch}
                  className="pl-9 w-[250px]"
                />
              </div>
            )}
            {columns.some(c => c.filterable) && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowFilters(!showFilters)}
              >
                <Filter className="h-4 w-4 mr-2" />
                Filters
                {Object.keys(localFilters).length > 0 && (
                  <span className="ml-2 rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
                    {Object.keys(localFilters).length}
                  </span>
                )}
              </Button>
            )}
          </div>
          {onExport && (
            <Button variant="outline" size="sm" onClick={onExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          )}
        </div>
      )}

      {/* Filter Row */}
      {showFilters && (
        <div className="flex flex-wrap gap-2 p-4 bg-muted/50 rounded-lg">
          {columns.filter(c => c.filterable).map(column => (
            <div key={column.key as string} className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">
                {column.label}
              </label>
              <Input
                type="text"
                placeholder={`Filter ${column.label}`}
                value={localFilters[column.key as string] || ''}
                onChange={e => handleFilterChange(column.key as string, e.target.value)}
                className="h-8 w-[150px]"
              />
            </div>
          ))}
        </div>
      )}

      {/* Data Table */}
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map(column => (
                <TableHead
                  key={column.key as string}
                  className={cn(
                    column.align === 'center' && "text-center",
                    column.align === 'right' && "text-right",
                    column.sortable && "cursor-pointer select-none hover:bg-muted/50",
                    column.className
                  )}
                  style={{ width: column.width }}
                  onClick={() => handleSort(column)}
                >
                  <div className="flex items-center gap-1">
                    <span>{column.label}</span>
                    {renderSortIcon(column)}
                  </div>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((row, rowIndex) => (
              <TableRow
                key={rowIndex}
                className={cn(
                  onRowClick && "cursor-pointer",
                  hoverable && "hover:bg-muted/50",
                  striped && rowIndex % 2 === 1 && "bg-muted/20"
                )}
                onClick={() => onRowClick?.(row)}
              >
                {columns.map(column => {
                  const value = getValue(row, column.key as string)
                  return (
                    <TableCell
                      key={column.key as string}
                      className={cn(
                        column.align === 'center' && "text-center",
                        column.align === 'right' && "text-right",
                        compact && "py-2",
                        column.className
                      )}
                    >
                      {column.render ? column.render(value, row) : value}
                    </TableCell>
                  )
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {pagination && (
        <div className="flex items-center justify-between px-2">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span>Rows per page:</span>
            <select
              value={pagination.pageSize}
              onChange={e => pagination.onPageSizeChange(Number(e.target.value))}
              className="h-8 rounded border bg-background px-2"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <span>
              {((pagination.page - 1) * pagination.pageSize) + 1}-
              {Math.min(pagination.page * pagination.pageSize, pagination.total)} of {pagination.total}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(1)}
              disabled={pagination.page === 1}
            >
              <ChevronsLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(pagination.page - 1)}
              disabled={pagination.page === 1}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="px-3 text-sm">
              Page {pagination.page} of {Math.ceil(pagination.total / pagination.pageSize)}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(pagination.page + 1)}
              disabled={pagination.page >= Math.ceil(pagination.total / pagination.pageSize)}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => pagination.onPageChange(Math.ceil(pagination.total / pagination.pageSize))}
              disabled={pagination.page >= Math.ceil(pagination.total / pagination.pageSize)}
            >
              <ChevronsRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}