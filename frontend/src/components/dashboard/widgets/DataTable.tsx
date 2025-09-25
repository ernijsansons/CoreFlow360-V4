/**
 * Data Table Widget
 * Advanced data table with filtering, sorting, and pagination
 */

import React, { useState, useMemo, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Search,
  Filter,
  Download,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  Eye,
  Edit,
  Trash2
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator
} from '@/components/ui/dropdown-menu'
import type { Widget } from '@/types/dashboard'

export interface Column {
  key: string
  label: string
  type?: 'text' | 'number' | 'currency' | 'date' | 'status' | 'actions'
  sortable?: boolean
  filterable?: boolean
  width?: number
  align?: 'left' | 'center' | 'right'
  render?: (value: any, row: any) => React.ReactNode
}

export interface TableData {
  columns: Column[]
  rows: Record<string, any>[]
  totalRows?: number
  pagination?: {
    page: number
    pageSize: number
    totalPages: number
  }
  filters?: Record<string, any>
  sorting?: {
    column: string
    direction: 'asc' | 'desc'
  }
}

export interface DataTableProps {
  widget: Widget
  data?: TableData
  isExpanded?: boolean
  isLoading?: boolean
  onSort?: (column: string, direction: 'asc' | 'desc') => void
  onFilter?: (filters: Record<string, any>) => void
  onPageChange?: (page: number) => void
  onRowAction?: (action: string, row: any) => void
  onExport?: () => void
  className?: string
}

const formatCellValue = (value: any, type?: string): React.ReactNode => {
  if (value === null || value === undefined) {
    return <span className="text-gray-400">—</span>
  }

  switch (type) {
    case 'currency':
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
      }).format(value)

    case 'number':
      return new Intl.NumberFormat('en-US').format(value)

    case 'date':
      return new Date(value).toLocaleDateString()

    case 'status':
      const statusColors: Record<string, string> = {
        active: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        inactive: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
        pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        error: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
        success: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
        warning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
        danger: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      }

      const statusColor = statusColors[value.toLowerCase()] || statusColors.inactive

      return (
        <Badge variant="secondary" className={cn("text-xs", statusColor)}>
          {value}
        </Badge>
      )

    default:
      return String(value)
  }
}

export const DataTable: React.FC<DataTableProps> = ({
  widget,
  data,
  isExpanded = false,
  isLoading = false,
  onSort,
  onFilter,
  onPageChange,
  onRowAction,
  onExport,
  className
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [columnFilters, setColumnFilters] = useState<Record<string, string>>({})
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set())

  const { columns = [], rows = [], pagination, sorting } = data || {}

  // Filter rows based on search and column filters
  const filteredRows = useMemo(() => {
    let filtered = [...rows]

    // Global search
    if (searchTerm) {
      filtered = filtered.filter(row =>
        columns.some(col =>
          String(row[col.key] || '').toLowerCase().includes(searchTerm.toLowerCase())
        )
      )
    }

    // Column filters
    Object.entries(columnFilters).forEach(([columnKey, filterValue]) => {
      if (filterValue) {
        filtered = filtered.filter(row =>
          String(row[columnKey] || '').toLowerCase().includes(filterValue.toLowerCase())
        )
      }
    })

    return filtered
  }, [rows, searchTerm, columnFilters, columns])

  // Handle sorting
  const handleSort = useCallback((columnKey: string) => {
    const column = columns.find(col => col.key === columnKey)
    if (!column?.sortable) return

    const currentDirection = sorting?.column === columnKey ? sorting.direction : null
    const newDirection = currentDirection === 'asc' ? 'desc' : 'asc'

    onSort?.(columnKey, newDirection)
  }, [columns, sorting, onSort])

  // Handle column filter
  const handleColumnFilter = useCallback((columnKey: string, value: string) => {
    const newFilters = { ...columnFilters, [columnKey]: value }
    setColumnFilters(newFilters)
    onFilter?.(newFilters)
  }, [columnFilters, onFilter])

  // Handle row selection
  const handleRowSelect = useCallback((rowId: string, selected: boolean) => {
    const newSelection = new Set(selectedRows)
    if (selected) {
      newSelection.add(rowId)
    } else {
      newSelection.delete(rowId)
    }
    setSelectedRows(newSelection)
  }, [selectedRows])

  // Handle select all
  const handleSelectAll = useCallback((selected: boolean) => {
    if (selected) {
      setSelectedRows(new Set(filteredRows.map((row, index) => String(index))))
    } else {
      setSelectedRows(new Set())
    }
  }, [filteredRows])

  const getSortIcon = (columnKey: string) => {
    if (sorting?.column !== columnKey) {
      return <ArrowUpDown className="w-4 h-4 opacity-50" />
    }
    return sorting.direction === 'asc'
      ? <ArrowUp className="w-4 h-4 text-blue-600" />
      : <ArrowDown className="w-4 h-4 text-blue-600" />
  }

  const RowActions: React.FC<{ row: any; index: number }> = ({ row, index }) => (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="w-8 h-8 p-0">
          <MoreHorizontal className="w-4 h-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onRowAction?.('view', row)}>
          <Eye className="w-4 h-4 mr-2" />
          View Details
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onRowAction?.('edit', row)}>
          <Edit className="w-4 h-4 mr-2" />
          Edit
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => onRowAction?.('delete', row)}
          className="text-red-600"
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Delete
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  if (isLoading) {
    return (
      <div className={cn("h-full flex items-center justify-center", className)}>
        <div className="animate-spin w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <motion.div
      className={cn("h-full flex flex-col bg-white dark:bg-gray-800 rounded-lg", className)}
      layout
    >
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {widget.title}
          </h3>
          <div className="flex items-center space-x-2">
            {selectedRows.size > 0 && (
              <Badge variant="secondary">
                {selectedRows.size} selected
              </Badge>
            )}
            {onExport && (
              <Button variant="outline" size="sm" onClick={onExport}>
                <Download className="w-4 h-4 mr-2" />
                Export
              </Button>
            )}
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center space-x-4">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <Input
              placeholder="Search all columns..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          <Button variant="outline" size="sm">
            <Filter className="w-4 h-4 mr-2" />
            Filters
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900">
              {/* Select All Checkbox */}
              <th className="w-12 px-4 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedRows.size === filteredRows.length && filteredRows.length > 0}
                  onChange={(e) => handleSelectAll(e.target.checked)}
                  className="rounded border-gray-300"
                />
              </th>

              {/* Column Headers */}
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={cn(
                    "px-4 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider",
                    column.align === 'center' && "text-center",
                    column.align === 'right' && "text-right",
                    column.sortable && "cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  )}
                  style={{ width: column.width }}
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  <div className="flex items-center space-x-1">
                    <span>{column.label}</span>
                    {column.sortable && getSortIcon(column.key)}
                  </div>
                </th>
              ))}

              {/* Actions Column */}
              <th className="w-16 px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>

          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            <AnimatePresence>
              {filteredRows.map((row, index) => (
                <motion.tr
                  key={row.id || index}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.05 }}
                >
                  {/* Row Checkbox */}
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedRows.has(String(index))}
                      onChange={(e) => handleRowSelect(String(index), e.target.checked)}
                      className="rounded border-gray-300"
                    />
                  </td>

                  {/* Data Cells */}
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={cn(
                        "px-4 py-3 text-sm text-gray-900 dark:text-gray-100",
                        column.align === 'center' && "text-center",
                        column.align === 'right' && "text-right"
                      )}
                    >
                      {column.render
                        ? column.render(row[column.key], row)
                        : formatCellValue(row[column.key], column.type)
                      }
                    </td>
                  ))}

                  {/* Actions Cell */}
                  <td className="px-4 py-3 text-center">
                    <RowActions row={row} index={index} />
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>

        {/* Empty State */}
        {filteredRows.length === 0 && (
          <div className="text-center py-12">
            <div className="text-gray-400 mb-2">
              <Search className="w-8 h-8 mx-auto" />
            </div>
            <p className="text-gray-500 dark:text-gray-400">
              {searchTerm || Object.values(columnFilters).some(v => v)
                ? 'No results found for your search'
                : 'No data available'
              }
            </p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {pagination && pagination.totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-700">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Showing {((pagination.page - 1) * pagination.pageSize) + 1} to{' '}
            {Math.min(pagination.page * pagination.pageSize, filteredRows.length)} of{' '}
            {pagination.totalPages * pagination.pageSize} results
          </div>

          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange?.(pagination.page - 1)}
              disabled={pagination.page <= 1}
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </Button>

            <div className="flex items-center space-x-1">
              {Array.from({ length: Math.min(5, pagination.totalPages) }, (_, i) => {
                const page = i + 1
                const isActive = page === pagination.page

                return (
                  <Button
                    key={page}
                    variant={isActive ? "default" : "outline"}
                    size="sm"
                    className="w-8 h-8 p-0"
                    onClick={() => onPageChange?.(page)}
                  >
                    {page}
                  </Button>
                )
              })}
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange?.(pagination.page + 1)}
              disabled={pagination.page >= pagination.totalPages}
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default DataTable