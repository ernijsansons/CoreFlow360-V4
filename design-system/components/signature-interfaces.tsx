/**
 * SIGNATURE INTERFACES - Redefining Enterprise Interaction
 * Practical innovation meets exceptional user experience
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import { Search, Command, ArrowUp, ArrowDown, Enter, X, ChevronRight, TrendingUp, TrendingDown, AlertCircle } from 'lucide-react';

// ============================================
// COMMAND BAR - Universal control center
// ============================================

interface CommandBarProps {
  onCommand?: (command: string) => void;
  suggestions?: CommandSuggestion[];
  placeholder?: string;
}

interface CommandSuggestion {
  id: string;
  title: string;
  description?: string;
  category?: string;
  action: () => void;
  shortcut?: string;
  icon?: React.ReactNode;
}

export const CommandBar: React.FC<CommandBarProps> = ({
  onCommand,
  suggestions = [],
  placeholder = "Type '/' for commands or search naturally..."
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Natural language processing simulation
  const processedSuggestions = React.useMemo(() => {
    if (!query) return suggestions.slice(0, 5);

    // Simple fuzzy matching for demonstration
    const filtered = suggestions.filter(s =>
      s.title.toLowerCase().includes(query.toLowerCase()) ||
      s.description?.toLowerCase().includes(query.toLowerCase())
    );

    return filtered.slice(0, 8);
  }, [query, suggestions]);

  // Global keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !isOpen) {
        e.preventDefault();
        setIsOpen(true);
      } else if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
        setQuery('');
      } else if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setIsOpen(!isOpen);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % processedSuggestions.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + processedSuggestions.length) % processedSuggestions.length);
    } else if (e.key === 'Enter' && processedSuggestions[selectedIndex]) {
      e.preventDefault();
      processedSuggestions[selectedIndex].action();
      setIsOpen(false);
      setQuery('');
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] bg-black/20 dark:bg-white/5"
          onClick={() => setIsOpen(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
            className="w-full max-w-2xl bg-white dark:bg-black border border-black/8 dark:border-white/8 overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Input Section */}
            <div className="flex items-center h-12 px-5 border-b border-black/8 dark:border-white/8">
              <Search className="w-4 h-4 text-black/36 dark:text-white/36 mr-3" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={placeholder}
                className="flex-1 bg-transparent text-black dark:text-white placeholder-black/36 dark:placeholder-white/36 outline-none"
              />
              <div className="flex items-center gap-2 ml-3">
                <kbd className="px-1.5 py-0.5 text-[11px] bg-black/8 dark:bg-white/8 rounded">ESC</kbd>
              </div>
            </div>

            {/* Suggestions */}
            {processedSuggestions.length > 0 && (
              <div className="max-h-96 overflow-y-auto">
                {processedSuggestions.map((suggestion, index) => (
                  <motion.div
                    key={suggestion.id}
                    className={`
                      flex items-center justify-between px-5 py-3
                      cursor-pointer transition-colors duration-150
                      ${index === selectedIndex
                        ? 'bg-black/4 dark:bg-white/4'
                        : 'hover:bg-black/2 dark:hover:bg-white/2'}
                    `}
                    onClick={() => {
                      suggestion.action();
                      setIsOpen(false);
                      setQuery('');
                    }}
                    whileHover={{ x: 4 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="flex items-center gap-3">
                      {suggestion.icon && (
                        <div className="w-4 h-4 text-black/36 dark:text-white/36">
                          {suggestion.icon}
                        </div>
                      )}
                      <div>
                        <div className="text-black dark:text-white">
                          {suggestion.title}
                        </div>
                        {suggestion.description && (
                          <div className="text-[13px] text-black/36 dark:text-white/36">
                            {suggestion.description}
                          </div>
                        )}
                      </div>
                    </div>
                    {suggestion.shortcut && (
                      <kbd className="px-2 py-1 text-[11px] bg-black/8 dark:bg-white/8 rounded">
                        {suggestion.shortcut}
                      </kbd>
                    )}
                  </motion.div>
                ))}
              </div>
            )}

            {/* AI Context (subtle) */}
            {query && processedSuggestions.length === 0 && (
              <div className="px-5 py-8 text-center text-black/36 dark:text-white/36">
                <div className="text-[13px]">Analyzing "{query}"...</div>
                <div className="text-[11px] mt-2">AI-powered suggestions loading</div>
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// ============================================
// INTELLIGENT DASHBOARD - Context-aware metrics
// ============================================

interface DashboardMetric {
  id: string;
  value: string | number;
  label: string;
  change?: number;
  trend?: 'up' | 'down' | 'neutral';
  priority?: 'high' | 'medium' | 'low';
  detail?: string;
  sparkline?: number[];
}

interface IntelligentDashboardProps {
  primaryMetric: DashboardMetric;
  secondaryMetrics?: DashboardMetric[];
  onTimeRangeChange?: (range: string) => void;
}

export const IntelligentDashboard: React.FC<IntelligentDashboardProps> = ({
  primaryMetric,
  secondaryMetrics = [],
  onTimeRangeChange
}) => {
  const [hoveredMetric, setHoveredMetric] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('today');

  const timeRanges = ['today', 'week', 'month', 'quarter', 'year'];

  return (
    <div className="relative">
      {/* Primary Metric - Hero Display */}
      <motion.div
        className="relative mb-12"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.4, 0, 0.2, 1] }}
      >
        <div className="flex items-baseline gap-6">
          <h1 className="text-[64px] font-medium leading-none tracking-[-0.02em] text-black dark:text-white">
            {primaryMetric.value}
          </h1>
          {primaryMetric.change !== undefined && (
            <motion.div
              className={`flex items-center gap-1 ${
                primaryMetric.change > 0 ? 'text-green-600' : 'text-red-600'
              }`}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
            >
              {primaryMetric.trend === 'up' ? <TrendingUp className="w-5 h-5" /> : <TrendingDown className="w-5 h-5" />}
              <span className="text-[20px] font-medium">
                {primaryMetric.change > 0 ? '+' : ''}{primaryMetric.change}%
              </span>
            </motion.div>
          )}
        </div>
        <div className="mt-2 text-[16px] text-black/64 dark:text-white/64">
          {primaryMetric.label}
        </div>
        {primaryMetric.detail && (
          <motion.div
            className="mt-4 text-[13px] text-black/36 dark:text-white/36"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {primaryMetric.detail}
          </motion.div>
        )}
      </motion.div>

      {/* Time Range Selector */}
      <div className="flex gap-1 mb-8">
        {timeRanges.map((range) => (
          <button
            key={range}
            onClick={() => {
              setTimeRange(range);
              onTimeRangeChange?.(range);
            }}
            className={`
              px-4 py-2 text-[13px] capitalize transition-all duration-200
              ${timeRange === range
                ? 'text-black dark:text-white bg-black/8 dark:bg-white/8'
                : 'text-black/36 dark:text-white/36 hover:text-black dark:hover:text-white'
              }
            `}
          >
            {range}
          </button>
        ))}
      </div>

      {/* Secondary Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-px bg-black/8 dark:bg-white/8">
        {secondaryMetrics.map((metric, index) => (
          <motion.div
            key={metric.id}
            className="relative bg-white dark:bg-black p-5 cursor-pointer"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1, duration: 0.4 }}
            onMouseEnter={() => setHoveredMetric(metric.id)}
            onMouseLeave={() => setHoveredMetric(null)}
            whileHover={{ scale: 1.02 }}
          >
            <div className="text-[28px] font-medium text-black dark:text-white">
              {metric.value}
            </div>
            <div className="text-[13px] text-black/64 dark:text-white/64 mt-1">
              {metric.label}
            </div>

            {/* Hover Details */}
            <AnimatePresence>
              {hoveredMetric === metric.id && metric.detail && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 4 }}
                  className="absolute top-full left-0 right-0 mt-2 p-3 bg-black text-white dark:bg-white dark:text-black text-[13px] z-10"
                >
                  {metric.detail}
                  {metric.sparkline && (
                    <div className="mt-2 flex items-end gap-px h-8">
                      {metric.sparkline.map((value, i) => (
                        <div
                          key={i}
                          className="flex-1 bg-current opacity-40"
                          style={{ height: `${(value / Math.max(...metric.sparkline)) * 100}%` }}
                        />
                      ))}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Priority Indicator */}
            {metric.priority === 'high' && (
              <div className="absolute top-2 right-2">
                <AlertCircle className="w-3 h-3 text-red-500" />
              </div>
            )}
          </motion.div>
        ))}
      </div>
    </div>
  );
};

// ============================================
// DATA TABLE - Spreadsheet reimagined
// ============================================

interface DataTableColumn<T> {
  key: keyof T;
  title: string;
  width?: string;
  align?: 'left' | 'center' | 'right';
  render?: (value: any, row: T) => React.ReactNode;
  sortable?: boolean;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  selectedRows?: T[];
  onSelectionChange?: (rows: T[]) => void;
  loading?: boolean;
}

export function DataTable<T extends { id: string }>({
  columns,
  data,
  onRowClick,
  selectedRows = [],
  onSelectionChange,
  loading = false
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<keyof T | null>(null);
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [hoveredRow, setHoveredRow] = useState<string | null>(null);

  const sortedData = React.useMemo(() => {
    if (!sortKey) return data;

    return [...data].sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];

      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [data, sortKey, sortOrder]);

  const handleSort = (key: keyof T) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortOrder('asc');
    }
  };

  const toggleRowSelection = (row: T) => {
    const isSelected = selectedRows.some(r => r.id === row.id);
    if (isSelected) {
      onSelectionChange?.(selectedRows.filter(r => r.id !== row.id));
    } else {
      onSelectionChange?.([...selectedRows, row]);
    }
  };

  return (
    <div className="relative overflow-hidden">
      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-black/8 dark:border-white/8">
              {onSelectionChange && (
                <th className="w-12 h-10 text-left">
                  <input
                    type="checkbox"
                    className="w-4 h-4"
                    checked={selectedRows.length === data.length}
                    onChange={(e) => {
                      onSelectionChange(e.target.checked ? data : []);
                    }}
                  />
                </th>
              )}
              {columns.map((column) => (
                <th
                  key={String(column.key)}
                  className={`
                    h-10 px-5 text-[13px] font-medium text-black/64 dark:text-white/64 text-left
                    ${column.sortable ? 'cursor-pointer hover:text-black dark:hover:text-white' : ''}
                  `}
                  style={{ width: column.width }}
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  <div className="flex items-center gap-2">
                    {column.title}
                    {column.sortable && sortKey === column.key && (
                      <motion.span
                        initial={{ opacity: 0, rotate: 0 }}
                        animate={{ opacity: 1, rotate: sortOrder === 'desc' ? 180 : 0 }}
                        className="text-[10px]"
                      >
                        ↑
                      </motion.span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              // Loading skeleton
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-black/4 dark:border-white/4">
                  {columns.map((column) => (
                    <td key={String(column.key)} className="h-12 px-5">
                      <div className="h-4 bg-black/8 dark:bg-white/8 animate-pulse rounded" />
                    </td>
                  ))}
                </tr>
              ))
            ) : (
              sortedData.map((row) => (
                <motion.tr
                  key={row.id}
                  className={`
                    border-b border-black/4 dark:border-white/4 cursor-pointer
                    transition-colors duration-150
                    ${selectedRows.some(r => r.id === row.id) ? 'bg-blue-500/4' : ''}
                    ${hoveredRow === row.id ? 'bg-black/2 dark:bg-white/2' : ''}
                  `}
                  onClick={() => onRowClick?.(row)}
                  onMouseEnter={() => setHoveredRow(row.id)}
                  onMouseLeave={() => setHoveredRow(null)}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {onSelectionChange && (
                    <td className="w-12 h-12 px-3">
                      <input
                        type="checkbox"
                        className="w-4 h-4"
                        checked={selectedRows.some(r => r.id === row.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          toggleRowSelection(row);
                        }}
                      />
                    </td>
                  )}
                  {columns.map((column) => (
                    <td
                      key={String(column.key)}
                      className={`h-12 px-5 text-[16px] text-black dark:text-white ${
                        column.align === 'right' ? 'text-right' :
                        column.align === 'center' ? 'text-center' : 'text-left'
                      }`}
                    >
                      {column.render
                        ? column.render(row[column.key], row)
                        : String(row[column.key])}
                    </td>
                  ))}
                </motion.tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Infinite scroll indicator */}
      {data.length > 20 && (
        <div className="mt-8 text-center text-[13px] text-black/36 dark:text-white/36">
          Scroll for more • {data.length} total records
        </div>
      )}
    </div>
  );
}

export default {
  CommandBar,
  IntelligentDashboard,
  DataTable,
};