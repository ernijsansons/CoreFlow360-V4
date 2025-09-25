/**
 * Command Palette Component
 * Advanced command interface with slash commands and quick actions
 */

import React, { useState, useEffect, useRef, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search,
  Command as CommandIcon,
  FileText,
  Users,
  Package,
  DollarSign,
  BarChart3,
  Settings,
  Calculator,
  Download,
  Send,
  Clock,
  ArrowRight,
  Zap,
  Brain
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { useKeyboardNavigation } from '@/hooks/useKeyboardNavigation'
import { useChatStore } from '@/stores/chatStore'
import type { CommandItem, CommandCategory } from '@/types/chat'

export interface CommandPaletteProps {
  isOpen: boolean
  onClose: () => void
  onCommand: (command: CommandItem) => void
  className?: string
}

const commandCategories: CommandCategory[] = [
  {
    id: 'quick-actions',
    name: 'Quick Actions',
    icon: Zap,
    commands: [
      {
        id: 'create-invoice',
        name: 'Create Invoice',
        description: 'Generate a new invoice for a customer',
        icon: FileText,
        shortcut: ['⌘', 'I'],
        category: 'quick-actions',
        keywords: ['invoice', 'bill', 'create', 'new']
      },
      {
        id: 'add-customer',
        name: 'Add Customer',
        description: 'Add a new customer to the system',
        icon: Users,
        shortcut: ['⌘', 'U'],
        category: 'quick-actions',
        keywords: ['customer', 'add', 'new', 'client']
      },
      {
        id: 'add-product',
        name: 'Add Product',
        description: 'Add a new product to inventory',
        icon: Package,
        shortcut: ['⌘', 'P'],
        category: 'quick-actions',
        keywords: ['product', 'add', 'inventory', 'item']
      }
    ]
  },
  {
    id: 'search',
    name: 'Search',
    icon: Search,
    commands: [
      {
        id: 'search-invoices',
        name: 'Search Invoices',
        description: 'Find invoices by number, customer, or amount',
        icon: FileText,
        category: 'search',
        keywords: ['search', 'invoice', 'find', 'lookup']
      },
      {
        id: 'search-customers',
        name: 'Search Customers',
        description: 'Find customers by name, email, or company',
        icon: Users,
        category: 'search',
        keywords: ['search', 'customer', 'find', 'client']
      },
      {
        id: 'search-products',
        name: 'Search Products',
        description: 'Find products by name, SKU, or category',
        icon: Package,
        category: 'search',
        keywords: ['search', 'product', 'find', 'inventory']
      }
    ]
  },
  {
    id: 'reports',
    name: 'Reports & Analytics',
    icon: BarChart3,
    commands: [
      {
        id: 'revenue-report',
        name: 'Revenue Report',
        description: 'Generate revenue analytics and trends',
        icon: DollarSign,
        category: 'reports',
        keywords: ['revenue', 'sales', 'report', 'analytics']
      },
      {
        id: 'inventory-report',
        name: 'Inventory Report',
        description: 'View stock levels and inventory status',
        icon: Package,
        category: 'reports',
        keywords: ['inventory', 'stock', 'report', 'levels']
      },
      {
        id: 'customer-report',
        name: 'Customer Report',
        description: 'Analyze customer metrics and behavior',
        icon: Users,
        category: 'reports',
        keywords: ['customer', 'report', 'analytics', 'metrics']
      }
    ]
  },
  {
    id: 'calculations',
    name: 'Calculations',
    icon: Calculator,
    commands: [
      {
        id: 'calculate-tax',
        name: 'Calculate Tax',
        description: 'Calculate taxes for a given amount',
        icon: Calculator,
        category: 'calculations',
        keywords: ['tax', 'calculate', 'computation']
      },
      {
        id: 'currency-convert',
        name: 'Convert Currency',
        description: 'Convert between different currencies',
        icon: DollarSign,
        category: 'calculations',
        keywords: ['currency', 'convert', 'exchange', 'rate']
      },
      {
        id: 'profit-margin',
        name: 'Profit Margin',
        description: 'Calculate profit margins and markup',
        icon: BarChart3,
        category: 'calculations',
        keywords: ['profit', 'margin', 'markup', 'calculate']
      }
    ]
  },
  {
    id: 'ai-assistance',
    name: 'AI Assistance',
    icon: Brain,
    commands: [
      {
        id: 'ai-insights',
        name: 'Business Insights',
        description: 'Get AI-powered business insights and recommendations',
        icon: Brain,
        category: 'ai-assistance',
        keywords: ['ai', 'insights', 'recommendations', 'analysis']
      },
      {
        id: 'ai-forecast',
        name: 'Sales Forecast',
        description: 'Generate AI-powered sales predictions',
        icon: BarChart3,
        category: 'ai-assistance',
        keywords: ['forecast', 'prediction', 'ai', 'sales']
      },
      {
        id: 'ai-optimize',
        name: 'Optimization Suggestions',
        description: 'Get AI recommendations for process optimization',
        icon: Zap,
        category: 'ai-assistance',
        keywords: ['optimize', 'suggestions', 'ai', 'improve']
      }
    ]
  }
]

const getAllCommands = (): CommandItem[] => {
  return commandCategories.flatMap(category => category.commands)
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onCommand,
  className
}) => {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const { sendMessage } = useChatStore()

  // Filter commands based on query
  const filteredCommands = useMemo(() => {
    if (!query.trim()) {
      return getAllCommands()
    }

    const searchTerm = query.toLowerCase().trim()
    return getAllCommands().filter(command => {
      const searchableText = [
        command.name,
        command.description,
        ...command.keywords
      ].join(' ').toLowerCase()

      return searchableText.includes(searchTerm)
    })
  }, [query])

  // Group filtered commands by category
  const groupedCommands = useMemo(() => {
    const groups: Record<string, CommandItem[]> = {}

    filteredCommands.forEach(command => {
      if (!groups[command.category]) {
        groups[command.category] = []
      }
      groups[command.category].push(command)
    })

    return groups
  }, [filteredCommands])

  // Keyboard navigation
  useKeyboardNavigation({
    isEnabled: isOpen,
    itemCount: filteredCommands.length,
    selectedIndex,
    onSelectionChange: setSelectedIndex,
    onSelect: () => {
      const command = filteredCommands[selectedIndex]
      if (command) {
        handleCommandSelect(command)
      }
    },
    onEscape: onClose
  })

  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
    }
  }, [isOpen])

  // Reset selection when query changes
  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  const handleCommandSelect = (command: CommandItem) => {
    // Convert command to chat message
    const message = `/${command.id}`
    sendMessage(message)
    onCommand(command)
    onClose()
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose()
    }
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-start justify-center pt-[20vh]"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.div
          className={cn(
            "bg-white dark:bg-gray-900 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700",
            "w-full max-w-2xl mx-4",
            "max-h-[60vh] overflow-hidden",
            className
          )}
          initial={{ opacity: 0, scale: 0.95, y: -20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: -20 }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center p-4 border-b border-gray-200 dark:border-gray-700">
            <CommandIcon className="w-5 h-5 text-gray-400 mr-3" />
            <Input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a command or search..."
              className="flex-1 border-0 bg-transparent p-0 text-lg focus:ring-0 focus:border-transparent"
            />
            <Badge variant="outline" className="ml-3 text-xs">
              ESC to close
            </Badge>
          </div>

          {/* Content */}
          <div
            ref={listRef}
            className="overflow-y-auto max-h-96 p-2"
          >
            {filteredCommands.length === 0 ? (
              <div className="py-8 text-center text-gray-500 dark:text-gray-400">
                <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No commands found</p>
                <p className="text-sm mt-1">Try a different search term</p>
              </div>
            ) : (
              <div className="space-y-1">
                {Object.entries(groupedCommands).map(([categoryId, commands], categoryIndex) => {
                  const category = commandCategories.find(c => c.id === categoryId)
                  if (!category || commands.length === 0) return null

                  return (
                    <div key={categoryId}>
                      {categoryIndex > 0 && <Separator className="my-2" />}

                      {/* Category Header */}
                      <div className="flex items-center px-3 py-2 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                        <category.icon className="w-3 h-3 mr-2" />
                        {category.name}
                      </div>

                      {/* Commands */}
                      {commands.map((command, commandIndex) => {
                        const globalIndex = filteredCommands.indexOf(command)
                        const isSelected = globalIndex === selectedIndex

                        return (
                          <motion.div
                            key={command.id}
                            className={cn(
                              "flex items-center px-3 py-2 mx-1 rounded-lg cursor-pointer transition-colors",
                              isSelected
                                ? "bg-blue-600 text-white"
                                : "hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-900 dark:text-gray-100"
                            )}
                            onClick={() => handleCommandSelect(command)}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                          >
                            <command.icon className={cn(
                              "w-4 h-4 mr-3 flex-shrink-0",
                              isSelected ? "text-white" : "text-gray-500 dark:text-gray-400"
                            )} />

                            <div className="flex-1 min-w-0">
                              <div className="font-medium text-sm">
                                {command.name}
                              </div>
                              <div className={cn(
                                "text-xs mt-0.5 truncate",
                                isSelected
                                  ? "text-blue-100"
                                  : "text-gray-500 dark:text-gray-400"
                              )}>
                                {command.description}
                              </div>
                            </div>

                            <div className="flex items-center space-x-1 ml-2">
                              {command.shortcut && (
                                <div className="flex items-center space-x-1">
                                  {command.shortcut.map((key, index) => (
                                    <Badge
                                      key={index}
                                      variant={isSelected ? "secondary" : "outline"}
                                      className="text-xs px-1.5 py-0.5 h-auto"
                                    >
                                      {key}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                              <ArrowRight className={cn(
                                "w-3 h-3",
                                isSelected ? "text-white" : "text-gray-400"
                              )} />
                            </div>
                          </motion.div>
                        )
                      })}
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 dark:text-gray-400">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-1">
                <Badge variant="outline" className="text-xs">↑↓</Badge>
                <span>Navigate</span>
              </div>
              <div className="flex items-center space-x-1">
                <Badge variant="outline" className="text-xs">⏎</Badge>
                <span>Select</span>
              </div>
            </div>
            <div>
              {filteredCommands.length} command{filteredCommands.length !== 1 ? 's' : ''}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default CommandPalette