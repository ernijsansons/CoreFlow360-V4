import * as React from 'react'
import { cn } from '@/lib/utils'
import { Input } from './input'
import { Button } from './button'
import { Search, X, Loader2 } from 'lucide-react'

export interface SearchInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'size'> {
  onSearch?: (value: string) => void
  onClear?: () => void
  debounce?: number
  loading?: boolean
  showButton?: boolean
  buttonText?: string
  size?: 'sm' | 'md' | 'lg'
  variant?: 'default' | 'outline' | 'filled'
}

export const SearchInput = React.forwardRef<HTMLInputElement, SearchInputProps>(
  (
    {
      className,
      onSearch,
      onClear,
      debounce = 300,
      loading = false,
      showButton = false,
      buttonText = 'Search',
      size = 'md',
      variant = 'default',
      placeholder = 'Search...',
      value: controlledValue,
      defaultValue,
      disabled,
      ...props
    },
    ref
  ) => {
    const [value, setValue] = React.useState(controlledValue || defaultValue || '')
    const [isSearching, setIsSearching] = React.useState(false)
    const debounceTimerRef = React.useRef<NodeJS.Timeout>()

    React.useEffect(() => {
      if (controlledValue !== undefined) {
        setValue(controlledValue)
      }
    }, [controlledValue])

    const handleSearch = React.useCallback((searchValue: string) => {
      if (onSearch) {
        setIsSearching(true)
        onSearch(searchValue)
        // Simulate search completion
        setTimeout(() => setIsSearching(false), 500)
      }
    }, [onSearch])

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const newValue = e.target.value
      setValue(newValue)

      if (debounce && !showButton) {
        if (debounceTimerRef.current) {
          clearTimeout(debounceTimerRef.current)
        }
        debounceTimerRef.current = setTimeout(() => {
          handleSearch(newValue)
        }, debounce)
      } else if (!showButton) {
        handleSearch(newValue)
      }
    }

    const handleClear = () => {
      setValue('')
      onClear?.()
      if (!showButton) {
        handleSearch('')
      }
    }

    const handleSubmit = (e?: React.FormEvent) => {
      e?.preventDefault()
      handleSearch(String(value))
    }

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter' && showButton) {
        handleSubmit()
      }
      props.onKeyDown?.(e)
    }

    React.useEffect(() => {
      return () => {
        if (debounceTimerRef.current) {
          clearTimeout(debounceTimerRef.current)
        }
      }
    }, [])

    const sizeClasses = {
      sm: {
        input: 'h-8 text-sm pl-8 pr-8',
        icon: 'h-3 w-3',
        button: 'h-8 text-sm'
      },
      md: {
        input: 'h-10 pl-10 pr-10',
        icon: 'h-4 w-4',
        button: 'h-10'
      },
      lg: {
        input: 'h-12 text-lg pl-12 pr-12',
        icon: 'h-5 w-5',
        button: 'h-12'
      }
    }

    const variantClasses = {
      default: '',
      outline: 'border-2',
      filled: 'bg-muted border-transparent'
    }

    const sizes = sizeClasses[size]
    const isLoading = loading || isSearching

    const searchInput = (
      <div className="relative flex-1">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none">
          {isLoading ? (
            <Loader2 className={cn(sizes.icon, "animate-spin text-muted-foreground")} />
          ) : (
            <Search className={cn(sizes.icon, "text-muted-foreground")} />
          )}
        </div>
        <Input
          ref={ref}
          type="text"
          value={value}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          disabled={disabled || isLoading}
          className={cn(
            sizes.input,
            variantClasses[variant],
            className
          )}
          {...props}
        />
        {value && !disabled && (
          <button
            type="button"
            onClick={handleClear}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
            aria-label="Clear search"
          >
            <X className={sizes.icon} />
          </button>
        )}
      </div>
    )

    if (showButton) {
      return (
        <form onSubmit={handleSubmit} className="flex gap-2 w-full">
          {searchInput}
          <Button
            type="submit"
            disabled={disabled || isLoading}
            size={size === 'sm' ? 'sm' : size === 'lg' ? 'lg' : 'default'}
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              buttonText
            )}
          </Button>
        </form>
      )
    }

    return searchInput
  }
)

SearchInput.displayName = 'SearchInput'

export interface SearchSuggestionsProps {
  suggestions: string[]
  onSelect: (suggestion: string) => void
  highlightedIndex?: number
  className?: string
}

export function SearchSuggestions({
  suggestions,
  onSelect,
  highlightedIndex = -1,
  className
}: SearchSuggestionsProps) {
  if (suggestions.length === 0) return null

  return (
    <div className={cn(
      "absolute top-full left-0 right-0 z-50 mt-1 max-h-60 overflow-auto rounded-md border bg-popover p-1 text-popover-foreground shadow-md",
      className
    )}>
      {suggestions.map((suggestion, index) => (
        <button
          key={index}
          type="button"
          onClick={() => onSelect(suggestion)}
          className={cn(
            "w-full text-left px-3 py-2 text-sm rounded-sm hover:bg-accent hover:text-accent-foreground",
            highlightedIndex === index && "bg-accent text-accent-foreground"
          )}
        >
          {suggestion}
        </button>
      ))}
    </div>
  )
}

export interface SearchWithSuggestionsProps extends SearchInputProps {
  suggestions?: string[]
  onSuggestionSelect?: (suggestion: string) => void
  showSuggestionsOnFocus?: boolean
  minCharsForSuggestions?: number
}

export function SearchWithSuggestions({
  suggestions = [],
  onSuggestionSelect,
  showSuggestionsOnFocus = false,
  minCharsForSuggestions = 1,
  onSearch,
  ...props
}: SearchWithSuggestionsProps) {
  const [showSuggestions, setShowSuggestions] = React.useState(false)
  const [highlightedIndex, setHighlightedIndex] = React.useState(-1)
  const [value, setValue] = React.useState('')
  const containerRef = React.useRef<HTMLDivElement>(null)

  const filteredSuggestions = React.useMemo(() => {
    if (value.length < minCharsForSuggestions) return []
    return suggestions.filter(s => 
      s.toLowerCase().includes(value.toLowerCase())
    )
  }, [suggestions, value, minCharsForSuggestions])

  const handleSearch = (searchValue: string) => {
    setValue(searchValue)
    setShowSuggestions(
      searchValue.length >= minCharsForSuggestions && filteredSuggestions.length > 0
    )
    onSearch?.(searchValue)
  }

  const handleSuggestionSelect = (suggestion: string) => {
    setValue(suggestion)
    setShowSuggestions(false)
    setHighlightedIndex(-1)
    onSuggestionSelect?.(suggestion)
    onSearch?.(suggestion)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!showSuggestions || filteredSuggestions.length === 0) return

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setHighlightedIndex(prev => 
          prev < filteredSuggestions.length - 1 ? prev + 1 : 0
        )
        break
      case 'ArrowUp':
        e.preventDefault()
        setHighlightedIndex(prev => 
          prev > 0 ? prev - 1 : filteredSuggestions.length - 1
        )
        break
      case 'Enter':
        if (highlightedIndex >= 0) {
          e.preventDefault()
          handleSuggestionSelect(filteredSuggestions[highlightedIndex])
        }
        break
      case 'Escape':
        setShowSuggestions(false)
        setHighlightedIndex(-1)
        break
    }
  }

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setShowSuggestions(false)
        setHighlightedIndex(-1)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <div ref={containerRef} className="relative w-full">
      <SearchInput
        {...props}
        value={value}
        onSearch={handleSearch}
        onKeyDown={handleKeyDown}
        onFocus={() => {
          if (showSuggestionsOnFocus && value.length >= minCharsForSuggestions) {
            setShowSuggestions(filteredSuggestions.length > 0)
          }
        }}
      />
      {showSuggestions && (
        <SearchSuggestions
          suggestions={filteredSuggestions}
          onSelect={handleSuggestionSelect}
          highlightedIndex={highlightedIndex}
        />
      )}
    </div>
  )
}