import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { Calendar } from '@/@/components/ui/calendar'
import {
  Popover,
  PopoverContent,
  PopoverTrigger
} from '@/@/components/ui/popover'
import { CalendarIcon, X } from 'lucide-react'
import { format, isValid, parse } from 'date-fns'

export interface DatePickerProps {
  value?: Date
  onChange?: (date: Date | undefined) => void
  placeholder?: string
  className?: string
  disabled?: boolean
  clearable?: boolean
  minDate?: Date
  maxDate?: Date
  dateFormat?: string
  showTime?: boolean
  size?: 'sm' | 'md' | 'lg'
}

export function DatePicker({
  value,
  onChange,
  placeholder = 'Pick a date',
  className,
  disabled = false,
  clearable = true,
  minDate,
  maxDate,
  dateFormat = 'PPP',
  showTime = false,
  size = 'md'
}: DatePickerProps) {
  const [open, setOpen] = React.useState(false)
  const [inputValue, setInputValue] = React.useState('')

  React.useEffect(() => {
    if (value && isValid(value)) {
      setInputValue(format(value, dateFormat))
    } else {
      setInputValue('')
    }
  }, [value, dateFormat])

  const handleSelect = (date: Date | undefined) => {
    onChange?.(date)
    setOpen(false)
  }

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation()
    onChange?.(undefined)
    setInputValue('')
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setInputValue(val)
    
    // Try to parse the input as a date
    const parsed = parse(val, dateFormat, new Date())
    if (isValid(parsed)) {
      onChange?.(parsed)
    }
  }

  const sizeClasses = {
    sm: 'h-8 text-sm',
    md: 'h-10',
    lg: 'h-12 text-lg'
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn(
            "w-full justify-start text-left font-normal",
            !value && "text-muted-foreground",
            sizeClasses[size],
            className
          )}
          disabled={disabled}
        >
          <CalendarIcon className="mr-2 h-4 w-4" />
          <span className="flex-1">
            {value && isValid(value) ? format(value, dateFormat) : placeholder}
          </span>
          {clearable && value && !disabled && (
            <X
              className="h-4 w-4 opacity-50 hover:opacity-100"
              onClick={handleClear}
            />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start">
        <Calendar
          mode="single"
          selected={value}
          onSelect={handleSelect}
          disabled={(date) => {
            if (minDate && date < minDate) return true
            if (maxDate && date > maxDate) return true
            return false
          }}
          initialFocus
        />
        {showTime && (
          <div className="border-t p-3">
            <TimeInput
              value={value}
              onChange={handleSelect}
            />
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}

interface TimeInputProps {
  value?: Date
  onChange?: (date: Date) => void
}

function TimeInput({ value, onChange }: TimeInputProps) {
  const [hours, setHours] = React.useState(
    value ? String(value.getHours()).padStart(2, '0') : '00'
  )
  const [minutes, setMinutes] = React.useState(
    value ? String(value.getMinutes()).padStart(2, '0') : '00'
  )

  const handleTimeChange = (newHours: string, newMinutes: string) => {
    const date = value || new Date()
    date.setHours(parseInt(newHours, 10))
    date.setMinutes(parseInt(newMinutes, 10))
    onChange?.(date)
  }

  return (
    <div className="flex items-center gap-2">
      <label className="text-sm font-medium">Time:</label>
      <input
        type="number"
        min="0"
        max="23"
        value={hours}
        onChange={(e) => {
          const val = e.target.value.padStart(2, '0')
          setHours(val)
          handleTimeChange(val, minutes)
        }}
        className="w-12 rounded border px-2 py-1 text-center"
      />
      <span>:</span>
      <input
        type="number"
        min="0"
        max="59"
        value={minutes}
        onChange={(e) => {
          const val = e.target.value.padStart(2, '0')
          setMinutes(val)
          handleTimeChange(hours, val)
        }}
        className="w-12 rounded border px-2 py-1 text-center"
      />
    </div>
  )
}

export interface DateRangePickerProps {
  value?: { from: Date | undefined; to: Date | undefined }
  onChange?: (range: { from: Date | undefined; to: Date | undefined }) => void
  placeholder?: string
  className?: string
  disabled?: boolean
  clearable?: boolean
  minDate?: Date
  maxDate?: Date
  dateFormat?: string
  size?: 'sm' | 'md' | 'lg'
  presets?: Array<{
    label: string
    value: { from: Date; to: Date }
  }>
}

export function DateRangePicker({
  value,
  onChange,
  placeholder = 'Pick a date range',
  className,
  disabled = false,
  clearable = true,
  minDate,
  maxDate,
  dateFormat = 'PPP',
  size = 'md',
  presets = []
}: DateRangePickerProps) {
  const [open, setOpen] = React.useState(false)

  const handleSelect = (range: { from: Date | undefined; to: Date | undefined } | undefined) => {
    onChange?.(range || { from: undefined, to: undefined })
    if (range?.from && range?.to) {
      setOpen(false)
    }
  }

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation()
    onChange?.({ from: undefined, to: undefined })
  }

  const handlePreset = (preset: { from: Date; to: Date }) => {
    onChange?.(preset)
    setOpen(false)
  }

  const sizeClasses = {
    sm: 'h-8 text-sm',
    md: 'h-10',
    lg: 'h-12 text-lg'
  }

  const displayValue = React.useMemo(() => {
    if (!value?.from) return placeholder
    if (!value.to) return format(value.from, dateFormat)
    return `${format(value.from, dateFormat)} - ${format(value.to, dateFormat)}`
  }, [value, dateFormat, placeholder])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn(
            "w-full justify-start text-left font-normal",
            !value?.from && "text-muted-foreground",
            sizeClasses[size],
            className
          )}
          disabled={disabled}
        >
          <CalendarIcon className="mr-2 h-4 w-4" />
          <span className="flex-1 truncate">{displayValue}</span>
          {clearable && value?.from && !disabled && (
            <X
              className="h-4 w-4 opacity-50 hover:opacity-100"
              onClick={handleClear}
            />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start">
        {presets.length > 0 && (
          <div className="border-b p-2 space-y-1">
            <p className="text-xs font-medium text-muted-foreground mb-2">Quick Select</p>
            {presets.map((preset, i) => (
              <Button
                key={i}
                variant="ghost"
                size="sm"
                className="w-full justify-start"
                onClick={() => handlePreset(preset.value)}
              >
                {preset.label}
              </Button>
            ))}
          </div>
        )}
        <Calendar
          mode="range"
          selected={value}
          onSelect={handleSelect}
          disabled={(date) => {
            if (minDate && date < minDate) return true
            if (maxDate && date > maxDate) return true
            return false
          }}
          numberOfMonths={2}
          initialFocus
        />
      </PopoverContent>
    </Popover>
  )
}

// Common date range presets
export const dateRangePresets = [
  {
    label: 'Today',
    value: {
      from: new Date(),
      to: new Date()
    }
  },
  {
    label: 'Last 7 days',
    value: {
      from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      to: new Date()
    }
  },
  {
    label: 'Last 30 days',
    value: {
      from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      to: new Date()
    }
  },
  {
    label: 'This month',
    value: {
      from: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
      to: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0)
    }
  },
  {
    label: 'Last month',
    value: {
      from: new Date(new Date().getFullYear(), new Date().getMonth() - 1, 1),
      to: new Date(new Date().getFullYear(), new Date().getMonth(), 0)
    }
  }
]