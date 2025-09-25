import * as React from 'react'
import { cn } from '@/lib/utils'
import { Label } from './label'
import { Input } from './input'
import { AlertCircle, Check, Info } from 'lucide-react'

export interface FormFieldProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  success?: boolean
  hint?: string
  required?: boolean
  containerClassName?: string
  labelClassName?: string
  inputClassName?: string
}

export const FormField = React.forwardRef<HTMLInputElement, FormFieldProps>(
  (
    {
      label,
      error,
      success,
      hint,
      required,
      containerClassName,
      labelClassName,
      inputClassName,
      className,
      id,
      ...props
    },
    ref
  ) => {
    const fieldId = id || React.useId()
    
    return (
      <div className={cn("space-y-2", containerClassName)}>
        {label && (
          <Label
            htmlFor={fieldId}
            className={cn(
              "text-sm font-medium",
              error && "text-destructive",
              labelClassName
            )}
          >
            {label}
            {required && <span className="text-destructive ml-1">*</span>}
          </Label>
        )}
        
        <div className="relative">
          <Input
            ref={ref}
            id={fieldId}
            className={cn(
              "pr-10",
              error && "border-destructive focus:ring-destructive",
              success && "border-green-500 focus:ring-green-500",
              inputClassName,
              className
            )}
            aria-invalid={!!error}
            aria-describedby={
              error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined
            }
            {...props}
          />
          
          {(error || success) && (
            <div className="absolute right-3 top-1/2 -translate-y-1/2">
              {error ? (
                <AlertCircle className="h-4 w-4 text-destructive" />
              ) : success ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : null}
            </div>
          )}
        </div>
        
        {error && (
          <p id={`${fieldId}-error`} className="text-sm text-destructive flex items-center gap-1">
            <AlertCircle className="h-3 w-3" />
            {error}
          </p>
        )}
        
        {hint && !error && (
          <p id={`${fieldId}-hint`} className="text-sm text-muted-foreground flex items-center gap-1">
            <Info className="h-3 w-3" />
            {hint}
          </p>
        )}
      </div>
    )
  }
)

FormField.displayName = 'FormField'

export interface FormGroupProps {
  children: React.ReactNode
  className?: string
  columns?: 1 | 2 | 3 | 4
}

export function FormGroup({ children, className, columns = 1 }: FormGroupProps) {
  const gridClass = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  }[columns]

  return (
    <div className={cn(`grid ${gridClass} gap-4`, className)}>
      {children}
    </div>
  )
}