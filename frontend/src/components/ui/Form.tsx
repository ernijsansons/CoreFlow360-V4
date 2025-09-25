/**
 * Form Component
 * Advanced form with validation, error handling, and accessibility
 */

import React, { createContext, useContext, useId } from 'react'
import { cn } from '@/lib/utils'
import { Label } from './label'
import { Slot } from '@radix-ui/react-slot'

// Form Context
interface FormFieldContextValue {
  id: string
  name: string
  error?: string
  required?: boolean
}

const FormFieldContext = createContext<FormFieldContextValue | null>(null)

export const useFormField = () => {
  const context = useContext(FormFieldContext)
  if (!context) {
    throw new Error('useFormField must be used within a FormField')
  }
  return context
}

// Form Field Component
export interface FormFieldProps {
  children: React.ReactNode
  name: string
  error?: string
  required?: boolean
  className?: string
}

export const FormField: React.FC<FormFieldProps> = ({
  children,
  name,
  error,
  required,
  className,
}) => {
  const id = useId()

  return (
    <FormFieldContext.Provider value={{ id, name, error, required }}>
      <div className={cn('space-y-2', className)}>
        {children}
      </div>
    </FormFieldContext.Provider>
  )
}

// Form Label Component
export interface FormLabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  required?: boolean
}

export const FormLabel: React.FC<FormLabelProps> = ({
  className,
  required,
  children,
  ...props
}) => {
  const { id, required: fieldRequired } = useFormField()
  const isRequired = required ?? fieldRequired

  return (
    <Label
      htmlFor={id}
      className={cn(
        'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
        className
      )}
      {...props}
    >
      {children}
      {isRequired && <span className="text-destructive ml-1">*</span>}
    </Label>
  )
}

// Form Control Component
export interface FormControlProps {
  children: React.ReactNode
}

export const FormControl: React.FC<FormControlProps> = ({ children }) => {
  const { id, name, error } = useFormField()

  return (
    <Slot
      id={id}
      name={name}
      aria-describedby={error ? `${id}-error` : undefined}
      aria-invalid={!!error}
    >
      {children}
    </Slot>
  )
}

// Form Description Component
export interface FormDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {}

export const FormDescription: React.FC<FormDescriptionProps> = ({
  className,
  ...props
}) => {
  const { id } = useFormField()

  return (
    <p
      id={`${id}-description`}
      className={cn('text-sm text-muted-foreground', className)}
      {...props}
    />
  )
}

// Form Message Component
export interface FormMessageProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children?: React.ReactNode
}

export const FormMessage: React.FC<FormMessageProps> = ({
  className,
  children,
  ...props
}) => {
  const { id, error } = useFormField()
  const body = error || children

  if (!body) return null

  return (
    <p
      id={`${id}-error`}
      className={cn('text-sm font-medium text-destructive', className)}
      {...props}
    >
      {body}
    </p>
  )
}

// Main Form Component
export interface FormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  children: React.ReactNode
  onSubmit?: (event: React.FormEvent<HTMLFormElement>) => void
  loading?: boolean
  errors?: Record<string, string>
}

export const Form: React.FC<FormProps> = ({
  children,
  onSubmit,
  loading = false,
  errors = {},
  className,
  ...props
}) => {
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!loading && onSubmit) {
      onSubmit(event)
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className={cn('space-y-6', className)}
      {...props}
    >
      {React.Children.map(children, (child) => {
        if (React.isValidElement(child) && child.type === FormField) {
          const fieldName = child.props.name
          const fieldError = errors[fieldName]

          return React.cloneElement(child, {
            ...child.props,
            error: fieldError,
          })
        }
        return child
      })}
    </form>
  )
}

// Form Section Component
export interface FormSectionProps {
  title?: string
  description?: string
  children: React.ReactNode
  className?: string
}

export const FormSection: React.FC<FormSectionProps> = ({
  title,
  description,
  children,
  className,
}) => {
  return (
    <div className={cn('space-y-4', className)}>
      {(title || description) && (
        <div className="space-y-1">
          {title && (
            <h3 className="text-lg font-medium leading-none">{title}</h3>
          )}
          {description && (
            <p className="text-sm text-muted-foreground">{description}</p>
          )}
        </div>
      )}
      <div className="space-y-4">
        {children}
      </div>
    </div>
  )
}

// Form Grid Component
export interface FormGridProps {
  children: React.ReactNode
  columns?: 1 | 2 | 3 | 4
  className?: string
}

export const FormGrid: React.FC<FormGridProps> = ({
  children,
  columns = 2,
  className,
}) => {
  const gridClasses = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  }

  return (
    <div className={cn('grid gap-4', gridClasses[columns], className)}>
      {children}
    </div>
  )
}

// Validation Helpers
export const validateRequired = (value: any, fieldName: string) => {
  if (!value || (typeof value === 'string' && value.trim() === '')) {
    return `${fieldName} is required`
  }
  return null
}

export const validateEmail = (email: string) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email)) {
    return 'Please enter a valid email address'
  }
  return null
}

export const validateMinLength = (value: string, minLength: number, fieldName: string) => {
  if (value.length < minLength) {
    return `${fieldName} must be at least ${minLength} characters`
  }
  return null
}

export const validateMaxLength = (value: string, maxLength: number, fieldName: string) => {
  if (value.length > maxLength) {
    return `${fieldName} must be no more than ${maxLength} characters`
  }
  return null
}

export const validatePattern = (value: string, pattern: RegExp, message: string) => {
  if (!pattern.test(value)) {
    return message
  }
  return null
}

export const validateRange = (value: number, min: number, max: number, fieldName: string) => {
  if (value < min || value > max) {
    return `${fieldName} must be between ${min} and ${max}`
  }
  return null
}

// Form Validation Hook
export interface ValidationRule {
  required?: boolean
  minLength?: number
  maxLength?: number
  pattern?: RegExp
  patternMessage?: string
  min?: number
  max?: number
  email?: boolean
  custom?: (value: any) => string | null
}

export interface ValidationRules {
  [fieldName: string]: ValidationRule
}

export const useFormValidation = (rules: ValidationRules) => {
  const validateField = (name: string, value: any): string | null => {
    const rule = rules[name]
    if (!rule) return null

    // Required validation
    if (rule.required) {
      const error = validateRequired(value, name)
      if (error) return error
    }

    // Skip other validations if field is empty and not required
    if (!value && !rule.required) return null

    // Email validation
    if (rule.email) {
      const error = validateEmail(value)
      if (error) return error
    }

    // Length validations
    if (rule.minLength && typeof value === 'string') {
      const error = validateMinLength(value, rule.minLength, name)
      if (error) return error
    }

    if (rule.maxLength && typeof value === 'string') {
      const error = validateMaxLength(value, rule.maxLength, name)
      if (error) return error
    }

    // Pattern validation
    if (rule.pattern && typeof value === 'string') {
      const error = validatePattern(value, rule.pattern, rule.patternMessage || `Invalid ${name}`)
      if (error) return error
    }

    // Range validation
    if ((rule.min !== undefined || rule.max !== undefined) && typeof value === 'number') {
      const min = rule.min ?? Number.MIN_SAFE_INTEGER
      const max = rule.max ?? Number.MAX_SAFE_INTEGER
      const error = validateRange(value, min, max, name)
      if (error) return error
    }

    // Custom validation
    if (rule.custom) {
      const error = rule.custom(value)
      if (error) return error
    }

    return null
  }

  const validateForm = (formData: Record<string, any>): Record<string, string> => {
    const errors: Record<string, string> = {}

    Object.keys(rules).forEach(fieldName => {
      const error = validateField(fieldName, formData[fieldName])
      if (error) {
        errors[fieldName] = error
      }
    })

    return errors
  }

  return { validateField, validateForm }
}

export type {
  FormProps,
  FormFieldProps,
  FormLabelProps,
  FormControlProps,
  FormDescriptionProps,
  FormMessageProps,
  FormSectionProps,
  FormGridProps,
  ValidationRule,
  ValidationRules,
}