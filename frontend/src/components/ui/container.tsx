import * as React from 'react'
import { cn } from '@/lib/utils'

export interface ContainerProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full'
  padding?: 'none' | 'sm' | 'md' | 'lg' | 'xl'
  center?: boolean
  as?: React.ElementType
}

export const Container = React.forwardRef<HTMLDivElement, ContainerProps>(
  (
    {
      className,
      size = 'lg',
      padding = 'md',
      center = true,
      as: Component = 'div',
      children,
      ...props
    },
    ref
  ) => {
    const sizeClasses = {
      sm: 'max-w-3xl',
      md: 'max-w-5xl',
      lg: 'max-w-7xl',
      xl: 'max-w-[90rem]',
      full: 'max-w-full'
    }

    const paddingClasses = {
      none: '',
      sm: 'px-4 py-4 sm:px-6 lg:px-8',
      md: 'px-6 py-6 sm:px-8 lg:px-10',
      lg: 'px-8 py-8 sm:px-10 lg:px-12',
      xl: 'px-10 py-10 sm:px-12 lg:px-16'
    }

    return (
      <Component
        ref={ref}
        className={cn(
          'w-full',
          sizeClasses[size],
          paddingClasses[padding],
          center && 'mx-auto',
          className
        )}
        {...props}
      >
        {children}
      </Component>
    )
  }
)

Container.displayName = 'Container'

export interface FlexContainerProps extends ContainerProps {
  direction?: 'row' | 'col'
  wrap?: boolean
  gap?: 'none' | 'sm' | 'md' | 'lg' | 'xl'
  align?: 'start' | 'center' | 'end' | 'stretch' | 'baseline'
  justify?: 'start' | 'center' | 'end' | 'between' | 'around' | 'evenly'
}

export const FlexContainer = React.forwardRef<HTMLDivElement, FlexContainerProps>(
  (
    {
      className,
      direction = 'row',
      wrap = false,
      gap = 'md',
      align = 'stretch',
      justify = 'start',
      ...props
    },
    ref
  ) => {
    const gapClasses = {
      none: '',
      sm: 'gap-2',
      md: 'gap-4',
      lg: 'gap-6',
      xl: 'gap-8'
    }

    const alignClasses = {
      start: 'items-start',
      center: 'items-center',
      end: 'items-end',
      stretch: 'items-stretch',
      baseline: 'items-baseline'
    }

    const justifyClasses = {
      start: 'justify-start',
      center: 'justify-center',
      end: 'justify-end',
      between: 'justify-between',
      around: 'justify-around',
      evenly: 'justify-evenly'
    }

    return (
      <Container
        ref={ref}
        className={cn(
          'flex',
          direction === 'col' && 'flex-col',
          wrap && 'flex-wrap',
          gapClasses[gap],
          alignClasses[align],
          justifyClasses[justify],
          className
        )}
        {...props}
      />
    )
  }
)

FlexContainer.displayName = 'FlexContainer'

export interface GridContainerProps extends ContainerProps {
  cols?: 1 | 2 | 3 | 4 | 5 | 6 | 12 | 'auto'
  gap?: 'none' | 'sm' | 'md' | 'lg' | 'xl'
  responsive?: boolean
}

export const GridContainer = React.forwardRef<HTMLDivElement, GridContainerProps>(
  (
    {
      className,
      cols = 'auto',
      gap = 'md',
      responsive = true,
      ...props
    },
    ref
  ) => {
    const gapClasses = {
      none: '',
      sm: 'gap-2',
      md: 'gap-4',
      lg: 'gap-6',
      xl: 'gap-8'
    }

    const getColsClasses = () => {
      if (cols === 'auto') {
        return 'grid-cols-[repeat(auto-fit,minmax(250px,1fr))]'
      }

      if (!responsive) {
        return `grid-cols-${cols}`
      }

      // Responsive grid columns
      switch (cols) {
        case 1:
          return 'grid-cols-1'
        case 2:
          return 'grid-cols-1 sm:grid-cols-2'
        case 3:
          return 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3'
        case 4:
          return 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4'
        case 5:
          return 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5'
        case 6:
          return 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6'
        case 12:
          return 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 2xl:grid-cols-12'
        default:
          return 'grid-cols-1'
      }
    }

    return (
      <Container
        ref={ref}
        className={cn(
          'grid',
          getColsClasses(),
          gapClasses[gap],
          className
        )}
        {...props}
      />
    )
  }
)

GridContainer.displayName = 'GridContainer'

export interface SectionContainerProps extends ContainerProps {
  title?: string
  description?: string
  headerActions?: React.ReactNode
  variant?: 'default' | 'bordered' | 'elevated'
}

export const SectionContainer = React.forwardRef<HTMLDivElement, SectionContainerProps>(
  (
    {
      title,
      description,
      headerActions,
      variant = 'default',
      className,
      children,
      ...props
    },
    ref
  ) => {
    const variantClasses = {
      default: '',
      bordered: 'border rounded-lg',
      elevated: 'bg-card rounded-lg shadow-sm'
    }

    const content = (
      <>
        {(title || description || headerActions) && (
          <div className={cn(
            "mb-6",
            variant !== 'default' && "pb-6 border-b"
          )}>
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                {title && (
                  <h2 className="text-2xl font-bold tracking-tight">{title}</h2>
                )}
                {description && (
                  <p className="text-muted-foreground">{description}</p>
                )}
              </div>
              {headerActions && (
                <div className="flex items-center gap-2 shrink-0">
                  {headerActions}
                </div>
              )}
            </div>
          </div>
        )}
        {children}
      </>
    )

    if (variant === 'default') {
      return (
        <Container
          ref={ref}
          className={className}
          {...props}
        >
          {content}
        </Container>
      )
    }

    return (
      <Container
        ref={ref}
        className={cn(
          variantClasses[variant],
          variant !== 'default' && "p-6",
          className
        )}
        {...props}
      >
        {content}
      </Container>
    )
  }
)

SectionContainer.displayName = 'SectionContainer'

export interface MaxWidthWrapperProps extends React.HTMLAttributes<HTMLDivElement> {
  maxWidth?: string | number
  center?: boolean
}

export const MaxWidthWrapper = React.forwardRef<HTMLDivElement, MaxWidthWrapperProps>(
  (
    {
      className,
      maxWidth = '1440px',
      center = true,
      style,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <div
        ref={ref}
        className={cn(
          'w-full',
          center && 'mx-auto',
          className
        )}
        style={{
          maxWidth: typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth,
          ...style
        }}
        {...props}
      >
        {children}
      </div>
    )
  }
)

MaxWidthWrapper.displayName = 'MaxWidthWrapper'