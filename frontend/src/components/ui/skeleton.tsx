import * as React from "react"
import { motion } from "framer-motion"
import { loadingAnimations } from "@/lib/animations"
import { cn } from "@/lib/utils"

export interface SkeletonProps {
  className?: string
  variant?: 'text' | 'circular' | 'rectangular' | 'rounded'
  width?: string | number
  height?: string | number
  animation?: 'pulse' | 'wave' | 'shimmer' | 'none'
  lines?: number
  aspectRatio?: number
}

const Skeleton = React.forwardRef<HTMLDivElement, SkeletonProps>(
  ({
    className,
    variant = 'rectangular',
    width,
    height,
    animation = 'shimmer',
    lines = 1,
    aspectRatio,
    ...props
  }, ref) => {
    const getVariantClasses = () => {
      switch (variant) {
        case 'text':
          return 'h-4 rounded-[var(--radius-sm)]'
        case 'circular':
          return 'rounded-full'
        case 'rounded':
          return 'rounded-[var(--radius-lg)]'
        default:
          return 'rounded-[var(--radius-md)]'
      }
    }

    const getAnimationVariants = () => {
      switch (animation) {
        case 'pulse':
          return {
            animate: {
              opacity: [0.6, 1, 0.6],
              transition: {
                duration: 1.5,
                repeat: Infinity,
                ease: 'easeInOut'
              }
            }
          }
        case 'wave':
          return {
            animate: {
              backgroundPosition: ['200% 0', '-200% 0'],
              transition: {
                duration: 2,
                repeat: Infinity,
                ease: 'linear'
              }
            }
          }
        case 'shimmer':
          return {
            animate: {
              backgroundPosition: ['200% 0', '-200% 0'],
              transition: {
                duration: 1.5,
                repeat: Infinity,
                ease: 'easeInOut'
              }
            }
          }
        default:
          return {}
      }
    }

    const getBackgroundStyle = () => {
      if (animation === 'shimmer' || animation === 'wave') {
        return {
          background: `linear-gradient(
            90deg,
            var(--color-bg-subtle) 25%,
            var(--color-bg-muted) 50%,
            var(--color-bg-subtle) 75%
          )`,
          backgroundSize: '200% 100%'
        }
      }
      return {
        backgroundColor: 'var(--color-bg-subtle)'
      }
    }

    const renderSkeleton = () => (
      <motion.div
        ref={ref}
        className={cn(
          "inline-block",
          getVariantClasses(),
          className
        )}
        style={{
          width,
          height: aspectRatio ? `${(Number(width) || 200) / aspectRatio}px` : height,
          ...getBackgroundStyle()
        }}
        variants={getAnimationVariants()}
        animate={animation !== 'none' ? 'animate' : undefined}
        {...props}
      />
    )

    if (variant === 'text' && lines > 1) {
      return (
        <div className="space-y-2">
          {Array.from({ length: lines }).map((_, index) => (
            <div key={index}>
              {renderSkeleton()}
            </div>
          ))}
        </div>
      )
    }

    return renderSkeleton()
  }
)

Skeleton.displayName = "Skeleton"

// Pre-built skeleton components
const SkeletonCard: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn("p-6 space-y-4", className)}>
    <Skeleton variant="rectangular" height={200} />
    <div className="space-y-2">
      <Skeleton variant="text" height={20} />
      <Skeleton variant="text" height={16} width="80%" />
    </div>
    <div className="flex gap-2">
      <Skeleton variant="rectangular" height={32} width={80} />
      <Skeleton variant="rectangular" height={32} width={60} />
    </div>
  </div>
)

const SkeletonTable: React.FC<{ rows?: number; cols?: number; className?: string }> = ({
  rows = 5,
  cols = 4,
  className
}) => (
  <div className={cn("space-y-3", className)}>
    {/* Header */}
    <div className="flex gap-4">
      {Array.from({ length: cols }).map((_, index) => (
        <Skeleton key={index} variant="text" height={16} className="flex-1" />
      ))}
    </div>
    {/* Rows */}
    {Array.from({ length: rows }).map((_, rowIndex) => (
      <div key={rowIndex} className="flex gap-4">
        {Array.from({ length: cols }).map((_, colIndex) => (
          <Skeleton key={colIndex} variant="text" height={12} className="flex-1" />
        ))}
      </div>
    ))}
  </div>
)

const SkeletonAvatar: React.FC<{ size?: number; className?: string }> = ({
  size = 40,
  className
}) => (
  <Skeleton
    variant="circular"
    width={size}
    height={size}
    className={className}
  />
)

const SkeletonButton: React.FC<{ className?: string }> = ({ className }) => (
  <Skeleton
    variant="rounded"
    height={40}
    width={100}
    className={className}
  />
)

const SkeletonText: React.FC<{
  lines?: number
  className?: string
  width?: string
}> = ({ lines = 3, className, width }) => (
  <div className={cn("space-y-2", className)}>
    {Array.from({ length: lines }).map((_, index) => (
      <Skeleton
        key={index}
        variant="text"
        width={index === lines - 1 ? width || "60%" : "100%"}
      />
    ))}
  </div>
)

const SkeletonChart: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn("space-y-4", className)}>
    <div className="flex justify-between items-end h-32">
      {Array.from({ length: 7 }).map((_, index) => (
        <Skeleton
          key={index}
          variant="rectangular"
          width={20}
          height={Math.random() * 80 + 20}
        />
      ))}
    </div>
    <div className="flex justify-between">
      {Array.from({ length: 7 }).map((_, index) => (
        <Skeleton key={index} variant="text" width={20} height={12} />
      ))}
    </div>
  </div>
)

const SkeletonList: React.FC<{
  items?: number
  showAvatar?: boolean
  className?: string
}> = ({ items = 5, showAvatar = true, className }) => (
  <div className={cn("space-y-4", className)}>
    {Array.from({ length: items }).map((_, index) => (
      <div key={index} className="flex items-center gap-3">
        {showAvatar && <SkeletonAvatar size={32} />}
        <div className="flex-1 space-y-2">
          <Skeleton variant="text" height={14} width="70%" />
          <Skeleton variant="text" height={12} width="40%" />
        </div>
      </div>
    ))}
  </div>
)

// Loading page skeleton
const SkeletonPage: React.FC<{ className?: string }> = ({ className }) => (
  <div className={cn("space-y-6 p-6", className)}>
    {/* Header */}
    <div className="flex justify-between items-center">
      <div className="space-y-2">
        <Skeleton variant="text" height={24} width={200} />
        <Skeleton variant="text" height={16} width={300} />
      </div>
      <SkeletonButton />
    </div>

    {/* Stats Cards */}
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} className="p-4 border rounded-lg space-y-3">
          <Skeleton variant="text" height={16} width="60%" />
          <Skeleton variant="text" height={32} width="40%" />
          <Skeleton variant="text" height={12} width="80%" />
        </div>
      ))}
    </div>

    {/* Chart */}
    <div className="p-4 border rounded-lg">
      <Skeleton variant="text" height={20} width={150} className="mb-4" />
      <SkeletonChart />
    </div>

    {/* Table */}
    <div className="p-4 border rounded-lg">
      <Skeleton variant="text" height={20} width={120} className="mb-4" />
      <SkeletonTable />
    </div>
  </div>
)

export {
  Skeleton,
  SkeletonCard,
  SkeletonTable,
  SkeletonAvatar,
  SkeletonButton,
  SkeletonText,
  SkeletonChart,
  SkeletonList,
  SkeletonPage
}