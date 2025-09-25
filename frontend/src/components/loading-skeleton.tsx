import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

interface LoadingSkeletonProps {
  className?: string
  count?: number
  type?: 'text' | 'card' | 'avatar' | 'button' | 'table' | 'list'
}

export function LoadingSkeleton({
  className,
  count = 1,
  type = 'text'
}: LoadingSkeletonProps) {
  const renderSkeleton = () => {
    switch (type) {
      case 'text':
        return (
          <div className="space-y-2">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
          </div>
        )

      case 'card':
        return (
          <div className="rounded-lg border p-4">
            <Skeleton className="h-32 w-full mb-4" />
            <Skeleton className="h-4 w-3/4 mb-2" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        )

      case 'avatar':
        return (
          <div className="flex items-center space-x-4">
            <Skeleton className="h-12 w-12 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-[200px]" />
              <Skeleton className="h-4 w-[150px]" />
            </div>
          </div>
        )

      case 'button':
        return <Skeleton className="h-10 w-32 rounded-md" />

      case 'table':
        return (
          <div className="w-full">
            <div className="flex items-center justify-between p-4 border-b">
              <Skeleton className="h-4 w-[100px]" />
              <Skeleton className="h-4 w-[150px]" />
              <Skeleton className="h-4 w-[100px]" />
              <Skeleton className="h-4 w-[80px]" />
            </div>
          </div>
        )

      case 'list':
        return (
          <div className="flex items-center space-x-4 p-4">
            <Skeleton className="h-10 w-10 rounded" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-3 w-3/4" />
            </div>
          </div>
        )

      default:
        return <Skeleton className="h-4 w-full" />
    }
  }

  return (
    <div className={cn("animate-pulse", className)}>
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className={count > 1 ? "mb-4" : ""}>
          {renderSkeleton()}
        </div>
      ))}
    </div>
  )
}

export function PageSkeleton() {
  return (
    <div className="container mx-auto p-6 space-y-6">
      <LoadingSkeleton type="text" />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <LoadingSkeleton type="card" count={6} />
      </div>
    </div>
  )
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="w-full rounded-lg border">
      <div className="border-b bg-muted/50 p-4">
        <Skeleton className="h-6 w-[200px]" />
      </div>
      <LoadingSkeleton type="table" count={rows} />
    </div>
  )
}

export function FormSkeleton() {
  return (
    <div className="space-y-4">
      <div>
        <Skeleton className="h-4 w-[100px] mb-2" />
        <Skeleton className="h-10 w-full" />
      </div>
      <div>
        <Skeleton className="h-4 w-[100px] mb-2" />
        <Skeleton className="h-10 w-full" />
      </div>
      <div>
        <Skeleton className="h-4 w-[100px] mb-2" />
        <Skeleton className="h-20 w-full" />
      </div>
      <Skeleton className="h-10 w-32" />
    </div>
  )
}