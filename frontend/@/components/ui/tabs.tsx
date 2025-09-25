import * as React from "react"
import * as TabsPrimitive from "@radix-ui/react-tabs"
import { cn } from "@/lib/utils"
import { Badge } from "./badge"
import { type LucideIcon } from "lucide-react"

const Tabs = TabsPrimitive.Root

const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List
    ref={ref}
    className={cn(
      "inline-flex h-10 items-center justify-center rounded-md bg-muted p-1 text-muted-foreground",
      className
    )}
    {...props}
  />
))
TabsList.displayName = TabsPrimitive.List.displayName

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      "inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1.5 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm",
      className
    )}
    {...props}
  />
))
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn(
      "mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
      className
    )}
    {...props}
  />
))
TabsContent.displayName = TabsPrimitive.Content.displayName

export { Tabs, TabsList, TabsTrigger, TabsContent }

// Enhanced Tabs with additional features
export interface TabItem {
  value: string
  label: string
  icon?: LucideIcon
  badge?: string | number
  disabled?: boolean
  content?: React.ReactNode
}

export interface EnhancedTabsProps {
  tabs: TabItem[]
  defaultValue?: string
  value?: string
  onValueChange?: (value: string) => void
  orientation?: "horizontal" | "vertical"
  className?: string
  listClassName?: string
  contentClassName?: string
  variant?: "default" | "pills" | "underline"
}

export function EnhancedTabs({
  tabs,
  defaultValue,
  value,
  onValueChange,
  orientation = "horizontal",
  className,
  listClassName,
  contentClassName,
  variant = "default"
}: EnhancedTabsProps) {
  const listVariants = {
    default: "bg-muted p-1 rounded-md",
    pills: "bg-transparent p-0 gap-2",
    underline: "bg-transparent p-0 border-b rounded-none h-auto"
  }

  const triggerVariants = {
    default: "",
    pills: "data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-full px-4",
    underline: "rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent pb-3"
  }

  return (
    <Tabs
      defaultValue={defaultValue || tabs[0]?.value}
      value={value}
      onValueChange={onValueChange}
      orientation={orientation}
      className={cn("w-full", className)}
    >
      <TabsList className={cn(
        listVariants[variant],
        orientation === "vertical" && "flex-col h-auto items-stretch",
        listClassName
      )}>
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <TabsTrigger
              key={tab.value}
              value={tab.value}
              disabled={tab.disabled}
              className={cn(
                triggerVariants[variant],
                orientation === "vertical" && "justify-start",
                "gap-2"
              )}
            >
              {Icon && <Icon className="h-4 w-4" />}
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <Badge variant="secondary" className="ml-auto">
                  {tab.badge}
                </Badge>
              )}
            </TabsTrigger>
          )
        })}
      </TabsList>
      {tabs.map((tab) => (
        <TabsContent
          key={tab.value}
          value={tab.value}
          className={cn(
            orientation === "vertical" && "ml-4",
            contentClassName
          )}
        >
          {tab.content}
        </TabsContent>
      ))}
    </Tabs>
  )
}

export interface ScrollableTabsProps {
  tabs: TabItem[]
  defaultValue?: string
  value?: string
  onValueChange?: (value: string) => void
  className?: string
}

export function ScrollableTabs({
  tabs,
  defaultValue,
  value,
  onValueChange,
  className
}: ScrollableTabsProps) {
  const scrollRef = React.useRef<HTMLDivElement>(null)
  const [canScrollLeft, setCanScrollLeft] = React.useState(false)
  const [canScrollRight, setCanScrollRight] = React.useState(false)

  const checkScroll = React.useCallback(() => {
    if (scrollRef.current) {
      const { scrollLeft, scrollWidth, clientWidth } = scrollRef.current
      setCanScrollLeft(scrollLeft > 0)
      setCanScrollRight(scrollLeft + clientWidth < scrollWidth)
    }
  }, [])

  React.useEffect(() => {
    checkScroll()
    window.addEventListener('resize', checkScroll)
    return () => window.removeEventListener('resize', checkScroll)
  }, [checkScroll])

  const scroll = (direction: 'left' | 'right') => {
    if (scrollRef.current) {
      const scrollAmount = 200
      scrollRef.current.scrollBy({
        left: direction === 'left' ? -scrollAmount : scrollAmount,
        behavior: 'smooth'
      })
      setTimeout(checkScroll, 300)
    }
  }

  return (
    <div className={cn("relative", className)}>
      {canScrollLeft && (
        <button
          onClick={() => scroll('left')}
          className="absolute left-0 top-1/2 -translate-y-1/2 z-10 h-8 w-8 rounded-full bg-background shadow-md flex items-center justify-center"
          aria-label="Scroll left"
        >
          <svg width="16" height="16" viewBox="0 0 16 16">
            <path
              fill="currentColor"
              d="M10.354 3.646a.5.5 0 0 1 0 .708L6.707 8l3.647 3.646a.5.5 0 0 1-.708.708l-4-4a.5.5 0 0 1 0-.708l4-4a.5.5 0 0 1 .708 0z"
            />
          </svg>
        </button>
      )}
      {canScrollRight && (
        <button
          onClick={() => scroll('right')}
          className="absolute right-0 top-1/2 -translate-y-1/2 z-10 h-8 w-8 rounded-full bg-background shadow-md flex items-center justify-center"
          aria-label="Scroll right"
        >
          <svg width="16" height="16" viewBox="0 0 16 16">
            <path
              fill="currentColor"
              d="M5.646 12.354a.5.5 0 0 1 0-.708L9.293 8 5.646 4.354a.5.5 0 1 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708 0z"
            />
          </svg>
        </button>
      )}
      <div
        ref={scrollRef}
        className="overflow-x-auto scrollbar-hide"
        onScroll={checkScroll}
      >
        <Tabs
          defaultValue={defaultValue || tabs[0]?.value}
          value={value}
          onValueChange={onValueChange}
        >
          <TabsList className="inline-flex w-max">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <TabsTrigger
                  key={tab.value}
                  value={tab.value}
                  disabled={tab.disabled}
                  className="gap-2"
                >
                  {Icon && <Icon className="h-4 w-4" />}
                  <span>{tab.label}</span>
                  {tab.badge !== undefined && (
                    <Badge variant="secondary" className="ml-2">
                      {tab.badge}
                    </Badge>
                  )}
                </TabsTrigger>
              )
            })}
          </TabsList>
          {tabs.map((tab) => (
            <TabsContent key={tab.value} value={tab.value}>
              {tab.content}
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </div>
  )
}
