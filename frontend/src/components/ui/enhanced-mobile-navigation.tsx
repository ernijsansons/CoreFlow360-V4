import * as React from "react"
import { motion, useDragControls, PanInfo } from "framer-motion"
import { X, Menu, ChevronLeft, ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"
import { modalAnimations, gestureConfig } from "@/lib/animations"

export interface MobileNavigationProps {
  children: React.ReactNode
  isOpen: boolean
  onOpenChange: (open: boolean) => void
  position?: 'left' | 'right' | 'bottom'
  title?: string
  showBackdrop?: boolean
  swipeToClose?: boolean
  swipeThreshold?: number
  className?: string
}

const EnhancedMobileNavigation: React.FC<MobileNavigationProps> = ({
  children,
  isOpen,
  onOpenChange,
  position = 'left',
  title,
  showBackdrop = true,
  swipeToClose = true,
  swipeThreshold = 100,
  className
}) => {
  const dragControls = useDragControls()
  const [isDragging, setIsDragging] = React.useState(false)

  const handleDragEnd = (event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    setIsDragging(false)

    if (!swipeToClose) return

    const velocity = position === 'bottom' ? info.velocity.y :
                    position === 'right' ? info.velocity.x : -info.velocity.x
    const offset = position === 'bottom' ? info.offset.y :
                   position === 'right' ? info.offset.x : -info.offset.x

    // Close if swipe exceeds threshold or has sufficient velocity
    if (offset > swipeThreshold || velocity > 500) {
      onOpenChange(false)
    }
  }

  const getDrawerVariants = () => {
    switch (position) {
      case 'right':
        return {
          closed: { x: '100%' },
          open: { x: 0 }
        }
      case 'bottom':
        return {
          closed: { y: '100%' },
          open: { y: 0 }
        }
      default: // left
        return {
          closed: { x: '-100%' },
          open: { x: 0 }
        }
    }
  }

  const getDragConstraints = () => {
    switch (position) {
      case 'right':
        return { left: 0, right: 300 }
      case 'bottom':
        return { top: 0, bottom: 400 }
      default: // left
        return { left: -300, right: 0 }
    }
  }

  const getPositionClasses = () => {
    switch (position) {
      case 'right':
        return 'inset-y-0 right-0 w-80 max-w-[85vw]'
      case 'bottom':
        return 'inset-x-0 bottom-0 h-[70vh] max-h-[600px]'
      default: // left
        return 'inset-y-0 left-0 w-80 max-w-[85vw]'
    }
  }

  const getBorderRadius = () => {
    switch (position) {
      case 'right':
        return 'rounded-l-[var(--radius-2xl)]'
      case 'bottom':
        return 'rounded-t-[var(--radius-2xl)]'
      default: // left
        return 'rounded-r-[var(--radius-2xl)]'
    }
  }

  return (
    <>
      {/* Backdrop */}
      {showBackdrop && isOpen && (
        <motion.div
          className="fixed inset-0 z-[var(--z-index-overlay)] bg-black/60 backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => onOpenChange(false)}
          role="presentation"
          aria-hidden="true"
        />
      )}

      {/* Navigation Drawer */}
      <motion.div
        className={cn(
          "fixed z-[var(--z-index-modal)] bg-[var(--color-bg-surface)] shadow-[var(--shadow-2xl)]",
          "border-[var(--color-border-subtle)] overflow-hidden",
          getPositionClasses(),
          getBorderRadius(),
          className
        )}
        role="navigation"
        aria-label={title || "Navigation menu"}
        aria-modal="true"
        variants={getDrawerVariants()}
        initial="closed"
        animate={isOpen ? "open" : "closed"}
        transition={{
          type: "spring",
          damping: 30,
          stiffness: 300
        }}
        drag={swipeToClose ? (position === 'bottom' ? 'y' : 'x') : false}
        dragControls={dragControls}
        dragConstraints={getDragConstraints()}
        dragElastic={0.1}
        onDragStart={() => setIsDragging(true)}
        onDragEnd={handleDragEnd}
      >
        {/* Drag Handle */}
        {swipeToClose && (
          <div
            className={cn(
              "flex justify-center p-2 cursor-grab active:cursor-grabbing",
              position === 'bottom' ? 'border-b' : 'hidden'
            )}
            onPointerDown={(e) => dragControls.start(e)}
          >
            <div className="w-10 h-1 bg-[var(--color-border-default)] rounded-full" />
          </div>
        )}

        {/* Header */}
        {title && (
          <div className="flex items-center justify-between p-4 border-b border-[var(--color-border-subtle)]">
            <h2 className="text-[var(--font-size-lg)] font-semibold text-[var(--color-text-primary)]">
              {title}
            </h2>
            <motion.button
              className="p-2 rounded-[var(--radius-md)] hover:bg-[var(--color-bg-hover)] transition-colors"
              onClick={() => onOpenChange(false)}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <X className="w-5 h-5" />
            </motion.button>
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {children}
        </div>

        {/* Drag indicator for side panels */}
        {swipeToClose && position !== 'bottom' && (
          <div
            className={cn(
              "absolute top-1/2 -translate-y-1/2 w-1 h-12 bg-[var(--color-border-default)] rounded-full cursor-grab active:cursor-grabbing",
              position === 'left' ? '-right-2' : '-left-2'
            )}
            onPointerDown={(e) => dragControls.start(e)}
          />
        )}
      </motion.div>
    </>
  )
}

// Navigation Trigger Button
export interface NavigationTriggerProps {
  isOpen: boolean
  onToggle: () => void
  position?: 'left' | 'right'
  className?: string
}

const NavigationTrigger: React.FC<NavigationTriggerProps> = ({
  isOpen,
  onToggle,
  position = 'left',
  className
}) => {
  return (
    <motion.button
      className={cn(
        "p-2 rounded-[var(--radius-md)] bg-[var(--color-bg-surface)] border border-[var(--color-border-default)]",
        "hover:bg-[var(--color-bg-hover)] transition-colors shadow-sm",
        className
      )}
      onClick={onToggle}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      aria-label={isOpen ? 'Close navigation' : 'Open navigation'}
    >
      <motion.div
        animate={isOpen ? 'open' : 'closed'}
        variants={{
          closed: { rotate: 0 },
          open: { rotate: 180 }
        }}
        transition={{ duration: 0.2 }}
      >
        {isOpen ? (
          <X className="w-5 h-5" />
        ) : (
          <Menu className="w-5 h-5" />
        )}
      </motion.div>
    </motion.button>
  )
}

// Swipeable Tab Navigation
export interface SwipeableTabsProps {
  tabs: Array<{ id: string; label: string; content: React.ReactNode }>
  activeTab: string
  onTabChange: (tabId: string) => void
  className?: string
}

const SwipeableTabs: React.FC<SwipeableTabsProps> = ({
  tabs,
  activeTab,
  onTabChange,
  className
}) => {
  const [tabIndex, setTabIndex] = React.useState(
    tabs.findIndex(tab => tab.id === activeTab)
  )

  const handleDragEnd = (event: MouseEvent | TouchEvent | PointerEvent, info: PanInfo) => {
    const threshold = 50
    const velocity = info.velocity.x

    if (Math.abs(info.offset.x) > threshold || Math.abs(velocity) > 500) {
      if (info.offset.x > 0 && tabIndex > 0) {
        // Swipe right - go to previous tab
        const newIndex = tabIndex - 1
        setTabIndex(newIndex)
        onTabChange(tabs[newIndex].id)
      } else if (info.offset.x < 0 && tabIndex < tabs.length - 1) {
        // Swipe left - go to next tab
        const newIndex = tabIndex + 1
        setTabIndex(newIndex)
        onTabChange(tabs[newIndex].id)
      }
    }
  }

  React.useEffect(() => {
    const newIndex = tabs.findIndex(tab => tab.id === activeTab)
    if (newIndex !== -1) {
      setTabIndex(newIndex)
    }
  }, [activeTab, tabs])

  return (
    <div className={cn("space-y-4", className)}>
      {/* Tab Headers */}
      <div className="flex space-x-1 bg-[var(--color-bg-muted)] p-1 rounded-[var(--radius-lg)]">
        {tabs.map((tab, index) => (
          <motion.button
            key={tab.id}
            className={cn(
              "flex-1 px-3 py-2 text-sm font-medium rounded-[var(--radius-md)] transition-colors",
              tab.id === activeTab
                ? "bg-[var(--color-bg-surface)] text-[var(--color-text-primary)] shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            )}
            onClick={() => onTabChange(tab.id)}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {tab.label}
          </motion.button>
        ))}
      </div>

      {/* Tab Content */}
      <motion.div
        className="overflow-hidden"
        drag="x"
        dragConstraints={{ left: 0, right: 0 }}
        dragElastic={0.1}
        onDragEnd={handleDragEnd}
      >
        <motion.div
          className="flex"
          animate={{ x: `-${tabIndex * 100}%` }}
          transition={{ type: "spring", damping: 30, stiffness: 300 }}
        >
          {tabs.map((tab) => (
            <div key={tab.id} className="w-full flex-shrink-0">
              {tab.content}
            </div>
          ))}
        </motion.div>
      </motion.div>

      {/* Swipe Indicators */}
      <div className="flex justify-center space-x-1">
        {tabs.map((_, index) => (
          <motion.div
            key={index}
            className={cn(
              "w-2 h-2 rounded-full transition-colors",
              index === tabIndex
                ? "bg-[var(--color-interactive-primary)]"
                : "bg-[var(--color-bg-muted)]"
            )}
            whileHover={{ scale: 1.2 }}
          />
        ))}
      </div>
    </div>
  )
}

export {
  EnhancedMobileNavigation,
  NavigationTrigger,
  SwipeableTabs
}