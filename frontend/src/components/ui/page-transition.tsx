import * as React from "react"
import { motion, AnimatePresence } from "framer-motion"
import { pageTransitions, animationConfig } from "@/lib/animations"
import { cn } from "@/lib/utils"

export interface PageTransitionProps {
  children: React.ReactNode
  className?: string
  type?: 'fadeIn' | 'slideUp' | 'slideRight' | 'scaleIn' | 'sophisticated'
  duration?: 'fast' | 'normal' | 'slow' | 'slower'
  delay?: number
  exitBeforeEnter?: boolean
  preserveHeight?: boolean
}

const PageTransition = React.forwardRef<HTMLDivElement, PageTransitionProps>(
  ({
    children,
    className,
    type = 'sophisticated',
    duration = 'normal',
    delay = 0,
    exitBeforeEnter = true,
    preserveHeight = false,
    ...props
  }, ref) => {
    const variants = pageTransitions[type]
    const transitionConfig = {
      duration: animationConfig.duration[duration],
      ease: animationConfig.easing.easeOut,
      delay
    }

    return (
      <AnimatePresence mode={exitBeforeEnter ? 'wait' : 'sync'}>
        <motion.div
          ref={ref}
          className={cn(
            "w-full",
            preserveHeight && "min-h-full",
            className
          )}
          initial="initial"
          animate="animate"
          exit="exit"
          variants={{
            ...variants,
            animate: {
              ...variants.animate,
              transition: {
                ...variants.animate?.transition,
                ...transitionConfig
              }
            }
          }}
          {...props}
        >
          {children}
        </motion.div>
      </AnimatePresence>
    )
  }
)

PageTransition.displayName = "PageTransition"

// Route transition wrapper for React Router
export interface RouteTransitionProps extends PageTransitionProps {
  location?: string
}

const RouteTransition: React.FC<RouteTransitionProps> = ({
  location,
  children,
  ...props
}) => {
  return (
    <AnimatePresence mode="wait">
      <PageTransition key={location} {...props}>
        {children}
      </PageTransition>
    </AnimatePresence>
  )
}

// Staggered children animation
export interface StaggeredAnimationProps {
  children: React.ReactNode
  className?: string
  stagger?: number
  delay?: number
}

const StaggeredAnimation: React.FC<StaggeredAnimationProps> = ({
  children,
  className,
  stagger = 0.1,
  delay = 0
}) => {
  const containerVariants = {
    initial: {},
    animate: {
      transition: {
        staggerChildren: stagger,
        delayChildren: delay
      }
    }
  }

  const itemVariants = {
    initial: { opacity: 0, y: 20 },
    animate: {
      opacity: 1,
      y: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    }
  }

  return (
    <motion.div
      className={className}
      variants={containerVariants}
      initial="initial"
      animate="animate"
    >
      {React.Children.map(children, (child, index) => (
        <motion.div
          key={index}
          variants={itemVariants}
        >
          {child}
        </motion.div>
      ))}
    </motion.div>
  )
}

// Parallax section
export interface ParallaxSectionProps {
  children: React.ReactNode
  className?: string
  speed?: number
  offset?: number
}

const ParallaxSection: React.FC<ParallaxSectionProps> = ({
  children,
  className,
  speed = 0.5,
  offset = 0
}) => {
  const [scrollY, setScrollY] = React.useState(0)

  React.useEffect(() => {
    const handleScroll = () => {
      setScrollY(window.scrollY)
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <motion.div
      className={className}
      style={{
        y: (scrollY - offset) * speed
      }}
    >
      {children}
    </motion.div>
  )
}

// Reveal on scroll
export interface RevealOnScrollProps {
  children: React.ReactNode
  className?: string
  threshold?: number
  triggerOnce?: boolean
  animation?: 'fadeIn' | 'slideUp' | 'slideLeft' | 'slideRight' | 'scaleIn'
}

const RevealOnScroll: React.FC<RevealOnScrollProps> = ({
  children,
  className,
  threshold = 0.1,
  triggerOnce = true,
  animation = 'fadeIn'
}) => {
  const [ref, inView] = useInView({
    threshold,
    triggerOnce
  })

  const getVariants = () => {
    switch (animation) {
      case 'slideUp':
        return {
          hidden: { opacity: 0, y: 50 },
          visible: { opacity: 1, y: 0 }
        }
      case 'slideLeft':
        return {
          hidden: { opacity: 0, x: 50 },
          visible: { opacity: 1, x: 0 }
        }
      case 'slideRight':
        return {
          hidden: { opacity: 0, x: -50 },
          visible: { opacity: 1, x: 0 }
        }
      case 'scaleIn':
        return {
          hidden: { opacity: 0, scale: 0.8 },
          visible: { opacity: 1, scale: 1 }
        }
      default:
        return {
          hidden: { opacity: 0 },
          visible: { opacity: 1 }
        }
    }
  }

  return (
    <motion.div
      ref={ref}
      className={className}
      initial="hidden"
      animate={inView ? "visible" : "hidden"}
      variants={getVariants()}
      transition={{
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }}
    >
      {children}
    </motion.div>
  )
}

// Hook for intersection observer
const useInView = (options: IntersectionObserverInit) => {
  const [inView, setInView] = React.useState(false)
  const ref = React.useRef<HTMLDivElement | null>(null)

  React.useEffect(() => {
    const element = ref.current
    if (!element) return

    const observer = new IntersectionObserver(([entry]) => {
      setInView(entry.isIntersecting)
    }, options)

    observer.observe(element)

    return () => {
      observer.disconnect()
    }
  }, [options])

  return [ref, inView] as const
}

export {
  PageTransition,
  RouteTransition,
  StaggeredAnimation,
  ParallaxSection,
  RevealOnScroll
}