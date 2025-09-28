import * as React from "react"
import { motion, useMotionValue, useTransform, AnimatePresence } from "framer-motion"
import { cn } from "@/lib/utils"
import { microInteractions, animationConfig } from "@/lib/animations"

// Hover lift effect
export interface HoverLiftProps {
  children: React.ReactNode
  className?: string
  intensity?: 'subtle' | 'medium' | 'strong'
  disabled?: boolean
}

export const HoverLift: React.FC<HoverLiftProps> = React.memo(({
  children,
  className,
  intensity = 'medium',
  disabled = false
}) => {
  const liftValues = {
    subtle: { y: -2, scale: 1.01, shadow: '0 4px 8px rgba(0,0,0,0.1)' },
    medium: { y: -4, scale: 1.02, shadow: '0 8px 16px rgba(0,0,0,0.15)' },
    strong: { y: -8, scale: 1.05, shadow: '0 16px 32px rgba(0,0,0,0.2)' }
  }

  const lift = liftValues[intensity]

  return (
    <motion.div
      className={cn("cursor-pointer", className)}
      whileHover={disabled ? undefined : {
        y: lift.y,
        scale: lift.scale,
        boxShadow: lift.shadow,
        transition: { duration: animationConfig.duration.fast }
      }}
      whileTap={disabled ? undefined : {
        scale: lift.scale * 0.98,
        transition: { duration: animationConfig.duration.fast }
      }}
    >
      {children}
    </motion.div>
  )
})

// Floating element
export interface FloatingElementProps {
  children: React.ReactNode
  className?: string
  amplitude?: number
  duration?: number
  delay?: number
}

export const FloatingElement: React.FC<FloatingElementProps> = ({
  children,
  className,
  amplitude = 10,
  duration = 3,
  delay = 0
}) => {
  return (
    <motion.div
      className={className}
      animate={{
        y: [-amplitude, amplitude, -amplitude],
        transition: {
          duration,
          repeat: Infinity,
          ease: "easeInOut",
          delay
        }
      }}
    >
      {children}
    </motion.div>
  )
}

// Magnetic button
export interface MagneticButtonProps {
  children: React.ReactNode
  className?: string
  strength?: number
  disabled?: boolean
}

export const MagneticButton: React.FC<MagneticButtonProps> = ({
  children,
  className,
  strength = 20,
  disabled = false
}) => {
  const ref = React.useRef<HTMLDivElement>(null)
  const x = useMotionValue(0)
  const y = useMotionValue(0)

  const handleMouseMove = (e: React.MouseEvent) => {
    if (disabled || !ref.current) return

    const rect = ref.current.getBoundingClientRect()
    const centerX = rect.left + rect.width / 2
    const centerY = rect.top + rect.height / 2

    const distanceX = e.clientX - centerX
    const distanceY = e.clientY - centerY

    x.set(distanceX * (strength / 100))
    y.set(distanceY * (strength / 100))
  }

  const handleMouseLeave = () => {
    if (disabled) return
    x.set(0)
    y.set(0)
  }

  return (
    <motion.div
      ref={ref}
      className={cn("cursor-pointer", className)}
      style={{ x, y }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
    >
      {children}
    </motion.div>
  )
}

// Ripple effect
export interface RippleEffectProps {
  children: React.ReactNode
  className?: string
  color?: string
  duration?: number
  disabled?: boolean
}

export const RippleEffect: React.FC<RippleEffectProps> = ({
  children,
  className,
  color = 'rgba(255,255,255,0.3)',
  duration = 600,
  disabled = false
}) => {
  const [ripples, setRipples] = React.useState<Array<{
    id: number
    x: number
    y: number
    size: number
  }>>([])

  const addRipple = (e: React.MouseEvent) => {
    if (disabled) return

    const rect = e.currentTarget.getBoundingClientRect()
    const size = Math.max(rect.width, rect.height)
    const x = e.clientX - rect.left - size / 2
    const y = e.clientY - rect.top - size / 2

    const newRipple = {
      id: Date.now(),
      x,
      y,
      size
    }

    setRipples(prev => [...prev, newRipple])

    setTimeout(() => {
      setRipples(prev => prev.filter(ripple => ripple.id !== newRipple.id))
    }, duration)
  }

  return (
    <div
      className={cn("relative overflow-hidden", className)}
      onMouseDown={addRipple}
    >
      {children}
      <AnimatePresence>
        {ripples.map(ripple => (
          <motion.span
            key={ripple.id}
            className="absolute rounded-full pointer-events-none"
            style={{
              left: ripple.x,
              top: ripple.y,
              width: ripple.size,
              height: ripple.size,
              backgroundColor: color
            }}
            initial={{ scale: 0, opacity: 1 }}
            animate={{ scale: 2, opacity: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: duration / 1000, ease: "easeOut" }}
          />
        ))}
      </AnimatePresence>
    </div>
  )
}

// Shake animation
export interface ShakeAnimationProps {
  children: React.ReactNode
  className?: string
  trigger?: boolean
  intensity?: 'subtle' | 'medium' | 'strong'
}

export const ShakeAnimation: React.FC<ShakeAnimationProps> = ({
  children,
  className,
  trigger = false,
  intensity = 'medium'
}) => {
  const shakeValues = {
    subtle: [-2, 2, -2, 2, 0],
    medium: [-5, 5, -5, 5, 0],
    strong: [-10, 10, -10, 10, 0]
  }

  return (
    <motion.div
      className={className}
      animate={trigger ? {
        x: shakeValues[intensity],
        transition: {
          duration: 0.5,
          times: [0, 0.25, 0.5, 0.75, 1]
        }
      } : {}}
    >
      {children}
    </motion.div>
  )
}

// Pulse animation
export interface PulseAnimationProps {
  children: React.ReactNode
  className?: string
  isActive?: boolean
  intensity?: 'subtle' | 'medium' | 'strong'
  duration?: number
}

export const PulseAnimation: React.FC<PulseAnimationProps> = ({
  children,
  className,
  isActive = true,
  intensity = 'medium',
  duration = 2
}) => {
  const pulseValues = {
    subtle: [1, 1.02, 1],
    medium: [1, 1.05, 1],
    strong: [1, 1.1, 1]
  }

  return (
    <motion.div
      className={className}
      animate={isActive ? {
        scale: pulseValues[intensity],
        transition: {
          duration,
          repeat: Infinity,
          ease: "easeInOut"
        }
      } : {}}
    >
      {children}
    </motion.div>
  )
}

// Morphing icon
export interface MorphingIconProps {
  icon1: React.ReactNode
  icon2: React.ReactNode
  isToggled?: boolean
  className?: string
  duration?: number
}

export const MorphingIcon: React.FC<MorphingIconProps> = ({
  icon1,
  icon2,
  isToggled = false,
  className,
  duration = 0.3
}) => {
  return (
    <div className={cn("relative", className)}>
      <AnimatePresence mode="wait">
        <motion.div
          key={isToggled ? 'icon2' : 'icon1'}
          initial={{ scale: 0, rotate: -90 }}
          animate={{ scale: 1, rotate: 0 }}
          exit={{ scale: 0, rotate: 90 }}
          transition={{ duration }}
        >
          {isToggled ? icon2 : icon1}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

// Number counter
export interface NumberCounterProps {
  value: number
  className?: string
  duration?: number
  prefix?: string
  suffix?: string
  decimals?: number
}

export const NumberCounter: React.FC<NumberCounterProps> = ({
  value,
  className,
  duration = 1,
  prefix = '',
  suffix = '',
  decimals = 0
}) => {
  const motionValue = useMotionValue(0)
  const rounded = useTransform(motionValue, (latest) => {
    return `${prefix}${latest.toFixed(decimals)}${suffix}`
  })

  React.useEffect(() => {
    motionValue.set(value)
  }, [value, motionValue])

  return (
    <motion.span
      className={className}
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      <motion.span
        animate={{ color: ['#000', '#3b82f6', '#000'] }}
        transition={{ duration: 0.5 }}
      >
        {rounded}
      </motion.span>
    </motion.span>
  )
}

// Loading dots
export interface LoadingDotsProps {
  className?: string
  color?: string
  size?: 'sm' | 'md' | 'lg'
}

export const LoadingDots: React.FC<LoadingDotsProps> = ({
  className,
  color = 'currentColor',
  size = 'md'
}) => {
  const sizeClasses = {
    sm: 'w-1 h-1',
    md: 'w-2 h-2',
    lg: 'w-3 h-3'
  }

  const dotClass = cn('rounded-full', sizeClasses[size])

  return (
    <div className={cn("flex space-x-1", className)}>
      {[0, 1, 2].map((index) => (
        <motion.div
          key={index}
          className={dotClass}
          style={{ backgroundColor: color }}
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.5, 1, 0.5]
          }}
          transition={{
            duration: 0.8,
            repeat: Infinity,
            delay: index * 0.2
          }}
        />
      ))}
    </div>
  )
}

// Parallax text
export interface ParallaxTextProps {
  children: React.ReactNode
  className?: string
  speed?: number
  direction?: 'up' | 'down' | 'left' | 'right'
}

export const ParallaxText: React.FC<ParallaxTextProps> = ({
  children,
  className,
  speed = 0.5,
  direction = 'up'
}) => {
  const [scrollY, setScrollY] = React.useState(0)

  React.useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const getTransform = () => {
    const offset = scrollY * speed
    switch (direction) {
      case 'up': return { y: -offset }
      case 'down': return { y: offset }
      case 'left': return { x: -offset }
      case 'right': return { x: offset }
    }
  }

  return (
    <motion.div
      className={className}
      style={getTransform()}
    >
      {children}
    </motion.div>
  )
}

// Spotlight effect
export interface SpotlightEffectProps {
  children: React.ReactNode
  className?: string
  intensity?: number
  color?: string
}

export const SpotlightEffect: React.FC<SpotlightEffectProps> = ({
  children,
  className,
  intensity = 0.1,
  color = 'rgba(59, 130, 246, 0.1)'
}) => {
  const [mousePosition, setMousePosition] = React.useState({ x: 0, y: 0 })
  const [isHovered, setIsHovered] = React.useState(false)

  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    })
  }

  return (
    <div
      className={cn("relative overflow-hidden", className)}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {children}
      <AnimatePresence>
        {isHovered && (
          <motion.div
            className="absolute pointer-events-none rounded-full"
            style={{
              left: mousePosition.x - 100,
              top: mousePosition.y - 100,
              width: 200,
              height: 200,
              background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
              mixBlendMode: 'overlay'
            }}
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: intensity, scale: 1 }}
            exit={{ opacity: 0, scale: 0 }}
            transition={{ duration: 0.3 }}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

// Expanding circle
export interface ExpandingCircleProps {
  isActive?: boolean
  className?: string
  color?: string
  size?: number
}

export const ExpandingCircle: React.FC<ExpandingCircleProps> = ({
  isActive = false,
  className,
  color = 'rgba(59, 130, 246, 0.2)',
  size = 40
}) => {
  return (
    <div className={cn("relative", className)}>
      <AnimatePresence>
        {isActive && (
          <motion.div
            className="absolute inset-0 rounded-full pointer-events-none"
            style={{
              backgroundColor: color,
              width: size,
              height: size,
              left: -size / 2,
              top: -size / 2
            }}
            initial={{ scale: 0, opacity: 1 }}
            animate={{ scale: 3, opacity: 0 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

