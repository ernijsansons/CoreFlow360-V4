import * as React from "react"
import { motion } from "framer-motion"
import { Button, ButtonProps } from "./button"
import { microInteractions, animationConfig } from "@/lib/animations"
import { cn } from "@/lib/utils"

export interface AnimatedButtonProps extends Omit<ButtonProps, 'asChild'> {
  animation?: 'default' | 'bounce' | 'scale' | 'rotate' | 'pulse'
  ripple?: boolean
  haptic?: boolean
}

const AnimatedButton = React.forwardRef<HTMLButtonElement, AnimatedButtonProps>(
  ({
    className,
    children,
    animation = 'default',
    ripple = true,
    haptic = false,
    onClick,
    disabled,
    loading,
    ...props
  }, ref) => {
    const [ripples, setRipples] = React.useState<Array<{ id: number; x: number; y: number }>>([])
    const rippleId = React.useRef(0)

    const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
      // Haptic feedback for mobile devices
      if (haptic && 'vibrate' in navigator) {
        navigator.vibrate(10)
      }

      // Ripple effect
      if (ripple && !disabled && !loading) {
        const button = e.currentTarget
        const rect = button.getBoundingClientRect()
        const x = e.clientX - rect.left
        const y = e.clientY - rect.top

        const newRipple = { id: rippleId.current++, x, y }
        setRipples(prev => [...prev, newRipple])

        // Remove ripple after animation
        setTimeout(() => {
          setRipples(prev => prev.filter(r => r.id !== newRipple.id))
        }, 600)
      }

      onClick?.(e)
    }

    const getAnimationVariants = () => {
      switch (animation) {
        case 'bounce':
          return {
            hover: { scale: 1.05, transition: { type: 'spring', bounce: 0.4 } },
            tap: { scale: 0.95 }
          }
        case 'scale':
          return microInteractions.button
        case 'rotate':
          return {
            hover: { scale: 1.02, rotate: 2 },
            tap: { scale: 0.98, rotate: -2 }
          }
        case 'pulse':
          return {
            hover: {
              scale: [1, 1.02, 1],
              transition: { duration: 0.3, repeat: Infinity }
            },
            tap: { scale: 0.98 }
          }
        default:
          return microInteractions.button
      }
    }

    return (
      <motion.div
        className="relative inline-flex"
        variants={getAnimationVariants()}
        initial="idle"
        whileHover={!disabled && !loading ? "hover" : undefined}
        whileTap={!disabled && !loading ? "tap" : undefined}
        role="button"
        tabIndex={disabled ? -1 : 0}
      >
        <Button
          ref={ref}
          className={cn(
            "relative overflow-hidden",
            className
          )}
          onClick={handleClick}
          disabled={disabled}
          loading={loading}
          {...props}
        >
          {children}

          {/* Ripple Effects */}
          {ripples.map(ripple => (
            <motion.span
              key={ripple.id}
              className="absolute rounded-full bg-white/30 pointer-events-none"
              style={{
                left: ripple.x - 10,
                top: ripple.y - 10,
                width: 20,
                height: 20,
              }}
              initial={{ scale: 0, opacity: 1 }}
              animate={{
                scale: 12,
                opacity: 0,
                transition: { duration: 0.6, ease: "easeOut" }
              }}
            />
          ))}
        </Button>
      </motion.div>
    )
  }
)

AnimatedButton.displayName = "AnimatedButton"

export { AnimatedButton }