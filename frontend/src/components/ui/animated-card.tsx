import * as React from "react"
import { motion } from "framer-motion"
import { Card, CardProps } from "./card"
import { microInteractions, animationConfig } from "@/lib/animations"
import { cn } from "@/lib/utils"

export interface AnimatedCardProps extends CardProps {
  animation?: 'default' | 'float' | 'tilt' | 'lift' | 'glow'
  interactive?: boolean
  entrance?: 'fadeIn' | 'slideUp' | 'scaleIn' | 'none'
  delay?: number
}

const AnimatedCard = React.forwardRef<HTMLDivElement, AnimatedCardProps>(
  ({
    className,
    children,
    animation = 'default',
    interactive = true,
    entrance = 'fadeIn',
    delay = 0,
    onClick,
    ...props
  }, ref) => {
    const [isHovered, setIsHovered] = React.useState(false)

    const getAnimationVariants = () => {
      const baseVariants = {
        idle: {
          scale: 1,
          y: 0,
          rotateX: 0,
          rotateY: 0,
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
        }
      }

      switch (animation) {
        case 'float':
          return {
            ...baseVariants,
            hover: {
              y: -8,
              scale: 1.02,
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
              transition: {
                duration: animationConfig.duration.normal,
                ease: animationConfig.easing.easeOut
              }
            },
            tap: { scale: 0.98, y: -4 }
          }

        case 'tilt':
          return {
            ...baseVariants,
            hover: {
              rotateX: 5,
              rotateY: 5,
              scale: 1.02,
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.15)',
              transition: {
                duration: animationConfig.duration.normal,
                ease: animationConfig.easing.easeOut
              }
            },
            tap: { scale: 0.98 }
          }

        case 'lift':
          return {
            ...baseVariants,
            hover: {
              y: -12,
              scale: 1.03,
              boxShadow: '0 35px 60px -12px rgba(0, 0, 0, 0.3)',
              transition: {
                duration: animationConfig.duration.slow,
                ease: animationConfig.easing.easeOut
              }
            },
            tap: { scale: 0.97, y: -6 }
          }

        case 'glow':
          return {
            ...baseVariants,
            hover: {
              scale: 1.02,
              boxShadow: [
                '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                '0 0 20px rgba(59, 130, 246, 0.5)',
                '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
              ],
              transition: {
                duration: animationConfig.duration.normal,
                ease: animationConfig.easing.easeOut
              }
            },
            tap: { scale: 0.98 }
          }

        default:
          return microInteractions.card
      }
    }

    const getEntranceVariants = () => {
      switch (entrance) {
        case 'fadeIn':
          return {
            initial: { opacity: 0 },
            animate: {
              opacity: 1,
              transition: {
                delay,
                duration: animationConfig.duration.normal
              }
            }
          }
        case 'slideUp':
          return {
            initial: { opacity: 0, y: 30 },
            animate: {
              opacity: 1,
              y: 0,
              transition: {
                delay,
                duration: animationConfig.duration.normal,
                ease: animationConfig.easing.easeOut
              }
            }
          }
        case 'scaleIn':
          return {
            initial: { opacity: 0, scale: 0.9 },
            animate: {
              opacity: 1,
              scale: 1,
              transition: {
                delay,
                duration: animationConfig.duration.normal,
                ease: animationConfig.easing.easeOut
              }
            }
          }
        default:
          return {}
      }
    }

    const animationVariants = getAnimationVariants()
    const entranceVariants = getEntranceVariants()

    return (
      <motion.div
        ref={ref}
        className={cn("cursor-pointer", interactive && "group", className)}
        variants={animationVariants}
        initial={entrance !== 'none' ? entranceVariants.initial : "idle"}
        animate={entrance !== 'none' ? entranceVariants.animate : "idle"}
        whileHover={interactive ? "hover" : undefined}
        whileTap={interactive && onClick ? "tap" : undefined}
        onHoverStart={() => setIsHovered(true)}
        onHoverEnd={() => setIsHovered(false)}
        onClick={onClick}
        style={{ perspective: 1000 }}
      >
        <Card {...props}>
          {children}

          {/* Glow effect overlay */}
          {animation === 'glow' && isHovered && (
            <motion.div
              className="absolute inset-0 rounded-[var(--radius-lg)] bg-gradient-to-r from-blue-500/10 to-purple-500/10 pointer-events-none"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
            />
          )}
        </Card>
      </motion.div>
    )
  }
)

AnimatedCard.displayName = "AnimatedCard"

export { AnimatedCard }