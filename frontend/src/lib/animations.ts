import { Variants, Transition } from 'framer-motion'

// Animation configuration
export const animationConfig = {
  duration: {
    fast: 0.15,
    normal: 0.3,
    slow: 0.5,
    slower: 0.8
  },
  easing: {
    ease: [0.25, 0.1, 0.25, 1],
    easeIn: [0.4, 0, 1, 1],
    easeOut: [0, 0, 0.2, 1],
    easeInOut: [0.4, 0, 0.2, 1],
    bounce: [0.68, -0.6, 0.32, 1.6],
    spring: { type: 'spring', stiffness: 300, damping: 30 }
  }
} as const

// Page transition variants
export const pageTransitions: Record<string, Variants> = {
  fadeIn: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    exit: { opacity: 0 }
  },
  slideUp: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -20 }
  },
  slideRight: {
    initial: { opacity: 0, x: -20 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 20 }
  },
  scaleIn: {
    initial: { opacity: 0, scale: 0.95 },
    animate: { opacity: 1, scale: 1 },
    exit: { opacity: 0, scale: 0.95 }
  },
  sophisticated: {
    initial: {
      opacity: 0,
      y: 30,
      scale: 0.98,
      filter: 'blur(4px)'
    },
    animate: {
      opacity: 1,
      y: 0,
      scale: 1,
      filter: 'blur(0px)',
      transition: {
        duration: animationConfig.duration.slow,
        ease: animationConfig.easing.easeOut,
        staggerChildren: 0.1
      }
    },
    exit: {
      opacity: 0,
      y: -20,
      scale: 0.98,
      filter: 'blur(2px)',
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  }
}

// Component micro-interactions
export const microInteractions: Record<string, Variants> = {
  button: {
    idle: { scale: 1 },
    hover: {
      scale: 1.02,
      transition: { duration: animationConfig.duration.fast }
    },
    tap: {
      scale: 0.98,
      transition: { duration: animationConfig.duration.fast }
    }
  },
  card: {
    idle: {
      scale: 1,
      y: 0,
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
    },
    hover: {
      scale: 1.01,
      y: -2,
      boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    }
  },
  icon: {
    idle: { rotate: 0, scale: 1 },
    hover: {
      rotate: 5,
      scale: 1.1,
      transition: { duration: animationConfig.duration.fast }
    },
    tap: {
      rotate: -5,
      scale: 0.9,
      transition: { duration: animationConfig.duration.fast }
    }
  },
  floating: {
    animate: {
      y: [-4, 4, -4],
      transition: {
        duration: 3,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  },
  pulse: {
    animate: {
      scale: [1, 1.05, 1],
      transition: {
        duration: 2,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  }
}

// Loading animations
export const loadingAnimations: Record<string, Variants> = {
  skeleton: {
    animate: {
      opacity: [0.5, 1, 0.5],
      transition: {
        duration: 1.5,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  },
  spin: {
    animate: {
      rotate: 360,
      transition: {
        duration: 1,
        repeat: Infinity,
        ease: 'linear'
      }
    }
  },
  bounce: {
    animate: {
      y: [0, -10, 0],
      transition: {
        duration: 0.6,
        repeat: Infinity,
        ease: 'easeInOut'
      }
    }
  },
  wave: {
    animate: {
      scaleY: [1, 1.5, 1],
      transition: {
        duration: 0.8,
        repeat: Infinity,
        ease: 'easeInOut',
        staggerChildren: 0.1
      }
    }
  }
}

// List animations
export const listAnimations: Record<string, Variants> = {
  container: {
    animate: {
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.1
      }
    }
  },
  item: {
    initial: { opacity: 0, x: -20 },
    animate: {
      opacity: 1,
      x: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    },
    exit: {
      opacity: 0,
      x: 20,
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  }
}

// Modal animations
export const modalAnimations: Record<string, Variants> = {
  backdrop: {
    initial: { opacity: 0 },
    animate: { opacity: 1 },
    exit: { opacity: 0 }
  },
  modal: {
    initial: {
      opacity: 0,
      scale: 0.95,
      y: 10
    },
    animate: {
      opacity: 1,
      scale: 1,
      y: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    },
    exit: {
      opacity: 0,
      scale: 0.95,
      y: 10,
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  },
  drawer: {
    initial: { x: '100%' },
    animate: {
      x: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    },
    exit: {
      x: '100%',
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  }
}

// Toast animations
export const toastAnimations: Record<string, Variants> = {
  toast: {
    initial: {
      opacity: 0,
      y: 50,
      scale: 0.95
    },
    animate: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.bounce
      }
    },
    exit: {
      opacity: 0,
      y: -20,
      scale: 0.95,
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  }
}

// Form animations
export const formAnimations: Record<string, Variants> = {
  field: {
    initial: { opacity: 0, y: 10 },
    animate: {
      opacity: 1,
      y: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    }
  },
  error: {
    initial: { opacity: 0, height: 0 },
    animate: {
      opacity: 1,
      height: 'auto',
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    },
    exit: {
      opacity: 0,
      height: 0,
      transition: {
        duration: animationConfig.duration.fast,
        ease: animationConfig.easing.easeIn
      }
    }
  }
}

// Gesture configurations
export const gestureConfig = {
  drag: {
    dragConstraints: { left: 0, right: 0, top: -100, bottom: 100 },
    dragElastic: 0.3,
    dragTransition: { bounceStiffness: 600, bounceDamping: 20 }
  },
  swipe: {
    threshold: 50,
    velocity: 500
  }
}

// Utility functions
export const createStaggeredAnimation = (
  children: number,
  stagger: number = 0.1
): Variants => ({
  animate: {
    transition: {
      staggerChildren: stagger,
      delayChildren: 0.1
    }
  }
})

export const createBounceIn = (delay: number = 0): Variants => ({
  initial: { opacity: 0, scale: 0.3 },
  animate: {
    opacity: 1,
    scale: 1,
    transition: {
      delay,
      duration: animationConfig.duration.slow,
      ease: animationConfig.easing.bounce
    }
  }
})

export const createSlideIn = (
  direction: 'left' | 'right' | 'up' | 'down' = 'up',
  distance: number = 20
): Variants => {
  const getInitialPosition = () => {
    switch (direction) {
      case 'left': return { x: -distance, y: 0 }
      case 'right': return { x: distance, y: 0 }
      case 'up': return { x: 0, y: distance }
      case 'down': return { x: 0, y: -distance }
    }
  }

  return {
    initial: { opacity: 0, ...getInitialPosition() },
    animate: {
      opacity: 1,
      x: 0,
      y: 0,
      transition: {
        duration: animationConfig.duration.normal,
        ease: animationConfig.easing.easeOut
      }
    }
  }
}