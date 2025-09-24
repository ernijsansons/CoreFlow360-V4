/**
 * PRIMITIVE COMPONENTS - The Building Blocks of the Future
 * Every component is poetry in code
 */

import React, { forwardRef, ButtonHTMLAttributes, InputHTMLAttributes, HTMLAttributes } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { tokens } from '../foundation/tokens';

// ============================================
// BUTTON - Not just clickable, but irresistible
// ============================================

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost';
  size?: 'small' | 'default';
  loading?: boolean;
  icon?: React.ReactNode;
  shortcut?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ children, variant = 'primary', size = 'default', loading, icon, shortcut, className = '', ...props }, ref) => {
    const baseStyles = `
      relative inline-flex items-center justify-center
      font-medium tracking-wide
      transition-all duration-200 ease-out
      transform-gpu will-change-transform
      select-none cursor-pointer
      focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500
      disabled:opacity-30 disabled:cursor-not-allowed
      active:scale-[0.98]
    `;

    const variants = {
      primary: 'bg-black text-white hover:bg-gray-900 dark:bg-white dark:text-black dark:hover:bg-gray-100',
      secondary: 'bg-transparent text-black border border-black/8 hover:bg-black/4 dark:text-white dark:border-white/8 dark:hover:bg-white/4',
      ghost: 'bg-transparent text-black/64 hover:text-black hover:bg-black/4 dark:text-white/64 dark:hover:text-white dark:hover:bg-white/4',
    };

    const sizes = {
      small: 'h-8 px-5 text-[13px]',
      default: 'h-10 px-8 text-[16px]',
    };

    return (
      <motion.button
        ref={ref}
        className={`${baseStyles} ${variants[variant]} ${sizes[size]} ${className}`}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
        {...props}
      >
        <AnimatePresence mode="wait">
          {loading ? (
            <motion.div
              key="loading"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
            </motion.div>
          ) : (
            <motion.div
              key="content"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center gap-2"
            >
              {icon && <span className="w-4 h-4">{icon}</span>}
              {children}
              {shortcut && (
                <span className="ml-2 px-1.5 py-0.5 text-[11px] bg-black/8 dark:bg-white/8 rounded">
                  {shortcut}
                </span>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.button>
    );
  }
);

Button.displayName = 'Button';

// ============================================
// INPUT - Text entry as a conversation
// ============================================

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  suffix?: React.ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, icon, suffix, className = '', ...props }, ref) => {
    const [focused, setFocused] = React.useState(false);

    return (
      <div className="relative">
        {label && (
          <motion.label
            className={`absolute left-4 transition-all duration-200 pointer-events-none ${
              focused || props.value
                ? 'top-1 text-[11px] text-black/36 dark:text-white/36'
                : 'top-1/2 -translate-y-1/2 text-[16px] text-black/64 dark:text-white/64'
            }`}
            animate={{
              y: focused || props.value ? -12 : 0,
              fontSize: focused || props.value ? 11 : 16,
            }}
          >
            {label}
          </motion.label>
        )}
        <div className="relative">
          {icon && (
            <div className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-black/36 dark:text-white/36">
              {icon}
            </div>
          )}
          <input
            ref={ref}
            className={`
              w-full h-12 px-4 ${icon ? 'pl-12' : ''} ${suffix ? 'pr-12' : ''}
              bg-transparent
              border border-black/8 dark:border-white/8
              text-black dark:text-white
              placeholder-black/36 dark:placeholder-white/36
              transition-all duration-200
              focus:outline-none focus:border-black/24 dark:focus:border-white/24
              hover:border-black/16 dark:hover:border-white/16
              disabled:opacity-30 disabled:cursor-not-allowed
              ${error ? 'border-red-500/50' : ''}
              ${className}
            `}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            {...props}
          />
          {suffix && (
            <div className="absolute right-4 top-1/2 -translate-y-1/2">
              {suffix}
            </div>
          )}
        </div>
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              className="mt-1 text-[13px] text-red-500"
            >
              {error}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    );
  }
);

Input.displayName = 'Input';

// ============================================
// CARD - Content that floats
// ============================================

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  interactive?: boolean;
  selected?: boolean;
  hoverable?: boolean;
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ children, interactive = false, selected = false, hoverable = true, className = '', ...props }, ref) => {
    return (
      <motion.div
        ref={ref}
        className={`
          relative p-5
          bg-white dark:bg-black
          border border-black/8 dark:border-white/8
          transition-all duration-300
          ${interactive ? 'cursor-pointer' : ''}
          ${selected ? 'border-blue-500 bg-blue-500/2' : ''}
          ${hoverable && interactive ? 'hover:border-black/16 dark:hover:border-white/16' : ''}
          ${className}
        `}
        whileHover={interactive ? { y: -4, transition: { duration: 0.2 } } : {}}
        {...props}
      >
        {children}
      </motion.div>
    );
  }
);

Card.displayName = 'Card';

// ============================================
// SKELETON - Loading states that don't annoy
// ============================================

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  variant?: 'text' | 'rectangular' | 'circular';
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  width = '100%',
  height = 20,
  variant = 'rectangular',
  className = '',
}) => {
  const variants = {
    text: 'rounded',
    rectangular: '',
    circular: 'rounded-full',
  };

  return (
    <motion.div
      className={`
        bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200
        dark:from-gray-800 dark:via-gray-700 dark:to-gray-800
        animate-shimmer bg-[length:200%_100%]
        ${variants[variant]}
        ${className}
      `}
      style={{ width, height }}
      animate={{ backgroundPosition: ['100% 0', '-100% 0'] }}
      transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
    />
  );
};

// ============================================
// BADGE - Status that speaks
// ============================================

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'error';
  size?: 'small' | 'default';
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'default',
}) => {
  const variants = {
    default: 'bg-black/8 text-black dark:bg-white/8 dark:text-white',
    success: 'bg-green-500/10 text-green-700 dark:text-green-400',
    warning: 'bg-amber-500/10 text-amber-700 dark:text-amber-400',
    error: 'bg-red-500/10 text-red-700 dark:text-red-400',
  };

  const sizes = {
    small: 'px-2 py-0.5 text-[11px]',
    default: 'px-3 py-1 text-[13px]',
  };

  return (
    <span
      className={`
        inline-flex items-center font-medium
        ${variants[variant]}
        ${sizes[size]}
      `}
    >
      {children}
    </span>
  );
};

// ============================================
// SEPARATOR - Division without walls
// ============================================

export const Separator: React.FC<{ className?: string }> = ({ className = '' }) => {
  return (
    <div
      className={`
        h-px w-full
        bg-gradient-to-r from-transparent via-black/8 to-transparent
        dark:via-white/8
        ${className}
      `}
    />
  );
};

// ============================================
// TEXT - Typography with purpose
// ============================================

interface TextProps {
  children: React.ReactNode;
  variant?: 'hero' | 'display' | 'heading' | 'subheading' | 'body' | 'caption';
  weight?: 'regular' | 'medium';
  color?: 'primary' | 'secondary' | 'tertiary';
  className?: string;
}

export const Text: React.FC<TextProps> = ({
  children,
  variant = 'body',
  weight = 'regular',
  color = 'primary',
  className = '',
}) => {
  const variants = {
    hero: 'text-[64px] leading-[1.2] tracking-[-0.02em]',
    display: 'text-[40px] leading-[1.2] tracking-[-0.02em]',
    heading: 'text-[28px] leading-[1.3]',
    subheading: 'text-[20px] leading-[1.4]',
    body: 'text-[16px] leading-[1.5]',
    caption: 'text-[13px] leading-[1.5] tracking-[0.02em]',
  };

  const weights = {
    regular: 'font-normal',
    medium: 'font-medium',
  };

  const colors = {
    primary: 'text-black dark:text-white',
    secondary: 'text-black/64 dark:text-white/64',
    tertiary: 'text-black/36 dark:text-white/36',
  };

  const Component = variant === 'hero' ? 'h1' :
                   variant === 'display' ? 'h2' :
                   variant === 'heading' ? 'h3' :
                   variant === 'subheading' ? 'h4' : 'p';

  return (
    <Component
      className={`
        ${variants[variant]}
        ${weights[weight]}
        ${colors[color]}
        ${className}
      `}
    >
      {children}
    </Component>
  );
};

// ============================================
// TOOLTIP - Whispered wisdom
// ============================================

interface TooltipProps {
  children: React.ReactNode;
  content: string;
  shortcut?: string;
}

export const Tooltip: React.FC<TooltipProps> = ({ children, content, shortcut }) => {
  const [visible, setVisible] = React.useState(false);

  return (
    <div className="relative inline-block">
      <div
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
      >
        {children}
      </div>
      <AnimatePresence>
        {visible && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            transition={{ duration: 0.2, delay: 0.3 }}
            className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 text-[13px] bg-black text-white dark:bg-white dark:text-black whitespace-nowrap z-50"
          >
            {content}
            {shortcut && (
              <span className="ml-2 px-1 py-0.5 text-[11px] bg-white/20 dark:bg-black/20 rounded">
                {shortcut}
              </span>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default {
  Button,
  Input,
  Card,
  Skeleton,
  Badge,
  Separator,
  Text,
  Tooltip,
};