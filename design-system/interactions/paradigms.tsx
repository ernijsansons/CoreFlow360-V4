/**
 * INTERACTION PARADIGMS - The soul of the experience
 * Every interaction is intentional, delightful, and productive
 */

import React, { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { motion, AnimatePresence, useAnimation } from 'framer-motion';
import {
  Command, Undo, Redo, Info, Keyboard, MousePointer,
  Check, X, AlertCircle, Loader, Zap
} from 'lucide-react';

// ============================================
// HOVER INTELLIGENCE - Context on demand
// ============================================

interface HoverIntelligenceProps {
  children: React.ReactNode;
  content: {
    what: string;
    why?: string;
    how?: string;
    shortcut?: string;
  };
  delay?: number;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

export const HoverIntelligence: React.FC<HoverIntelligenceProps> = ({
  children,
  content,
  delay = 300,
  position = 'top'
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const timeoutRef = useRef<NodeJS.Timeout>();
  const detailTimeoutRef = useRef<NodeJS.Timeout>();

  const handleMouseEnter = () => {
    timeoutRef.current = setTimeout(() => {
      setIsVisible(true);
      // Progressive disclosure - show more details after longer hover
      detailTimeoutRef.current = setTimeout(() => {
        setShowDetails(true);
      }, 500);
    }, delay);
  };

  const handleMouseLeave = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (detailTimeoutRef.current) clearTimeout(detailTimeoutRef.current);
    setIsVisible(false);
    setShowDetails(false);
  };

  const positions = {
    top: 'bottom-full mb-2',
    bottom: 'top-full mt-2',
    left: 'right-full mr-2',
    right: 'left-full ml-2'
  };

  return (
    <div className="relative inline-block">
      <div
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        {children}
      </div>

      <AnimatePresence>
        {isVisible && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: position === 'top' ? 5 : -5 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.15, ease: [0.4, 0, 0.2, 1] }}
            className={`absolute ${positions[position]} left-1/2 -translate-x-1/2 z-50`}
          >
            <div className="bg-black dark:bg-white text-white dark:text-black p-3 min-w-[200px] max-w-[300px]">
              {/* What - Always visible */}
              <div className="text-[13px] font-medium mb-1">
                {content.what}
              </div>

              {/* Progressive disclosure */}
              <AnimatePresence>
                {showDetails && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    {content.why && (
                      <div className="text-[11px] opacity-80 mt-2 pt-2 border-t border-white/10 dark:border-black/10">
                        <strong>Why:</strong> {content.why}
                      </div>
                    )}
                    {content.how && (
                      <div className="text-[11px] opacity-80 mt-1">
                        <strong>How:</strong> {content.how}
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Shortcut badge */}
              {content.shortcut && (
                <div className="mt-2 pt-2 border-t border-white/10 dark:border-black/10">
                  <kbd className="px-1.5 py-0.5 text-[10px] bg-white/20 dark:bg-black/20 rounded">
                    {content.shortcut}
                  </kbd>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ============================================
// KEYBOARD NAVIGATION - Power user paradise
// ============================================

interface KeyboardShortcut {
  key: string;
  modifiers?: ('ctrl' | 'cmd' | 'alt' | 'shift')[];
  action: () => void;
  description: string;
  category?: string;
}

interface KeyboardNavigationContextType {
  registerShortcut: (shortcut: KeyboardShortcut) => void;
  unregisterShortcut: (key: string) => void;
  shortcuts: KeyboardShortcut[];
  showHelp: boolean;
  setShowHelp: (show: boolean) => void;
}

const KeyboardNavigationContext = createContext<KeyboardNavigationContextType | null>(null);

export const KeyboardNavigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [shortcuts, setShortcuts] = useState<KeyboardShortcut[]>([]);
  const [showHelp, setShowHelp] = useState(false);

  const registerShortcut = useCallback((shortcut: KeyboardShortcut) => {
    setShortcuts(prev => [...prev, shortcut]);
  }, []);

  const unregisterShortcut = useCallback((key: string) => {
    setShortcuts(prev => prev.filter(s => s.key !== key));
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Show help on ?
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        setShowHelp(true);
        return;
      }

      // Hide help on Escape
      if (e.key === 'Escape' && showHelp) {
        setShowHelp(false);
        return;
      }

      // Check shortcuts
      shortcuts.forEach(shortcut => {
        const modifierMatch =
          (!shortcut.modifiers || shortcut.modifiers.length === 0) ||
          (shortcut.modifiers.every(mod => {
            switch(mod) {
              case 'ctrl': return e.ctrlKey;
              case 'cmd': return e.metaKey;
              case 'alt': return e.altKey;
              case 'shift': return e.shiftKey;
              default: return false;
            }
          }));

        if (e.key.toLowerCase() === shortcut.key.toLowerCase() && modifierMatch) {
          e.preventDefault();
          shortcut.action();
        }
      });
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts, showHelp]);

  return (
    <KeyboardNavigationContext.Provider value={{
      registerShortcut,
      unregisterShortcut,
      shortcuts,
      showHelp,
      setShowHelp
    }}>
      {children}
      <KeyboardShortcutHelp />
    </KeyboardNavigationContext.Provider>
  );
};

// Keyboard shortcut help overlay
const KeyboardShortcutHelp: React.FC = () => {
  const context = useContext(KeyboardNavigationContext);
  if (!context) return null;

  const { shortcuts, showHelp, setShowHelp } = context;

  // Group shortcuts by category
  const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
    const category = shortcut.category || 'General';
    if (!acc[category]) acc[category] = [];
    acc[category].push(shortcut);
    return acc;
  }, {} as Record<string, KeyboardShortcut[]>);

  return (
    <AnimatePresence>
      {showHelp && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 bg-black/50 dark:bg-white/10 flex items-center justify-center p-8"
          onClick={() => setShowHelp(false)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            className="bg-white dark:bg-black border border-black/8 dark:border-white/8 max-w-2xl w-full max-h-[70vh] overflow-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-[20px] font-medium text-black dark:text-white">
                  Keyboard Shortcuts
                </h2>
                <button
                  onClick={() => setShowHelp(false)}
                  className="p-2 hover:bg-black/4 dark:hover:bg-white/4 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-6">
                {Object.entries(groupedShortcuts).map(([category, shortcuts]) => (
                  <div key={category}>
                    <h3 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide mb-3">
                      {category}
                    </h3>
                    <div className="space-y-2">
                      {shortcuts.map(shortcut => (
                        <div key={shortcut.key} className="flex items-center justify-between py-2">
                          <span className="text-[13px] text-black dark:text-white">
                            {shortcut.description}
                          </span>
                          <div className="flex items-center gap-1">
                            {shortcut.modifiers?.map(mod => (
                              <kbd key={mod} className="px-1.5 py-0.5 text-[11px] bg-black/8 dark:bg-white/8 rounded capitalize">
                                {mod === 'cmd' ? '⌘' : mod}
                              </kbd>
                            ))}
                            <kbd className="px-2 py-0.5 text-[11px] bg-black/8 dark:bg-white/8 rounded">
                              {shortcut.key}
                            </kbd>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-4 border-t border-black/8 dark:border-white/8 text-[11px] text-black/36 dark:text-white/36">
                Press <kbd className="px-1.5 py-0.5 bg-black/8 dark:bg-white/8 rounded">?</kbd> anytime to show this help
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

// Hook to use keyboard shortcuts
export const useKeyboardShortcut = (shortcut: KeyboardShortcut) => {
  const context = useContext(KeyboardNavigationContext);

  useEffect(() => {
    if (context) {
      context.registerShortcut(shortcut);
      return () => context.unregisterShortcut(shortcut.key);
    }
  }, [context, shortcut]);
};

// ============================================
// UNDO SYSTEM - Forgiveness everywhere
// ============================================

interface UndoAction {
  id: string;
  description: string;
  undo: () => void;
  redo: () => void;
  timestamp: Date;
}

interface UndoSystemContextType {
  addAction: (action: Omit<UndoAction, 'id' | 'timestamp'>) => void;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;
  history: UndoAction[];
}

const UndoSystemContext = createContext<UndoSystemContextType | null>(null);

export const UndoSystemProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [history, setHistory] = useState<UndoAction[]>([]);
  const [currentIndex, setCurrentIndex] = useState(-1);

  const addAction = useCallback((action: Omit<UndoAction, 'id' | 'timestamp'>) => {
    const newAction: UndoAction = {
      ...action,
      id: Math.random().toString(36),
      timestamp: new Date()
    };

    setHistory(prev => [...prev.slice(0, currentIndex + 1), newAction]);
    setCurrentIndex(prev => prev + 1);

    // Show notification
    showUndoNotification(action.description);
  }, [currentIndex]);

  const undo = useCallback(() => {
    if (currentIndex >= 0) {
      history[currentIndex].undo();
      setCurrentIndex(prev => prev - 1);
      showUndoNotification(`Undid: ${history[currentIndex].description}`);
    }
  }, [currentIndex, history]);

  const redo = useCallback(() => {
    if (currentIndex < history.length - 1) {
      const nextAction = history[currentIndex + 1];
      nextAction.redo();
      setCurrentIndex(prev => prev + 1);
      showUndoNotification(`Redid: ${nextAction.description}`);
    }
  }, [currentIndex, history]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        undo();
      } else if ((e.metaKey || e.ctrlKey) && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) {
        e.preventDefault();
        redo();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [undo, redo]);

  return (
    <UndoSystemContext.Provider value={{
      addAction,
      undo,
      redo,
      canUndo: currentIndex >= 0,
      canRedo: currentIndex < history.length - 1,
      history
    }}>
      {children}
      <UndoNotificationContainer />
    </UndoSystemContext.Provider>
  );
};

// Undo notification system
let notificationQueue: string[] = [];
let showNotification: (message: string) => void;

const UndoNotificationContainer: React.FC = () => {
  const [notifications, setNotifications] = useState<{ id: string; message: string }[]>([]);

  showNotification = useCallback((message: string) => {
    const id = Math.random().toString(36);
    setNotifications(prev => [...prev, { id, message }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 3000);
  }, []);

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 pointer-events-none">
      <AnimatePresence>
        {notifications.map(notification => (
          <motion.div
            key={notification.id}
            initial={{ opacity: 0, y: 20, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.9 }}
            className="mb-2 px-4 py-2 bg-black text-white dark:bg-white dark:text-black text-[13px] rounded pointer-events-auto"
          >
            <div className="flex items-center gap-2">
              <Check className="w-3 h-3" />
              {notification.message}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

const showUndoNotification = (message: string) => {
  if (showNotification) showNotification(message);
};

// Hook to use undo system
export const useUndo = () => {
  const context = useContext(UndoSystemContext);
  if (!context) throw new Error('useUndo must be used within UndoSystemProvider');
  return context;
};

// ============================================
// OPTIMISTIC UPDATES - Instant feedback
// ============================================

interface OptimisticUpdateProps<T> {
  value: T;
  onUpdate: (newValue: T) => Promise<void>;
  children: (props: {
    optimisticValue: T;
    isPending: boolean;
    error: Error | null;
    update: (newValue: T) => void;
  }) => React.ReactNode;
}

export function OptimisticUpdate<T>({ value, onUpdate, children }: OptimisticUpdateProps<T>) {
  const [optimisticValue, setOptimisticValue] = useState(value);
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    setOptimisticValue(value);
  }, [value]);

  const update = useCallback(async (newValue: T) => {
    setOptimisticValue(newValue);
    setIsPending(true);
    setError(null);

    try {
      await onUpdate(newValue);
    } catch (err) {
      setError(err as Error);
      setOptimisticValue(value); // Revert on error
      showUndoNotification('Change reverted due to error');
    } finally {
      setIsPending(false);
    }
  }, [value, onUpdate]);

  return <>{children({ optimisticValue, isPending, error, update })}</>;
}

// ============================================
// LOADING STATES - Beautiful waiting
// ============================================

interface LoadingStateProps {
  variant?: 'spinner' | 'dots' | 'pulse' | 'skeleton';
  size?: 'small' | 'medium' | 'large';
  label?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  variant = 'spinner',
  size = 'medium',
  label
}) => {
  const sizes = {
    small: 'w-4 h-4',
    medium: 'w-6 h-6',
    large: 'w-8 h-8'
  };

  const renderLoader = () => {
    switch (variant) {
      case 'spinner':
        return (
          <motion.div
            className={`${sizes[size]} border-2 border-black/20 dark:border-white/20 border-t-black dark:border-t-white rounded-full`}
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          />
        );

      case 'dots':
        return (
          <div className="flex gap-1">
            {[0, 1, 2].map(i => (
              <motion.div
                key={i}
                className="w-2 h-2 bg-black dark:bg-white rounded-full"
                animate={{
                  scale: [1, 1.2, 1],
                  opacity: [0.5, 1, 0.5]
                }}
                transition={{
                  duration: 0.6,
                  repeat: Infinity,
                  delay: i * 0.1
                }}
              />
            ))}
          </div>
        );

      case 'pulse':
        return (
          <motion.div
            className={`${sizes[size]} bg-black dark:bg-white rounded-full`}
            animate={{
              scale: [1, 1.2, 1],
              opacity: [0.5, 0.2, 0.5]
            }}
            transition={{ duration: 1.5, repeat: Infinity }}
          />
        );

      case 'skeleton':
        return (
          <div className="space-y-3">
            <div className="h-4 bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200 dark:from-gray-800 dark:via-gray-700 dark:to-gray-800 animate-shimmer bg-[length:200%_100%]" />
            <div className="h-4 w-3/4 bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200 dark:from-gray-800 dark:via-gray-700 dark:to-gray-800 animate-shimmer bg-[length:200%_100%]" />
            <div className="h-4 w-1/2 bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200 dark:from-gray-800 dark:via-gray-700 dark:to-gray-800 animate-shimmer bg-[length:200%_100%]" />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="flex flex-col items-center justify-center gap-3">
      {renderLoader()}
      {label && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-[13px] text-black/64 dark:text-white/64"
        >
          {label}
        </motion.div>
      )}
    </div>
  );
};

// ============================================
// GESTURE RECOGNITION - Touch-first thinking
// ============================================

interface GestureHandlerProps {
  onSwipeLeft?: () => void;
  onSwipeRight?: () => void;
  onSwipeUp?: () => void;
  onSwipeDown?: () => void;
  onPinch?: (scale: number) => void;
  onRotate?: (angle: number) => void;
  children: React.ReactNode;
}

export const GestureHandler: React.FC<GestureHandlerProps> = ({
  onSwipeLeft,
  onSwipeRight,
  onSwipeUp,
  onSwipeDown,
  onPinch,
  onRotate,
  children
}) => {
  const [touchStart, setTouchStart] = useState<{ x: number; y: number } | null>(null);
  const [touchEnd, setTouchEnd] = useState<{ x: number; y: number } | null>(null);

  const minSwipeDistance = 50;

  const onTouchStart = (e: React.TouchEvent) => {
    setTouchEnd(null);
    setTouchStart({
      x: e.targetTouches[0].clientX,
      y: e.targetTouches[0].clientY
    });
  };

  const onTouchMove = (e: React.TouchEvent) => {
    setTouchEnd({
      x: e.targetTouches[0].clientX,
      y: e.targetTouches[0].clientY
    });
  };

  const onTouchEnd = () => {
    if (!touchStart || !touchEnd) return;

    const distanceX = touchStart.x - touchEnd.x;
    const distanceY = touchStart.y - touchEnd.y;
    const isLeftSwipe = distanceX > minSwipeDistance;
    const isRightSwipe = distanceX < -minSwipeDistance;
    const isUpSwipe = distanceY > minSwipeDistance;
    const isDownSwipe = distanceY < -minSwipeDistance;

    if (isLeftSwipe && Math.abs(distanceX) > Math.abs(distanceY)) {
      onSwipeLeft?.();
    }
    if (isRightSwipe && Math.abs(distanceX) > Math.abs(distanceY)) {
      onSwipeRight?.();
    }
    if (isUpSwipe && Math.abs(distanceY) > Math.abs(distanceX)) {
      onSwipeUp?.();
    }
    if (isDownSwipe && Math.abs(distanceY) > Math.abs(distanceX)) {
      onSwipeDown?.();
    }
  };

  return (
    <div
      onTouchStart={onTouchStart}
      onTouchMove={onTouchMove}
      onTouchEnd={onTouchEnd}
    >
      {children}
    </div>
  );
};

export default {
  HoverIntelligence,
  KeyboardNavigationProvider,
  useKeyboardShortcut,
  UndoSystemProvider,
  useUndo,
  OptimisticUpdate,
  LoadingState,
  GestureHandler
};