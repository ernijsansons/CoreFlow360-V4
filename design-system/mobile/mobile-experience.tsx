/**
 * MOBILE EXPERIENCE - Enterprise power in your pocket
 * Touch-first, gesture-driven, beautifully responsive
 */

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence, PanInfo, useAnimation } from 'framer-motion';
import {
  Menu, X, Home, BarChart3, Users, Settings, Search,
  Bell, ChevronDown, ChevronUp, Plus, Filter, MoreVertical,
  DollarSign, TrendingUp, Clock, ArrowLeft, Share,
  Maximize2, Minimize2, ChevronRight
} from 'lucide-react';

// ============================================
// MOBILE NAVIGATION - Bottom sheet excellence
// ============================================

interface MobileNavigationProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

export const MobileNavigation: React.FC<MobileNavigationProps> = ({ activeTab, onTabChange }) => {
  const tabs = [
    { id: 'home', icon: Home, label: 'Home' },
    { id: 'analytics', icon: BarChart3, label: 'Analytics' },
    { id: 'customers', icon: Users, label: 'Customers' },
    { id: 'settings', icon: Settings, label: 'Settings' }
  ];

  return (
    <motion.nav
      initial={{ y: 100 }}
      animate={{ y: 0 }}
      className="fixed bottom-0 left-0 right-0 bg-white dark:bg-black border-t border-black/8 dark:border-white/8 z-40"
    >
      <div className="flex justify-around items-center h-16 px-4 pb-safe">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className="flex-1 flex flex-col items-center justify-center gap-1 py-2"
          >
            <motion.div
              whileTap={{ scale: 0.9 }}
              className={`p-2 rounded-full ${
                activeTab === tab.id
                  ? 'bg-black dark:bg-white'
                  : ''
              }`}
            >
              <tab.icon
                className={`w-5 h-5 ${
                  activeTab === tab.id
                    ? 'text-white dark:text-black'
                    : 'text-black/36 dark:text-white/36'
                }`}
              />
            </motion.div>
            <span className={`text-[10px] ${
              activeTab === tab.id
                ? 'text-black dark:text-white'
                : 'text-black/36 dark:text-white/36'
            }`}>
              {tab.label}
            </span>
          </button>
        ))}
      </div>
    </motion.nav>
  );
};

// ============================================
// MOBILE HEADER - Contextual and minimal
// ============================================

interface MobileHeaderProps {
  title: string;
  showBack?: boolean;
  onBack?: () => void;
  actions?: React.ReactNode;
}

export const MobileHeader: React.FC<MobileHeaderProps> = ({
  title,
  showBack,
  onBack,
  actions
}) => {
  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      className="sticky top-0 bg-white/95 dark:bg-black/95 backdrop-blur-lg border-b border-black/8 dark:border-white/8 z-30"
    >
      <div className="flex items-center justify-between h-14 px-4">
        <div className="flex items-center gap-3">
          {showBack && (
            <button
              onClick={onBack}
              className="p-2 -ml-2 rounded-full active:bg-black/4 dark:active:bg-white/4"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
          )}
          <h1 className="text-[18px] font-medium text-black dark:text-white">
            {title}
          </h1>
        </div>
        {actions && (
          <div className="flex items-center gap-2">
            {actions}
          </div>
        )}
      </div>
    </motion.header>
  );
};

// ============================================
// MOBILE CARD - Touch-optimized containers
// ============================================

interface MobileCardProps {
  children: React.ReactNode;
  onPress?: () => void;
  onLongPress?: () => void;
  swipeable?: boolean;
  onSwipeLeft?: () => void;
  onSwipeRight?: () => void;
}

export const MobileCard: React.FC<MobileCardProps> = ({
  children,
  onPress,
  onLongPress,
  swipeable,
  onSwipeLeft,
  onSwipeRight
}) => {
  const [isPressed, setIsPressed] = useState(false);
  const longPressTimer = useRef<NodeJS.Timeout>();
  const x = useAnimation();

  const handleTouchStart = () => {
    setIsPressed(true);
    if (onLongPress) {
      longPressTimer.current = setTimeout(() => {
        onLongPress();
        // Haptic feedback would go here
      }, 500);
    }
  };

  const handleTouchEnd = () => {
    setIsPressed(false);
    if (longPressTimer.current) {
      clearTimeout(longPressTimer.current);
    }
  };

  const handleDragEnd = (event: any, info: PanInfo) => {
    const threshold = 100;
    if (info.offset.x > threshold && onSwipeRight) {
      onSwipeRight();
    } else if (info.offset.x < -threshold && onSwipeLeft) {
      onSwipeLeft();
    } else {
      x.start({ x: 0 });
    }
  };

  return (
    <motion.div
      drag={swipeable ? 'x' : false}
      dragConstraints={{ left: -100, right: 100 }}
      dragElastic={0.2}
      onDragEnd={handleDragEnd}
      animate={x}
      whileTap={{ scale: onPress ? 0.98 : 1 }}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
      onClick={onPress}
      className={`bg-white dark:bg-black border border-black/8 dark:border-white/8 p-4 rounded-lg ${
        onPress ? 'active:bg-black/2 dark:active:bg-white/2' : ''
      } ${isPressed ? 'bg-black/2 dark:bg-white/2' : ''}`}
    >
      {children}
    </motion.div>
  );
};

// ============================================
// MOBILE METRIC - Glanceable data
// ============================================

interface MobileMetricProps {
  value: string | number;
  label: string;
  change?: number;
  icon?: React.ReactNode;
  compact?: boolean;
}

export const MobileMetric: React.FC<MobileMetricProps> = ({
  value,
  label,
  change,
  icon,
  compact
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`${compact ? 'p-3' : 'p-4'} bg-white dark:bg-black border border-black/8 dark:border-white/8 rounded-lg`}
    >
      <div className="flex items-start justify-between mb-2">
        <span className="text-[11px] text-black/64 dark:text-white/64 uppercase tracking-wide">
          {label}
        </span>
        {icon && (
          <div className="w-4 h-4 text-black/36 dark:text-white/36">
            {icon}
          </div>
        )}
      </div>
      <div className={`${compact ? 'text-[20px]' : 'text-[28px]'} font-medium text-black dark:text-white`}>
        {value}
      </div>
      {change !== undefined && (
        <div className="flex items-center gap-1 mt-1">
          {change >= 0 ? (
            <TrendingUp className="w-3 h-3 text-green-600" />
          ) : (
            <TrendingUp className="w-3 h-3 text-red-600 rotate-180" />
          )}
          <span className={`text-[11px] ${
            change >= 0 ? 'text-green-600' : 'text-red-600'
          }`}>
            {Math.abs(change)}%
          </span>
        </div>
      )}
    </motion.div>
  );
};

// ============================================
// MOBILE BOTTOM SHEET - Contextual actions
// ============================================

interface MobileBottomSheetProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  snapPoints?: number[]; // Percentages of screen height
}

export const MobileBottomSheet: React.FC<MobileBottomSheetProps> = ({
  isOpen,
  onClose,
  title,
  children,
  snapPoints = [0.5, 0.9]
}) => {
  const [currentSnap, setCurrentSnap] = useState(0);
  const sheetRef = useRef<HTMLDivElement>(null);

  const handleDragEnd = (event: any, info: PanInfo) => {
    const velocity = info.velocity.y;
    const offset = info.offset.y;

    if (velocity > 500 || offset > 100) {
      onClose();
    } else if (velocity < -500 || offset < -100) {
      setCurrentSnap(Math.min(currentSnap + 1, snapPoints.length - 1));
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/50 z-40"
          />

          {/* Sheet */}
          <motion.div
            ref={sheetRef}
            initial={{ y: '100%' }}
            animate={{ y: `${(1 - snapPoints[currentSnap]) * 100}%` }}
            exit={{ y: '100%' }}
            transition={{ type: 'spring', damping: 30, stiffness: 300 }}
            drag="y"
            dragConstraints={{ top: 0 }}
            dragElastic={0.2}
            onDragEnd={handleDragEnd}
            className="fixed bottom-0 left-0 right-0 bg-white dark:bg-black rounded-t-2xl z-50"
            style={{ height: '90vh' }}
          >
            {/* Handle */}
            <div className="flex justify-center pt-3 pb-2">
              <div className="w-12 h-1 bg-black/20 dark:bg-white/20 rounded-full" />
            </div>

            {/* Header */}
            {title && (
              <div className="flex items-center justify-between px-4 pb-3 border-b border-black/8 dark:border-white/8">
                <h2 className="text-[16px] font-medium text-black dark:text-white">
                  {title}
                </h2>
                <button
                  onClick={onClose}
                  className="p-2 rounded-full active:bg-black/4 dark:active:bg-white/4"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            )}

            {/* Content */}
            <div className="flex-1 overflow-y-auto px-4 py-4">
              {children}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

// ============================================
// MOBILE LIST - Optimized for scrolling
// ============================================

interface MobileListItem {
  id: string;
  title: string;
  subtitle?: string;
  value?: string;
  icon?: React.ReactNode;
  badge?: string;
}

interface MobileListProps {
  items: MobileListItem[];
  onItemPress?: (item: MobileListItem) => void;
  onItemLongPress?: (item: MobileListItem) => void;
  grouped?: boolean;
}

export const MobileList: React.FC<MobileListProps> = ({
  items,
  onItemPress,
  onItemLongPress,
  grouped
}) => {
  return (
    <div className={`${grouped ? 'space-y-4' : 'divide-y divide-black/8 dark:divide-white/8'}`}>
      {items.map((item, index) => (
        <motion.div
          key={item.id}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.05 }}
        >
          <MobileListItemComponent
            item={item}
            onPress={() => onItemPress?.(item)}
            onLongPress={() => onItemLongPress?.(item)}
            grouped={grouped}
          />
        </motion.div>
      ))}
    </div>
  );
};

const MobileListItemComponent: React.FC<{
  item: MobileListItem;
  onPress?: () => void;
  onLongPress?: () => void;
  grouped?: boolean;
}> = ({ item, onPress, onLongPress, grouped }) => {
  const [isPressed, setIsPressed] = useState(false);
  const longPressTimer = useRef<NodeJS.Timeout>();

  const handleTouchStart = () => {
    setIsPressed(true);
    if (onLongPress) {
      longPressTimer.current = setTimeout(() => {
        onLongPress();
      }, 500);
    }
  };

  const handleTouchEnd = () => {
    setIsPressed(false);
    if (longPressTimer.current) {
      clearTimeout(longPressTimer.current);
    }
  };

  return (
    <div
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
      onClick={onPress}
      className={`
        flex items-center gap-3 py-3 ${grouped ? 'px-4 bg-white dark:bg-black rounded-lg' : ''}
        ${isPressed ? 'bg-black/2 dark:bg-white/2' : ''}
        transition-colors
      `}
    >
      {item.icon && (
        <div className="w-10 h-10 bg-black/4 dark:bg-white/4 rounded-full flex items-center justify-center">
          {item.icon}
        </div>
      )}
      <div className="flex-1">
        <div className="text-[14px] font-medium text-black dark:text-white">
          {item.title}
        </div>
        {item.subtitle && (
          <div className="text-[12px] text-black/64 dark:text-white/64">
            {item.subtitle}
          </div>
        )}
      </div>
      {item.value && (
        <div className="text-[14px] font-medium text-black dark:text-white">
          {item.value}
        </div>
      )}
      {item.badge && (
        <div className="px-2 py-0.5 bg-blue-500/10 text-blue-600 text-[11px] font-medium rounded">
          {item.badge}
        </div>
      )}
      <ChevronRight className="w-4 h-4 text-black/20 dark:text-white/20" />
    </div>
  );
};

// ============================================
// MOBILE DASHBOARD - Complete experience
// ============================================

export const MobileDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState('home');
  const [showSearch, setShowSearch] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 pb-16">
      <MobileHeader
        title="Dashboard"
        actions={
          <>
            <button
              onClick={() => setShowSearch(!showSearch)}
              className="p-2 rounded-full active:bg-black/4 dark:active:bg-white/4"
            >
              <Search className="w-5 h-5" />
            </button>
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="p-2 rounded-full active:bg-black/4 dark:active:bg-white/4 relative"
            >
              <Bell className="w-5 h-5" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
            </button>
          </>
        }
      />

      {/* Search Bar */}
      <AnimatePresence>
        {showSearch && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-b border-black/8 dark:border-white/8"
          >
            <input
              type="search"
              placeholder="Search everything..."
              className="w-full px-4 py-3 bg-transparent text-[14px] placeholder-black/36 dark:placeholder-white/36 outline-none"
              autoFocus
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="px-4 py-4 space-y-4">
        {/* Welcome Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h2 className="text-[20px] font-medium text-black dark:text-white mb-1">
            Good morning, Alex
          </h2>
          <p className="text-[14px] text-black/64 dark:text-white/64">
            Your business is up 12% this week
          </p>
        </motion.div>

        {/* Key Metrics */}
        <div className="grid grid-cols-2 gap-3">
          <MobileMetric
            value="$2.4M"
            label="Revenue"
            change={12.5}
            icon={<DollarSign />}
            compact
          />
          <MobileMetric
            value="1,284"
            label="Customers"
            change={8.3}
            icon={<Users />}
            compact
          />
          <MobileMetric
            value="94%"
            label="Efficiency"
            change={2.1}
            icon={<TrendingUp />}
            compact
          />
          <MobileMetric
            value="2.1%"
            label="Churn"
            change={-0.3}
            icon={<Clock />}
            compact
          />
        </div>

        {/* Recent Activity */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[16px] font-medium text-black dark:text-white">
              Recent Activity
            </h3>
            <button className="text-[12px] text-blue-600">
              View all →
            </button>
          </div>
          <MobileList
            items={[
              {
                id: '1',
                title: 'Acme Corp',
                subtitle: 'Negotiation stage',
                value: '$125K',
                badge: '80%'
              },
              {
                id: '2',
                title: 'TechStart Inc',
                subtitle: 'Proposal sent',
                value: '$85K',
                badge: '60%'
              },
              {
                id: '3',
                title: 'Global Systems',
                subtitle: 'Qualification',
                value: '$310K',
                badge: '40%'
              }
            ]}
            onItemPress={(item) => console.log('Pressed:', item)}
            grouped
          />
        </div>

        {/* Quick Actions */}
        <MobileCard>
          <h3 className="text-[14px] font-medium text-black dark:text-white mb-3">
            Quick Actions
          </h3>
          <div className="grid grid-cols-4 gap-3">
            {[
              { icon: Plus, label: 'Add' },
              { icon: DollarSign, label: 'Invoice' },
              { icon: Users, label: 'Contact' },
              { icon: BarChart3, label: 'Report' }
            ].map((action, i) => (
              <button
                key={i}
                className="flex flex-col items-center gap-2 p-3 rounded-lg active:bg-black/4 dark:active:bg-white/4"
              >
                <div className="w-10 h-10 bg-black/4 dark:bg-white/4 rounded-full flex items-center justify-center">
                  <action.icon className="w-5 h-5 text-black/64 dark:text-white/64" />
                </div>
                <span className="text-[11px] text-black/64 dark:text-white/64">
                  {action.label}
                </span>
              </button>
            ))}
          </div>
        </MobileCard>
      </div>

      {/* Bottom Navigation */}
      <MobileNavigation activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Notifications Sheet */}
      <MobileBottomSheet
        isOpen={showNotifications}
        onClose={() => setShowNotifications(false)}
        title="Notifications"
        snapPoints={[0.5, 0.9]}
      >
        <MobileList
          items={[
            {
              id: '1',
              title: 'Deal closed',
              subtitle: 'Acme Corp deal worth $125K has been won',
              icon: <CheckCircle className="w-4 h-4 text-green-600" />
            },
            {
              id: '2',
              title: 'Meeting reminder',
              subtitle: 'Call with TechStart Inc in 30 minutes',
              icon: <Clock className="w-4 h-4 text-blue-600" />
            },
            {
              id: '3',
              title: 'Target achieved',
              subtitle: 'Q3 revenue target exceeded by 18%',
              icon: <TrendingUp className="w-4 h-4 text-purple-600" />
            }
          ]}
          grouped
        />
      </MobileBottomSheet>
    </div>
  );
};

// ============================================
// MOBILE PIPELINE - Horizontal scroll excellence
// ============================================

export const MobilePipeline: React.FC = () => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [activeStage, setActiveStage] = useState(0);

  const stages = [
    { name: 'Prospect', deals: 12, value: '$234K' },
    { name: 'Qualified', deals: 8, value: '$456K' },
    { name: 'Proposal', deals: 5, value: '$890K' },
    { name: 'Negotiation', deals: 3, value: '$1.2M' },
    { name: 'Closed', deals: 2, value: '$450K' }
  ];

  const handleScroll = () => {
    if (!scrollRef.current) return;
    const scrollPosition = scrollRef.current.scrollLeft;
    const stageWidth = scrollRef.current.offsetWidth * 0.8;
    const newActiveStage = Math.round(scrollPosition / stageWidth);
    setActiveStage(newActiveStage);
  };

  return (
    <div className="relative">
      {/* Stage Indicator */}
      <div className="flex justify-center gap-1 mb-4">
        {stages.map((_, i) => (
          <div
            key={i}
            className={`h-1 rounded-full transition-all ${
              i === activeStage ? 'w-6 bg-black dark:bg-white' : 'w-1 bg-black/20 dark:bg-white/20'
            }`}
          />
        ))}
      </div>

      {/* Horizontal Scroll Container */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex gap-4 overflow-x-auto snap-x snap-mandatory scrollbar-hide px-4"
      >
        {stages.map((stage, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.1 }}
            className="min-w-[80vw] snap-center"
          >
            <MobileCard>
              <div className="mb-4">
                <h3 className="text-[16px] font-medium text-black dark:text-white">
                  {stage.name}
                </h3>
                <div className="flex items-center gap-2 text-[12px] text-black/64 dark:text-white/64">
                  <span>{stage.deals} deals</span>
                  <span>•</span>
                  <span>{stage.value}</span>
                </div>
              </div>

              {/* Deal Cards */}
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, j) => (
                  <div
                    key={j}
                    className="p-3 bg-black/2 dark:bg-white/2 rounded"
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="text-[13px] font-medium text-black dark:text-white">
                          Company {j + 1}
                        </div>
                        <div className="text-[11px] text-black/64 dark:text-white/64">
                          {3 + j * 2} days in stage
                        </div>
                      </div>
                      <div className="text-[13px] font-medium text-black dark:text-white">
                        ${25 + j * 10}K
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </MobileCard>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default {
  MobileNavigation,
  MobileHeader,
  MobileCard,
  MobileMetric,
  MobileBottomSheet,
  MobileList,
  MobileDashboard,
  MobilePipeline
};