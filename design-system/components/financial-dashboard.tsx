/**
 * FINANCIAL DASHBOARDS - Numbers as Art
 * Data visualization that would make Tufte weep with joy
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence, useMotionValue, useTransform, animate } from 'framer-motion';
import {
  TrendingUp, TrendingDown, DollarSign, Percent, Calendar,
  ArrowUp, ArrowDown, Activity, BarChart3, PieChart,
  Target, AlertTriangle, CheckCircle, Info
} from 'lucide-react';

// ============================================
// METRIC CARD - Single number with maximum impact
// ============================================

interface MetricCardProps {
  title: string;
  value: number | string;
  format?: 'currency' | 'percentage' | 'number' | 'compact';
  change?: number;
  changeLabel?: string;
  sparkline?: number[];
  target?: number;
  status?: 'success' | 'warning' | 'danger' | 'neutral';
  detail?: string;
  icon?: React.ReactNode;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  format = 'number',
  change,
  changeLabel = 'vs last period',
  sparkline,
  target,
  status = 'neutral',
  detail,
  icon
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const displayValue = useMotionValue(0);

  // Animate number changes
  useEffect(() => {
    const numValue = typeof value === 'string' ? parseFloat(value.replace(/[^0-9.-]/g, '')) : value;
    if (!isNaN(numValue)) {
      animate(displayValue, numValue, {
        duration: 0.8,
        ease: [0.4, 0, 0.2, 1]
      });
    }
  }, [value, displayValue]);

  const formatValue = (val: number) => {
    switch (format) {
      case 'currency':
        if (val >= 1000000) return `$${(val / 1000000).toFixed(1)}M`;
        if (val >= 1000) return `$${(val / 1000).toFixed(0)}K`;
        return `$${val.toFixed(0)}`;
      case 'percentage':
        return `${val.toFixed(1)}%`;
      case 'compact':
        if (val >= 1000000) return `${(val / 1000000).toFixed(1)}M`;
        if (val >= 1000) return `${(val / 1000).toFixed(0)}K`;
        return val.toFixed(0);
      default:
        return val.toLocaleString();
    }
  };

  const statusColors = {
    success: 'text-green-600 dark:text-green-400',
    warning: 'text-amber-600 dark:text-amber-400',
    danger: 'text-red-600 dark:text-red-400',
    neutral: 'text-black dark:text-white'
  };

  const animatedValue = useTransform(displayValue, (val) => formatValue(val));

  return (
    <motion.div
      className="relative p-6 bg-white dark:bg-black border border-black/8 dark:border-white/8"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      whileHover={{ scale: 1.01 }}
      transition={{ duration: 0.2 }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide">
          {title}
        </h3>
        {icon && (
          <div className="w-4 h-4 text-black/36 dark:text-white/36">
            {icon}
          </div>
        )}
      </div>

      {/* Main Value */}
      <div className={`text-[40px] font-medium leading-none ${statusColors[status]}`}>
        <motion.span>
          {typeof value === 'string' ? value : animatedValue}
        </motion.span>
      </div>

      {/* Change Indicator */}
      {change !== undefined && (
        <div className="flex items-center gap-2 mt-3">
          <div className={`flex items-center gap-1 ${change >= 0 ? 'text-green-600' : 'text-red-600'}`}>
            {change >= 0 ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />}
            <span className="text-[13px] font-medium">
              {Math.abs(change).toFixed(1)}%
            </span>
          </div>
          <span className="text-[11px] text-black/36 dark:text-white/36">
            {changeLabel}
          </span>
        </div>
      )}

      {/* Sparkline */}
      {sparkline && sparkline.length > 0 && (
        <div className="mt-4 h-12 flex items-end gap-px">
          {sparkline.map((point, i) => {
            const height = (point / Math.max(...sparkline)) * 100;
            return (
              <motion.div
                key={i}
                className="flex-1 bg-current opacity-20"
                initial={{ height: 0 }}
                animate={{ height: `${height}%` }}
                transition={{ delay: i * 0.02, duration: 0.3 }}
              />
            );
          })}
        </div>
      )}

      {/* Target Progress */}
      {target && (
        <div className="mt-4">
          <div className="flex justify-between text-[11px] text-black/36 dark:text-white/36 mb-1">
            <span>Target</span>
            <span>{formatValue(target)}</span>
          </div>
          <div className="h-1 bg-black/8 dark:bg-white/8 overflow-hidden">
            <motion.div
              className={`h-full ${
                typeof value === 'number' && value >= target
                  ? 'bg-green-500'
                  : 'bg-blue-500'
              }`}
              initial={{ width: 0 }}
              animate={{
                width: `${Math.min((typeof value === 'number' ? value : 0) / target * 100, 100)}%`
              }}
              transition={{ duration: 0.8, ease: [0.4, 0, 0.2, 1] }}
            />
          </div>
        </div>
      )}

      {/* Hover Detail */}
      <AnimatePresence>
        {isHovered && detail && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            className="absolute top-full left-0 right-0 mt-2 p-3 bg-black text-white dark:bg-white dark:text-black text-[13px] z-10"
          >
            {detail}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// ============================================
// LINE CHART - Smooth, interactive trends
// ============================================

interface DataPoint {
  x: string | number;
  y: number;
  label?: string;
}

interface LineChartProps {
  data: DataPoint[];
  height?: number;
  showAxis?: boolean;
  showGrid?: boolean;
  animate?: boolean;
  color?: string;
  fillOpacity?: number;
}

export const LineChart: React.FC<LineChartProps> = ({
  data,
  height = 200,
  showAxis = true,
  showGrid = true,
  animate = true,
  color = '#0066FF',
  fillOpacity = 0.1
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const { path, area, points } = useMemo(() => {
    if (data.length === 0) return { path: '', area: '', points: [] };

    const padding = 20;
    const width = 800; // We'll make this responsive
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;

    const xScale = (i: number) => padding + (i / (data.length - 1)) * chartWidth;
    const yMin = Math.min(...data.map(d => d.y));
    const yMax = Math.max(...data.map(d => d.y));
    const yScale = (val: number) => {
      const normalized = (val - yMin) / (yMax - yMin);
      return padding + chartHeight - normalized * chartHeight;
    };

    const pathPoints = data.map((d, i) => ({
      x: xScale(i),
      y: yScale(d.y)
    }));

    // Create smooth path with bezier curves
    let path = `M ${pathPoints[0].x} ${pathPoints[0].y}`;
    for (let i = 1; i < pathPoints.length; i++) {
      const cp1x = pathPoints[i - 1].x + (pathPoints[i].x - pathPoints[i - 1].x) / 2;
      const cp1y = pathPoints[i - 1].y;
      const cp2x = pathPoints[i - 1].x + (pathPoints[i].x - pathPoints[i - 1].x) / 2;
      const cp2y = pathPoints[i].y;
      path += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${pathPoints[i].x} ${pathPoints[i].y}`;
    }

    // Create area path
    const area = `${path} L ${pathPoints[pathPoints.length - 1].x} ${height - padding} L ${pathPoints[0].x} ${height - padding} Z`;

    return { path, area, points: pathPoints };
  }, [data, height]);

  return (
    <div className="relative w-full" style={{ height }}>
      <svg
        ref={svgRef}
        className="w-full h-full"
        viewBox={`0 0 800 ${height}`}
        preserveAspectRatio="none"
      >
        {/* Grid Lines */}
        {showGrid && (
          <g className="opacity-10">
            {[0, 0.25, 0.5, 0.75, 1].map((y) => (
              <line
                key={y}
                x1={20}
                x2={780}
                y1={20 + y * (height - 40)}
                y2={20 + y * (height - 40)}
                stroke="currentColor"
                strokeWidth="1"
              />
            ))}
          </g>
        )}

        {/* Area Fill */}
        <motion.path
          d={area}
          fill={color}
          fillOpacity={fillOpacity}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        />

        {/* Line */}
        <motion.path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: animate ? 1 : 1 }}
          transition={{ duration: 1, ease: [0.4, 0, 0.2, 1] }}
        />

        {/* Interactive Points */}
        {points.map((point, i) => (
          <g key={i}>
            <motion.circle
              cx={point.x}
              cy={point.y}
              r={hoveredPoint === i ? 5 : 3}
              fill={color}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: i * 0.02 }}
              onMouseEnter={() => setHoveredPoint(i)}
              onMouseLeave={() => setHoveredPoint(null)}
              className="cursor-pointer"
            />
            {hoveredPoint === i && (
              <motion.g
                initial={{ opacity: 0, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <rect
                  x={point.x - 30}
                  y={point.y - 35}
                  width={60}
                  height={25}
                  rx={2}
                  fill="black"
                />
                <text
                  x={point.x}
                  y={point.y - 18}
                  textAnchor="middle"
                  fill="white"
                  fontSize="11"
                >
                  {data[i].y.toFixed(0)}
                </text>
              </motion.g>
            )}
          </g>
        ))}
      </svg>
    </div>
  );
};

// ============================================
// DONUT CHART - Beautiful proportions
// ============================================

interface DonutChartProps {
  data: { label: string; value: number; color: string }[];
  size?: number;
  thickness?: number;
  showLabels?: boolean;
  centerContent?: React.ReactNode;
}

export const DonutChart: React.FC<DonutChartProps> = ({
  data,
  size = 200,
  thickness = 40,
  showLabels = true,
  centerContent
}) => {
  const [hoveredSegment, setHoveredSegment] = useState<number | null>(null);

  const total = data.reduce((sum, d) => sum + d.value, 0);
  const radius = size / 2;
  const innerRadius = radius - thickness;

  let cumulativeAngle = -Math.PI / 2;

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        {data.map((segment, i) => {
          const angle = (segment.value / total) * Math.PI * 2;
          const startAngle = cumulativeAngle;
          const endAngle = cumulativeAngle + angle;
          cumulativeAngle = endAngle;

          const x1 = radius + Math.cos(startAngle) * innerRadius;
          const y1 = radius + Math.sin(startAngle) * innerRadius;
          const x2 = radius + Math.cos(startAngle) * radius;
          const y2 = radius + Math.sin(startAngle) * radius;
          const x3 = radius + Math.cos(endAngle) * radius;
          const y3 = radius + Math.sin(endAngle) * radius;
          const x4 = radius + Math.cos(endAngle) * innerRadius;
          const y4 = radius + Math.sin(endAngle) * innerRadius;

          const largeArc = angle > Math.PI ? 1 : 0;

          const path = `
            M ${x1} ${y1}
            L ${x2} ${y2}
            A ${radius} ${radius} 0 ${largeArc} 1 ${x3} ${y3}
            L ${x4} ${y4}
            A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${x1} ${y1}
          `;

          return (
            <motion.path
              key={i}
              d={path}
              fill={segment.color}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{
                opacity: hoveredSegment === null || hoveredSegment === i ? 1 : 0.5,
                scale: hoveredSegment === i ? 1.05 : 1
              }}
              transition={{ duration: 0.2 }}
              onMouseEnter={() => setHoveredSegment(i)}
              onMouseLeave={() => setHoveredSegment(null)}
              className="cursor-pointer transition-all"
              style={{ transformOrigin: `${radius}px ${radius}px` }}
            />
          );
        })}
      </svg>

      {/* Center Content */}
      {centerContent && (
        <div className="absolute inset-0 flex items-center justify-center">
          {centerContent}
        </div>
      )}

      {/* Hover Label */}
      <AnimatePresence>
        {hoveredSegment !== null && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="absolute inset-0 flex items-center justify-center pointer-events-none"
          >
            <div className="bg-black text-white dark:bg-white dark:text-black px-3 py-2 rounded">
              <div className="text-[11px] opacity-60">{data[hoveredSegment].label}</div>
              <div className="text-[16px] font-medium">
                {((data[hoveredSegment].value / total) * 100).toFixed(1)}%
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// ============================================
// FINANCIAL SUMMARY - Complete dashboard view
// ============================================

interface FinancialSummaryProps {
  revenue: {
    current: number;
    target: number;
    change: number;
    trend: DataPoint[];
  };
  expenses: {
    categories: { label: string; value: number; color: string }[];
    total: number;
    change: number;
  };
  profit: {
    margin: number;
    amount: number;
    change: number;
  };
  cashFlow: {
    data: DataPoint[];
    current: number;
  };
}

export const FinancialSummary: React.FC<FinancialSummaryProps> = ({
  revenue,
  expenses,
  profit,
  cashFlow
}) => {
  return (
    <div className="space-y-6">
      {/* Top KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <MetricCard
          title="Revenue"
          value={revenue.current}
          format="currency"
          change={revenue.change}
          target={revenue.target}
          status={revenue.change >= 0 ? 'success' : 'danger'}
          icon={<TrendingUp />}
        />
        <MetricCard
          title="Expenses"
          value={expenses.total}
          format="currency"
          change={expenses.change}
          status={expenses.change <= 0 ? 'success' : 'warning'}
          icon={<Activity />}
        />
        <MetricCard
          title="Profit Margin"
          value={profit.margin}
          format="percentage"
          change={profit.change}
          status={profit.margin >= 20 ? 'success' : 'warning'}
          icon={<Percent />}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Revenue Trend */}
        <div className="p-6 bg-white dark:bg-black border border-black/8 dark:border-white/8">
          <h3 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide mb-4">
            Revenue Trend
          </h3>
          <LineChart
            data={revenue.trend}
            height={200}
            color="#0066FF"
            fillOpacity={0.05}
          />
        </div>

        {/* Expense Breakdown */}
        <div className="p-6 bg-white dark:bg-black border border-black/8 dark:border-white/8">
          <h3 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide mb-4">
            Expense Categories
          </h3>
          <div className="flex items-center justify-center">
            <DonutChart
              data={expenses.categories}
              size={200}
              thickness={30}
              centerContent={
                <div className="text-center">
                  <div className="text-[11px] text-black/36 dark:text-white/36">Total</div>
                  <div className="text-[20px] font-medium text-black dark:text-white">
                    ${(expenses.total / 1000000).toFixed(1)}M
                  </div>
                </div>
              }
            />
          </div>
        </div>
      </div>

      {/* Cash Flow */}
      <div className="p-6 bg-white dark:bg-black border border-black/8 dark:border-white/8">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[13px] font-medium text-black/64 dark:text-white/64 uppercase tracking-wide">
            Cash Flow
          </h3>
          <div className="text-[20px] font-medium text-black dark:text-white">
            ${(cashFlow.current / 1000000).toFixed(1)}M
          </div>
        </div>
        <LineChart
          data={cashFlow.data}
          height={150}
          color={cashFlow.current >= 0 ? '#00C851' : '#FF3547'}
          showGrid={false}
        />
      </div>
    </div>
  );
};

export default {
  MetricCard,
  LineChart,
  DonutChart,
  FinancialSummary
};