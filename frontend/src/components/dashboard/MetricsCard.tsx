import React from 'react';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/utils/cn';

interface MetricsCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  subtitle?: string;
  colorClass?: string;
}

/**
 * Reusable metrics card for dashboard KPIs
 */
export const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  subtitle,
  colorClass = 'bg-brand-primary-600',
}) => {
  return (
    <div className="rounded-sm border border-stroke bg-white px-7.5 py-6 shadow-default dark:border-strokedark dark:bg-boxdark">
      <div className="flex items-start justify-between">
        <div className="flex flex-col gap-2">
          <h4 className="text-title-md font-bold text-black dark:text-white">
            {value}
          </h4>
          <span className="text-sm font-medium">{title}</span>
          {subtitle && (
            <span className="text-xs text-bodydark">{subtitle}</span>
          )}
        </div>

        <div
          className={cn(
            'flex h-11.5 w-11.5 items-center justify-center rounded-full',
            colorClass
          )}
        >
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>

      {trend && (
        <div className="mt-4 flex items-center gap-2">
          <span
            className={cn(
              'flex items-center gap-1 text-sm font-medium',
              trend.isPositive ? 'text-meta-3' : 'text-meta-1'
            )}
          >
            {trend.isPositive ? '↑' : '↓'}
            {Math.abs(trend.value)}%
          </span>
          <span className="text-sm text-bodydark">vs last month</span>
        </div>
      )}
    </div>
  );
};
