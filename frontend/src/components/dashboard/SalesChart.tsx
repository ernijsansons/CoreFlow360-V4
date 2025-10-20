import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { SalesData } from '@/utils/dashboardMockData';

interface SalesChartProps {
  data: SalesData[];
}

/**
 * Bar chart for quarterly sales data using Recharts
 */
export const SalesChart: React.FC<SalesChartProps> = React.memo(({ data }) => {
  return (
    <div className="rounded-sm border border-stroke bg-white p-7.5 shadow-default dark:border-strokedark dark:bg-boxdark">
      <div className="mb-4 flex items-center justify-between">
        <h4 className="text-xl font-semibold text-black dark:text-white">
          Quarterly Sales Performance
        </h4>
      </div>

      <div className="h-[350px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="quarter"
              stroke="#9CA3AF"
              tick={{ fill: '#9CA3AF' }}
            />
            <YAxis stroke="#9CA3AF" tick={{ fill: '#9CA3AF' }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1F2937',
                border: '1px solid #374151',
                borderRadius: '0.375rem',
                color: '#F9FAFB',
              }}
            />
            <Legend wrapperStyle={{ color: '#9CA3AF' }} />
            <Bar dataKey="leads" fill="#3B82F6" name="Total Leads" />
            <Bar dataKey="conversions" fill="#10B981" name="Conversions" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
});

SalesChart.displayName = 'SalesChart';
