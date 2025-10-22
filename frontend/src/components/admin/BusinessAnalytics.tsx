/**
 * Business Analytics Component
 * Business intelligence with revenue trends and top performers
 */

import { useQuery } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8790';

interface RevenueTrend {
  month: string;
  revenue: number;
  transactions: number;
}

interface UserGrowth {
  month: string;
  new_users: number;
}

interface TopBusiness {
  id: string;
  name: string;
  total_revenue: number;
  transaction_count: number;
}

export default function BusinessAnalytics() {
  const userId = localStorage.getItem('userId');
  const token = localStorage.getItem('token');

  // Fetch business intelligence
  const { data: biData, isLoading } = useQuery({
    queryKey: ['admin', 'business-intelligence'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/admin/analytics/business-intelligence`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-User-ID': userId || ''
        }
      });
      if (!response.ok) throw new Error('Failed to fetch business intelligence');
      return response.json();
    },
    refetchInterval: 60000 // Refresh every minute
  });

  const revenueTrend: RevenueTrend[] = biData?.data?.revenueTrend || [];
  const userGrowth: UserGrowth[] = biData?.data?.userGrowth || [];
  const topBusinesses: TopBusiness[] = biData?.data?.topBusinesses || [];

  // Calculate totals
  const totalRevenue = revenueTrend.reduce((sum, item) => sum + (item.revenue || 0), 0);
  const totalTransactions = revenueTrend.reduce((sum, item) => sum + (item.transactions || 0), 0);
  const totalNewUsers = userGrowth.reduce((sum, item) => sum + (item.new_users || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Business Analytics
        </h2>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          12-month business intelligence and performance trends
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SummaryCard
          title="Total Revenue (12 months)"
          value={`$${totalRevenue.toLocaleString()}`}
          subtitle={`${totalTransactions.toLocaleString()} transactions`}
          loading={isLoading}
        />
        <SummaryCard
          title="New Users (12 months)"
          value={totalNewUsers.toLocaleString()}
          subtitle="Total signups"
          loading={isLoading}
        />
        <SummaryCard
          title="Top Businesses"
          value={topBusinesses.length.toString()}
          subtitle="Active businesses"
          loading={isLoading}
        />
      </div>

      {/* Revenue Trend Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          Revenue Trend (12 Months)
        </h3>
        {isLoading ? (
          <div className="h-64 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
        ) : revenueTrend.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-gray-500 dark:text-gray-400">
            No revenue data available
          </div>
        ) : (
          <div className="space-y-3">
            {revenueTrend.map((item, idx) => {
              const maxRevenue = Math.max(...revenueTrend.map(r => r.revenue || 0));
              const percentage = maxRevenue > 0 ? ((item.revenue || 0) / maxRevenue) * 100 : 0;

              return (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-300 font-medium">
                      {item.month}
                    </span>
                    <span className="text-gray-900 dark:text-white font-bold">
                      ${(item.revenue || 0).toLocaleString()}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                    <div
                      className="bg-blue-600 h-3 rounded-full transition-all duration-500"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    {item.transactions || 0} transactions
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* User Growth Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          User Growth (12 Months)
        </h3>
        {isLoading ? (
          <div className="h-64 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
        ) : userGrowth.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-gray-500 dark:text-gray-400">
            No user growth data available
          </div>
        ) : (
          <div className="space-y-3">
            {userGrowth.map((item, idx) => {
              const maxUsers = Math.max(...userGrowth.map(u => u.new_users || 0));
              const percentage = maxUsers > 0 ? ((item.new_users || 0) / maxUsers) * 100 : 0;

              return (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-300 font-medium">
                      {item.month}
                    </span>
                    <span className="text-gray-900 dark:text-white font-bold">
                      {item.new_users || 0} new users
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                    <div
                      className="bg-green-600 h-3 rounded-full transition-all duration-500"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Top Performing Businesses */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Top Performing Businesses
          </h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Ranked by total revenue
          </p>
        </div>

        {isLoading ? (
          <div className="p-8 text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-blue-600 border-r-transparent"></div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Loading businesses...</p>
          </div>
        ) : topBusinesses.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-500 dark:text-gray-400">No business data available</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Rank
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Business Name
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Revenue
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Transactions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {topBusinesses.map((business, idx) => (
                  <tr key={business.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center justify-center h-8 w-8 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300 font-bold">
                        {idx + 1}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {business.name}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="text-sm font-bold text-gray-900 dark:text-white">
                        ${(business.total_revenue || 0).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {business.transaction_count || 0}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// Summary Card Component
function SummaryCard({ title, value, subtitle, loading }: {
  title: string;
  value: string;
  subtitle: string;
  loading?: boolean;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
        {title}
      </div>
      {loading ? (
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
      ) : (
        <>
          <div className="text-3xl font-bold text-gray-900 dark:text-white">
            {value}
          </div>
          <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {subtitle}
          </div>
        </>
      )}
    </div>
  );
}
