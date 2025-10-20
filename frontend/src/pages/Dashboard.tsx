import React, { useEffect, useState } from 'react';
import { useDashboardStore } from '@/stores/dashboardStore';
import { MetricsCard } from '@/components/dashboard/MetricsCard';
import { SalesChart } from '@/components/dashboard/SalesChart';
import { RevenueChart } from '@/components/dashboard/RevenueChart';
import { CustomersTable } from '@/components/dashboard/CustomersTable';
import { AddLeadModal } from '@/components/dashboard/AddLeadModal';
import {
  Users,
  TrendingUp,
  DollarSign,
  UserCheck,
  Plus,
} from 'lucide-react';

/**
 * Main dashboard page composing all widgets
 * Displays KPI metrics, charts, and data tables
 */
export const Dashboard: React.FC = () => {
  const {
    metrics,
    customers,
    salesData,
    revenueData,
    isLoading,
    error,
    fetchDashboardData,
  } = useDashboardStore();

  const [isAddLeadModalOpen, setIsAddLeadModalOpen] = useState(false);

  // Fetch dashboard data on mount
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Loading state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-brand-primary-600 mx-auto mb-4"></div>
          <p className="text-lg text-bodydark dark:text-bodydark1">
            Loading dashboard...
          </p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center max-w-md">
          <div className="text-6xl mb-4">⚠️</div>
          <h3 className="text-xl font-semibold text-black dark:text-white mb-2">
            Failed to Load Dashboard
          </h3>
          <p className="text-bodydark dark:text-bodydark1 mb-4">{error}</p>
          <button
            onClick={fetchDashboardData}
            className="px-6 py-3 bg-brand-primary-600 text-white rounded-lg hover:bg-brand-primary-700 transition"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Page Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-black dark:text-white mb-2">
          Dashboard Overview
        </h1>
        <p className="text-bodydark dark:text-bodydark1">
          Welcome back! Here's your business performance at a glance.
        </p>
      </div>

      {/* KPI Metrics Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4 mb-6">
        <MetricsCard
          title="Total Leads"
          value={metrics?.totalLeads || 0}
          icon={Users}
          trend={{
            value: 12.5,
            isPositive: true,
          }}
          colorClass="bg-meta-5"
        />
        <MetricsCard
          title="Conversion Rate"
          value={`${metrics?.conversionRate || 0}%`}
          icon={TrendingUp}
          trend={{
            value: 3.2,
            isPositive: true,
          }}
          colorClass="bg-meta-3"
        />
        <MetricsCard
          title="Monthly Revenue"
          value={`$${metrics?.revenue.toLocaleString() || 0}`}
          icon={DollarSign}
          trend={{
            value: 8.1,
            isPositive: true,
          }}
          colorClass="bg-brand-primary-600"
        />
        <MetricsCard
          title="Active Customers"
          value={metrics?.activeCustomers || 0}
          icon={UserCheck}
          trend={{
            value: 2.3,
            isPositive: false,
          }}
          colorClass="bg-warning"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 mb-6">
        <SalesChart data={salesData} />
        <RevenueChart data={revenueData} />
      </div>

      {/* Customers Table with Add Lead Button */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-semibold text-black dark:text-white">
            Recent Activity
          </h2>
          <button
            onClick={() => setIsAddLeadModalOpen(true)}
            className="flex items-center gap-2 rounded-lg bg-brand-primary-600 px-5 py-2.5 text-white transition hover:bg-brand-primary-700"
          >
            <Plus className="h-5 w-5" />
            Add Lead
          </button>
        </div>
        <CustomersTable data={customers} />
      </div>

      {/* Add Lead Modal */}
      <AddLeadModal
        isOpen={isAddLeadModalOpen}
        onClose={() => setIsAddLeadModalOpen(false)}
      />
    </>
  );
};
