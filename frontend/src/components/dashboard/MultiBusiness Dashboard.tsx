import React, { useState, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Building2,
  TrendingUp,
  Users,
  DollarSign,
  Package,
  Bot,
  Brain,
  Activity,
  Globe,
  ArrowUpRight,
  ArrowDownRight,
  ChevronRight,
  Plus,
  Settings,
  BarChart3,
  PieChart,
  LineChart,
  Zap,
  Shield,
  Bell,
  Search,
  Filter,
  Calendar,
  Download,
  RefreshCw,
  MoreVertical,
  CheckCircle,
  AlertCircle,
  Clock
} from 'lucide-react';

interface Business {
  id: string;
  name: string;
  type: string;
  logo?: string;
  status: 'active' | 'paused' | 'maintenance';
  metrics: {
    revenue: number;
    revenueChange: number;
    customers: number;
    customersChange: number;
    health: number;
    aiAgents: number;
  };
}

interface AIAgent {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'idle' | 'processing';
  tasksCompleted: number;
  efficiency: number;
  lastAction: string;
  businessId: string;
}

export const MultiBusinessDashboard: React.FC = () => {
  const [selectedBusiness, setSelectedBusiness] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('7d');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  // Mock data for demonstration
  const businesses: Business[] = [
    {
      id: 'saas-1',
      name: 'TechFlow SaaS',
      type: 'Software',
      status: 'active',
      metrics: {
        revenue: 248592,
        revenueChange: 18.3,
        customers: 1847,
        customersChange: 12.5,
        health: 94,
        aiAgents: 5
      }
    },
    {
      id: 'ecom-1',
      name: 'StyleHub Store',
      type: 'E-commerce',
      status: 'active',
      metrics: {
        revenue: 185420,
        revenueChange: 24.7,
        customers: 5832,
        customersChange: 15.2,
        health: 88,
        aiAgents: 4
      }
    },
    {
      id: 'consulting-1',
      name: 'ProConsult',
      type: 'Consulting',
      status: 'active',
      metrics: {
        revenue: 142300,
        revenueChange: -5.2,
        customers: 48,
        customersChange: 8.1,
        health: 76,
        aiAgents: 3
      }
    }
  ];

  const aiAgents: AIAgent[] = [
    {
      id: 'agent-1',
      name: 'Finance Orchestrator',
      type: 'Financial',
      status: 'active',
      tasksCompleted: 1247,
      efficiency: 98,
      lastAction: 'Reconciled Q1 transactions',
      businessId: 'saas-1'
    },
    {
      id: 'agent-2',
      name: 'Customer Success AI',
      type: 'CRM',
      status: 'processing',
      tasksCompleted: 892,
      efficiency: 94,
      lastAction: 'Processing support tickets',
      businessId: 'saas-1'
    },
    {
      id: 'agent-3',
      name: 'Inventory Manager',
      type: 'Operations',
      status: 'active',
      tasksCompleted: 563,
      efficiency: 91,
      lastAction: 'Optimized stock levels',
      businessId: 'ecom-1'
    }
  ];

  const totalMetrics = useMemo(() => {
    const totals = businesses.reduce(
      (acc, business) => ({
        revenue: acc.revenue + business.metrics.revenue,
        customers: acc.customers + business.metrics.customers,
        aiAgents: acc.aiAgents + business.metrics.aiAgents,
        avgHealth: acc.avgHealth + business.metrics.health / businesses.length
      }),
      { revenue: 0, customers: 0, aiAgents: 0, avgHealth: 0 }
    );

    return {
      ...totals,
      revenueChange: 15.8, // Calculated average
      customersChange: 11.9 // Calculated average
    };
  }, [businesses]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-500 bg-green-100 dark:bg-green-900/20';
      case 'processing':
        return 'text-blue-500 bg-blue-100 dark:bg-blue-900/20';
      case 'idle':
        return 'text-gray-500 bg-gray-100 dark:bg-gray-900/20';
      case 'paused':
        return 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900/20';
      default:
        return 'text-gray-500 bg-gray-100 dark:bg-gray-900/20';
    }
  };

  const getHealthColor = (health: number) => {
    if (health >= 90) return 'text-green-500';
    if (health >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl">
              <Building2 className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Multi-Business Portfolio
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Managing {businesses.length} businesses with {totalMetrics.aiAgents} AI agents
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm hover:shadow-md transition-shadow">
              <Calendar className="h-4 w-4" />
              <span className="text-sm">{timeRange === '7d' ? 'Last 7 days' : timeRange}</span>
            </button>
            <button className="p-2 bg-white dark:bg-gray-800 rounded-lg shadow-sm hover:shadow-md transition-shadow">
              <RefreshCw className="h-4 w-4" />
            </button>
            <button className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-colors">
              <Plus className="h-4 w-4" />
              Add Business
            </button>
          </div>
        </div>
      </div>

      {/* Portfolio Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
              <DollarSign className="h-5 w-5 text-green-600" />
            </div>
            <span className="flex items-center gap-1 text-sm text-green-600">
              <ArrowUpRight className="h-3 w-3" />
              {totalMetrics.revenueChange}%
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Total Revenue</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            ${totalMetrics.revenue.toLocaleString()}
          </p>
          <p className="text-xs text-gray-500 mt-2">Across all businesses</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <Users className="h-5 w-5 text-blue-600" />
            </div>
            <span className="flex items-center gap-1 text-sm text-green-600">
              <ArrowUpRight className="h-3 w-3" />
              {totalMetrics.customersChange}%
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Total Customers</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {totalMetrics.customers.toLocaleString()}
          </p>
          <p className="text-xs text-gray-500 mt-2">Active customers</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Bot className="h-5 w-5 text-purple-600" />
            </div>
            <span className="flex items-center gap-1 text-sm text-green-600">
              <CheckCircle className="h-3 w-3" />
              Active
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">AI Agents</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {totalMetrics.aiAgents}
          </p>
          <p className="text-xs text-gray-500 mt-2">Automating operations</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="p-2 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg">
              <Activity className="h-5 w-5 text-yellow-600" />
            </div>
            <span className={`flex items-center gap-1 text-sm ${getHealthColor(totalMetrics.avgHealth)}`}>
              <Activity className="h-3 w-3" />
              {Math.round(totalMetrics.avgHealth)}%
            </span>
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Portfolio Health</p>
          <div className="mt-3">
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className={`h-2 rounded-full bg-gradient-to-r ${
                  totalMetrics.avgHealth >= 90
                    ? 'from-green-400 to-green-600'
                    : totalMetrics.avgHealth >= 70
                    ? 'from-yellow-400 to-yellow-600'
                    : 'from-red-400 to-red-600'
                }`}
                style={{ width: `${totalMetrics.avgHealth}%` }}
              />
            </div>
          </div>
          <p className="text-xs text-gray-500 mt-2">Overall performance</p>
        </motion.div>
      </div>

      {/* Business Cards Grid */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Business Overview
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-lg ${
                viewMode === 'grid'
                  ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-600'
                  : 'bg-white dark:bg-gray-800 text-gray-600'
              }`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <rect x="3" y="3" width="7" height="7" strokeWidth="2" />
                <rect x="14" y="3" width="7" height="7" strokeWidth="2" />
                <rect x="3" y="14" width="7" height="7" strokeWidth="2" />
                <rect x="14" y="14" width="7" height="7" strokeWidth="2" />
              </svg>
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded-lg ${
                viewMode === 'list'
                  ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-600'
                  : 'bg-white dark:bg-gray-800 text-gray-600'
              }`}
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <line x1="3" y1="6" x2="21" y2="6" strokeWidth="2" />
                <line x1="3" y1="12" x2="21" y2="12" strokeWidth="2" />
                <line x1="3" y1="18" x2="21" y2="18" strokeWidth="2" />
              </svg>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {businesses.map((business, index) => (
            <motion.div
              key={business.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.1 }}
              className="bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-shadow cursor-pointer"
              onClick={() => setSelectedBusiness(business.id)}
            >
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg">
                      <Building2 className="h-5 w-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        {business.name}
                      </h3>
                      <p className="text-sm text-gray-500">{business.type}</p>
                    </div>
                  </div>
                  <span
                    className={`px-2 py-1 text-xs font-medium rounded-full ${
                      business.status === 'active'
                        ? 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                        : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400'
                    }`}
                  >
                    {business.status}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Revenue</p>
                    <p className="text-lg font-semibold text-gray-900 dark:text-white">
                      ${(business.metrics.revenue / 1000).toFixed(0)}k
                    </p>
                    <p
                      className={`text-xs flex items-center gap-1 ${
                        business.metrics.revenueChange >= 0 ? 'text-green-600' : 'text-red-600'
                      }`}
                    >
                      {business.metrics.revenueChange >= 0 ? (
                        <ArrowUpRight className="h-3 w-3" />
                      ) : (
                        <ArrowDownRight className="h-3 w-3" />
                      )}
                      {Math.abs(business.metrics.revenueChange)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Customers</p>
                    <p className="text-lg font-semibold text-gray-900 dark:text-white">
                      {business.metrics.customers.toLocaleString()}
                    </p>
                    <p
                      className={`text-xs flex items-center gap-1 ${
                        business.metrics.customersChange >= 0 ? 'text-green-600' : 'text-red-600'
                      }`}
                    >
                      {business.metrics.customersChange >= 0 ? (
                        <ArrowUpRight className="h-3 w-3" />
                      ) : (
                        <ArrowDownRight className="h-3 w-3" />
                      )}
                      {Math.abs(business.metrics.customersChange)}%
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex items-center gap-2">
                    <Bot className="h-4 w-4 text-purple-600" />
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {business.metrics.aiAgents} AI Agents
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Activity className={`h-4 w-4 ${getHealthColor(business.metrics.health)}`} />
                    <span className="text-sm font-medium">
                      {business.metrics.health}% Health
                    </span>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* AI Agents Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Brain className="h-5 w-5 text-purple-600" />
            </div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              Autonomous AI Agents
            </h2>
          </div>
          <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">
            View All Agents →
          </button>
        </div>

        <div className="space-y-4">
          {aiAgents.map((agent) => (
            <div
              key={agent.id}
              className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-900 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              <div className="flex items-center gap-4">
                <div className={`p-2 rounded-lg ${getStatusColor(agent.status)}`}>
                  <Bot className="h-4 w-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-gray-900 dark:text-white">{agent.name}</p>
                    <span className="px-2 py-0.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                      {agent.type}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    {agent.lastAction}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-6">
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {agent.tasksCompleted}
                  </p>
                  <p className="text-xs text-gray-500">Tasks</p>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    {agent.efficiency}%
                  </p>
                  <p className="text-xs text-gray-500">Efficiency</p>
                </div>
                <button className="p-2 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-lg transition-colors">
                  <MoreVertical className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default MultiBusinessDashboard;