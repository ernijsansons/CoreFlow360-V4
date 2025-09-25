/**
 * KEY SCREENS - Complete application experiences
 * Where all components come together in harmony
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Lock, Mail, ArrowRight, Sparkles, Command,
  Home, BarChart3, Users, Settings, Search, Bell,
  TrendingUp, DollarSign, Activity, Target,
  Calendar, Filter, Download, Share2, MoreHorizontal
} from 'lucide-react';

// Import all our components
import { Button, Input, Card, Text, Badge, Separator } from '../components/primitives';
import { CommandBar, IntelligentDashboard, DataTable } from '../components/signature-interfaces';
import { Pipeline, Deal } from '../components/pipeline-crm';
import { MetricCard, LineChart, DonutChart, FinancialSummary } from '../components/financial-dashboard';

// ============================================
// LOGIN SCREEN - First impression that lasts
// ============================================

export const LoginScreen: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async () => {
    setIsLoading(true);
    // Simulate login
    await new Promise(resolve => setTimeout(resolve, 1500));
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen flex">
      {/* Left Side - Form */}
      <div className="flex-1 flex items-center justify-center p-8 bg-white dark:bg-black">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="w-full max-w-md"
        >
          {/* Logo */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="mb-12"
          >
            <div className="w-12 h-12 bg-black dark:bg-white mb-4" />
            <Text variant="heading" weight="medium">
              Welcome to the future
            </Text>
            <Text variant="body" color="secondary" className="mt-2">
              Enterprise software that inspires
            </Text>
          </motion.div>

          {/* Form */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="space-y-6"
          >
            <Input
              type="email"
              label="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              icon={<Mail className="w-4 h-4" />}
            />

            <Input
              type="password"
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              icon={<Lock className="w-4 h-4" />}
            />

            <div className="flex items-center justify-between text-[13px]">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" className="w-4 h-4" />
                <span className="text-black/64 dark:text-white/64">Remember me</span>
              </label>
              <a href="#" className="text-blue-600 hover:text-blue-700">
                Forgot password?
              </a>
            </div>

            <Button
              variant="primary"
              size="default"
              onClick={handleLogin}
              loading={isLoading}
              className="w-full"
            >
              Sign in
            </Button>

            <div className="text-center text-[13px] text-black/36 dark:text-white/36">
              Press <kbd className="px-1.5 py-0.5 bg-black/8 dark:bg-white/8 rounded">⌘K</kbd> to use command palette
            </div>
          </motion.div>

          {/* Footer */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
            className="mt-12 text-center text-[11px] text-black/36 dark:text-white/36"
          >
            By continuing, you agree to our Terms of Service
          </motion.div>
        </motion.div>
      </div>

      {/* Right Side - Visual */}
      <div className="flex-1 bg-gradient-to-br from-blue-600 to-blue-400 p-8 hidden lg:flex items-center justify-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8 }}
          className="text-white text-center"
        >
          <Sparkles className="w-16 h-16 mx-auto mb-6" />
          <h2 className="text-[40px] font-medium leading-tight mb-4">
            Work beautifully
          </h2>
          <p className="text-[16px] opacity-90 max-w-md">
            Experience enterprise software that doesn't just function—it inspires.
            Every pixel crafted for productivity and joy.
          </p>

          {/* Floating metrics preview */}
          <motion.div
            animate={{ y: [0, -10, 0] }}
            transition={{ duration: 4, repeat: Infinity }}
            className="mt-12 grid grid-cols-3 gap-4"
          >
            {[
              { value: '$2.4M', label: 'Revenue' },
              { value: '94%', label: 'Efficiency' },
              { value: '1.2K', label: 'Customers' }
            ].map((metric, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.8 + i * 0.1 }}
                className="bg-white/10 backdrop-blur p-4 rounded"
              >
                <div className="text-[20px] font-medium">{metric.value}</div>
                <div className="text-[11px] opacity-75">{metric.label}</div>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
};

// ============================================
// MAIN DASHBOARD - Command center
// ============================================

export const DashboardScreen: React.FC = () => {
  const [timeRange, setTimeRange] = useState('today');
  const [showCommandBar, setShowCommandBar] = useState(false);

  // Sample data
  const primaryMetric = {
    id: 'revenue',
    value: 2437650,
    label: 'Total Revenue',
    change: 12.5,
    trend: 'up' as const,
    detail: 'On track to exceed quarterly target by 18%'
  };

  const secondaryMetrics = [
    {
      id: 'customers',
      value: 1284,
      label: 'Active Customers',
      change: 8.3,
      trend: 'up' as const,
      priority: 'high' as const,
      sparkline: [40, 45, 42, 48, 52, 58, 61, 65]
    },
    {
      id: 'arpu',
      value: 1898,
      label: 'Average Revenue',
      change: 4.2,
      trend: 'up' as const,
      sparkline: [1750, 1780, 1820, 1850, 1870, 1890, 1895, 1898]
    },
    {
      id: 'churn',
      value: 2.1,
      label: 'Churn Rate %',
      change: -0.3,
      trend: 'down' as const,
      priority: 'medium' as const,
      sparkline: [2.4, 2.3, 2.2, 2.2, 2.1, 2.1, 2.1, 2.1]
    },
    {
      id: 'nps',
      value: 72,
      label: 'Net Promoter Score',
      change: 5,
      trend: 'up' as const,
      sparkline: [68, 69, 70, 71, 71, 72, 72, 72]
    }
  ];

  const recentActivity = [
    { id: '1', company: 'Acme Corp', amount: 125000, stage: 'Negotiation', daysInStage: 3, probability: 80 },
    { id: '2', company: 'TechStart Inc', amount: 85000, stage: 'Proposal', daysInStage: 5, probability: 60 },
    { id: '3', company: 'Global Systems', amount: 310000, stage: 'Qualification', daysInStage: 2, probability: 40 },
    { id: '4', company: 'Innovation Labs', amount: 92000, stage: 'Discovery', daysInStage: 7, probability: 25 },
    { id: '5', company: 'Future Works', amount: 178000, stage: 'Negotiation', daysInStage: 1, probability: 85 }
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <header className="h-16 bg-white dark:bg-black border-b border-black/8 dark:border-white/8">
        <div className="h-full max-w-[1440px] mx-auto px-6 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <div className="w-8 h-8 bg-black dark:bg-white" />
            <nav className="flex gap-6">
              {[
                { icon: Home, label: 'Dashboard', active: true },
                { icon: Users, label: 'Customers' },
                { icon: BarChart3, label: 'Analytics' },
                { icon: Settings, label: 'Settings' }
              ].map((item) => (
                <button
                  key={item.label}
                  className={`flex items-center gap-2 text-[13px] transition-colors ${
                    item.active
                      ? 'text-black dark:text-white'
                      : 'text-black/36 dark:text-white/36 hover:text-black dark:hover:text-white'
                  }`}
                >
                  <item.icon className="w-4 h-4" />
                  {item.label}
                </button>
              ))}
            </nav>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowCommandBar(true)}
              className="flex items-center gap-2 px-3 py-1.5 text-[13px] text-black/64 dark:text-white/64 hover:text-black dark:hover:text-white transition-colors"
            >
              <Search className="w-4 h-4" />
              <span>Search</span>
              <kbd className="px-1.5 py-0.5 text-[11px] bg-black/8 dark:bg-white/8 rounded">/</kbd>
            </button>
            <button className="relative p-2">
              <Bell className="w-4 h-4 text-black/64 dark:text-white/64" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
            </button>
            <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-400 rounded-full" />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1440px] mx-auto px-6 py-8">
        {/* Welcome Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-[28px] font-medium text-black dark:text-white mb-2">
            Good morning, Alex
          </h1>
          <p className="text-[16px] text-black/64 dark:text-white/64">
            Here's what's happening with your business today
          </p>
        </motion.div>

        {/* Intelligent Dashboard */}
        <div className="mb-8">
          <IntelligentDashboard
            primaryMetric={primaryMetric}
            secondaryMetrics={secondaryMetrics}
            onTimeRangeChange={setTimeRange}
          />
        </div>

        {/* Activity Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Recent Deals */}
          <div className="lg:col-span-2">
            <Card className="h-full">
              <div className="flex items-center justify-between mb-4">
                <Text variant="subheading" weight="medium">Recent Activity</Text>
                <button className="text-[13px] text-blue-600 hover:text-blue-700">
                  View all →
                </button>
              </div>
              <DataTable
                columns={[
                  { key: 'company', title: 'Company', sortable: true },
                  {
                    key: 'amount',
                    title: 'Value',
                    align: 'right',
                    render: (val) => `$${(val / 1000).toFixed(0)}K`,
                    sortable: true
                  },
                  {
                    key: 'stage',
                    title: 'Stage',
                    render: (val) => <Badge variant="default" size="small">{val}</Badge>
                  },
                  {
                    key: 'probability',
                    title: 'Probability',
                    align: 'right',
                    render: (val) => `${val}%`,
                    sortable: true
                  }
                ]}
                data={recentActivity}
                onRowClick={(row) => console.log('Clicked:', row)}
              />
            </Card>
          </div>

          {/* Quick Actions */}
          <div>
            <Card>
              <Text variant="subheading" weight="medium" className="mb-4">
                Quick Actions
              </Text>
              <div className="space-y-3">
                {[
                  { label: 'Create Invoice', icon: DollarSign, color: 'text-green-600' },
                  { label: 'Add Customer', icon: Users, color: 'text-blue-600' },
                  { label: 'Generate Report', icon: BarChart3, color: 'text-purple-600' },
                  { label: 'Schedule Meeting', icon: Calendar, color: 'text-orange-600' }
                ].map((action) => (
                  <button
                    key={action.label}
                    className="w-full flex items-center gap-3 p-3 text-left hover:bg-black/2 dark:hover:bg-white/2 transition-colors rounded"
                  >
                    <action.icon className={`w-4 h-4 ${action.color}`} />
                    <span className="text-[13px] text-black dark:text-white">
                      {action.label}
                    </span>
                    <ArrowRight className="w-3 h-3 ml-auto text-black/36 dark:text-white/36" />
                  </button>
                ))}
              </div>
            </Card>

            {/* AI Insights */}
            <Card className="mt-6 bg-gradient-to-br from-blue-500/5 to-transparent border-blue-500/20">
              <div className="flex items-start gap-3">
                <Sparkles className="w-4 h-4 text-blue-500 mt-1" />
                <div className="flex-1">
                  <Text variant="body" weight="medium" className="mb-1">
                    AI Insight
                  </Text>
                  <Text variant="caption" color="secondary">
                    3 deals are likely to close this week, potentially adding $518K to revenue.
                    Focus on Acme Corp - they're most ready to sign.
                  </Text>
                </div>
              </div>
            </Card>
          </div>
        </div>
      </main>

      {/* Command Bar */}
      {showCommandBar && (
        <CommandBar
          onCommand={(cmd) => console.log('Command:', cmd)}
          suggestions={[
            {
              id: '1',
              title: 'Create new invoice',
              description: 'Start a new invoice draft',
              category: 'Actions',
              action: () => console.log('Create invoice'),
              shortcut: '⌘I',
              icon: <DollarSign className="w-4 h-4" />
            },
            {
              id: '2',
              title: 'View analytics',
              description: 'Open analytics dashboard',
              category: 'Navigation',
              action: () => console.log('View analytics'),
              shortcut: '⌘A',
              icon: <BarChart3 className="w-4 h-4" />
            }
          ]}
        />
      )}
    </div>
  );
};

// ============================================
// ANALYTICS SCREEN - Data storytelling
// ============================================

export const AnalyticsScreen: React.FC = () => {
  const [selectedPeriod, setSelectedPeriod] = useState('month');
  const [selectedMetric, setSelectedMetric] = useState('revenue');

  // Sample data for visualizations
  const revenueData = {
    current: 2437650,
    target: 2500000,
    change: 12.5,
    trend: Array.from({ length: 30 }, (_, i) => ({
      x: i,
      y: 1800000 + Math.random() * 600000 + i * 20000
    }))
  };

  const expenseData = {
    categories: [
      { label: 'Salaries', value: 850000, color: '#0066FF' },
      { label: 'Marketing', value: 320000, color: '#00C851' },
      { label: 'Operations', value: 280000, color: '#FFBB33' },
      { label: 'Technology', value: 190000, color: '#FF3547' },
      { label: 'Other', value: 160000, color: '#AA66CC' }
    ],
    total: 1800000,
    change: -5.2
  };

  const profitData = {
    margin: 26.2,
    amount: 637650,
    change: 18.7
  };

  const cashFlowData = {
    data: Array.from({ length: 12 }, (_, i) => ({
      x: i,
      y: 500000 + Math.sin(i / 2) * 300000
    })),
    current: 750000
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <header className="bg-white dark:bg-black border-b border-black/8 dark:border-white/8">
        <div className="max-w-[1440px] mx-auto px-6 py-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-[28px] font-medium text-black dark:text-white">
                Analytics
              </h1>
              <p className="text-[13px] text-black/64 dark:text-white/64">
                Deep insights into your business performance
              </p>
            </div>

            <div className="flex items-center gap-3">
              <Button variant="secondary" size="small" icon={<Filter className="w-4 h-4" />}>
                Filter
              </Button>
              <Button variant="secondary" size="small" icon={<Download className="w-4 h-4" />}>
                Export
              </Button>
              <Button variant="secondary" size="small" icon={<Share2 className="w-4 h-4" />}>
                Share
              </Button>
            </div>
          </div>

          {/* Period Selector */}
          <div className="flex gap-1">
            {['day', 'week', 'month', 'quarter', 'year'].map((period) => (
              <button
                key={period}
                onClick={() => setSelectedPeriod(period)}
                className={`
                  px-4 py-2 text-[13px] capitalize transition-all duration-200
                  ${selectedPeriod === period
                    ? 'text-black dark:text-white bg-black/8 dark:bg-white/8'
                    : 'text-black/36 dark:text-white/36 hover:text-black dark:hover:text-white'
                  }
                `}
              >
                {period}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1440px] mx-auto px-6 py-8">
        {/* Financial Summary */}
        <FinancialSummary
          revenue={revenueData}
          expenses={expenseData}
          profit={profitData}
          cashFlow={cashFlowData}
        />

        {/* Detailed Metrics */}
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Conversion Funnel */}
          <Card>
            <Text variant="subheading" weight="medium" className="mb-4">
              Conversion Funnel
            </Text>
            <div className="space-y-3">
              {[
                { stage: 'Visitors', value: 45280, conversion: 100 },
                { stage: 'Leads', value: 8956, conversion: 19.8 },
                { stage: 'Opportunities', value: 1234, conversion: 13.8 },
                { stage: 'Customers', value: 287, conversion: 23.3 }
              ].map((item, i) => (
                <div key={item.stage}>
                  <div className="flex justify-between text-[13px] mb-1">
                    <span className="text-black dark:text-white">{item.stage}</span>
                    <span className="text-black/64 dark:text-white/64">
                      {item.value.toLocaleString()}
                    </span>
                  </div>
                  <div className="h-2 bg-black/8 dark:bg-white/8 overflow-hidden">
                    <motion.div
                      className="h-full bg-gradient-to-r from-blue-500 to-blue-400"
                      initial={{ width: 0 }}
                      animate={{ width: `${100 - i * 25}%` }}
                      transition={{ delay: i * 0.1, duration: 0.5 }}
                    />
                  </div>
                  {i < 3 && (
                    <div className="text-[11px] text-black/36 dark:text-white/36 mt-1 text-right">
                      {item.conversion}% conversion
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Card>

          {/* Top Products */}
          <Card>
            <Text variant="subheading" weight="medium" className="mb-4">
              Top Products
            </Text>
            <div className="space-y-3">
              {[
                { name: 'Enterprise Plan', revenue: 892000, growth: 15 },
                { name: 'Professional Plan', revenue: 654000, growth: 8 },
                { name: 'Starter Plan', revenue: 421000, growth: 22 },
                { name: 'Custom Solutions', revenue: 338000, growth: -5 },
                { name: 'Add-ons', revenue: 132000, growth: 31 }
              ].map((product) => (
                <div key={product.name} className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="text-[13px] text-black dark:text-white">
                      {product.name}
                    </div>
                    <div className="text-[11px] text-black/36 dark:text-white/36">
                      ${(product.revenue / 1000).toFixed(0)}K revenue
                    </div>
                  </div>
                  <div className={`flex items-center gap-1 text-[11px] ${
                    product.growth >= 0 ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {product.growth >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                    {Math.abs(product.growth)}%
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Performance Score */}
          <Card className="flex flex-col items-center justify-center text-center">
            <Text variant="subheading" weight="medium" className="mb-4">
              Performance Score
            </Text>
            <div className="relative">
              <DonutChart
                data={[
                  { label: 'Score', value: 87, color: '#0066FF' },
                  { label: 'Remaining', value: 13, color: '#E0E0E0' }
                ]}
                size={160}
                thickness={20}
                showLabels={false}
                centerContent={
                  <div>
                    <div className="text-[32px] font-medium text-black dark:text-white">87</div>
                    <div className="text-[11px] text-black/36 dark:text-white/36">Excellent</div>
                  </div>
                }
              />
            </div>
            <div className="mt-4 text-[11px] text-black/64 dark:text-white/64">
              Top 10% of similar companies
            </div>
          </Card>
        </div>

        {/* AI Analysis */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mt-8"
        >
          <Card className="bg-gradient-to-r from-blue-500/5 via-transparent to-transparent border-blue-500/20">
            <div className="flex items-start gap-4">
              <Sparkles className="w-5 h-5 text-blue-500 mt-1" />
              <div className="flex-1">
                <Text variant="body" weight="medium" className="mb-2">
                  AI-Powered Analysis
                </Text>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[13px] text-black/64 dark:text-white/64">
                  <div>
                    <strong className="text-black dark:text-white">Revenue Trend:</strong> Strong upward trajectory
                    with 12.5% MoM growth. Seasonal adjustment expected in Q4.
                  </div>
                  <div>
                    <strong className="text-black dark:text-white">Cost Optimization:</strong> Marketing spend
                    efficiency improved by 18%. Consider reallocating budget from Operations.
                  </div>
                  <div>
                    <strong className="text-black dark:text-white">Forecast:</strong> 94% probability of meeting
                    quarterly targets. Focus on Enterprise Plan upsells for maximum impact.
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </motion.div>
      </main>
    </div>
  );
};

export default {
  LoginScreen,
  DashboardScreen,
  AnalyticsScreen
};