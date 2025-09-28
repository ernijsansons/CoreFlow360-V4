import React, { useState, useMemo, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  AreaChart,
  Area,
  PieChart,
  Pie,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ComposedChart,
  Scatter,
  Treemap
} from 'recharts';
import {
  TrendingUp,
  TrendingDown,
  Activity,
  BarChart3,
  PieChart as PieChartIcon,
  Target,
  Zap,
  Globe,
  Users,
  DollarSign,
  Package,
  ShoppingCart,
  Calendar,
  Filter,
  Download,
  Maximize2,
  RefreshCw,
  Info,
  ChevronRight,
  Eye,
  Brain,
  Layers,
  GitBranch
} from 'lucide-react';

interface BusinessData {
  id: string;
  name: string;
  revenue: number[];
  customers: number[];
  growth: number;
  marketShare: number;
  efficiency: number;
  satisfaction: number;
}

interface InsightCard {
  id: string;
  type: 'opportunity' | 'risk' | 'trend' | 'anomaly';
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  impact: string;
  action: string;
  metric?: number;
}

export const CrossBusinessIntelligence: React.FC = () => {
  const [selectedMetric, setSelectedMetric] = useState<string>('revenue');
  const [timeRange, setTimeRange] = useState<string>('30d');
  const [comparisonMode, setComparisonMode] = useState<boolean>(true);
  const [selectedBusinesses, setSelectedBusinesses] = useState<string[]>(['all']);

  // Mock data for demonstration
  const businessPerformanceData = [
    { month: 'Jan', TechFlow: 45000, StyleHub: 38000, ProConsult: 28000, Portfolio: 111000 },
    { month: 'Feb', TechFlow: 48000, StyleHub: 42000, ProConsult: 30000, Portfolio: 120000 },
    { month: 'Mar', TechFlow: 52000, StyleHub: 45000, ProConsult: 32000, Portfolio: 129000 },
    { month: 'Apr', TechFlow: 55000, StyleHub: 48000, ProConsult: 31000, Portfolio: 134000 },
    { month: 'May', TechFlow: 58000, StyleHub: 52000, ProConsult: 35000, Portfolio: 145000 },
    { month: 'Jun', TechFlow: 62000, StyleHub: 55000, ProConsult: 38000, Portfolio: 155000 },
  ];

  const marketShareData = [
    { name: 'TechFlow SaaS', value: 40, color: '#3b82f6' },
    { name: 'StyleHub Store', value: 35, color: '#a855f7' },
    { name: 'ProConsult', value: 25, color: '#10b981' },
  ];

  const efficiencyRadarData = [
    { metric: 'Automation', TechFlow: 95, StyleHub: 82, ProConsult: 78 },
    { metric: 'Productivity', TechFlow: 88, StyleHub: 90, ProConsult: 85 },
    { metric: 'Cost Efficiency', TechFlow: 92, StyleHub: 85, ProConsult: 88 },
    { metric: 'Resource Utilization', TechFlow: 87, StyleHub: 83, ProConsult: 90 },
    { metric: 'Customer Satisfaction', TechFlow: 94, StyleHub: 91, ProConsult: 96 },
    { metric: 'Innovation', TechFlow: 90, StyleHub: 86, ProConsult: 82 },
  ];

  const correlationData = [
    { x: 45, y: 92, z: 200, name: 'Marketing Spend vs Revenue' },
    { x: 38, y: 85, z: 150, name: 'Customer Support vs Satisfaction' },
    { x: 52, y: 78, z: 180, name: 'Product Dev vs Growth' },
    { x: 61, y: 88, z: 220, name: 'Sales Effort vs Conversion' },
    { x: 48, y: 95, z: 190, name: 'Automation vs Efficiency' },
  ];

  const insights: InsightCard[] = [
    {
      id: '1',
      type: 'opportunity',
      priority: 'high',
      title: 'Cross-Selling Opportunity Detected',
      description: 'StyleHub customers show high interest in TechFlow products based on behavior analysis',
      impact: 'Potential 25% revenue increase',
      action: 'Launch integrated marketing campaign',
      metric: 25
    },
    {
      id: '2',
      type: 'trend',
      priority: 'medium',
      title: 'Seasonal Pattern Emerging',
      description: 'Q2 shows consistent 18% growth across all businesses for 3 consecutive years',
      impact: 'Predictable revenue surge',
      action: 'Scale resources for Q2 demand',
      metric: 18
    },
    {
      id: '3',
      type: 'risk',
      priority: 'high',
      title: 'Resource Allocation Imbalance',
      description: 'ProConsult operating at 95% capacity while TechFlow has 30% idle resources',
      impact: 'Efficiency loss of $15k/month',
      action: 'Redistribute team resources',
      metric: -15000
    },
    {
      id: '4',
      type: 'anomaly',
      priority: 'low',
      title: 'Unusual Traffic Spike',
      description: 'StyleHub experienced 300% traffic increase from social media',
      impact: 'Conversion opportunity',
      action: 'Optimize landing pages',
      metric: 300
    }
  ];

  const getInsightIcon = (type: string) => {
    switch (type) {
      case 'opportunity':
        return <Zap className="h-4 w-4" />;
      case 'risk':
        return <AlertTriangle className="h-4 w-4" />;
      case 'trend':
        return <TrendingUp className="h-4 w-4" />;
      case 'anomaly':
        return <Activity className="h-4 w-4" />;
      default:
        return <Info className="h-4 w-4" />;
    }
  };

  const getInsightColor = (type: string, priority: string) => {
    if (type === 'risk') return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400';
    if (type === 'opportunity') return 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400';
    if (type === 'trend') return 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400';
    return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400';
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <div key={index} className="flex items-center justify-between gap-4 text-sm">
              <span style={{ color: entry.color }}>{entry.name}:</span>
              <span className="font-medium">${entry.value.toLocaleString()}</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-r from-purple-600 to-blue-600 rounded-xl">
              <Brain className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Cross-Business Intelligence
              </h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                AI-powered insights across your entire portfolio
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg"
            >
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="90d">Last 90 days</option>
              <option value="1y">Last year</option>
            </select>
            <button className="p-2 bg-white dark:bg-gray-800 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
              <RefreshCw className="h-4 w-4" />
            </button>
            <button className="px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg hover:from-purple-700 hover:to-blue-700">
              <Download className="h-4 w-4 inline mr-2" />
              Export Report
            </button>
          </div>
        </div>
      </div>

      {/* AI Insights Cards */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-purple-600" />
          AI-Generated Insights
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {insights.map((insight) => (
            <motion.div
              key={insight.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-start justify-between mb-3">
                <div className={`p-2 rounded-lg ${getInsightColor(insight.type, insight.priority)}`}>
                  {getInsightIcon(insight.type)}
                </div>
                <span className={`text-xs px-2 py-1 rounded-full ${
                  insight.priority === 'high' ? 'bg-red-100 text-red-700' :
                  insight.priority === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                  'bg-gray-100 text-gray-700'
                }`}>
                  {insight.priority}
                </span>
              </div>
              <h3 className="font-medium text-gray-900 dark:text-white mb-2">
                {insight.title}
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                {insight.description}
              </p>
              <div className="flex items-center justify-between pt-3 border-t border-gray-200 dark:border-gray-700">
                <span className="text-sm font-medium text-gray-900 dark:text-white">
                  {insight.impact}
                </span>
                <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                  Act →
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Revenue Comparison Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-600" />
              Revenue Comparison
            </h3>
            <button className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
              <Maximize2 className="h-4 w-4 text-gray-600" />
            </button>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={businessPerformanceData}>
              <defs>
                <linearGradient id="colorTech" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorStyle" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorConsult" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis dataKey="month" />
              <YAxis />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              <Area type="monotone" dataKey="TechFlow" stroke="#3b82f6" fillOpacity={1} fill="url(#colorTech)" />
              <Area type="monotone" dataKey="StyleHub" stroke="#a855f7" fillOpacity={1} fill="url(#colorStyle)" />
              <Area type="monotone" dataKey="ProConsult" stroke="#10b981" fillOpacity={1} fill="url(#colorConsult)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Efficiency Radar Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Target className="h-5 w-5 text-purple-600" />
              Business Efficiency Matrix
            </h3>
            <button className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
              <Maximize2 className="h-4 w-4 text-gray-600" />
            </button>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={efficiencyRadarData}>
              <PolarGrid className="opacity-30" />
              <PolarAngleAxis dataKey="metric" className="text-xs" />
              <PolarRadiusAxis angle={90} domain={[0, 100]} />
              <Radar name="TechFlow" dataKey="TechFlow" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
              <Radar name="StyleHub" dataKey="StyleHub" stroke="#a855f7" fill="#a855f7" fillOpacity={0.6} />
              <Radar name="ProConsult" dataKey="ProConsult" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
              <Legend />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Secondary Charts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Market Share */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <PieChartIcon className="h-5 w-5 text-green-600" />
            Portfolio Distribution
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={marketShareData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {marketShareData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Growth Metrics */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-blue-600" />
            Growth Metrics
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-gray-600 dark:text-gray-400">Revenue Growth</span>
                <span className="text-sm font-medium text-green-600">+24.5%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div className="bg-gradient-to-r from-green-400 to-green-600 h-2 rounded-full" style={{ width: '78%' }} />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-gray-600 dark:text-gray-400">Customer Growth</span>
                <span className="text-sm font-medium text-blue-600">+18.2%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div className="bg-gradient-to-r from-blue-400 to-blue-600 h-2 rounded-full" style={{ width: '65%' }} />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-gray-600 dark:text-gray-400">Market Expansion</span>
                <span className="text-sm font-medium text-purple-600">+31.8%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div className="bg-gradient-to-r from-purple-400 to-purple-600 h-2 rounded-full" style={{ width: '85%' }} />
              </div>
            </div>
          </div>
        </div>

        {/* Correlation Analysis */}
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-orange-600" />
            Correlation Insights
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm text-gray-700 dark:text-gray-300">Marketing → Revenue</span>
              <span className="text-sm font-medium text-green-600">0.92</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm text-gray-700 dark:text-gray-300">Support → Retention</span>
              <span className="text-sm font-medium text-blue-600">0.87</span>
            </div>
            <div className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-900 rounded-lg">
              <span className="text-sm text-gray-700 dark:text-gray-300">Innovation → Growth</span>
              <span className="text-sm font-medium text-purple-600">0.78</span>
            </div>
          </div>
        </div>
      </div>

      {/* Predictive Analytics Section */}
      <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Layers className="h-5 w-5 text-indigo-600" />
            Predictive Analytics & Forecasting
          </h3>
          <div className="flex items-center gap-2">
            <button className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600">
              Configure Model
            </button>
            <button className="px-3 py-1 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700">
              Run Analysis
            </button>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 rounded-lg">
            <p className="text-sm text-blue-700 dark:text-blue-400 mb-1">Q3 Revenue Forecast</p>
            <p className="text-2xl font-bold text-blue-900 dark:text-blue-300">$487K</p>
            <p className="text-xs text-blue-600 dark:text-blue-500 mt-1">95% confidence</p>
          </div>
          <div className="p-4 bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 rounded-lg">
            <p className="text-sm text-green-700 dark:text-green-400 mb-1">Customer Acquisition</p>
            <p className="text-2xl font-bold text-green-900 dark:text-green-300">+2,847</p>
            <p className="text-xs text-green-600 dark:text-green-500 mt-1">Next 30 days</p>
          </div>
          <div className="p-4 bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 rounded-lg">
            <p className="text-sm text-purple-700 dark:text-purple-400 mb-1">Churn Risk</p>
            <p className="text-2xl font-bold text-purple-900 dark:text-purple-300">2.1%</p>
            <p className="text-xs text-purple-600 dark:text-purple-500 mt-1">147 accounts at risk</p>
          </div>
          <div className="p-4 bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900/20 dark:to-orange-800/20 rounded-lg">
            <p className="text-sm text-orange-700 dark:text-orange-400 mb-1">Resource Needs</p>
            <p className="text-2xl font-bold text-orange-900 dark:text-orange-300">+12</p>
            <p className="text-xs text-orange-600 dark:text-orange-500 mt-1">Team members by Q4</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CrossBusinessIntelligence;