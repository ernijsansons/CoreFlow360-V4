import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot,
  Brain,
  Cpu,
  MessageSquare,
  Zap,
  Play,
  Pause,
  Settings,
  CheckCircle,
  AlertCircle,
  Info,
  TrendingUp,
  Activity,
  Clock,
  BarChart3,
  Send,
  Mic,
  Paperclip,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Download,
  Upload,
  Shield,
  AlertTriangle,
  Command,
  Sparkles
} from 'lucide-react';

interface AIAgent {
  id: string;
  name: string;
  type: 'finance' | 'crm' | 'inventory' | 'compliance' | 'growth';
  status: 'active' | 'idle' | 'processing' | 'error' | 'learning';
  capabilities: string[];
  performance: {
    accuracy: number;
    speed: number;
    reliability: number;
    efficiency: number;
  };
  currentTask?: {
    id: string;
    description: string;
    progress: number;
    estimatedCompletion: string;
  };
  metrics: {
    tasksCompleted: number;
    successRate: number;
    avgResponseTime: number;
    savingsGenerated: number;
  };
}

interface Conversation {
  id: string;
  agentId: string;
  messages: Message[];
  status: 'active' | 'resolved' | 'pending';
}

interface Message {
  id: string;
  sender: 'user' | 'agent';
  content: string;
  timestamp: Date;
  attachments?: string[];
  suggestions?: string[];
}

export const AIAgentInterface: React.FC = () => {
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null);
  const [activeConversation, setActiveConversation] = useState<Conversation | null>(null);
  const [message, setMessage] = useState('');
  const [isRecording, setIsRecording] = useState(false);
  const [showCapabilities, setShowCapabilities] = useState(false);
  const [agentFilter, setAgentFilter] = useState<string>('all');

  // Mock AI Agents
  const agents: AIAgent[] = [
    {
      id: 'finance-ai',
      name: 'Finance Orchestrator',
      type: 'finance',
      status: 'active',
      capabilities: [
        'Automated bookkeeping',
        'Tax calculations',
        'Invoice generation',
        'Cash flow forecasting',
        'Expense optimization'
      ],
      performance: {
        accuracy: 99.2,
        speed: 95,
        reliability: 98,
        efficiency: 97
      },
      currentTask: {
        id: 'task-001',
        description: 'Reconciling Q1 2024 transactions',
        progress: 67,
        estimatedCompletion: '15 minutes'
      },
      metrics: {
        tasksCompleted: 1847,
        successRate: 98.5,
        avgResponseTime: 1.2,
        savingsGenerated: 48500
      }
    },
    {
      id: 'crm-ai',
      name: 'Customer Success AI',
      type: 'crm',
      status: 'processing',
      capabilities: [
        'Lead qualification',
        'Automated nurturing',
        'Deal progression',
        'Customer insights',
        'Churn prediction'
      ],
      performance: {
        accuracy: 94,
        speed: 92,
        reliability: 96,
        efficiency: 93
      },
      currentTask: {
        id: 'task-002',
        description: 'Analyzing customer engagement patterns',
        progress: 43,
        estimatedCompletion: '25 minutes'
      },
      metrics: {
        tasksCompleted: 923,
        successRate: 94.2,
        avgResponseTime: 2.3,
        savingsGenerated: 32000
      }
    },
    {
      id: 'growth-ai',
      name: 'Growth Predictor',
      type: 'growth',
      status: 'learning',
      capabilities: [
        'Market analysis',
        'Scaling recommendations',
        'Resource allocation',
        'Opportunity identification',
        'Risk assessment'
      ],
      performance: {
        accuracy: 91,
        speed: 88,
        reliability: 93,
        efficiency: 90
      },
      metrics: {
        tasksCompleted: 456,
        successRate: 91.8,
        avgResponseTime: 3.5,
        savingsGenerated: 125000
      }
    }
  ];

  const getAgentIcon = (type: string) => {
    switch (type) {
      case 'finance':
        return <TrendingUp className="h-5 w-5" />;
      case 'crm':
        return <MessageSquare className="h-5 w-5" />;
      case 'inventory':
        return <Package className="h-5 w-5" />;
      case 'compliance':
        return <Shield className="h-5 w-5" />;
      case 'growth':
        return <Sparkles className="h-5 w-5" />;
      default:
        return <Bot className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400';
      case 'processing':
        return 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400';
      case 'idle':
        return 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400';
      case 'error':
        return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400';
      case 'learning':
        return 'bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400';
    }
  };

  const handleSendMessage = () => {
    if (!message.trim() || !selectedAgent) return;

    const newMessage: Message = {
      id: Date.now().toString(),
      sender: 'user',
      content: message,
      timestamp: new Date()
    };

    // Simulate agent response
    setTimeout(() => {
      const agentResponse: Message = {
        id: (Date.now() + 1).toString(),
        sender: 'agent',
        content: `I understand your request about "${message}". I'm processing this now and will have results for you shortly.`,
        timestamp: new Date(),
        suggestions: [
          'View detailed analysis',
          'Export report',
          'Schedule follow-up'
        ]
      };
      // Update conversation with agent response
    }, 1000);

    setMessage('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="flex h-screen">
        {/* Agents Sidebar */}
        <div className="w-80 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 overflow-y-auto">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-gradient-to-r from-purple-600 to-blue-600 rounded-lg">
                <Brain className="h-5 w-5 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  AI Agent Control
                </h2>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {agents.length} agents active
                </p>
              </div>
            </div>

            {/* Filter Buttons */}
            <div className="flex gap-2 flex-wrap">
              {['all', 'active', 'processing', 'idle'].map((filter) => (
                <button
                  key={filter}
                  onClick={() => setAgentFilter(filter)}
                  className={`px-3 py-1 text-xs font-medium rounded-lg transition-colors ${
                    agentFilter === filter
                      ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                      : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                  }`}
                >
                  {filter.charAt(0).toUpperCase() + filter.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Agents List */}
          <div className="p-4 space-y-3">
            {agents
              .filter(agent => agentFilter === 'all' || agent.status === agentFilter)
              .map((agent) => (
                <motion.div
                  key={agent.id}
                  whileHover={{ scale: 1.02 }}
                  className={`p-4 rounded-lg cursor-pointer transition-all ${
                    selectedAgent?.id === agent.id
                      ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700'
                      : 'bg-gray-50 dark:bg-gray-900 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                  onClick={() => setSelectedAgent(agent)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${getStatusColor(agent.status)}`}>
                        {getAgentIcon(agent.type)}
                      </div>
                      <div>
                        <h3 className="font-medium text-gray-900 dark:text-white">
                          {agent.name}
                        </h3>
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${getStatusColor(agent.status)}`}>
                          {agent.status}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Agent Metrics */}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-gray-500">Tasks</span>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {agent.metrics.tasksCompleted}
                      </p>
                    </div>
                    <div>
                      <span className="text-gray-500">Success</span>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {agent.metrics.successRate}%
                      </p>
                    </div>
                  </div>

                  {/* Current Task Progress */}
                  {agent.currentTask && (
                    <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                      <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">
                        {agent.currentTask.description}
                      </p>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                        <div
                          className="bg-blue-600 h-1.5 rounded-full transition-all"
                          style={{ width: `${agent.currentTask.progress}%` }}
                        />
                      </div>
                      <p className="text-xs text-gray-500 mt-1">
                        {agent.currentTask.progress}% - {agent.currentTask.estimatedCompletion}
                      </p>
                    </div>
                  )}
                </motion.div>
              ))}
          </div>
        </div>

        {/* Agent Detail & Interaction Panel */}
        <div className="flex-1 flex flex-col">
          {selectedAgent ? (
            <>
              {/* Agent Header */}
              <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-gradient-to-r from-purple-600 to-blue-600 rounded-xl">
                      {getAgentIcon(selectedAgent.type)}
                    </div>
                    <div>
                      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                        {selectedAgent.name}
                      </h1>
                      <p className="text-gray-600 dark:text-gray-400">
                        {selectedAgent.type.charAt(0).toUpperCase() + selectedAgent.type.slice(1)} AI Agent
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <button className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600">
                      <RefreshCw className="h-4 w-4" />
                    </button>
                    <button className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600">
                      <Settings className="h-4 w-4" />
                    </button>
                    <button className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700">
                      <Command className="h-4 w-4 inline mr-2" />
                      Assign Task
                    </button>
                  </div>
                </div>

                {/* Performance Metrics */}
                <div className="grid grid-cols-4 gap-4">
                  {Object.entries(selectedAgent.performance).map(([key, value]) => (
                    <div key={key} className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-gray-600 dark:text-gray-400 capitalize">
                          {key}
                        </span>
                        <Activity className="h-3 w-3 text-gray-400" />
                      </div>
                      <div className="flex items-end gap-2">
                        <span className="text-xl font-bold text-gray-900 dark:text-white">
                          {value}
                        </span>
                        <span className="text-xs text-gray-500 mb-1">%</span>
                      </div>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1 mt-2">
                        <div
                          className={`h-1 rounded-full ${
                            value >= 95
                              ? 'bg-green-500'
                              : value >= 90
                              ? 'bg-blue-500'
                              : value >= 80
                              ? 'bg-yellow-500'
                              : 'bg-red-500'
                          }`}
                          style={{ width: `${value}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Capabilities Section */}
              <div className="bg-gray-50 dark:bg-gray-900 p-6 border-b border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setShowCapabilities(!showCapabilities)}
                  className="flex items-center gap-2 text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 hover:text-blue-600"
                >
                  {showCapabilities ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  Agent Capabilities ({selectedAgent.capabilities.length})
                </button>
                
                <AnimatePresence>
                  {showCapabilities && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="flex flex-wrap gap-2"
                    >
                      {selectedAgent.capabilities.map((capability, index) => (
                        <span
                          key={index}
                          className="px-3 py-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-sm text-gray-700 dark:text-gray-300"
                        >
                          {capability}
                        </span>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Chat Interface */}
              <div className="flex-1 bg-gray-50 dark:bg-gray-900 p-6 overflow-y-auto">
                <div className="max-w-3xl mx-auto space-y-4">
                  {/* Welcome Message */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                        <Bot className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900 dark:text-white mb-1">
                          {selectedAgent.name}
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Hello! I'm ready to help you with {selectedAgent.type} operations. 
                          You can ask me to perform tasks, analyze data, or provide insights.
                        </p>
                        <div className="flex flex-wrap gap-2 mt-3">
                          <button className="px-3 py-1 bg-gray-100 dark:bg-gray-700 rounded-lg text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                            Generate report
                          </button>
                          <button className="px-3 py-1 bg-gray-100 dark:bg-gray-700 rounded-lg text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                            Analyze trends
                          </button>
                          <button className="px-3 py-1 bg-gray-100 dark:bg-gray-700 rounded-lg text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600">
                            Optimize processes
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Sample Task Card */}
                  <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 border border-blue-200 dark:border-blue-800">
                    <div className="flex items-center gap-2 mb-2">
                      <Zap className="h-4 w-4 text-blue-600" />
                      <span className="text-sm font-medium text-blue-900 dark:text-blue-300">
                        Autonomous Task in Progress
                      </span>
                    </div>
                    <p className="text-sm text-blue-800 dark:text-blue-400 mb-3">
                      Analyzing financial patterns for Q1 2024 to identify optimization opportunities
                    </p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4 text-xs text-blue-700 dark:text-blue-500">
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Started 10 min ago
                        </span>
                        <span>Progress: 67%</span>
                      </div>
                      <button className="text-xs text-blue-600 hover:text-blue-700 font-medium">
                        View Details →
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Message Input */}
              <div className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 p-4">
                <div className="max-w-3xl mx-auto">
                  <div className="flex items-end gap-3">
                    <button className="p-2 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                      <Paperclip className="h-5 w-5" />
                    </button>
                    <div className="flex-1">
                      <input
                        type="text"
                        value={message}
                        onChange={(e) => setMessage(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                        placeholder="Ask the agent to perform a task..."
                        className="w-full px-4 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <button
                      onClick={() => setIsRecording(!isRecording)}
                      className={`p-2 rounded-lg transition-colors ${
                        isRecording
                          ? 'bg-red-100 text-red-600 dark:bg-red-900/20'
                          : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
                      }`}
                    >
                      <Mic className="h-5 w-5" />
                    </button>
                    <button
                      onClick={handleSendMessage}
                      className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700"
                    >
                      <Send className="h-5 w-5" />
                    </button>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center bg-gray-50 dark:bg-gray-900">
              <div className="text-center">
                <div className="p-4 bg-gray-100 dark:bg-gray-800 rounded-full inline-block mb-4">
                  <Brain className="h-12 w-12 text-gray-400" />
                </div>
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                  Select an AI Agent
                </h2>
                <p className="text-gray-600 dark:text-gray-400">
                  Choose an agent from the sidebar to start interacting
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AIAgentInterface;