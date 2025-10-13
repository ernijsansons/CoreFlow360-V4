/**
 * AI Agents Management Dashboard
 * Monitor and manage autonomous AI agents
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Bot,
  Play,
  Pause,
  Settings,
  Activity,
  CheckCircle,
  AlertCircle,
  Clock,
  Zap,
  TrendingUp,
  Users,
  DollarSign,
  FileText
} from 'lucide-react';

export const Route = createFileRoute('/agents/')({
  component: AIAgentsPage,
});

interface Agent {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'idle' | 'paused' | 'error';
  tasksCompleted: number;
  successRate: number;
  avgResponseTime: number;
  lastActive: string;
  description: string;
}

function AIAgentsPage() {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  // Mock agent data
  const agents: Agent[] = [
    {
      id: '1',
      name: 'Finance Agent',
      type: 'Autonomous Finance',
      status: 'active',
      tasksCompleted: 1247,
      successRate: 98.5,
      avgResponseTime: 245,
      lastActive: '2 minutes ago',
      description: 'Handles double-entry bookkeeping, invoice generation, and financial reporting'
    },
    {
      id: '2',
      name: 'CRM Agent',
      type: 'Intelligent CRM',
      status: 'active',
      tasksCompleted: 856,
      successRate: 96.2,
      avgResponseTime: 180,
      lastActive: '5 minutes ago',
      description: 'Manages lead qualification, deal progression, and customer intelligence'
    },
    {
      id: '3',
      name: 'Inventory Agent',
      type: 'Smart Inventory',
      status: 'idle',
      tasksCompleted: 423,
      successRate: 99.1,
      avgResponseTime: 320,
      lastActive: '1 hour ago',
      description: 'Demand forecasting, supplier coordination, and stock optimization'
    },
    {
      id: '4',
      name: 'Compliance Agent',
      type: 'Compliance Monitoring',
      status: 'active',
      tasksCompleted: 234,
      successRate: 100,
      avgResponseTime: 150,
      lastActive: 'Just now',
      description: 'Regulatory monitoring, audit trail generation, and risk assessment'
    }
  ];

  const getStatusIcon = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return <Activity className="w-4 h-4 text-green-500 animate-pulse" />;
      case 'idle':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'paused':
        return <Pause className="w-4 h-4 text-gray-500" />;
      case 'error':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
    }
  };

  const getStatusColor = (status: Agent['status']) => {
    const colors = {
      active: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
      idle: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
      paused: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
      error: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
    };
    return colors[status];
  };

  const getAgentIcon = (type: string) => {
    if (type.includes('Finance')) return DollarSign;
    if (type.includes('CRM')) return Users;
    if (type.includes('Inventory')) return FileText;
    return Bot;
  };

  // Calculate aggregate stats
  const totalTasks = agents.reduce((sum, agent) => sum + agent.tasksCompleted, 0);
  const avgSuccessRate = agents.reduce((sum, agent) => sum + agent.successRate, 0) / agents.length;
  const activeAgents = agents.filter(a => a.status === 'active').length;

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Bot className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">AI Agents</h1>
              <p className="text-muted-foreground mt-1">
                {activeAgents} of {agents.length} agents active
              </p>
            </div>
          </div>

          <Button>
            <Play className="w-4 h-4 mr-2" />
            Deploy New Agent
          </Button>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Tasks</p>
                <p className="text-2xl font-bold mt-1">{totalTasks.toLocaleString()}</p>
              </div>
              <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <Zap className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Success Rate</p>
                <p className="text-2xl font-bold mt-1">{avgSuccessRate.toFixed(1)}%</p>
              </div>
              <div className="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Agents</p>
                <p className="text-2xl font-bold mt-1">{activeAgents}</p>
              </div>
              <div className="p-3 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                <Activity className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Avg Response</p>
                <p className="text-2xl font-bold mt-1">
                  {Math.round(agents.reduce((sum, a) => sum + a.avgResponseTime, 0) / agents.length)}ms
                </p>
              </div>
              <div className="p-3 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                <TrendingUp className="w-6 h-6 text-orange-600 dark:text-orange-400" />
              </div>
            </div>
          </Card>
        </div>

        {/* Agents List */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {agents.map((agent) => {
            const AgentIcon = getAgentIcon(agent.type);

            return (
              <Card
                key={agent.id}
                className={`p-6 cursor-pointer transition-all ${
                  selectedAgent === agent.id ? 'ring-2 ring-primary' : 'hover:shadow-lg'
                }`}
                onClick={() => setSelectedAgent(agent.id)}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      <AgentIcon className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-semibold">{agent.name}</h3>
                      <p className="text-sm text-muted-foreground">{agent.type}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {getStatusIcon(agent.status)}
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(agent.status)}`}>
                      {agent.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <p className="text-sm text-muted-foreground mb-4">
                  {agent.description}
                </p>

                {/* Metrics */}
                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Tasks</p>
                    <p className="text-lg font-semibold">{agent.tasksCompleted}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Success</p>
                    <p className="text-lg font-semibold text-green-600 dark:text-green-400">
                      {agent.successRate}%
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Avg Time</p>
                    <p className="text-lg font-semibold">{agent.avgResponseTime}ms</p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-4 border-t">
                  <span className="text-xs text-muted-foreground">
                    Last active: {agent.lastActive}
                  </span>
                  <div className="flex items-center gap-2">
                    {agent.status === 'active' ? (
                      <Button variant="ghost" size="sm">
                        <Pause className="w-3 h-3 mr-1" />
                        Pause
                      </Button>
                    ) : (
                      <Button variant="ghost" size="sm">
                        <Play className="w-3 h-3 mr-1" />
                        Start
                      </Button>
                    )}
                    <Button variant="ghost" size="sm">
                      <Settings className="w-3 h-3 mr-1" />
                      Configure
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>

        {/* Activity Log */}
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Recent Agent Activity</h2>
          <div className="space-y-3">
            {[
              { agent: 'Finance Agent', action: 'Generated 3 invoices', time: '2 minutes ago', status: 'success' },
              { agent: 'CRM Agent', action: 'Qualified 5 new leads', time: '5 minutes ago', status: 'success' },
              { agent: 'Compliance Agent', action: 'Completed compliance scan', time: '10 minutes ago', status: 'success' },
              { agent: 'Finance Agent', action: 'Reconciled bank transactions', time: '15 minutes ago', status: 'success' },
            ].map((activity, idx) => (
              <div key={idx} className="flex items-center justify-between py-3 px-4 hover:bg-muted/50 rounded">
                <div className="flex items-center gap-3">
                  <CheckCircle className="w-4 h-4 text-green-500" />
                  <div>
                    <p className="font-medium">{activity.agent}</p>
                    <p className="text-sm text-muted-foreground">{activity.action}</p>
                  </div>
                </div>
                <span className="text-sm text-muted-foreground">{activity.time}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </MainLayout>
  );
}
