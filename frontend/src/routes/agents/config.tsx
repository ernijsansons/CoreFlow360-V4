/**
 * AI Agent Configuration Panel
 * Configure, schedule, and manage AI agent workflows
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Bot,
  Settings,
  Calendar,
  Zap,
  Play,
  Pause,
  Save,
  Trash2,
  Plus,
  Clock,
  Target,
  TrendingUp,
  AlertCircle,
  CheckCircle
} from 'lucide-react';

export const Route = createFileRoute('/agents/config')({
  component: AgentConfigPage,
});

interface AgentConfig {
  id: string;
  name: string;
  type: 'finance' | 'crm' | 'inventory' | 'compliance';
  status: 'active' | 'paused' | 'draft';
  schedule: {
    frequency: 'realtime' | 'hourly' | 'daily' | 'weekly' | 'monthly';
    time?: string;
    days?: number[];
  };
  triggers: Array<{
    type: 'data_change' | 'threshold' | 'time' | 'manual';
    condition: string;
    value?: any;
  }>;
  actions: Array<{
    type: string;
    config: Record<string, any>;
  }>;
  performance: {
    accuracy: number;
    tasks_completed: number;
    success_rate: number;
  };
}

function AgentConfigPage() {
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [configs, setConfigs] = useState<AgentConfig[]>([
    {
      id: 'agent-1',
      name: 'Finance Agent',
      type: 'finance',
      status: 'active',
      schedule: {
        frequency: 'daily',
        time: '09:00',
      },
      triggers: [
        { type: 'data_change', condition: 'New invoice created' },
        { type: 'threshold', condition: 'Revenue > $10,000', value: 10000 },
      ],
      actions: [
        { type: 'categorize_transaction', config: { auto_approve: true } },
        { type: 'reconcile_accounts', config: { threshold: 0.01 } },
      ],
      performance: {
        accuracy: 98.5,
        tasks_completed: 1247,
        success_rate: 97.8,
      },
    },
    {
      id: 'agent-2',
      name: 'CRM Agent',
      type: 'crm',
      status: 'active',
      schedule: {
        frequency: 'realtime',
      },
      triggers: [
        { type: 'data_change', condition: 'New lead added' },
        { type: 'time', condition: 'Every 2 hours' },
      ],
      actions: [
        { type: 'score_lead', config: { model: 'advanced' } },
        { type: 'send_follow_up', config: { delay_hours: 24 } },
      ],
      performance: {
        accuracy: 95.2,
        tasks_completed: 892,
        success_rate: 94.5,
      },
    },
  ]);

  const agentTypes = [
    { id: 'finance', name: 'Finance Agent', icon: TrendingUp, color: 'text-green-600' },
    { id: 'crm', name: 'CRM Agent', icon: Target, color: 'text-blue-600' },
    { id: 'inventory', name: 'Inventory Agent', icon: Bot, color: 'text-purple-600' },
    { id: 'compliance', name: 'Compliance Agent', icon: CheckCircle, color: 'text-orange-600' },
  ];

  const selectedConfig = configs.find((c) => c.id === selectedAgent);

  const handleSaveConfig = () => {
    console.log('Saving config:', selectedConfig);
    // API call to save configuration
  };

  const handleToggleStatus = (agentId: string) => {
    setConfigs(
      configs.map((c) =>
        c.id === agentId
          ? { ...c, status: c.status === 'active' ? 'paused' : 'active' }
          : c
      )
    );
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">AI Agent Configuration</h1>
            <p className="text-muted-foreground mt-1">
              Configure schedules, triggers, and workflows for your AI agents
            </p>
          </div>
          <Button>
            <Plus className="w-4 h-4 mr-2" />
            New Agent
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Agent List */}
          <div className="lg:col-span-1 space-y-4">
            <Card className="p-4">
              <h3 className="font-semibold mb-4">Your Agents</h3>
              <div className="space-y-2">
                {configs.map((config) => {
                  const agentType = agentTypes.find((t) => t.id === config.type);
                  return (
                    <button
                      key={config.id}
                      onClick={() => setSelectedAgent(config.id)}
                      className={`w-full p-4 border rounded-lg text-left transition-all ${
                        selectedAgent === config.id
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:border-primary/50'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {agentType && <agentType.icon className={`w-5 h-5 ${agentType.color}`} />}
                          <span className="font-medium">{config.name}</span>
                        </div>
                        {config.status === 'active' ? (
                          <span className="px-2 py-1 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 text-xs font-medium rounded">
                            Active
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-gray-50 dark:bg-gray-900/20 text-gray-700 dark:text-gray-400 text-xs font-medium rounded">
                            Paused
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {config.performance.tasks_completed} tasks • {config.performance.accuracy}% accuracy
                      </div>
                    </button>
                  );
                })}
              </div>
            </Card>

            <Card className="p-4">
              <h3 className="font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-2">
                <Button variant="outline" className="w-full justify-start">
                  <Play className="w-4 h-4 mr-2" />
                  Run All Agents
                </Button>
                <Button variant="outline" className="w-full justify-start">
                  <Pause className="w-4 h-4 mr-2" />
                  Pause All
                </Button>
                <Button variant="outline" className="w-full justify-start">
                  <Settings className="w-4 h-4 mr-2" />
                  Global Settings
                </Button>
              </div>
            </Card>
          </div>

          {/* Configuration Panel */}
          <div className="lg:col-span-2">
            {selectedConfig ? (
              <div className="space-y-6">
                {/* Agent Status Card */}
                <Card className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="p-3 bg-muted rounded-lg">
                        <Bot className="w-6 h-6 text-primary" />
                      </div>
                      <div>
                        <h2 className="text-2xl font-bold">{selectedConfig.name}</h2>
                        <p className="text-muted-foreground capitalize">{selectedConfig.type} Automation</p>
                      </div>
                    </div>
                    <Button
                      variant={selectedConfig.status === 'active' ? 'outline' : 'default'}
                      onClick={() => handleToggleStatus(selectedConfig.id)}
                    >
                      {selectedConfig.status === 'active' ? (
                        <>
                          <Pause className="w-4 h-4 mr-2" />
                          Pause
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-2" />
                          Activate
                        </>
                      )}
                    </Button>
                  </div>

                  {/* Performance Metrics */}
                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{selectedConfig.performance.accuracy}%</div>
                      <div className="text-sm text-muted-foreground">Accuracy</div>
                    </div>
                    <div className="p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{selectedConfig.performance.tasks_completed}</div>
                      <div className="text-sm text-muted-foreground">Tasks Completed</div>
                    </div>
                    <div className="p-4 bg-muted rounded-lg">
                      <div className="text-2xl font-bold">{selectedConfig.performance.success_rate}%</div>
                      <div className="text-sm text-muted-foreground">Success Rate</div>
                    </div>
                  </div>
                </Card>

                {/* Schedule Configuration */}
                <Card className="p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Calendar className="w-5 h-5" />
                    Schedule
                  </h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium mb-2">Run Frequency</label>
                      <select
                        value={selectedConfig.schedule.frequency}
                        className="w-full h-10 px-3 rounded-md border border-input bg-background"
                      >
                        <option value="realtime">Real-time (as events occur)</option>
                        <option value="hourly">Hourly</option>
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                      </select>
                    </div>
                    {selectedConfig.schedule.time && (
                      <div>
                        <label className="block text-sm font-medium mb-2">Time of Day</label>
                        <input
                          type="time"
                          value={selectedConfig.schedule.time}
                          className="w-full h-10 px-3 rounded-md border border-input bg-background"
                        />
                      </div>
                    )}
                  </div>
                </Card>

                {/* Triggers */}
                <Card className="p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Zap className="w-5 h-5" />
                    Triggers
                  </h3>
                  <div className="space-y-3">
                    {selectedConfig.triggers.map((trigger, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 border border-border rounded-lg">
                        <div className="flex items-center gap-3">
                          <AlertCircle className="w-4 h-4 text-muted-foreground" />
                          <div>
                            <div className="font-medium">{trigger.condition}</div>
                            <div className="text-sm text-muted-foreground capitalize">{trigger.type.replace('_', ' ')}</div>
                          </div>
                        </div>
                        <Button variant="ghost" size="sm">
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    ))}
                    <Button variant="outline" className="w-full">
                      <Plus className="w-4 h-4 mr-2" />
                      Add Trigger
                    </Button>
                  </div>
                </Card>

                {/* Actions */}
                <Card className="p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Target className="w-5 h-5" />
                    Actions
                  </h3>
                  <div className="space-y-3">
                    {selectedConfig.actions.map((action, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 border border-border rounded-lg">
                        <div className="flex items-center gap-3">
                          <CheckCircle className="w-4 h-4 text-green-500" />
                          <div>
                            <div className="font-medium capitalize">{action.type.replace('_', ' ')}</div>
                            <div className="text-sm text-muted-foreground">
                              {Object.entries(action.config)
                                .map(([key, value]) => `${key}: ${value}`)
                                .join(', ')}
                            </div>
                          </div>
                        </div>
                        <Button variant="ghost" size="sm">
                          <Settings className="w-4 h-4" />
                        </Button>
                      </div>
                    ))}
                    <Button variant="outline" className="w-full">
                      <Plus className="w-4 h-4 mr-2" />
                      Add Action
                    </Button>
                  </div>
                </Card>

                {/* Save Button */}
                <div className="flex gap-3">
                  <Button onClick={handleSaveConfig} className="flex-1">
                    <Save className="w-4 h-4 mr-2" />
                    Save Configuration
                  </Button>
                  <Button variant="outline">
                    <Play className="w-4 h-4 mr-2" />
                    Test Run
                  </Button>
                </div>
              </div>
            ) : (
              <Card className="p-12 text-center">
                <Bot className="w-16 h-16 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Select an Agent</h3>
                <p className="text-muted-foreground">
                  Choose an agent from the list to configure its settings
                </p>
              </Card>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
