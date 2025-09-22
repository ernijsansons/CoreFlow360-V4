import React, { useState, useEffect } from 'react';
import { AgentList } from './AgentList';
import { AgentMetrics } from './AgentMetrics';
import { AgentDecisionPanel } from './AgentDecisionPanel';
import { AgentOrchestrator } from './AgentOrchestrator';
import { SyncStatus } from './SyncStatus';

export interface Agent {
  id: string;
  name: string;
  type: 'executive' | 'department' | 'operational' | 'specialist';
  status: 'active' | 'idle' | 'busy' | 'error' | 'offline';
  capabilities: string[];
  lastActivity?: Date;
  metrics?: {
    totalRequests: number;
    successRate: number;
    avgResponseTime: number;
  };
}

export interface AgentDashboardProps {
  apiEndpoint?: string;
}

export const AgentDashboard: React.FC<AgentDashboardProps> = ({
  apiEndpoint = '/api/v4/agents'
}) => {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'decisions' | 'orchestrator' | 'sync'>('overview');
  const [loading, setLoading] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');
  const [syncStatus, setSyncStatus] = useState<any>(null);

  useEffect(() => {
    initializeAgentSystem();
    const interval = setInterval(refreshAgentStatus, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const initializeAgentSystem = async () => {
    try {
      setConnectionStatus('connecting');

      // Get agent capabilities
      const capabilitiesResponse = await fetch(`${apiEndpoint}/capabilities`);
      const { capabilities } = await capabilitiesResponse.json();

      // Get agent status
      const statusResponse = await fetch(`${apiEndpoint}/status`);
      const statusData = await statusResponse.json();

      // Map capabilities to agent format
      const agentList = capabilities.map((cap: any) => ({
        id: cap.id,
        name: cap.name,
        type: cap.type,
        status: statusData.agents[cap.id]?.status || 'offline',
        capabilities: cap.capabilities,
        lastActivity: statusData.agents[cap.id]?.lastActivity
          ? new Date(statusData.agents[cap.id].lastActivity)
          : undefined,
        metrics: statusData.agents[cap.id]?.metrics
      }));

      setAgents(agentList);
      setConnectionStatus('connected');

      // Get sync status
      const syncResponse = await fetch(`${apiEndpoint}/sync/status`);
      const syncData = await syncResponse.json();
      setSyncStatus(syncData.statistics);
    } catch (error) {
      console.error('Failed to initialize agent system:', error);
      setConnectionStatus('disconnected');
    } finally {
      setLoading(false);
    }
  };

  const refreshAgentStatus = async () => {
    try {
      const statusResponse = await fetch(`${apiEndpoint}/status`);
      const statusData = await statusResponse.json();

      setAgents(prev => prev.map(agent => ({
        ...agent,
        status: statusData.agents[agent.id]?.status || agent.status,
        lastActivity: statusData.agents[agent.id]?.lastActivity
          ? new Date(statusData.agents[agent.id].lastActivity)
          : agent.lastActivity,
        metrics: statusData.agents[agent.id]?.metrics || agent.metrics
      })));
    } catch (error) {
      console.error('Failed to refresh agent status:', error);
    }
  };

  const handleAgentSelect = (agentId: string) => {
    setSelectedAgent(agentId);
  };

  const handleRequestDecision = async (context: any) => {
    try {
      const response = await fetch(`${apiEndpoint}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(context)
      });

      const { decision } = await response.json();
      return decision;
    } catch (error) {
      console.error('Failed to request decision:', error);
      throw error;
    }
  };

  const handleStartSync = async () => {
    try {
      await fetch(`${apiEndpoint}/sync/start`, { method: 'POST' });

      // Refresh sync status
      const syncResponse = await fetch(`${apiEndpoint}/sync/status`);
      const syncData = await syncResponse.json();
      setSyncStatus(syncData.statistics);
    } catch (error) {
      console.error('Failed to start sync:', error);
    }
  };

  const handleStopSync = async () => {
    try {
      await fetch(`${apiEndpoint}/sync/stop`, { method: 'POST' });

      // Refresh sync status
      const syncResponse = await fetch(`${apiEndpoint}/sync/status`);
      const syncData = await response.json();
      setSyncStatus(syncData.statistics);
    } catch (error) {
      console.error('Failed to stop sync:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Agent Control Center</h1>
                <p className="mt-1 text-sm text-gray-500">
                  Manage and monitor your AI agent ecosystem
                </p>
              </div>
              <div className="flex items-center space-x-4">
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full ${
                  connectionStatus === 'connected' ? 'bg-green-100' :
                  connectionStatus === 'connecting' ? 'bg-yellow-100' :
                  'bg-red-100'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${
                    connectionStatus === 'connected' ? 'bg-green-600 animate-pulse' :
                    connectionStatus === 'connecting' ? 'bg-yellow-600 animate-pulse' :
                    'bg-red-600'
                  }`}></div>
                  <span className={`text-sm font-medium ${
                    connectionStatus === 'connected' ? 'text-green-800' :
                    connectionStatus === 'connecting' ? 'text-yellow-800' :
                    'text-red-800'
                  }`}>
                    {connectionStatus === 'connected' ? 'Connected' :
                     connectionStatus === 'connecting' ? 'Connecting...' :
                     'Disconnected'}
                  </span>
                </div>
                <button
                  onClick={initializeAgentSystem}
                  className="p-2 text-gray-400 hover:text-gray-600"
                  title="Refresh"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8">
            {(['overview', 'decisions', 'orchestrator', 'sync'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm capitalize ${
                  activeTab === tab
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2">
              <AgentList
                agents={agents}
                selectedAgent={selectedAgent}
                onAgentSelect={handleAgentSelect}
              />
            </div>
            <div className="lg:col-span-1">
              {selectedAgent ? (
                <AgentMetrics agentId={selectedAgent} apiEndpoint={apiEndpoint} />
              ) : (
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">System Overview</h3>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Total Agents</span>
                        <span className="font-medium">{agents.length}</span>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Active Agents</span>
                        <span className="font-medium text-green-600">
                          {agents.filter(a => a.status === 'active' || a.status === 'busy').length}
                        </span>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Idle Agents</span>
                        <span className="font-medium text-yellow-600">
                          {agents.filter(a => a.status === 'idle').length}
                        </span>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Offline Agents</span>
                        <span className="font-medium text-gray-600">
                          {agents.filter(a => a.status === 'offline').length}
                        </span>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Error State</span>
                        <span className="font-medium text-red-600">
                          {agents.filter(a => a.status === 'error').length}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-6 border-t">
                    <h4 className="text-sm font-medium text-gray-900 mb-3">Agent Types</h4>
                    <div className="space-y-2">
                      {['executive', 'department', 'operational', 'specialist'].map(type => {
                        const count = agents.filter(a => a.type === type).length;
                        return (
                          <div key={type} className="flex items-center justify-between">
                            <span className="text-sm text-gray-500 capitalize">{type}</span>
                            <div className="flex items-center space-x-2">
                              <div className="w-24 bg-gray-200 rounded-full h-2">
                                <div
                                  className="bg-indigo-600 h-2 rounded-full"
                                  style={{ width: `${(count / agents.length) * 100}%` }}
                                ></div>
                              </div>
                              <span className="text-sm font-medium text-gray-900 w-8 text-right">
                                {count}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'decisions' && (
          <AgentDecisionPanel apiEndpoint={apiEndpoint} agents={agents} />
        )}

        {activeTab === 'orchestrator' && (
          <AgentOrchestrator apiEndpoint={apiEndpoint} agents={agents} />
        )}

        {activeTab === 'sync' && (
          <SyncStatus
            status={syncStatus}
            onStartSync={handleStartSync}
            onStopSync={handleStopSync}
            apiEndpoint={apiEndpoint}
          />
        )}
      </div>
    </div>
  );
};