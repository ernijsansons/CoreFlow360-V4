/**
 * AI Agent Orchestration Dashboard
 * World-class visualization of autonomous AI agents managing business operations
 */

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain,
  Zap,
  Activity,
  CheckCircle,
  Clock,
  TrendingUp,
  Users,
  DollarSign,
  Package,
  FileText,
  Settings,
  Play,
  Pause,
  RotateCcw,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui'
import { Badge } from '@/components/ui'
import { Button } from '@/components/ui'

interface AgentStatus {
  id: string
  name: string
  type: 'finance' | 'crm' | 'inventory' | 'compliance' | 'growth'
  status: 'active' | 'idle' | 'processing' | 'error'
  tasksCompleted: number
  tasksInProgress: number
  efficiency: number
  lastActivity: string
  capabilities: string[]
}

interface AgentMetrics {
  totalAgents: number
  activeAgents: number
  tasksCompleted: number
  averageEfficiency: number
  automationRate: number
}

const mockAgents: AgentStatus[] = [
  {
    id: '1',
    name: 'Autonomous Finance Agent',
    type: 'finance',
    status: 'active',
    tasksCompleted: 342,
    tasksInProgress: 5,
    efficiency: 98,
    lastActivity: '2 min ago',
    capabilities: ['Double-entry bookkeeping', 'Invoice automation', 'Tax calculation', 'Cash flow prediction'],
  },
  {
    id: '2',
    name: 'Intelligent CRM Agent',
    type: 'crm',
    status: 'processing',
    tasksCompleted: 187,
    tasksInProgress: 12,
    efficiency: 94,
    lastActivity: 'Just now',
    capabilities: ['Lead qualification', 'Deal progression', 'Customer intelligence', 'Automated nurturing'],
  },
  {
    id: '3',
    name: 'Smart Inventory Agent',
    type: 'inventory',
    status: 'active',
    tasksCompleted: 256,
    tasksInProgress: 8,
    efficiency: 96,
    lastActivity: '5 min ago',
    capabilities: ['Demand forecasting', 'Supplier coordination', 'Stock optimization', 'Quality monitoring'],
  },
  {
    id: '4',
    name: 'Compliance Agent',
    type: 'compliance',
    status: 'idle',
    tasksCompleted: 89,
    tasksInProgress: 0,
    efficiency: 100,
    lastActivity: '1 hour ago',
    capabilities: ['Regulatory monitoring', 'Audit trail generation', 'Risk assessment', 'Report automation'],
  },
  {
    id: '5',
    name: 'Growth Prediction Agent',
    type: 'growth',
    status: 'processing',
    tasksCompleted: 134,
    tasksInProgress: 3,
    efficiency: 92,
    lastActivity: 'Just now',
    capabilities: ['Scaling readiness', 'Market opportunity', 'Resource allocation', 'Performance optimization'],
  },
]

const agentTypeIcons = {
  finance: DollarSign,
  crm: Users,
  inventory: Package,
  compliance: FileText,
  growth: TrendingUp,
}

const statusColors = {
  active: 'bg-green-500',
  idle: 'bg-gray-400',
  processing: 'bg-blue-500',
  error: 'bg-red-500',
}

const statusLabels = {
  active: 'Active',
  idle: 'Idle',
  processing: 'Processing',
  error: 'Error',
}

export function AgentOrchestrationDashboard() {
  const [agents, setAgents] = useState<AgentStatus[]>(mockAgents)
  const [selectedAgent, setSelectedAgent] = useState<AgentStatus | null>(null)
  const [metrics] = useState<AgentMetrics>({
    totalAgents: 5,
    activeAgents: 3,
    tasksCompleted: 1008,
    averageEfficiency: 96,
    automationRate: 87,
  })

  useEffect(() => {
    // Simulate real-time updates
    const interval = setInterval(() => {
      setAgents((prev) =>
        prev.map((agent) => ({
          ...agent,
          tasksCompleted: agent.tasksCompleted + Math.floor(Math.random() * 3),
          efficiency: Math.min(100, agent.efficiency + (Math.random() - 0.5)),
        }))
      )
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const handleAgentAction = (agentId: string, action: 'pause' | 'resume' | 'restart') => {
    setAgents((prev) =>
      prev.map((agent) => {
        if (agent.id === agentId) {
          if (action === 'pause') return { ...agent, status: 'idle' as const }
          if (action === 'resume') return { ...agent, status: 'active' as const }
          if (action === 'restart') return { ...agent, status: 'processing' as const, tasksInProgress: 0 }
        }
        return agent
      })
    )
  }

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
            AI Agent Orchestration
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Autonomous agents managing your business operations 24/7
          </p>
        </div>
        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          <Button className="bg-gradient-to-r from-purple-600 to-pink-600 text-white">
            <Settings className="w-4 h-4 mr-2" />
            Configure Agents
          </Button>
        </motion.div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="glass-effect border-purple-500/20">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Agents</p>
                  <p className="text-3xl font-bold mt-1">{metrics.totalAgents}</p>
                </div>
                <div className="h-12 w-12 rounded-lg bg-purple-500/10 flex items-center justify-center">
                  <Brain className="h-6 w-6 text-purple-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="glass-effect border-green-500/20">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Active Now</p>
                  <p className="text-3xl font-bold mt-1">{metrics.activeAgents}</p>
                </div>
                <div className="h-12 w-12 rounded-lg bg-green-500/10 flex items-center justify-center">
                  <Zap className="h-6 w-6 text-green-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="glass-effect border-blue-500/20">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Tasks Completed</p>
                  <p className="text-3xl font-bold mt-1">{metrics.tasksCompleted}</p>
                </div>
                <div className="h-12 w-12 rounded-lg bg-blue-500/10 flex items-center justify-center">
                  <CheckCircle className="h-6 w-6 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="glass-effect border-orange-500/20">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Avg Efficiency</p>
                  <p className="text-3xl font-bold mt-1">{metrics.averageEfficiency}%</p>
                </div>
                <div className="h-12 w-12 rounded-lg bg-orange-500/10 flex items-center justify-center">
                  <Activity className="h-6 w-6 text-orange-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card className="glass-effect border-pink-500/20">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Automation Rate</p>
                  <p className="text-3xl font-bold mt-1">{metrics.automationRate}%</p>
                </div>
                <div className="h-12 w-12 rounded-lg bg-pink-500/10 flex items-center justify-center">
                  <TrendingUp className="h-6 w-6 text-pink-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Agent Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {agents.map((agent, index) => {
          const Icon = agentTypeIcons[agent.type]
          return (
            <motion.div
              key={agent.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ y: -4 }}
              onClick={() => setSelectedAgent(agent)}
              className="cursor-pointer"
            >
              <Card className="glass-effect hover:shadow-xl transition-all duration-300">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`h-10 w-10 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center`}>
                        <Icon className="h-5 w-5 text-white" />
                      </div>
                      <div>
                        <CardTitle className="text-lg">{agent.name}</CardTitle>
                        <div className="flex items-center gap-2 mt-1">
                          <div className={`h-2 w-2 rounded-full ${statusColors[agent.status]} animate-pulse`} />
                          <span className="text-xs text-gray-600 dark:text-gray-400">
                            {statusLabels[agent.status]}
                          </span>
                        </div>
                      </div>
                    </div>
                    <Badge variant="secondary" className="bg-purple-500/10 text-purple-600">
                      {agent.efficiency}% Efficient
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Progress Stats */}
                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">Completed</p>
                        <p className="text-2xl font-bold text-green-600">{agent.tasksCompleted}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">In Progress</p>
                        <p className="text-2xl font-bold text-blue-600">{agent.tasksInProgress}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-600 dark:text-gray-400">Last Active</p>
                        <p className="text-sm font-medium mt-1 flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {agent.lastActivity}
                        </p>
                      </div>
                    </div>

                    {/* Capabilities */}
                    <div>
                      <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Capabilities</p>
                      <div className="flex flex-wrap gap-2">
                        {agent.capabilities.slice(0, 2).map((capability, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {capability}
                          </Badge>
                        ))}
                        {agent.capabilities.length > 2 && (
                          <Badge variant="outline" className="text-xs">
                            +{agent.capabilities.length - 2} more
                          </Badge>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex gap-2 pt-2">
                      {agent.status === 'active' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleAgentAction(agent.id, 'pause')
                          }}
                        >
                          <Pause className="h-3 w-3 mr-1" />
                          Pause
                        </Button>
                      )}
                      {agent.status === 'idle' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleAgentAction(agent.id, 'resume')
                          }}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          Resume
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleAgentAction(agent.id, 'restart')
                        }}
                      >
                        <RotateCcw className="h-3 w-3 mr-1" />
                        Restart
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )
        })}
      </div>

      {/* Agent Detail Modal */}
      <AnimatePresence>
        {selectedAgent && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-6"
            onClick={() => setSelectedAgent(null)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-2xl w-full p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold">{selectedAgent.name}</h2>
                <Button variant="ghost" size="sm" onClick={() => setSelectedAgent(null)}>
                  ✕
                </Button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="font-semibold mb-3">All Capabilities</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {selectedAgent.capabilities.map((capability, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                        <CheckCircle className="h-4 w-4 text-green-600" />
                        <span className="text-sm">{capability}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold mb-3">Performance Metrics</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Efficiency</span>
                        <span className="font-medium">{selectedAgent.efficiency}%</span>
                      </div>
                      <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${selectedAgent.efficiency}%` }}
                          className="h-full bg-gradient-to-r from-green-500 to-emerald-500"
                        />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Task Completion Rate</span>
                        <span className="font-medium">97%</span>
                      </div>
                      <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: '97%' }}
                          className="h-full bg-gradient-to-r from-blue-500 to-cyan-500"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
