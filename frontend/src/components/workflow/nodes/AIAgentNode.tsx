/**
 * AI Agent Node - Advanced React Flow Node Component
 * Supports dynamic agent selection, prompt engineering, and cost estimation
 */

import React, { useState, useEffect, memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Slider } from '@/components/ui/slider';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  Brain,
  Settings,
  DollarSign,
  Clock,
  Zap,
  BarChart3,
  AlertCircle,
  CheckCircle,
  Play,
  Pause
} from 'lucide-react';

interface AIAgentNodeData {
  label: string;
  agentType: 'ceo' | 'cfo' | 'sales_manager' | 'marketing_director' | 'custom';
  model: 'claude-3-haiku' | 'claude-3-sonnet' | 'gpt-4' | 'gpt-3.5-turbo';
  prompt: string;
  systemPrompt?: string;
  temperature: number;
  maxTokens: number;
  costEstimate?: number;
  executionTime?: number;
  status?: 'idle' | 'running' | 'completed' | 'failed';
  variables: Record<string, string>;
  memoryContext: string[];
  streaming: boolean;
  showPreview: boolean;
}

const AGENT_TEMPLATES = {
  ceo: {
    label: 'CEO Assistant',
    systemPrompt: 'You are a strategic CEO assistant focused on high-level business decisions, growth opportunities, and executive insights.',
    icon: '👔',
    color: 'bg-purple-500'
  },
  cfo: {
    label: 'CFO Assistant',
    systemPrompt: 'You are a financial expert focused on budgets, forecasts, risk analysis, and financial strategy.',
    icon: '💰',
    color: 'bg-green-500'
  },
  sales_manager: {
    label: 'Sales Manager',
    systemPrompt: 'You are a sales expert focused on pipeline management, deal strategy, and revenue optimization.',
    icon: '📈',
    color: 'bg-blue-500'
  },
  marketing_director: {
    label: 'Marketing Director',
    systemPrompt: 'You are a marketing strategist focused on campaigns, brand positioning, and customer acquisition.',
    icon: '🎯',
    color: 'bg-orange-500'
  },
  custom: {
    label: 'Custom Agent',
    systemPrompt: '',
    icon: '🤖',
    color: 'bg-gray-500'
  }
};

const MODEL_COSTS = {
  'claude-3-haiku': { input: 0.25, output: 1.25, speed: 'fast' },
  'claude-3-sonnet': { input: 3, output: 15, speed: 'medium' },
  'gpt-4': { input: 30, output: 60, speed: 'slow' },
  'gpt-3.5-turbo': { input: 0.5, output: 1.5, speed: 'fast' }
};

export const AIAgentNode = memo(({ data, selected }: NodeProps<AIAgentNodeData>) => {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [localData, setLocalData] = useState(data);
  const [costEstimate, setCostEstimate] = useState(0);
  const [previewResponse, setPreviewResponse] = useState<string>('');

  useEffect(() => {
    // Calculate cost estimate based on prompt length and model
    const estimatedTokens = Math.ceil((localData.prompt.length + (localData.systemPrompt?.length || 0)) / 4);
    const model = MODEL_COSTS[localData.model];
    const inputCost = (estimatedTokens * model.input) / 1000;
    const outputCost = (localData.maxTokens * model.output) / 1000;
    setCostEstimate((inputCost + outputCost) / 100); // Convert to dollars
  }, [localData.prompt, localData.systemPrompt, localData.model, localData.maxTokens]);

  const agentTemplate = AGENT_TEMPLATES[localData.agentType];

  const getStatusIcon = () => {
    switch (localData.status) {
      case 'running':
        return <Zap className="w-4 h-4 animate-pulse text-yellow-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      default:
        return <Brain className="w-4 h-4 text-blue-500" />;
    }
  };

  const handleConfigChange = (field: string, value: any) => {
    const newData = { ...localData, [field]: value };
    setLocalData(newData);
    // In real implementation, this would update the node data
  };

  const generatePreview = async () => {
    // Mock AI response generation for preview
    setPreviewResponse('Generating preview...');
    setTimeout(() => {
      setPreviewResponse(`Preview response for "${localData.prompt.substring(0, 50)}..."\n\nThis is a sample AI response showing how the agent would respond with the current configuration.`);
    }, 1000);
  };

  return (
    <Card className={`min-w-[300px] ${selected ? 'ring-2 ring-blue-500' : ''} relative`}>
      <Handle type="target" position={Position.Top} className="w-3 h-3" />

      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-lg ${agentTemplate.color} flex items-center justify-center text-white text-sm`}>
              {agentTemplate.icon}
            </div>
            <div>
              <div className="font-semibold text-sm">{localData.label || agentTemplate.label}</div>
              <div className="text-xs text-gray-500 flex items-center gap-1">
                {getStatusIcon()}
                <Badge variant="outline" className="text-xs">
                  {localData.model}
                </Badge>
              </div>
            </div>
          </div>

          <Popover open={isConfigOpen} onOpenChange={setIsConfigOpen}>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="sm">
                <Settings className="w-4 h-4" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-96 p-0">
              <Tabs defaultValue="prompt" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="prompt">Prompt</TabsTrigger>
                  <TabsTrigger value="model">Model</TabsTrigger>
                  <TabsTrigger value="variables">Variables</TabsTrigger>
                  <TabsTrigger value="preview">Preview</TabsTrigger>
                </TabsList>

                <TabsContent value="prompt" className="p-4 space-y-4">
                  <div>
                    <Label>Agent Type</Label>
                    <Select
                      value={localData.agentType}
                      onValueChange={(value) => handleConfigChange('agentType', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(AGENT_TEMPLATES).map(([key, template]) => (
                          <SelectItem key={key} value={key}>
                            <div className="flex items-center gap-2">
                              <span>{template.icon}</span>
                              <span>{template.label}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>System Prompt</Label>
                    <Textarea
                      value={localData.systemPrompt || agentTemplate.systemPrompt}
                      onChange={(e) => handleConfigChange('systemPrompt', e.target.value)}
                      placeholder="Define the agent's role and behavior..."
                      className="min-h-[80px]"
                    />
                  </div>

                  <div>
                    <Label>Main Prompt</Label>
                    <Textarea
                      value={localData.prompt}
                      onChange={(e) => handleConfigChange('prompt', e.target.value)}
                      placeholder="Enter your prompt here... Use {{variables}} for dynamic content."
                      className="min-h-[120px]"
                    />
                  </div>
                </TabsContent>

                <TabsContent value="model" className="p-4 space-y-4">
                  <div>
                    <Label>Model Selection</Label>
                    <Select
                      value={localData.model}
                      onValueChange={(value) => handleConfigChange('model', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Object.entries(MODEL_COSTS).map(([model, config]) => (
                          <SelectItem key={model} value={model}>
                            <div className="flex items-center justify-between w-full">
                              <span>{model}</span>
                              <div className="flex items-center gap-2 ml-2">
                                <Badge variant={config.speed === 'fast' ? 'default' : config.speed === 'medium' ? 'secondary' : 'destructive'}>
                                  {config.speed}
                                </Badge>
                                <span className="text-xs text-gray-500">
                                  ${config.input}/1K tokens
                                </span>
                              </div>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Temperature: {localData.temperature}</Label>
                    <Slider
                      value={[localData.temperature]}
                      onValueChange={([value]) => handleConfigChange('temperature', value)}
                      min={0}
                      max={2}
                      step={0.1}
                      className="mt-2"
                    />
                    <div className="text-xs text-gray-500 mt-1">
                      Lower = more focused, Higher = more creative
                    </div>
                  </div>

                  <div>
                    <Label>Max Tokens</Label>
                    <Input
                      type="number"
                      value={localData.maxTokens}
                      onChange={(e) => handleConfigChange('maxTokens', parseInt(e.target.value))}
                      min={1}
                      max={4000}
                    />
                  </div>

                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="flex items-center gap-2 text-sm">
                      <DollarSign className="w-4 h-4" />
                      <span>Estimated Cost: ${costEstimate.toFixed(4)} per execution</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-gray-600">
                      <Clock className="w-4 h-4" />
                      <span>Speed: {MODEL_COSTS[localData.model].speed}</span>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="variables" className="p-4 space-y-4">
                  <div>
                    <Label>Variable Injection</Label>
                    <div className="text-xs text-gray-500 mb-2">
                      Use {{variableName}} in your prompt to inject dynamic values
                    </div>
                  </div>

                  <div className="space-y-2">
                    {Object.entries(localData.variables || {}).map(([key, value]) => (
                      <div key={key} className="flex items-center gap-2">
                        <Input
                          placeholder="Variable name"
                          value={key}
                          className="flex-1"
                          disabled
                        />
                        <Input
                          placeholder="Default value"
                          value={value}
                          onChange={(e) => {
                            const newVars = { ...localData.variables };
                            newVars[key] = e.target.value;
                            handleConfigChange('variables', newVars);
                          }}
                          className="flex-1"
                        />
                      </div>
                    ))}
                  </div>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      const newVars = { ...localData.variables, [`var${Date.now()}`]: '' };
                      handleConfigChange('variables', newVars);
                    }}
                  >
                    Add Variable
                  </Button>

                  <div className="border-t pt-4">
                    <Label>Memory Context</Label>
                    <div className="text-xs text-gray-500 mb-2">
                      Previous outputs that this node should remember
                    </div>
                    <div className="space-y-1">
                      {(localData.memoryContext || []).map((context, index) => (
                        <div key={index} className="text-xs bg-gray-100 p-2 rounded">
                          {context}
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="preview" className="p-4 space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label>Response Preview</Label>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={generatePreview}
                        disabled={!localData.prompt}
                      >
                        <Play className="w-4 h-4 mr-1" />
                        Generate
                      </Button>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg min-h-[120px] text-sm">
                      {previewResponse || 'Click Generate to see a preview response'}
                    </div>
                  </div>

                  <div className="border-t pt-4">
                    <Label>Performance Metrics</Label>
                    <div className="grid grid-cols-2 gap-4 mt-2">
                      <div className="bg-blue-50 p-3 rounded-lg">
                        <div className="text-xs text-blue-600">Estimated Time</div>
                        <div className="text-lg font-semibold text-blue-800">
                          {MODEL_COSTS[localData.model].speed === 'fast' ? '2-5s' :
                           MODEL_COSTS[localData.model].speed === 'medium' ? '5-15s' : '15-30s'}
                        </div>
                      </div>
                      <div className="bg-green-50 p-3 rounded-lg">
                        <div className="text-xs text-green-600">Cost per Run</div>
                        <div className="text-lg font-semibold text-green-800">
                          ${costEstimate.toFixed(4)}
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </PopoverContent>
          </Popover>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="text-xs text-gray-600 mb-2">
          {localData.prompt?.substring(0, 80)}
          {localData.prompt?.length > 80 ? '...' : ''}
        </div>

        {localData.streaming && (
          <div className="bg-yellow-50 border border-yellow-200 rounded p-2 mb-2">
            <div className="flex items-center gap-1 text-xs text-yellow-800">
              <BarChart3 className="w-3 h-3" />
              <span>Streaming enabled</span>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Est. ${costEstimate.toFixed(4)}</span>
          <span>{localData.maxTokens} tokens max</span>
        </div>

        {localData.status === 'running' && (
          <div className="mt-2 w-full bg-gray-200 rounded-full h-1">
            <div className="bg-blue-500 h-1 rounded-full animate-pulse" style={{ width: '60%' }}></div>
          </div>
        )}
      </CardContent>

      <Handle type="source" position={Position.Bottom} className="w-3 h-3" />
    </Card>
  );
});

AIAgentNode.displayName = 'AIAgentNode';