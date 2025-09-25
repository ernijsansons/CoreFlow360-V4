/**
 * Logic Node - Advanced Conditional and Flow Control Node
 * Supports complex branching, loops, parallel execution, and pattern matching
 */

import React, { useState, memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  GitBranch,
  RotateCcw,
  Zap,
  Clock,
  Settings,
  Play,
  Pause,
  Square,
  CheckCircle,
  AlertCircle,
  ArrowUpDown,
  Filter,
  Code,
  Timer
} from 'lucide-react';

interface LogicNodeData {
  label: string;
  logicType: 'condition' | 'loop' | 'parallel' | 'delay' | 'transform' | 'pattern_match' | 'error_boundary';
  expression: string;
  conditions: LogicCondition[];
  loopConfig?: LoopConfig;
  parallelConfig?: ParallelConfig;
  delayConfig?: DelayConfig;
  transformConfig?: TransformConfig;
  patternConfig?: PatternConfig;
  errorConfig?: ErrorConfig;
  status?: 'idle' | 'running' | 'completed' | 'failed';
  executionCount?: number;
  lastExecutionTime?: number;
}

interface LogicCondition {
  id: string;
  field: string;
  operator: 'equals' | 'not_equals' | 'greater_than' | 'less_than' | 'contains' | 'regex' | 'exists';
  value: any;
  dataType: 'string' | 'number' | 'boolean' | 'array' | 'object';
}

interface LoopConfig {
  loopType: 'for' | 'while' | 'foreach';
  maxIterations: number;
  breakCondition: string;
  iteratorVariable: string;
  collectionPath: string;
}

interface ParallelConfig {
  mode: 'race' | 'wait_all' | 'wait_any' | 'wait_n';
  waitCount?: number;
  timeoutMs: number;
  failFast: boolean;
}

interface DelayConfig {
  delayType: 'fixed' | 'dynamic' | 'until_time' | 'until_condition';
  delayMs?: number;
  delayExpression?: string;
  untilTime?: string;
  untilCondition?: string;
}

interface TransformConfig {
  transformType: 'map' | 'filter' | 'reduce' | 'jsonpath' | 'javascript' | 'template';
  expression: string;
  outputPath: string;
  preserveInput: boolean;
}

interface PatternConfig {
  patterns: {
    regex?: string;
    jsonPath?: string;
    condition?: string;
    action: string;
  }[];
  defaultAction: string;
  caseSensitive: boolean;
}

interface ErrorConfig {
  retryAttempts: number;
  retryDelay: number;
  fallbackAction: 'fail' | 'skip' | 'default_value' | 'alternative_path';
  fallbackValue?: any;
  errorHandlers: {
    errorType: string;
    action: string;
  }[];
}

const LOGIC_TYPES = {
  condition: {
    label: 'Condition',
    icon: GitBranch,
    color: 'bg-blue-500',
    description: 'Branch execution based on conditions'
  },
  loop: {
    label: 'Loop',
    icon: RotateCcw,
    color: 'bg-purple-500',
    description: 'Repeat execution with break conditions'
  },
  parallel: {
    label: 'Parallel',
    icon: ArrowUpDown,
    color: 'bg-green-500',
    description: 'Execute multiple paths concurrently'
  },
  delay: {
    label: 'Delay',
    icon: Timer,
    color: 'bg-orange-500',
    description: 'Wait for time or condition'
  },
  transform: {
    label: 'Transform',
    icon: Filter,
    color: 'bg-cyan-500',
    description: 'Transform data between nodes'
  },
  pattern_match: {
    label: 'Pattern Match',
    icon: Code,
    color: 'bg-indigo-500',
    description: 'Pattern matching and routing'
  },
  error_boundary: {
    label: 'Error Handler',
    icon: AlertCircle,
    color: 'bg-red-500',
    description: 'Handle errors and provide fallbacks'
  }
};

const OPERATORS = [
  { value: 'equals', label: 'Equals', symbol: '==' },
  { value: 'not_equals', label: 'Not Equals', symbol: '!=' },
  { value: 'greater_than', label: 'Greater Than', symbol: '>' },
  { value: 'less_than', label: 'Less Than', symbol: '<' },
  { value: 'contains', label: 'Contains', symbol: '∋' },
  { value: 'regex', label: 'Regex Match', symbol: '~' },
  { value: 'exists', label: 'Exists', symbol: '∃' }
];

export const LogicNode = memo(({ data, selected }: NodeProps<LogicNodeData>) => {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [localData, setLocalData] = useState(data);

  const logicTypeConfig = LOGIC_TYPES[localData.logicType];
  const IconComponent = logicTypeConfig.icon;

  const getStatusIcon = () => {
    switch (localData.status) {
      case 'running':
        return <Zap className="w-4 h-4 animate-pulse text-yellow-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      default:
        return <IconComponent className="w-4 h-4 text-gray-500" />;
    }
  };

  const getHandleCount = () => {
    switch (localData.logicType) {
      case 'condition':
        return Math.max(2, localData.conditions?.length || 2);
      case 'parallel':
        return localData.parallelConfig?.waitCount || 3;
      case 'pattern_match':
        return localData.patternConfig?.patterns?.length || 2;
      default:
        return 1;
    }
  };

  const handleConfigChange = (field: string, value: any) => {
    const newData = { ...localData, [field]: value };
    setLocalData(newData);
  };

  const addCondition = () => {
    const newCondition: LogicCondition = {
      id: `cond_${Date.now()}`,
      field: '',
      operator: 'equals',
      value: '',
      dataType: 'string'
    };
    const conditions = [...(localData.conditions || []), newCondition];
    handleConfigChange('conditions', conditions);
  };

  const removeCondition = (id: string) => {
    const conditions = (localData.conditions || []).filter(c => c.id !== id);
    handleConfigChange('conditions', conditions);
  };

  const updateCondition = (id: string, updates: Partial<LogicCondition>) => {
    const conditions = (localData.conditions || []).map(c =>
      c.id === id ? { ...c, ...updates } : c
    );
    handleConfigChange('conditions', conditions);
  };

  const renderConditionEditor = () => (
    <div className="space-y-4">
      <div>
        <Label>Execution Logic</Label>
        <Select
          value={localData.expression || 'AND'}
          onValueChange={(value) => handleConfigChange('expression', value)}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="AND">ALL conditions must be true (AND)</SelectItem>
            <SelectItem value="OR">ANY condition must be true (OR)</SelectItem>
            <SelectItem value="XOR">ONLY ONE condition must be true (XOR)</SelectItem>
            <SelectItem value="CUSTOM">Custom expression</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {localData.expression === 'CUSTOM' && (
        <div>
          <Label>Custom Expression</Label>
          <Input
            placeholder="e.g., (A AND B) OR (C AND NOT D)"
            className="font-mono text-sm"
          />
          <div className="text-xs text-gray-500 mt-1">
            Use condition IDs (A, B, C...) with AND, OR, NOT operators
          </div>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-2">
          <Label>Conditions</Label>
          <Button variant="outline" size="sm" onClick={addCondition}>
            Add Condition
          </Button>
        </div>

        <div className="space-y-3">
          {(localData.conditions || []).map((condition, index) => (
            <div key={condition.id} className="border rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <Badge variant="outline">{String.fromCharCode(65 + index)}</Badge>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removeCondition(condition.id)}
                >
                  ×
                </Button>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div>
                  <Label className="text-xs">Field Path</Label>
                  <Input
                    placeholder="data.field"
                    value={condition.field}
                    onChange={(e) => updateCondition(condition.id, { field: e.target.value })}
                    className="text-sm"
                  />
                </div>

                <div>
                  <Label className="text-xs">Operator</Label>
                  <Select
                    value={condition.operator}
                    onValueChange={(value) => updateCondition(condition.id, { operator: value as any })}
                  >
                    <SelectTrigger className="text-sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {OPERATORS.map(op => (
                        <SelectItem key={op.value} value={op.value}>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs">{op.symbol}</span>
                            <span>{op.label}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label className="text-xs">Value</Label>
                  <Input
                    placeholder="comparison value"
                    value={condition.value}
                    onChange={(e) => updateCondition(condition.id, { value: e.target.value })}
                    className="text-sm"
                  />
                </div>
              </div>

              <div>
                <Label className="text-xs">Data Type</Label>
                <Select
                  value={condition.dataType}
                  onValueChange={(value) => updateCondition(condition.id, { dataType: value as any })}
                >
                  <SelectTrigger className="text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="string">String</SelectItem>
                    <SelectItem value="number">Number</SelectItem>
                    <SelectItem value="boolean">Boolean</SelectItem>
                    <SelectItem value="array">Array</SelectItem>
                    <SelectItem value="object">Object</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderLoopEditor = () => (
    <div className="space-y-4">
      <div>
        <Label>Loop Type</Label>
        <Select
          value={localData.loopConfig?.loopType || 'for'}
          onValueChange={(value) => handleConfigChange('loopConfig', {
            ...localData.loopConfig,
            loopType: value
          })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="for">For Loop (count-based)</SelectItem>
            <SelectItem value="while">While Loop (condition-based)</SelectItem>
            <SelectItem value="foreach">For Each (collection-based)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Max Iterations</Label>
          <Input
            type="number"
            value={localData.loopConfig?.maxIterations || 100}
            onChange={(e) => handleConfigChange('loopConfig', {
              ...localData.loopConfig,
              maxIterations: parseInt(e.target.value)
            })}
          />
        </div>

        <div>
          <Label>Iterator Variable</Label>
          <Input
            placeholder="i"
            value={localData.loopConfig?.iteratorVariable || 'i'}
            onChange={(e) => handleConfigChange('loopConfig', {
              ...localData.loopConfig,
              iteratorVariable: e.target.value
            })}
          />
        </div>
      </div>

      {localData.loopConfig?.loopType === 'foreach' && (
        <div>
          <Label>Collection Path</Label>
          <Input
            placeholder="data.items"
            value={localData.loopConfig.collectionPath || ''}
            onChange={(e) => handleConfigChange('loopConfig', {
              ...localData.loopConfig,
              collectionPath: e.target.value
            })}
          />
        </div>
      )}

      <div>
        <Label>Break Condition</Label>
        <Textarea
          placeholder="condition to break the loop early"
          value={localData.loopConfig?.breakCondition || ''}
          onChange={(e) => handleConfigChange('loopConfig', {
            ...localData.loopConfig,
            breakCondition: e.target.value
          })}
          className="min-h-[60px]"
        />
      </div>
    </div>
  );

  const renderParallelEditor = () => (
    <div className="space-y-4">
      <div>
        <Label>Execution Mode</Label>
        <Select
          value={localData.parallelConfig?.mode || 'wait_all'}
          onValueChange={(value) => handleConfigChange('parallelConfig', {
            ...localData.parallelConfig,
            mode: value
          })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="race">Race (first to complete)</SelectItem>
            <SelectItem value="wait_all">Wait All (all must complete)</SelectItem>
            <SelectItem value="wait_any">Wait Any (at least one success)</SelectItem>
            <SelectItem value="wait_n">Wait N (specific count)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {localData.parallelConfig?.mode === 'wait_n' && (
        <div>
          <Label>Wait Count</Label>
          <Input
            type="number"
            value={localData.parallelConfig.waitCount || 2}
            onChange={(e) => handleConfigChange('parallelConfig', {
              ...localData.parallelConfig,
              waitCount: parseInt(e.target.value)
            })}
          />
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Timeout (ms)</Label>
          <Input
            type="number"
            value={localData.parallelConfig?.timeoutMs || 30000}
            onChange={(e) => handleConfigChange('parallelConfig', {
              ...localData.parallelConfig,
              timeoutMs: parseInt(e.target.value)
            })}
          />
        </div>

        <div className="flex items-center space-x-2">
          <Switch
            checked={localData.parallelConfig?.failFast || false}
            onCheckedChange={(checked) => handleConfigChange('parallelConfig', {
              ...localData.parallelConfig,
              failFast: checked
            })}
          />
          <Label>Fail Fast</Label>
        </div>
      </div>
    </div>
  );

  const renderTransformEditor = () => (
    <div className="space-y-4">
      <div>
        <Label>Transform Type</Label>
        <Select
          value={localData.transformConfig?.transformType || 'map'}
          onValueChange={(value) => handleConfigChange('transformConfig', {
            ...localData.transformConfig,
            transformType: value
          })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="map">Map (transform each item)</SelectItem>
            <SelectItem value="filter">Filter (select items)</SelectItem>
            <SelectItem value="reduce">Reduce (aggregate)</SelectItem>
            <SelectItem value="jsonpath">JSONPath Query</SelectItem>
            <SelectItem value="javascript">JavaScript Expression</SelectItem>
            <SelectItem value="template">Template Engine</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div>
        <Label>Expression</Label>
        <Textarea
          placeholder="transformation expression"
          value={localData.transformConfig?.expression || ''}
          onChange={(e) => handleConfigChange('transformConfig', {
            ...localData.transformConfig,
            expression: e.target.value
          })}
          className="min-h-[80px] font-mono text-sm"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label>Output Path</Label>
          <Input
            placeholder="result"
            value={localData.transformConfig?.outputPath || 'result'}
            onChange={(e) => handleConfigChange('transformConfig', {
              ...localData.transformConfig,
              outputPath: e.target.value
            })}
          />
        </div>

        <div className="flex items-center space-x-2">
          <Switch
            checked={localData.transformConfig?.preserveInput || true}
            onCheckedChange={(checked) => handleConfigChange('transformConfig', {
              ...localData.transformConfig,
              preserveInput: checked
            })}
          />
          <Label>Preserve Input</Label>
        </div>
      </div>
    </div>
  );

  return (
    <Card className={`min-w-[250px] ${selected ? 'ring-2 ring-blue-500' : ''} relative`}>
      <Handle type="target" position={Position.Top} className="w-3 h-3" />

      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-lg ${logicTypeConfig.color} flex items-center justify-center text-white`}>
              <IconComponent className="w-4 h-4" />
            </div>
            <div>
              <div className="font-semibold text-sm">{localData.label || logicTypeConfig.label}</div>
              <div className="text-xs text-gray-500 flex items-center gap-1">
                {getStatusIcon()}
                <Badge variant="outline" className="text-xs">
                  {localData.logicType}
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
              <Tabs defaultValue="config" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="config">Configuration</TabsTrigger>
                  <TabsTrigger value="advanced">Advanced</TabsTrigger>
                </TabsList>

                <TabsContent value="config" className="p-4">
                  <div className="space-y-4">
                    <div>
                      <Label>Logic Type</Label>
                      <Select
                        value={localData.logicType}
                        onValueChange={(value) => handleConfigChange('logicType', value)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {Object.entries(LOGIC_TYPES).map(([key, config]) => (
                            <SelectItem key={key} value={key}>
                              <div className="flex items-center gap-2">
                                <config.icon className="w-4 h-4" />
                                <div>
                                  <div>{config.label}</div>
                                  <div className="text-xs text-gray-500">{config.description}</div>
                                </div>
                              </div>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {localData.logicType === 'condition' && renderConditionEditor()}
                    {localData.logicType === 'loop' && renderLoopEditor()}
                    {localData.logicType === 'parallel' && renderParallelEditor()}
                    {localData.logicType === 'transform' && renderTransformEditor()}
                  </div>
                </TabsContent>

                <TabsContent value="advanced" className="p-4">
                  <div className="space-y-4">
                    <div>
                      <Label>Node Label</Label>
                      <Input
                        value={localData.label || ''}
                        onChange={(e) => handleConfigChange('label', e.target.value)}
                        placeholder="Custom node label"
                      />
                    </div>

                    <div className="bg-gray-50 p-3 rounded-lg">
                      <div className="text-sm font-medium mb-2">Execution Statistics</div>
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div>
                          <div className="text-gray-500">Executions</div>
                          <div className="font-mono">{localData.executionCount || 0}</div>
                        </div>
                        <div>
                          <div className="text-gray-500">Last Runtime</div>
                          <div className="font-mono">
                            {localData.lastExecutionTime ? `${localData.lastExecutionTime}ms` : 'N/A'}
                          </div>
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
          {logicTypeConfig.description}
        </div>

        {localData.expression && (
          <div className="bg-gray-50 p-2 rounded text-xs font-mono">
            {localData.expression.length > 40
              ? `${localData.expression.substring(0, 40)}...`
              : localData.expression
            }
          </div>
        )}

        {localData.status === 'running' && (
          <div className="mt-2 w-full bg-gray-200 rounded-full h-1">
            <div className="bg-blue-500 h-1 rounded-full animate-pulse" style={{ width: '40%' }}></div>
          </div>
        )}
      </CardContent>

      {/* Dynamic output handles based on logic type */}
      {Array.from({ length: getHandleCount() }, (_, index) => (
        <Handle
          key={index}
          type="source"
          position={Position.Bottom}
          id={`output-${index}`}
          className="w-3 h-3"
          style={{
            left: `${(100 / (getHandleCount() + 1)) * (index + 1)}%`,
            transform: 'translateX(-50%)'
          }}
        />
      ))}
    </Card>
  );
});

LogicNode.displayName = 'LogicNode';