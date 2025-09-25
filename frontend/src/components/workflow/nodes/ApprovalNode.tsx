/**
 * Approval Node - Multi-level Approval Chains with Escalation
 * Supports delegation, time-bound approvals, and quorum-based decisions
 */

import React, { useState, memo } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  UserCheck,
  Clock,
  Users,
  Settings,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowUp,
  Mail,
  Bell,
  Calendar,
  Shield
} from 'lucide-react';

interface ApprovalNodeData {
  label: string;
  approvalType: 'sequential' | 'parallel' | 'quorum' | 'unanimous';
  approvers: Approver[];
  escalationRules: EscalationRule[];
  timeoutHours: number;
  autoEscalate: boolean;
  allowDelegation: boolean;
  notificationChannels: NotificationChannel[];
  approvalCriteria: ApprovalCriteria;
  status?: 'idle' | 'pending' | 'approved' | 'rejected' | 'escalated' | 'expired';
  currentApprovals?: ApprovalStatus[];
  requiredApprovals?: number;
  receivedApprovals?: number;
}

interface Approver {
  id: string;
  name: string;
  email: string;
  role: string;
  department?: string;
  avatar?: string;
  isRequired: boolean;
  approvalWeight: number; // For weighted voting
  canDelegate: boolean;
  delegatedTo?: string;
  order?: number; // For sequential approvals
}

interface EscalationRule {
  id: string;
  triggerAfterHours: number;
  escalateTo: string[];
  escalationType: 'notify' | 'transfer' | 'additional';
  message?: string;
  maxEscalations: number;
  currentLevel: number;
}

interface NotificationChannel {
  type: 'email' | 'sms' | 'push' | 'slack' | 'teams';
  enabled: boolean;
  template?: string;
  immediateNotification: boolean;
  reminderFrequency?: number; // hours
}

interface ApprovalCriteria {
  dataValidation: DataValidation[];
  thresholds: ApprovalThreshold[];
  conditions: ApprovalCondition[];
  automaticRules: AutoRule[];
}

interface DataValidation {
  field: string;
  validationType: 'required' | 'min_value' | 'max_value' | 'format' | 'custom';
  value?: any;
  message?: string;
}

interface ApprovalThreshold {
  metric: string;
  operator: 'greater_than' | 'less_than' | 'equals' | 'between';
  value: number;
  secondValue?: number; // For 'between'
  requiredApproverLevel: 'any' | 'manager' | 'director' | 'executive';
}

interface ApprovalCondition {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'exists';
  value: any;
  action: 'require_additional' | 'skip_approval' | 'auto_approve' | 'auto_reject';
  additionalApprovers?: string[];
}

interface AutoRule {
  condition: string;
  action: 'approve' | 'reject' | 'escalate';
  confidence: number;
  enabled: boolean;
}

interface ApprovalStatus {
  approverId: string;
  status: 'pending' | 'approved' | 'rejected' | 'delegated';
  timestamp?: string;
  comments?: string;
  ipAddress?: string;
  userAgent?: string;
}

export const ApprovalNode = memo(({ data, selected }: NodeProps<ApprovalNodeData>) => {
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [localData, setLocalData] = useState(data);

  const getStatusIcon = () => {
    switch (localData.status) {
      case 'pending':
        return <Clock className="w-4 h-4 animate-pulse text-yellow-500" />;
      case 'approved':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'rejected':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'escalated':
        return <ArrowUp className="w-4 h-4 text-orange-500" />;
      case 'expired':
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      default:
        return <UserCheck className="w-4 h-4 text-blue-500" />;
    }
  };

  const getStatusColor = () => {
    switch (localData.status) {
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'approved':
        return 'bg-green-100 text-green-800';
      case 'rejected':
        return 'bg-red-100 text-red-800';
      case 'escalated':
        return 'bg-orange-100 text-orange-800';
      case 'expired':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };

  const getApprovalProgress = () => {
    const received = localData.receivedApprovals || 0;
    const required = localData.requiredApprovals || localData.approvers.length;
    return Math.min((received / required) * 100, 100);
  };

  const handleConfigChange = (field: string, value: any) => {
    const newData = { ...localData, [field]: value };
    setLocalData(newData);
  };

  const addApprover = () => {
    const newApprover: Approver = {
      id: `approver_${Date.now()}`,
      name: '',
      email: '',
      role: '',
      isRequired: true,
      approvalWeight: 1,
      canDelegate: true,
      order: localData.approvers.length + 1
    };
    const approvers = [...localData.approvers, newApprover];
    handleConfigChange('approvers', approvers);
  };

  const removeApprover = (id: string) => {
    const approvers = localData.approvers.filter(a => a.id !== id);
    handleConfigChange('approvers', approvers);
  };

  const updateApprover = (id: string, updates: Partial<Approver>) => {
    const approvers = localData.approvers.map(a =>
      a.id === id ? { ...a, ...updates } : a
    );
    handleConfigChange('approvers', approvers);
  };

  const addEscalationRule = () => {
    const newRule: EscalationRule = {
      id: `escalation_${Date.now()}`,
      triggerAfterHours: 24,
      escalateTo: [],
      escalationType: 'notify',
      maxEscalations: 3,
      currentLevel: 0
    };
    const rules = [...(localData.escalationRules || []), newRule];
    handleConfigChange('escalationRules', rules);
  };

  const removeEscalationRule = (id: string) => {
    const rules = (localData.escalationRules || []).filter(r => r.id !== id);
    handleConfigChange('escalationRules', rules);
  };

  return (
    <Card className={`min-w-[320px] ${selected ? 'ring-2 ring-blue-500' : ''} relative`}>
      <Handle type="target" position={Position.Top} className="w-3 h-3" />

      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500 flex items-center justify-center text-white">
              <UserCheck className="w-4 h-4" />
            </div>
            <div>
              <div className="font-semibold text-sm">{localData.label || 'Approval Process'}</div>
              <div className="text-xs text-gray-500 flex items-center gap-1">
                {getStatusIcon()}
                <Badge variant="outline" className="text-xs">
                  {localData.approvalType}
                </Badge>
                <Badge className={`text-xs ${getStatusColor()}`}>
                  {localData.status || 'idle'}
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
              <Tabs defaultValue="approvers" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="approvers">Approvers</TabsTrigger>
                  <TabsTrigger value="rules">Rules</TabsTrigger>
                  <TabsTrigger value="escalation">Escalation</TabsTrigger>
                  <TabsTrigger value="notifications">Notify</TabsTrigger>
                </TabsList>

                <TabsContent value="approvers" className="p-4 space-y-4">
                  <div>
                    <Label>Approval Type</Label>
                    <Select
                      value={localData.approvalType}
                      onValueChange={(value) => handleConfigChange('approvalType', value)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="sequential">Sequential (one after another)</SelectItem>
                        <SelectItem value="parallel">Parallel (all at once)</SelectItem>
                        <SelectItem value="quorum">Quorum (majority needed)</SelectItem>
                        <SelectItem value="unanimous">Unanimous (all required)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {localData.approvalType === 'quorum' && (
                    <div>
                      <Label>Required Approvals</Label>
                      <Input
                        type="number"
                        value={localData.requiredApprovals || Math.ceil(localData.approvers.length / 2)}
                        onChange={(e) => handleConfigChange('requiredApprovals', parseInt(e.target.value))}
                        min={1}
                        max={localData.approvers.length}
                      />
                    </div>
                  )}

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label>Approvers ({localData.approvers.length})</Label>
                      <Button variant="outline" size="sm" onClick={addApprover}>
                        Add Approver
                      </Button>
                    </div>

                    <div className="space-y-3 max-h-60 overflow-y-auto">
                      {localData.approvers.map((approver, index) => (
                        <div key={approver.id} className="border rounded-lg p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Avatar className="w-6 h-6">
                                <AvatarImage src={approver.avatar} />
                                <AvatarFallback className="text-xs">
                                  {approver.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                                </AvatarFallback>
                              </Avatar>
                              {localData.approvalType === 'sequential' && (
                                <Badge variant="outline" className="text-xs">{index + 1}</Badge>
                              )}
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeApprover(approver.id)}
                            >
                              ×
                            </Button>
                          </div>

                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <Label className="text-xs">Name</Label>
                              <Input
                                placeholder="Approver name"
                                value={approver.name}
                                onChange={(e) => updateApprover(approver.id, { name: e.target.value })}
                                className="text-sm"
                              />
                            </div>

                            <div>
                              <Label className="text-xs">Email</Label>
                              <Input
                                placeholder="email@company.com"
                                value={approver.email}
                                onChange={(e) => updateApprover(approver.id, { email: e.target.value })}
                                className="text-sm"
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <Label className="text-xs">Role</Label>
                              <Select
                                value={approver.role}
                                onValueChange={(value) => updateApprover(approver.id, { role: value })}
                              >
                                <SelectTrigger className="text-sm">
                                  <SelectValue placeholder="Select role" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="manager">Manager</SelectItem>
                                  <SelectItem value="director">Director</SelectItem>
                                  <SelectItem value="vp">VP</SelectItem>
                                  <SelectItem value="executive">Executive</SelectItem>
                                  <SelectItem value="finance">Finance</SelectItem>
                                  <SelectItem value="legal">Legal</SelectItem>
                                  <SelectItem value="hr">HR</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>

                            <div>
                              <Label className="text-xs">Weight</Label>
                              <Input
                                type="number"
                                value={approver.approvalWeight}
                                onChange={(e) => updateApprover(approver.id, { approvalWeight: parseFloat(e.target.value) })}
                                min={0.1}
                                max={10}
                                step={0.1}
                                className="text-sm"
                              />
                            </div>
                          </div>

                          <div className="flex items-center space-x-4">
                            <div className="flex items-center space-x-2">
                              <Switch
                                checked={approver.isRequired}
                                onCheckedChange={(checked) => updateApprover(approver.id, { isRequired: checked })}
                              />
                              <Label className="text-xs">Required</Label>
                            </div>

                            <div className="flex items-center space-x-2">
                              <Switch
                                checked={approver.canDelegate}
                                onCheckedChange={(checked) => updateApprover(approver.id, { canDelegate: checked })}
                              />
                              <Label className="text-xs">Can Delegate</Label>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="rules" className="p-4 space-y-4">
                  <div>
                    <Label>Timeout (Hours)</Label>
                    <Input
                      type="number"
                      value={localData.timeoutHours || 24}
                      onChange={(e) => handleConfigChange('timeoutHours', parseInt(e.target.value))}
                      min={1}
                      max={168} // 1 week
                    />
                    <div className="text-xs text-gray-500 mt-1">
                      Time limit for approval before escalation
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={localData.autoEscalate || false}
                      onCheckedChange={(checked) => handleConfigChange('autoEscalate', checked)}
                    />
                    <Label>Auto-escalate on timeout</Label>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={localData.allowDelegation || true}
                      onCheckedChange={(checked) => handleConfigChange('allowDelegation', checked)}
                    />
                    <Label>Allow approval delegation</Label>
                  </div>

                  <div>
                    <Label>Auto-approval Rules</Label>
                    <div className="text-xs text-gray-500 mb-2">
                      Define conditions for automatic approval/rejection
                    </div>
                    {/* Auto-approval rules would be implemented here */}
                  </div>
                </TabsContent>

                <TabsContent value="escalation" className="p-4 space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label>Escalation Rules</Label>
                      <Button variant="outline" size="sm" onClick={addEscalationRule}>
                        Add Rule
                      </Button>
                    </div>

                    <div className="space-y-3">
                      {(localData.escalationRules || []).map((rule) => (
                        <div key={rule.id} className="border rounded-lg p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="text-sm font-medium">Escalation Level {rule.currentLevel + 1}</div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeEscalationRule(rule.id)}
                            >
                              ×
                            </Button>
                          </div>

                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <Label className="text-xs">Trigger After (Hours)</Label>
                              <Input
                                type="number"
                                value={rule.triggerAfterHours}
                                className="text-sm"
                                min={1}
                              />
                            </div>

                            <div>
                              <Label className="text-xs">Escalation Type</Label>
                              <Select value={rule.escalationType}>
                                <SelectTrigger className="text-sm">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="notify">Notify Only</SelectItem>
                                  <SelectItem value="transfer">Transfer Approval</SelectItem>
                                  <SelectItem value="additional">Add Approvers</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </div>

                          <div>
                            <Label className="text-xs">Escalate To</Label>
                            <Input
                              placeholder="manager@company.com, director@company.com"
                              className="text-sm"
                            />
                          </div>

                          <div>
                            <Label className="text-xs">Message Template</Label>
                            <Input
                              placeholder="Approval required for {{item}} - escalated due to timeout"
                              className="text-sm"
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="notifications" className="p-4 space-y-4">
                  <div>
                    <Label>Notification Channels</Label>
                    <div className="space-y-3 mt-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Mail className="w-4 h-4" />
                          <span className="text-sm">Email</span>
                        </div>
                        <Switch defaultChecked />
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Bell className="w-4 h-4" />
                          <span className="text-sm">Push Notifications</span>
                        </div>
                        <Switch defaultChecked />
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Users className="w-4 h-4" />
                          <span className="text-sm">Slack</span>
                        </div>
                        <Switch />
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4" />
                          <span className="text-sm">SMS (High Priority)</span>
                        </div>
                        <Switch />
                      </div>
                    </div>
                  </div>

                  <div>
                    <Label>Reminder Frequency</Label>
                    <Select defaultValue="24">
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">Every Hour</SelectItem>
                        <SelectItem value="4">Every 4 Hours</SelectItem>
                        <SelectItem value="12">Every 12 Hours</SelectItem>
                        <SelectItem value="24">Daily</SelectItem>
                        <SelectItem value="72">Every 3 Days</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Email Template</Label>
                    <select className="w-full mt-1 p-2 border rounded">
                      <option>Standard Approval Request</option>
                      <option>Urgent Approval Required</option>
                      <option>Final Notice</option>
                      <option>Custom Template</option>
                    </select>
                  </div>
                </TabsContent>
              </Tabs>
            </PopoverContent>
          </Popover>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="space-y-3">
          {/* Approval Progress */}
          <div>
            <div className="flex items-center justify-between text-xs mb-1">
              <span>Approval Progress</span>
              <span>{localData.receivedApprovals || 0} / {localData.requiredApprovals || localData.approvers.length}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${getApprovalProgress()}%` }}
              ></div>
            </div>
          </div>

          {/* Approvers List */}
          <div>
            <div className="text-xs font-medium mb-2">Approvers ({localData.approvers.length})</div>
            <div className="flex flex-wrap gap-1">
              {localData.approvers.slice(0, 6).map((approver) => (
                <Avatar key={approver.id} className="w-6 h-6" title={approver.name}>
                  <AvatarImage src={approver.avatar} />
                  <AvatarFallback className="text-xs">
                    {approver.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                  </AvatarFallback>
                </Avatar>
              ))}
              {localData.approvers.length > 6 && (
                <div className="w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center text-xs">
                  +{localData.approvers.length - 6}
                </div>
              )}
            </div>
          </div>

          {/* Current Status */}
          {localData.status === 'pending' && (
            <div className="bg-yellow-50 border border-yellow-200 rounded p-2">
              <div className="flex items-center gap-1 text-xs text-yellow-800">
                <Clock className="w-3 h-3" />
                <span>Waiting for approvals</span>
              </div>
              <div className="text-xs text-yellow-600 mt-1">
                Timeout: {localData.timeoutHours}h
              </div>
            </div>
          )}

          {localData.status === 'escalated' && (
            <div className="bg-orange-50 border border-orange-200 rounded p-2">
              <div className="flex items-center gap-1 text-xs text-orange-800">
                <ArrowUp className="w-3 h-3" />
                <span>Escalated to management</span>
              </div>
            </div>
          )}

          {/* Quick Actions */}
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>{localData.approvalType} approval</span>
            <span>{localData.timeoutHours}h timeout</span>
          </div>
        </div>
      </CardContent>

      <Handle type="source" position={Position.Bottom} id="approved" className="w-3 h-3" style={{ left: '25%' }} />
      <Handle type="source" position={Position.Bottom} id="rejected" className="w-3 h-3" style={{ left: '75%' }} />
    </Card>
  );
});

ApprovalNode.displayName = 'ApprovalNode';