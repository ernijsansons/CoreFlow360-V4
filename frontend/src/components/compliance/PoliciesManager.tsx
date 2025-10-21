/**
 * Policies Manager Component
 *
 * CRUD interface for managing agent-specific compliance policies
 */

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Plus, Edit, Trash2, Filter, Search, Settings2 } from 'lucide-react';
import { toast } from 'sonner';

interface Policy {
  id: string;
  policyName: string;
  agentId: string;
  policyType: string;
  policyConfig: Record<string, any>;
  enforcementLevel: 'monitor' | 'warn' | 'enforce';
  isActive: boolean;
  createdAt: string;
}

const POLICY_TYPES = [
  { value: 'capability_restriction', label: 'Capability Restriction' },
  { value: 'data_access_control', label: 'Data Access Control' },
  { value: 'rate_limiting', label: 'Rate Limiting' },
  { value: 'response_filtering', label: 'Response Filtering' },
  { value: 'escalation_rules', label: 'Escalation Rules' },
  { value: 'quality_requirements', label: 'Quality Requirements' },
  { value: 'cost_limits', label: 'Cost Limits' },
];

const AGENTS = [
  { value: 'all', label: 'All Agents' },
  { value: 'onboarding-agent', label: 'Onboarding Agent' },
  { value: 'company-knowledge-agent', label: 'Company Knowledge Agent' },
  { value: 'chat-support-agent', label: 'Chat Support Agent' },
  { value: 'support-ticket-agent', label: 'Support Ticket Agent' },
  { value: 'knowledge-base-agent', label: 'Knowledge Base Agent' },
];

export function PoliciesManager() {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [agentFilter, setAgentFilter] = useState('all');
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);

  // Fetch policies
  const { data: policies, isLoading } = useQuery<Policy[]>({
    queryKey: ['compliance-policies', agentFilter],
    queryFn: async () => {
      const url = agentFilter === 'all'
        ? '/api/v1/admin/compliance/policies'
        : `/api/v1/admin/compliance/policies?agentId=${agentFilter}`;
      const response = await fetch(url, { credentials: 'include' });
      if (!response.ok) throw new Error('Failed to fetch policies');
      const data = await response.json();
      return data.policies;
    },
  });

  // Create policy mutation
  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await fetch('/api/v1/admin/compliance/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error('Failed to create policy');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-policies'] });
      toast.success('Policy created successfully');
      setIsCreateDialogOpen(false);
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Update policy mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const response = await fetch(`/api/v1/admin/compliance/policies/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error('Failed to update policy');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-policies'] });
      toast.success('Policy updated successfully');
      setEditingPolicy(null);
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Delete policy mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`/api/v1/admin/compliance/policies/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to delete policy');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-policies'] });
      toast.success('Policy deleted successfully');
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Filter policies by search term
  const filteredPolicies = policies?.filter(p =>
    p.policyName.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Agent Policies</CardTitle>
              <CardDescription>
                Configure agent-specific compliance policies and restrictions
              </CardDescription>
            </div>
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Policy
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <PolicyForm
                  onSubmit={(data) => createMutation.mutate(data)}
                  isLoading={createMutation.isPending}
                />
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search policies..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={agentFilter} onValueChange={setAgentFilter}>
              <SelectTrigger className="w-[250px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Filter by agent" />
              </SelectTrigger>
              <SelectContent>
                {AGENTS.map(agent => (
                  <SelectItem key={agent.value} value={agent.value}>
                    {agent.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Policies Table */}
      <Card>
        <CardContent className="pt-6">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading policies...</div>
          ) : filteredPolicies.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No policies found. Create your first policy to get started.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Policy Name</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Enforcement</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPolicies.map((policy) => (
                  <TableRow key={policy.id}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <Settings2 className="h-4 w-4 text-muted-foreground" />
                        {policy.policyName}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {AGENTS.find(a => a.value === policy.agentId)?.label || policy.agentId}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {POLICY_TYPES.find(t => t.value === policy.policyType)?.label}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={policy.enforcementLevel === 'enforce' ? 'default' : 'secondary'}>
                        {policy.enforcementLevel}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {policy.isActive ? (
                        <Badge variant="success">Active</Badge>
                      ) : (
                        <Badge variant="secondary">Inactive</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditingPolicy(policy)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this policy?')) {
                              deleteMutation.mutate(policy.id);
                            }
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      {editingPolicy && (
        <Dialog open={!!editingPolicy} onOpenChange={() => setEditingPolicy(null)}>
          <DialogContent className="max-w-2xl">
            <PolicyForm
              policy={editingPolicy}
              onSubmit={(data) => updateMutation.mutate({ id: editingPolicy.id, data })}
              isLoading={updateMutation.isPending}
            />
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}

// Policy Form Component
function PolicyForm({
  policy,
  onSubmit,
  isLoading,
}: {
  policy?: Policy;
  onSubmit: (data: any) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({
    policyName: policy?.policyName || '',
    agentId: policy?.agentId || 'onboarding-agent',
    policyType: policy?.policyType || 'rate_limiting',
    enforcementLevel: policy?.enforcementLevel || 'enforce',
    policyConfig: JSON.stringify(policy?.policyConfig || {}, null, 2),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const policyConfig = JSON.parse(formData.policyConfig);
      onSubmit({
        ...formData,
        policyConfig,
      });
    } catch (error) {
      toast.error('Invalid JSON in policy configuration');
    }
  };

  // Policy config examples based on type
  const getConfigExample = () => {
    switch (formData.policyType) {
      case 'rate_limiting':
        return JSON.stringify({ requestsPerMinute: 10, requestsPerHour: 100 }, null, 2);
      case 'cost_limits':
        return JSON.stringify({ maxCostPerRequest: 0.5, maxDailyCost: 10.0 }, null, 2);
      case 'capability_restriction':
        return JSON.stringify({ allowedCapabilities: ['data_import', 'account_setup'], blockedCapabilities: [] }, null, 2);
      case 'quality_requirements':
        return JSON.stringify({ minimumAccuracy: 0.85, minimumCompleteness: 0.80 }, null, 2);
      default:
        return JSON.stringify({}, null, 2);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>{policy ? 'Edit Policy' : 'Create Policy'}</DialogTitle>
        <DialogDescription>
          Configure agent-specific compliance policies
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-4 py-4">
        <div className="space-y-2">
          <Label htmlFor="policyName">Policy Name</Label>
          <Input
            id="policyName"
            value={formData.policyName}
            onChange={(e) => setFormData({ ...formData, policyName: e.target.value })}
            placeholder="e.g., Rate Limiting for Onboarding Agent"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="agentId">Agent</Label>
            <Select value={formData.agentId} onValueChange={(value) => setFormData({ ...formData, agentId: value })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AGENTS.filter(a => a.value !== 'all').map(agent => (
                  <SelectItem key={agent.value} value={agent.value}>
                    {agent.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="policyType">Policy Type</Label>
            <Select value={formData.policyType} onValueChange={(value) => setFormData({ ...formData, policyType: value, policyConfig: getConfigExample() })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {POLICY_TYPES.map(type => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="enforcementLevel">Enforcement Level</Label>
          <Select value={formData.enforcementLevel} onValueChange={(value) => setFormData({ ...formData, enforcementLevel: value })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="monitor">Monitor Only</SelectItem>
              <SelectItem value="warn">Warn</SelectItem>
              <SelectItem value="enforce">Enforce</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="policyConfig">Policy Configuration (JSON)</Label>
          <Textarea
            id="policyConfig"
            value={formData.policyConfig}
            onChange={(e) => setFormData({ ...formData, policyConfig: e.target.value })}
            placeholder={getConfigExample()}
            rows={10}
            className="font-mono text-sm"
            required
          />
          <p className="text-xs text-muted-foreground">
            Configure policy-specific settings as JSON. Example shown above.
          </p>
        </div>
      </div>

      <DialogFooter>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Saving...' : policy ? 'Update' : 'Create'}
        </Button>
      </DialogFooter>
    </form>
  );
}
