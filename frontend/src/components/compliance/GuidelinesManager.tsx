/**
 * Guidelines Manager Component
 *
 * CRUD interface for managing compliance guidelines
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
import { Switch } from '@/components/ui/switch';
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
import { Plus, Edit, Trash2, Filter, Search } from 'lucide-react';
import { toast } from 'sonner';

interface Guideline {
  id: string;
  name: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rules: Record<string, any>;
  enforcementMode: 'monitor' | 'warn' | 'enforce';
  autoRemediation: boolean;
  isActive: boolean;
  createdAt: string;
}

const CATEGORIES = [
  { value: 'tone_and_style', label: 'Tone & Style' },
  { value: 'content_restrictions', label: 'Content Restrictions' },
  { value: 'data_boundaries', label: 'Data Boundaries' },
  { value: 'privacy_and_security', label: 'Privacy & Security' },
  { value: 'brand_voice', label: 'Brand Voice' },
  { value: 'compliance_rules', label: 'Compliance Rules' },
  { value: 'escalation_triggers', label: 'Escalation Triggers' },
  { value: 'response_limits', label: 'Response Limits' },
];

const SEVERITIES = [
  { value: 'low', label: 'Low', color: 'bg-blue-500' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { value: 'high', label: 'High', color: 'bg-orange-500' },
  { value: 'critical', label: 'Critical', color: 'bg-red-500' },
];

export function GuidelinesManager() {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editingGuideline, setEditingGuideline] = useState<Guideline | null>(null);

  // Fetch guidelines
  const { data: guidelines, isLoading } = useQuery<Guideline[]>({
    queryKey: ['compliance-guidelines', categoryFilter],
    queryFn: async () => {
      const url = categoryFilter === 'all'
        ? '/api/v1/admin/compliance/guidelines'
        : `/api/v1/admin/compliance/guidelines?category=${categoryFilter}`;
      const response = await fetch(url, { credentials: 'include' });
      if (!response.ok) throw new Error('Failed to fetch guidelines');
      const data = await response.json();
      return data.guidelines;
    },
  });

  // Create guideline mutation
  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await fetch('/api/v1/admin/compliance/guidelines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error('Failed to create guideline');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-guidelines'] });
      toast.success('Guideline created successfully');
      setIsCreateDialogOpen(false);
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Update guideline mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const response = await fetch(`/api/v1/admin/compliance/guidelines/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(data),
      });
      if (!response.ok) throw new Error('Failed to update guideline');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-guidelines'] });
      toast.success('Guideline updated successfully');
      setEditingGuideline(null);
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Delete guideline mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`/api/v1/admin/compliance/guidelines/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to delete guideline');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-guidelines'] });
      toast.success('Guideline deleted successfully');
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Filter guidelines by search term
  const filteredGuidelines = guidelines?.filter(g =>
    g.name.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Compliance Guidelines</CardTitle>
              <CardDescription>
                Define rules and restrictions for AI agent behavior
              </CardDescription>
            </div>
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Guideline
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <GuidelineForm
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
                  placeholder="Search guidelines..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-[200px]">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Filter by category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {CATEGORIES.map(cat => (
                  <SelectItem key={cat.value} value={cat.value}>
                    {cat.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Guidelines Table */}
      <Card>
        <CardContent className="pt-6">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading guidelines...</div>
          ) : filteredGuidelines.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No guidelines found. Create your first guideline to get started.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Enforcement</TableHead>
                  <TableHead>Auto-Remediation</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredGuidelines.map((guideline) => (
                  <TableRow key={guideline.id}>
                    <TableCell className="font-medium">{guideline.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {CATEGORIES.find(c => c.value === guideline.category)?.label}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={SEVERITIES.find(s => s.value === guideline.severity)?.color}
                      >
                        {guideline.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={guideline.enforcementMode === 'enforce' ? 'default' : 'secondary'}>
                        {guideline.enforcementMode}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {guideline.autoRemediation ? (
                        <Badge variant="success">Enabled</Badge>
                      ) : (
                        <Badge variant="secondary">Disabled</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {guideline.isActive ? (
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
                          onClick={() => setEditingGuideline(guideline)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this guideline?')) {
                              deleteMutation.mutate(guideline.id);
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
      {editingGuideline && (
        <Dialog open={!!editingGuideline} onOpenChange={() => setEditingGuideline(null)}>
          <DialogContent className="max-w-2xl">
            <GuidelineForm
              guideline={editingGuideline}
              onSubmit={(data) => updateMutation.mutate({ id: editingGuideline.id, data })}
              isLoading={updateMutation.isPending}
            />
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}

// Guideline Form Component
function GuidelineForm({
  guideline,
  onSubmit,
  isLoading,
}: {
  guideline?: Guideline;
  onSubmit: (data: any) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({
    name: guideline?.name || '',
    category: guideline?.category || 'tone_and_style',
    severity: guideline?.severity || 'medium',
    enforcementMode: guideline?.enforcementMode || 'enforce',
    autoRemediation: guideline?.autoRemediation || false,
    rules: JSON.stringify(guideline?.rules || {}, null, 2),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const rules = JSON.parse(formData.rules);
      onSubmit({
        ...formData,
        rules,
      });
    } catch (error) {
      toast.error('Invalid JSON in rules field');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <DialogHeader>
        <DialogTitle>{guideline ? 'Edit Guideline' : 'Create Guideline'}</DialogTitle>
        <DialogDescription>
          Define compliance rules for AI agent behavior
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-4 py-4">
        <div className="space-y-2">
          <Label htmlFor="name">Guideline Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g., Professional Tone Required"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="category">Category</Label>
            <Select value={formData.category} onValueChange={(value) => setFormData({ ...formData, category: value })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CATEGORIES.map(cat => (
                  <SelectItem key={cat.value} value={cat.value}>
                    {cat.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="severity">Severity</Label>
            <Select value={formData.severity} onValueChange={(value) => setFormData({ ...formData, severity: value })}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map(sev => (
                  <SelectItem key={sev.value} value={sev.value}>
                    {sev.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="enforcementMode">Enforcement Mode</Label>
          <Select value={formData.enforcementMode} onValueChange={(value) => setFormData({ ...formData, enforcementMode: value })}>
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

        <div className="flex items-center justify-between">
          <Label htmlFor="autoRemediation">Auto-Remediation</Label>
          <Switch
            id="autoRemediation"
            checked={formData.autoRemediation}
            onCheckedChange={(checked) => setFormData({ ...formData, autoRemediation: checked })}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="rules">Rules (JSON)</Label>
          <Textarea
            id="rules"
            value={formData.rules}
            onChange={(e) => setFormData({ ...formData, rules: e.target.value })}
            placeholder='{"requiredTone": "professional", "prohibitedWords": ["casual"]}'
            rows={8}
            className="font-mono text-sm"
            required
          />
          <p className="text-xs text-muted-foreground">
            Define rules as JSON object. Example: {`{"prohibitedWords": ["competitor"], "requiredTone": "professional"}`}
          </p>
        </div>
      </div>

      <DialogFooter>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Saving...' : guideline ? 'Update' : 'Create'}
        </Button>
      </DialogFooter>
    </form>
  );
}
