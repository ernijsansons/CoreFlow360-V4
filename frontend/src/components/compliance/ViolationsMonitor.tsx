/**
 * Violations Monitor Component
 *
 * Monitor and manage compliance violations
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
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  AlertTriangle,
  XCircle,
  AlertCircle,
  Info,
  Filter,
  Search,
  CheckCircle,
  Eye,
  Clock
} from 'lucide-react';
import { toast } from 'sonner';
import { formatDistanceToNow } from 'date-fns';

interface Violation {
  id: string;
  agentId: string;
  taskId: string;
  violationType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  guidelineName?: string;
  policyName?: string;
  details: Record<string, any>;
  originalContent?: string;
  remediatedContent?: string;
  actionTaken: 'blocked' | 'modified' | 'warned' | 'escalated';
  occurredAt: string;
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  resolutionNotes?: string;
}

const VIOLATION_TYPES = [
  { value: 'all', label: 'All Types' },
  { value: 'prohibited_content', label: 'Prohibited Content' },
  { value: 'tone_violation', label: 'Tone Violation' },
  { value: 'data_boundary_breach', label: 'Data Boundary Breach' },
  { value: 'unauthorized_capability', label: 'Unauthorized Capability' },
  { value: 'rate_limit_exceeded', label: 'Rate Limit Exceeded' },
  { value: 'quality_below_threshold', label: 'Quality Below Threshold' },
  { value: 'escalation_required', label: 'Escalation Required' },
  { value: 'pii_exposure', label: 'PII Exposure' },
  { value: 'cost_limit_exceeded', label: 'Cost Limit Exceeded' },
];

const SEVERITIES = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical', icon: XCircle, color: 'text-red-500' },
  { value: 'high', label: 'High', icon: AlertTriangle, color: 'text-orange-500' },
  { value: 'medium', label: 'Medium', icon: AlertCircle, color: 'text-yellow-500' },
  { value: 'low', label: 'Low', icon: Info, color: 'text-blue-500' },
];

export function ViolationsMonitor() {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [resolvedFilter, setResolvedFilter] = useState('unresolved');
  const [selectedViolation, setSelectedViolation] = useState<Violation | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState('');

  // Fetch violations
  const { data: violations, isLoading } = useQuery<Violation[]>({
    queryKey: ['compliance-violations', typeFilter, severityFilter, resolvedFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (typeFilter !== 'all') params.append('violationType', typeFilter);
      if (severityFilter !== 'all') params.append('severity', severityFilter);
      if (resolvedFilter !== 'all') params.append('resolved', resolvedFilter === 'resolved' ? 'true' : 'false');

      const response = await fetch(`/api/v1/admin/compliance/violations?${params.toString()}`, {
        credentials: 'include'
      });
      if (!response.ok) throw new Error('Failed to fetch violations');
      const data = await response.json();
      return data.violations;
    },
    refetchInterval: 15000, // Refresh every 15 seconds
  });

  // Resolve violation mutation
  const resolveMutation = useMutation({
    mutationFn: async ({ id, notes }: { id: string; notes: string }) => {
      const response = await fetch(`/api/v1/admin/compliance/violations/${id}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ resolutionNotes: notes }),
      });
      if (!response.ok) throw new Error('Failed to resolve violation');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-violations'] });
      queryClient.invalidateQueries({ queryKey: ['compliance-violations-summary'] });
      toast.success('Violation resolved successfully');
      setSelectedViolation(null);
      setResolutionNotes('');
    },
    onError: (error: Error) => {
      toast.error(error.message);
    },
  });

  // Filter violations by search term
  const filteredViolations = violations?.filter(v =>
    v.agentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
    v.taskId.toLowerCase().includes(searchTerm.toLowerCase()) ||
    v.violationType.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  const getSeverityIcon = (severity: string) => {
    const sev = SEVERITIES.find(s => s.value === severity);
    if (!sev || !sev.icon) return Info;
    return sev.icon;
  };

  const getSeverityColor = (severity: string) => {
    return SEVERITIES.find(s => s.value === severity)?.color || 'text-gray-500';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <CardTitle>Compliance Violations</CardTitle>
          <CardDescription>
            Monitor and resolve AI agent compliance violations
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search violations..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger>
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent>
                {VIOLATION_TYPES.map(type => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by severity" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map(sev => (
                  <SelectItem key={sev.value} value={sev.value}>
                    {sev.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={resolvedFilter} onValueChange={setResolvedFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="unresolved">Unresolved Only</SelectItem>
                <SelectItem value="resolved">Resolved Only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Violations Table */}
      <Card>
        <CardContent className="pt-6">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading violations...</div>
          ) : filteredViolations.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
              <p className="text-lg font-medium">No violations found</p>
              <p className="text-sm">All agents are operating within compliance guidelines</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Guideline/Policy</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Time</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredViolations.map((violation) => {
                  const Icon = getSeverityIcon(violation.severity);
                  const colorClass = getSeverityColor(violation.severity);

                  return (
                    <TableRow key={violation.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Icon className={`h-4 w-4 ${colorClass}`} />
                          <Badge className={violation.severity === 'critical' ? 'bg-red-500' : violation.severity === 'high' ? 'bg-orange-500' : violation.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'}>
                            {violation.severity}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {VIOLATION_TYPES.find(t => t.value === violation.violationType)?.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {violation.agentId}
                      </TableCell>
                      <TableCell>
                        {violation.guidelineName || violation.policyName || '-'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={violation.actionTaken === 'blocked' ? 'destructive' : 'secondary'}>
                          {violation.actionTaken}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 text-sm text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {formatDistanceToNow(new Date(violation.occurredAt), { addSuffix: true })}
                        </div>
                      </TableCell>
                      <TableCell>
                        {violation.resolved ? (
                          <Badge variant="success">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Resolved
                          </Badge>
                        ) : (
                          <Badge variant="destructive">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Unresolved
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedViolation(violation)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Violation Details Dialog */}
      {selectedViolation && (
        <Dialog open={!!selectedViolation} onOpenChange={() => setSelectedViolation(null)}>
          <DialogContent className="max-w-3xl">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                {React.createElement(getSeverityIcon(selectedViolation.severity), {
                  className: `h-5 w-5 ${getSeverityColor(selectedViolation.severity)}`
                })}
                Violation Details
              </DialogTitle>
              <DialogDescription>
                Review violation information and resolve if necessary
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">Severity</Label>
                  <p className="font-medium capitalize">{selectedViolation.severity}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Type</Label>
                  <p className="font-medium">
                    {VIOLATION_TYPES.find(t => t.value === selectedViolation.violationType)?.label}
                  </p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Agent</Label>
                  <p className="font-mono text-sm">{selectedViolation.agentId}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Task ID</Label>
                  <p className="font-mono text-sm">{selectedViolation.taskId}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Occurred</Label>
                  <p className="text-sm">
                    {formatDistanceToNow(new Date(selectedViolation.occurredAt), { addSuffix: true })}
                  </p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Action Taken</Label>
                  <p className="font-medium capitalize">{selectedViolation.actionTaken}</p>
                </div>
              </div>

              {/* Guideline/Policy Info */}
              {(selectedViolation.guidelineName || selectedViolation.policyName) && (
                <div>
                  <Label className="text-muted-foreground">
                    {selectedViolation.guidelineName ? 'Guideline' : 'Policy'}
                  </Label>
                  <p className="font-medium">
                    {selectedViolation.guidelineName || selectedViolation.policyName}
                  </p>
                </div>
              )}

              {/* Details */}
              <div>
                <Label className="text-muted-foreground">Details</Label>
                <pre className="mt-1 p-3 bg-muted rounded-md text-sm overflow-auto max-h-32">
                  {JSON.stringify(selectedViolation.details, null, 2)}
                </pre>
              </div>

              {/* Original Content */}
              {selectedViolation.originalContent && (
                <div>
                  <Label className="text-muted-foreground">Original Content</Label>
                  <div className="mt-1 p-3 bg-muted rounded-md text-sm max-h-32 overflow-auto">
                    {selectedViolation.originalContent}
                  </div>
                </div>
              )}

              {/* Remediated Content */}
              {selectedViolation.remediatedContent && (
                <div>
                  <Label className="text-muted-foreground">Remediated Content</Label>
                  <div className="mt-1 p-3 bg-green-50 dark:bg-green-950 rounded-md text-sm max-h-32 overflow-auto">
                    {selectedViolation.remediatedContent}
                  </div>
                </div>
              )}

              {/* Resolution Section */}
              {selectedViolation.resolved ? (
                <div className="border-t pt-4">
                  <Label className="text-muted-foreground">Resolution</Label>
                  <div className="mt-2 space-y-2">
                    <p className="text-sm">
                      <span className="text-muted-foreground">Resolved by:</span>{' '}
                      <span className="font-medium">{selectedViolation.resolvedBy}</span>
                    </p>
                    <p className="text-sm">
                      <span className="text-muted-foreground">Resolved:</span>{' '}
                      {formatDistanceToNow(new Date(selectedViolation.resolvedAt!), { addSuffix: true })}
                    </p>
                    {selectedViolation.resolutionNotes && (
                      <div>
                        <Label className="text-muted-foreground">Notes</Label>
                        <p className="mt-1 text-sm">{selectedViolation.resolutionNotes}</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="border-t pt-4">
                  <Label htmlFor="resolutionNotes">Resolution Notes</Label>
                  <Textarea
                    id="resolutionNotes"
                    value={resolutionNotes}
                    onChange={(e) => setResolutionNotes(e.target.value)}
                    placeholder="Explain how this violation was resolved..."
                    rows={3}
                    className="mt-1"
                  />
                </div>
              )}
            </div>

            <DialogFooter>
              {!selectedViolation.resolved && (
                <Button
                  onClick={() => {
                    if (!resolutionNotes.trim()) {
                      toast.error('Please provide resolution notes');
                      return;
                    }
                    resolveMutation.mutate({
                      id: selectedViolation.id,
                      notes: resolutionNotes
                    });
                  }}
                  disabled={resolveMutation.isPending}
                >
                  {resolveMutation.isPending ? 'Resolving...' : 'Mark as Resolved'}
                </Button>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
