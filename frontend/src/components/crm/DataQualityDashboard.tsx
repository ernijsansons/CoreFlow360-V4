/**
 * Data Quality Dashboard
 * Real-time monitoring and management of CRM data quality
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  ShieldCheck, AlertTriangle, CheckCircle, XCircle, Zap,
  TrendingUp, TrendingDown, Minus, Filter, RefreshCw
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface DataQualityDashboard {
  quality_summary: QualitySummary[];
  duplicate_summary: any[];
  recent_issues: DataQualityIssue[];
}

interface QualitySummary {
  entity_type: string;
  total_records: number;
  avg_quality_score: number;
  healthy_count: number;
  at_risk_count: number;
  critical_count: number;
  total_issues: number;
  total_critical_issues: number;
}

interface DataQualityIssue {
  id: string;
  entity_type: string;
  entity_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  issue_type: string;
  field_name?: string;
  description: string;
  auto_fixable: boolean;
  detected_at: string;
}

export function DataQualityDashboard() {
  const [selectedEntityType, setSelectedEntityType] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const queryClient = useQueryClient();

  // Fetch dashboard data
  const { data: dashboard, isLoading } = useQuery({
    queryKey: ['crm', 'data-quality', 'dashboard'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/crm/data-quality/dashboard');
      return response.data.data as DataQualityDashboard;
    },
    refetchInterval: 60000 // Refresh every minute
  });

  // Fetch issues
  const { data: issues } = useQuery({
    queryKey: ['crm', 'data-quality', 'issues', selectedEntityType, severityFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ resolved: 'false' });

      if (selectedEntityType !== 'all') {
        params.append('entity_type', selectedEntityType);
      }
      if (severityFilter !== 'all') {
        params.append('severity', severityFilter);
      }

      const response = await apiClient.get(`/api/v1/crm/data-quality/issues?${params}`);
      return response.data.data as DataQualityIssue[];
    }
  });

  // Auto-fix mutation
  const autoFixMutation = useMutation({
    mutationFn: async ({ entity_type, entity_id }: { entity_type: string; entity_id: string }) => {
      const response = await apiClient.post('/api/v1/crm/data-quality/auto-fix', {
        entity_type,
        entity_id
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'data-quality'] });
    }
  });

  // Resolve issue mutation
  const resolveMutation = useMutation({
    mutationFn: async (issueId: string) => {
      await apiClient.post(`/api/v1/crm/data-quality/issues/${issueId}/resolve`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'data-quality'] });
    }
  });

  const qualitySummary = dashboard?.quality_summary || [];
  const overallScore = qualitySummary.length > 0
    ? Math.round(qualitySummary.reduce((sum, s) => sum + s.avg_quality_score, 0) / qualitySummary.length)
    : 0;

  const totalRecords = qualitySummary.reduce((sum, s) => sum + s.total_records, 0);
  const totalHealthy = qualitySummary.reduce((sum, s) => sum + s.healthy_count, 0);
  const totalAtRisk = qualitySummary.reduce((sum, s) => sum + s.at_risk_count, 0);
  const totalCritical = qualitySummary.reduce((sum, s) => sum + s.critical_count, 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Data Quality</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Monitor and improve your CRM data quality in real-time
          </p>
        </div>
        <Button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['crm', 'data-quality'] })}
          variant="outline"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Overall Quality Score */}
      <Card className="p-6 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10 border-brand-primary/20">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Overall Data Quality Score
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Across {totalRecords.toLocaleString()} records
            </p>
          </div>
          <div className="text-right">
            <div className="text-5xl font-bold text-brand-primary">{overallScore}</div>
            <div className="flex items-center gap-1 text-sm text-green-600 mt-1">
              <TrendingUp className="w-4 h-4" />
              <span>+5 from last week</span>
            </div>
          </div>
        </div>
        <Progress value={overallScore} className="h-3" />
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-6 border-green-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Healthy Records</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">
                {totalHealthy.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {totalRecords > 0 ? Math.round((totalHealthy / totalRecords) * 100) : 0}% of total
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
        </Card>

        <Card className="p-6 border-yellow-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">At Risk</p>
              <p className="text-3xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
                {totalAtRisk.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {totalRecords > 0 ? Math.round((totalAtRisk / totalRecords) * 100) : 0}% of total
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
          </div>
        </Card>

        <Card className="p-6 border-red-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Critical Issues</p>
              <p className="text-3xl font-bold text-red-600 dark:text-red-400 mt-1">
                {totalCritical.toLocaleString()}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Requires immediate attention
              </p>
            </div>
            <XCircle className="w-8 h-8 text-red-500" />
          </div>
        </Card>
      </div>

      {/* Entity Breakdown */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Quality by Entity Type
        </h2>
        <div className="space-y-4">
          {qualitySummary.map((summary) => (
            <EntityQualityCard key={summary.entity_type} summary={summary} />
          ))}
        </div>
      </Card>

      {/* Issues List */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Data Quality Issues
          </h2>
          <div className="flex items-center gap-2">
            <select
              value={selectedEntityType}
              onChange={(e) => setSelectedEntityType(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm"
            >
              <option value="all">All Types</option>
              <option value="contact">Contacts</option>
              <option value="company">Companies</option>
              <option value="lead">Leads</option>
              <option value="deal">Deals</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
            </select>
          </div>
        </div>

        <IssuesList
          issues={issues || []}
          onAutoFix={(entityType, entityId) => autoFixMutation.mutate({ entity_type: entityType, entity_id: entityId })}
          onResolve={(issueId) => resolveMutation.mutate(issueId)}
        />
      </Card>
    </div>
  );
}

interface EntityQualityCardProps {
  summary: QualitySummary;
}

function EntityQualityCard({ summary }: EntityQualityCardProps) {
  const scoreColor = summary.avg_quality_score >= 80 ? 'text-green-600' :
                     summary.avg_quality_score >= 60 ? 'text-yellow-600' :
                     'text-red-600';

  const TrendIcon = summary.avg_quality_score >= 80 ? TrendingUp :
                    summary.avg_quality_score >= 60 ? Minus :
                    TrendingDown;

  return (
    <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="font-medium text-gray-900 dark:text-white capitalize">
            {summary.entity_type}s
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            {summary.total_records.toLocaleString()} records
          </p>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${scoreColor}`}>
            {Math.round(summary.avg_quality_score)}
          </div>
          <TrendIcon className={`w-4 h-4 ${scoreColor} ml-auto`} />
        </div>
      </div>

      <Progress value={summary.avg_quality_score} className="h-2 mb-3" />

      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="text-center p-2 bg-green-50 dark:bg-green-900/20 rounded">
          <div className="font-semibold text-green-700 dark:text-green-400">
            {summary.healthy_count}
          </div>
          <div className="text-gray-600 dark:text-gray-400">Healthy</div>
        </div>
        <div className="text-center p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
          <div className="font-semibold text-yellow-700 dark:text-yellow-400">
            {summary.at_risk_count}
          </div>
          <div className="text-gray-600 dark:text-gray-400">At Risk</div>
        </div>
        <div className="text-center p-2 bg-red-50 dark:bg-red-900/20 rounded">
          <div className="font-semibold text-red-700 dark:text-red-400">
            {summary.critical_count}
          </div>
          <div className="text-gray-600 dark:text-gray-400">Critical</div>
        </div>
      </div>
    </div>
  );
}

interface IssuesListProps {
  issues: DataQualityIssue[];
  onAutoFix: (entityType: string, entityId: string) => void;
  onResolve: (issueId: string) => void;
}

function IssuesList({ issues, onAutoFix, onResolve }: IssuesListProps) {
  if (issues.length === 0) {
    return (
      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          No data quality issues found! Your CRM data is in excellent condition.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-3">
      {issues.map((issue) => (
        <IssueCard
          key={issue.id}
          issue={issue}
          onAutoFix={onAutoFix}
          onResolve={onResolve}
        />
      ))}
    </div>
  );
}

interface IssueCardProps {
  issue: DataQualityIssue;
  onAutoFix: (entityType: string, entityId: string) => void;
  onResolve: (issueId: string) => void;
}

function IssueCard({ issue, onAutoFix, onResolve }: IssueCardProps) {
  const severityConfig = {
    critical: { color: 'bg-red-100 text-red-800 border-red-200', icon: XCircle },
    high: { color: 'bg-orange-100 text-orange-800 border-orange-200', icon: AlertTriangle },
    medium: { color: 'bg-yellow-100 text-yellow-800 border-yellow-200', icon: AlertTriangle },
    low: { color: 'bg-blue-100 text-blue-800 border-blue-200', icon: AlertTriangle }
  };

  const config = severityConfig[issue.severity];
  const Icon = config.icon;

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3 flex-1">
          <Icon className={`w-5 h-5 mt-0.5 ${issue.severity === 'critical' ? 'text-red-500' : issue.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'}`} />

          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <Badge className={config.color}>
                {issue.severity}
              </Badge>
              <Badge variant="outline" className="capitalize">
                {issue.entity_type}
              </Badge>
              {issue.auto_fixable && (
                <Badge className="bg-green-100 text-green-800 border-green-200">
                  <Zap className="w-3 h-3 mr-1" />
                  Auto-fixable
                </Badge>
              )}
            </div>

            <p className="text-sm font-medium text-gray-900 dark:text-white mb-1">
              {issue.description}
            </p>

            <div className="flex items-center gap-4 text-xs text-gray-500">
              <span>Entity ID: {issue.entity_id.slice(0, 8)}...</span>
              {issue.field_name && <span>Field: {issue.field_name}</span>}
              <span>Detected: {new Date(issue.detected_at).toLocaleDateString()}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          {issue.auto_fixable && (
            <Button
              size="sm"
              onClick={() => onAutoFix(issue.entity_type, issue.entity_id)}
              className="bg-green-600 hover:bg-green-700"
            >
              <Zap className="w-4 h-4 mr-1" />
              Auto-Fix
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={() => onResolve(issue.id)}
          >
            Resolve
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default DataQualityDashboard;
