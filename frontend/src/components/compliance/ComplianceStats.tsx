/**
 * Compliance Stats Component
 *
 * Visual analytics and statistics for compliance monitoring
 */

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { TrendingUp, TrendingDown, Shield, AlertTriangle, Activity } from 'lucide-react';

interface ComplianceMetrics {
  totalGuidelines: number;
  activeGuidelines: number;
  totalPolicies: number;
  activePolicies: number;
  violationsByType: Array<{ type: string; count: number }>;
  violationsBySeverity: Array<{ severity: string; count: number }>;
  violationsByAgent: Array<{ agent: string; count: number }>;
  violationsTrend: Array<{ date: string; count: number }>;
  resolutionRate: number;
  avgResolutionTime: number;
}

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

export function ComplianceStats() {
  // Fetch compliance metrics
  const { data: metrics, isLoading } = useQuery<ComplianceMetrics>({
    queryKey: ['compliance-stats'],
    queryFn: async () => {
      // In production, this would fetch from an actual stats endpoint
      // For now, we'll aggregate from existing endpoints
      const [guidelinesRes, policiesRes, violationsRes] = await Promise.all([
        fetch('/api/v1/admin/compliance/guidelines', { credentials: 'include' }),
        fetch('/api/v1/admin/compliance/policies', { credentials: 'include' }),
        fetch('/api/v1/admin/compliance/violations', { credentials: 'include' }),
      ]);

      const guidelines = await guidelinesRes.json();
      const policies = await policiesRes.json();
      const violations = await violationsRes.json();

      // Aggregate violations by type
      const violationsByType = violations.violations.reduce((acc: any, v: any) => {
        const existing = acc.find((item: any) => item.type === v.violationType);
        if (existing) {
          existing.count++;
        } else {
          acc.push({ type: v.violationType, count: 1 });
        }
        return acc;
      }, []);

      // Aggregate violations by severity
      const violationsBySeverity = violations.violations.reduce((acc: any, v: any) => {
        const existing = acc.find((item: any) => item.severity === v.severity);
        if (existing) {
          existing.count++;
        } else {
          acc.push({ severity: v.severity, count: 1 });
        }
        return acc;
      }, []);

      // Aggregate violations by agent
      const violationsByAgent = violations.violations.reduce((acc: any, v: any) => {
        const existing = acc.find((item: any) => item.agent === v.agentId);
        if (existing) {
          existing.count++;
        } else {
          acc.push({ agent: v.agentId, count: 1 });
        }
        return acc;
      }, []);

      // Calculate resolution metrics
      const resolvedCount = violations.violations.filter((v: any) => v.resolved).length;
      const resolutionRate = violations.violations.length > 0
        ? (resolvedCount / violations.violations.length) * 100
        : 100;

      return {
        totalGuidelines: guidelines.guidelines.length,
        activeGuidelines: guidelines.guidelines.filter((g: any) => g.isActive).length,
        totalPolicies: policies.policies.length,
        activePolicies: policies.policies.filter((p: any) => p.isActive).length,
        violationsByType,
        violationsBySeverity,
        violationsByAgent,
        violationsTrend: [],
        resolutionRate,
        avgResolutionTime: 0,
      };
    },
    refetchInterval: 60000, // Refresh every minute
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {[1, 2, 3, 4].map(i => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="h-64 flex items-center justify-center text-muted-foreground">
                Loading stats...
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (!metrics) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Guidelines</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.activeGuidelines}</div>
            <p className="text-xs text-muted-foreground">
              of {metrics.totalGuidelines} total
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Policies</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.activePolicies}</div>
            <p className="text-xs text-muted-foreground">
              of {metrics.totalPolicies} total
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Resolution Rate</CardTitle>
            {metrics.resolutionRate >= 80 ? (
              <TrendingUp className="h-4 w-4 text-green-500" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-500" />
            )}
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${metrics.resolutionRate >= 80 ? 'text-green-500' : 'text-red-500'}`}>
              {Math.round(metrics.resolutionRate)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Violations resolved
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Violations</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {metrics.violationsByType.reduce((sum, v) => sum + v.count, 0)}
            </div>
            <p className="text-xs text-muted-foreground">
              Across all agents
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Violations by Type */}
        <Card>
          <CardHeader>
            <CardTitle>Violations by Type</CardTitle>
            <CardDescription>Distribution of violation types</CardDescription>
          </CardHeader>
          <CardContent>
            {metrics.violationsByType.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={metrics.violationsByType}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="type"
                    angle={-45}
                    textAnchor="end"
                    height={100}
                    fontSize={10}
                  />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                No violations recorded
              </div>
            )}
          </CardContent>
        </Card>

        {/* Violations by Severity */}
        <Card>
          <CardHeader>
            <CardTitle>Violations by Severity</CardTitle>
            <CardDescription>Breakdown by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            {metrics.violationsBySeverity.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={metrics.violationsBySeverity}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ severity, count, percent }) =>
                      `${severity}: ${count} (${(percent * 100).toFixed(0)}%)`
                    }
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="count"
                  >
                    {metrics.violationsBySeverity.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || '#6b7280'}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                No violations recorded
              </div>
            )}
          </CardContent>
        </Card>

        {/* Violations by Agent */}
        <Card>
          <CardHeader>
            <CardTitle>Violations by Agent</CardTitle>
            <CardDescription>Agent-specific violation counts</CardDescription>
          </CardHeader>
          <CardContent>
            {metrics.violationsByAgent.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={metrics.violationsByAgent} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="agent" type="category" width={150} fontSize={11} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#10b981" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                No violations recorded
              </div>
            )}
          </CardContent>
        </Card>

        {/* Compliance Health Score */}
        <Card>
          <CardHeader>
            <CardTitle>Compliance Health</CardTitle>
            <CardDescription>Overall system compliance status</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium">Guidelines Coverage</span>
                  <span className="text-sm text-muted-foreground">
                    {metrics.totalGuidelines > 0
                      ? Math.round((metrics.activeGuidelines / metrics.totalGuidelines) * 100)
                      : 0}%
                  </span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full"
                    style={{
                      width: metrics.totalGuidelines > 0
                        ? `${(metrics.activeGuidelines / metrics.totalGuidelines) * 100}%`
                        : '0%'
                    }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium">Policy Enforcement</span>
                  <span className="text-sm text-muted-foreground">
                    {metrics.totalPolicies > 0
                      ? Math.round((metrics.activePolicies / metrics.totalPolicies) * 100)
                      : 0}%
                  </span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full"
                    style={{
                      width: metrics.totalPolicies > 0
                        ? `${(metrics.activePolicies / metrics.totalPolicies) * 100}%`
                        : '0%'
                    }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium">Resolution Rate</span>
                  <span className="text-sm text-muted-foreground">
                    {Math.round(metrics.resolutionRate)}%
                  </span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      metrics.resolutionRate >= 80
                        ? 'bg-green-500'
                        : metrics.resolutionRate >= 60
                          ? 'bg-yellow-500'
                          : 'bg-red-500'
                    }`}
                    style={{ width: `${metrics.resolutionRate}%` }}
                  />
                </div>
              </div>

              <div className="pt-4 border-t">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Overall Health Score</span>
                  <Badge
                    className={
                      metrics.resolutionRate >= 80 && metrics.activeGuidelines >= metrics.totalGuidelines * 0.8
                        ? 'bg-green-500'
                        : 'bg-yellow-500'
                    }
                  >
                    {metrics.resolutionRate >= 80 && metrics.activeGuidelines >= metrics.totalGuidelines * 0.8
                      ? 'Healthy'
                      : 'Needs Attention'}
                  </Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
