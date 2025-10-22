/**
 * Compliance Dashboard - Admin UI
 *
 * Main dashboard for managing compliance guidelines, policies, and violations
 */

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  FileText,
  Settings,
  Activity
} from 'lucide-react';

import { GuidelinesManager } from '@/components/compliance/GuidelinesManager';
import { PoliciesManager } from '@/components/compliance/PoliciesManager';
import { ViolationsMonitor } from '@/components/compliance/ViolationsMonitor';
import { ComplianceStats } from '@/components/compliance/ComplianceStats';

interface ViolationSummary {
  totalViolations: number;
  unresolvedViolations: number;
  criticalViolations: number;
  highViolations: number;
  mediumViolations: number;
  lowViolations: number;
}

export function ComplianceDashboard() {
  const [activeTab, setActiveTab] = useState('overview');

  // Fetch violation summary
  const { data: violationSummary, isLoading: summaryLoading } = useQuery<ViolationSummary>({
    queryKey: ['compliance-violations-summary'],
    queryFn: async () => {
      const response = await fetch('/api/v1/admin/compliance/violations/summary', {
        credentials: 'include'
      });
      if (!response.ok) throw new Error('Failed to fetch violation summary');
      const data = await response.json();
      return data.summary;
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  return (
    <div className="container mx-auto py-8 px-4 max-w-7xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold">Compliance Management</h1>
        </div>
        <p className="text-muted-foreground">
          Manage AI agent compliance guidelines, policies, and monitor violations
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Violations</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summaryLoading ? '...' : violationSummary?.totalViolations || 0}
            </div>
            <p className="text-xs text-muted-foreground">All time</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unresolved</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">
              {summaryLoading ? '...' : violationSummary?.unresolvedViolations || 0}
            </div>
            <p className="text-xs text-muted-foreground">Requires attention</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">
              {summaryLoading ? '...' : violationSummary?.criticalViolations || 0}
            </div>
            <p className="text-xs text-muted-foreground">High priority</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Resolution Rate</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {summaryLoading
                ? '...'
                : violationSummary?.totalViolations
                  ? Math.round(((violationSummary.totalViolations - violationSummary.unresolvedViolations) / violationSummary.totalViolations) * 100)
                  : 100
              }%
            </div>
            <p className="text-xs text-muted-foreground">Violations resolved</p>
          </CardContent>
        </Card>
      </div>

      {/* Alert for Critical Violations */}
      {violationSummary && violationSummary.criticalViolations > 0 && (
        <Alert variant="destructive" className="mb-6">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            You have {violationSummary.criticalViolations} critical violation(s) that require immediate attention.
            Please review the Violations tab.
          </AlertDescription>
        </Alert>
      )}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="guidelines" className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Guidelines
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Policies
          </TabsTrigger>
          <TabsTrigger value="violations" className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Violations
            {violationSummary && violationSummary.unresolvedViolations > 0 && (
              <Badge variant="destructive" className="ml-1 h-5 min-w-[20px] px-1">
                {violationSummary.unresolvedViolations}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <ComplianceStats />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
                <CardDescription>Common compliance management tasks</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <button
                  onClick={() => setActiveTab('guidelines')}
                  className="w-full flex items-center justify-between p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    Create New Guideline
                  </span>
                  <span className="text-xs text-muted-foreground">→</span>
                </button>

                <button
                  onClick={() => setActiveTab('policies')}
                  className="w-full flex items-center justify-between p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Settings className="h-4 w-4" />
                    Configure Agent Policy
                  </span>
                  <span className="text-xs text-muted-foreground">→</span>
                </button>

                <button
                  onClick={() => setActiveTab('violations')}
                  className="w-full flex items-center justify-between p-3 rounded-lg border hover:bg-accent transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Review Violations
                  </span>
                  {violationSummary && violationSummary.unresolvedViolations > 0 && (
                    <Badge variant="destructive">
                      {violationSummary.unresolvedViolations}
                    </Badge>
                  )}
                </button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Compliance Status</CardTitle>
                <CardDescription>Current system compliance health</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Overall Health</span>
                  <div className="flex items-center gap-2">
                    {violationSummary && violationSummary.criticalViolations === 0 && violationSummary.unresolvedViolations < 5 ? (
                      <>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span className="text-sm text-green-500">Healthy</span>
                      </>
                    ) : violationSummary && violationSummary.criticalViolations > 0 ? (
                      <>
                        <XCircle className="h-4 w-4 text-red-500" />
                        <span className="text-sm text-red-500">Critical</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-orange-500" />
                        <span className="text-sm text-orange-500">Warning</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Critical Issues</span>
                    <span className="font-medium text-red-500">
                      {violationSummary?.criticalViolations || 0}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">High Priority</span>
                    <span className="font-medium text-orange-500">
                      {violationSummary?.highViolations || 0}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Medium Priority</span>
                    <span className="font-medium text-yellow-500">
                      {violationSummary?.mediumViolations || 0}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Low Priority</span>
                    <span className="font-medium text-blue-500">
                      {violationSummary?.lowViolations || 0}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="guidelines">
          <GuidelinesManager />
        </TabsContent>

        <TabsContent value="policies">
          <PoliciesManager />
        </TabsContent>

        <TabsContent value="violations">
          <ViolationsMonitor />
        </TabsContent>
      </Tabs>
    </div>
  );
}
