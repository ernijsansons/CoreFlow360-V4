import { useState } from 'react'
import {
  useDataQualityDashboard,
  usePendingMatches,
  useMergeDuplicates,
  useDismissMatch,
  useDataQualityIssues,
  useAutoFixIssues,
  useResolveIssue,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Merge,
  Eye,
  Wrench,
  TrendingUp,
  TrendingDown,
} from 'lucide-react'

export function DataQualityDashboard() {
  const [selectedTab, setSelectedTab] = useState<'overview' | 'duplicates' | 'issues'>('overview')
  const { data: dashboard, isLoading: dashboardLoading } = useDataQualityDashboard()
  const { data: pendingMatches, isLoading: matchesLoading } = usePendingMatches()
  const { data: issues, isLoading: issuesLoading } = useDataQualityIssues({
    status: 'pending',
    limit: 20,
  })

  const mergeDuplicates = useMergeDuplicates()
  const dismissMatch = useDismissMatch()
  const autoFixIssues = useAutoFixIssues()
  const resolveIssue = useResolveIssue()

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500'
      case 'high':
        return 'bg-orange-500'
      case 'medium':
        return 'bg-yellow-500'
      case 'low':
        return 'bg-blue-500'
      default:
        return 'bg-gray-500'
    }
  }

  const getScoreTrend = (current: number, previous: number) => {
    if (current > previous) {
      return <TrendingUp className="h-4 w-4 text-green-500" />
    } else if (current < previous) {
      return <TrendingDown className="h-4 w-4 text-red-500" />
    }
    return null
  }

  if (dashboardLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Data Quality</h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Monitor and improve your CRM data quality
        </p>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2">
        {(['overview', 'duplicates', 'issues'] as const).map((tab) => (
          <Button
            key={tab}
            variant={selectedTab === tab ? 'default' : 'outline'}
            onClick={() => setSelectedTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </Button>
        ))}
      </div>

      {/* Overview Tab */}
      {selectedTab === 'overview' && dashboard?.data && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Overall Score */}
          <Card className="p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400">
                Overall Score
              </h3>
              {getScoreTrend(
                dashboard.data.overall_score,
                dashboard.data.previous_score || 0
              )}
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-4xl font-bold">{dashboard.data.overall_score}</span>
              <span className="text-lg text-gray-500">/100</span>
            </div>
          </Card>

          {/* Total Issues */}
          <Card className="p-6">
            <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">
              Total Issues
            </h3>
            <div className="flex items-baseline space-x-2">
              <span className="text-4xl font-bold">{dashboard.data.total_issues}</span>
              <Badge
                variant={dashboard.data.total_issues > 0 ? 'destructive' : 'default'}
                className="ml-2"
              >
                {dashboard.data.critical_issues} Critical
              </Badge>
            </div>
          </Card>

          {/* Duplicate Matches */}
          <Card className="p-6">
            <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">
              Pending Duplicates
            </h3>
            <div className="flex items-baseline space-x-2">
              <span className="text-4xl font-bold">{dashboard.data.pending_duplicates}</span>
              <Badge variant="outline">{dashboard.data.auto_merge_eligible} Auto-merge</Badge>
            </div>
          </Card>

          {/* Completion Rate */}
          <Card className="p-6">
            <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">
              Completeness
            </h3>
            <div className="flex items-baseline space-x-2">
              <span className="text-4xl font-bold">
                {Math.round(dashboard.data.completeness_rate * 100)}
              </span>
              <span className="text-lg text-gray-500">%</span>
            </div>
          </Card>
        </div>
      )}

      {/* Duplicates Tab */}
      {selectedTab === 'duplicates' && (
        <Card className="p-6">
          <h2 className="text-2xl font-bold mb-6">Pending Duplicate Matches</h2>

          {matchesLoading ? (
            <div className="flex items-center justify-center h-48">
              <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
            </div>
          ) : pendingMatches?.data && pendingMatches.data.length > 0 ? (
            <div className="space-y-4">
              {pendingMatches.data.map((match) => (
                <div
                  key={match.id}
                  className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <Badge variant="outline" className="mb-2">
                        {match.entity_type}
                      </Badge>
                      <p className="font-medium">Potential duplicates found</p>
                      <p className="text-sm text-gray-500 mt-1">
                        Confidence: {match.confidence_score}%
                      </p>
                    </div>
                    <Badge className={getSeverityColor('medium')}>
                      {match.duplicate_ids.length} matches
                    </Badge>
                  </div>

                  <div className="flex space-x-3">
                    <Button
                      size="sm"
                      onClick={() => {
                        mergeDuplicates.mutate({
                          entity_type: match.entity_type as 'contact' | 'company',
                          primary_id: match.primary_id,
                          duplicate_ids: match.duplicate_ids,
                          merge_strategy: 'most_complete',
                        })
                      }}
                      disabled={mergeDuplicates.isPending}
                    >
                      {mergeDuplicates.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Merge className="h-4 w-4 mr-2" />
                      )}
                      Merge
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => dismissMatch.mutate(match.id)}
                      disabled={dismissMatch.isPending}
                    >
                      <Eye className="h-4 w-4 mr-2" />
                      Dismiss
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-3" />
              <p>No pending duplicate matches</p>
            </div>
          )}
        </Card>
      )}

      {/* Issues Tab */}
      {selectedTab === 'issues' && (
        <Card className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold">Data Quality Issues</h2>
            {issues?.data && issues.data.issues.length > 0 && (
              <Button
                onClick={() =>
                  autoFixIssues.mutate({
                    issue_ids: issues.data.issues
                      .filter((i) => i.auto_fixable)
                      .map((i) => i.id),
                  })
                }
                disabled={autoFixIssues.isPending}
              >
                {autoFixIssues.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Wrench className="h-4 w-4 mr-2" />
                )}
                Auto-fix All
              </Button>
            )}
          </div>

          {issuesLoading ? (
            <div className="flex items-center justify-center h-48">
              <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
            </div>
          ) : issues?.data && issues.data.issues.length > 0 ? (
            <div className="space-y-3">
              {issues.data.issues.map((issue) => (
                <div
                  key={issue.id}
                  className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <Badge className={getSeverityColor(issue.severity)}>
                          {issue.severity}
                        </Badge>
                        <Badge variant="outline">{issue.issue_type}</Badge>
                      </div>
                      <p className="font-medium mb-1">{issue.field}</p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {issue.description}
                      </p>
                      {issue.suggested_fix && (
                        <p className="text-sm text-brand-primary mt-2">
                          Suggested: {issue.suggested_fix}
                        </p>
                      )}
                    </div>
                    <div className="flex space-x-2 ml-4">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          resolveIssue.mutate({
                            issue_id: issue.id,
                            resolution: 'fixed',
                          })
                        }
                        disabled={resolveIssue.isPending}
                      >
                        <CheckCircle2 className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          resolveIssue.mutate({
                            issue_id: issue.id,
                            resolution: 'ignored',
                          })
                        }
                        disabled={resolveIssue.isPending}
                      >
                        <XCircle className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-3" />
              <p>No data quality issues found</p>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
