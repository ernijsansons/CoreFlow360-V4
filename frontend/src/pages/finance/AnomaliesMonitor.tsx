import { useState } from 'react'
import {
  useAnomalies,
  useAnomaly,
  useScanAnomalies,
  useResolveAnomaly,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import {
  Loader2,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  DollarSign,
  FileText,
  Copy,
  CheckCircle2,
  XCircle,
  Search,
} from 'lucide-react'

export function AnomaliesMonitor() {
  const [selectedAnomaly, setSelectedAnomaly] = useState<string | null>(null)
  const [filter, setFilter] = useState<'pending' | 'investigating' | 'resolved' | 'all'>('pending')

  const { data: anomalies, isLoading: anomaliesLoading } = useAnomalies({
    status: filter === 'all' ? undefined : filter,
    limit: 50,
  })
  const { data: anomalyDetail, isLoading: detailLoading } = useAnomaly(selectedAnomaly || '')
  const scanAnomalies = useScanAnomalies()
  const resolveAnomaly = useResolveAnomaly()

  const getAnomalyIcon = (type: string) => {
    switch (type) {
      case 'revenue_spike':
        return <TrendingUp className="h-5 w-5 text-green-500" />
      case 'revenue_drop':
        return <TrendingDown className="h-5 w-5 text-red-500" />
      case 'unusual_expense':
        return <DollarSign className="h-5 w-5 text-orange-500" />
      case 'duplicate_transaction':
        return <Copy className="h-5 w-5 text-blue-500" />
      case 'missing_invoice':
        return <FileText className="h-5 w-5 text-purple-500" />
      default:
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
    }
  }

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

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(amount)
  }

  if (anomaliesLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Financial Anomalies
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Monitor and investigate unusual financial patterns
          </p>
        </div>

        <Button
          onClick={() => scanAnomalies.mutate()}
          disabled={scanAnomalies.isPending}
        >
          {scanAnomalies.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Search className="h-4 w-4 mr-2" />
          )}
          Scan for Anomalies
        </Button>
      </div>

      {/* Filter Tabs */}
      <div className="flex space-x-2">
        {(['pending', 'investigating', 'resolved', 'all'] as const).map((status) => (
          <Button
            key={status}
            variant={filter === status ? 'default' : 'outline'}
            onClick={() => setFilter(status)}
          >
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Anomalies List */}
        <Card className="lg:col-span-2 p-6">
          <h2 className="text-xl font-bold mb-4">Detected Anomalies</h2>

          {anomalies?.data && anomalies.data.anomalies.length > 0 ? (
            <div className="space-y-3">
              {anomalies.data.anomalies.map((anomaly) => (
                <div
                  key={anomaly.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all ${
                    selectedAnomaly === anomaly.id
                      ? 'border-brand-primary bg-brand-primary/5'
                      : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                  }`}
                  onClick={() => setSelectedAnomaly(anomaly.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3 flex-1">
                      {getAnomalyIcon(anomaly.type)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <Badge className={getSeverityColor(anomaly.severity)}>
                            {anomaly.severity}
                          </Badge>
                          <Badge variant="outline">{anomaly.type.replace('_', ' ')}</Badge>
                        </div>
                        <p className="font-medium mb-1">{anomaly.description}</p>
                        {anomaly.amount && (
                          <p className="text-sm text-gray-600 dark:text-gray-400">
                            Amount: {formatCurrency(anomaly.amount)}
                          </p>
                        )}
                        <p className="text-xs text-gray-500 mt-1">
                          Detected: {new Date(anomaly.detected_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <Badge
                      variant={
                        anomaly.status === 'resolved'
                          ? 'default'
                          : anomaly.status === 'investigating'
                          ? 'secondary'
                          : 'outline'
                      }
                    >
                      {anomaly.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-3" />
              <p>No {filter !== 'all' && `${filter} `}anomalies found</p>
            </div>
          )}
        </Card>

        {/* Anomaly Detail Panel */}
        <Card className="p-6">
          {selectedAnomaly && anomalyDetail?.data ? (
            <>
              <h2 className="text-xl font-bold mb-4">Anomaly Details</h2>

              {detailLoading ? (
                <div className="flex items-center justify-center h-48">
                  <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Type
                    </label>
                    <div className="flex items-center space-x-2 mt-1">
                      {getAnomalyIcon(anomalyDetail.data.type)}
                      <span className="font-medium">
                        {anomalyDetail.data.type.replace('_', ' ')}
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Severity
                    </label>
                    <div className="mt-1">
                      <Badge className={getSeverityColor(anomalyDetail.data.severity)}>
                        {anomalyDetail.data.severity}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Description
                    </label>
                    <p className="mt-1 text-sm">{anomalyDetail.data.description}</p>
                  </div>

                  {anomalyDetail.data.amount && (
                    <div>
                      <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        Amount
                      </label>
                      <p className="mt-1 text-lg font-semibold">
                        {formatCurrency(anomalyDetail.data.amount)}
                      </p>
                    </div>
                  )}

                  {anomalyDetail.data.suggested_action && (
                    <div>
                      <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        Suggested Action
                      </label>
                      <p className="mt-1 text-sm text-brand-primary">
                        {anomalyDetail.data.suggested_action}
                      </p>
                    </div>
                  )}

                  <div>
                    <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      Detected At
                    </label>
                    <p className="mt-1 text-sm">
                      {new Date(anomalyDetail.data.detected_at).toLocaleString()}
                    </p>
                  </div>

                  {anomalyDetail.data.status === 'pending' && (
                    <div className="flex space-x-2 pt-4 border-t">
                      <Button
                        size="sm"
                        className="flex-1"
                        onClick={() =>
                          resolveAnomaly.mutate({
                            anomaly_id: selectedAnomaly,
                            resolution: 'resolved',
                            notes: 'Resolved from UI',
                          })
                        }
                        disabled={resolveAnomaly.isPending}
                      >
                        {resolveAnomaly.isPending ? (
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                          <CheckCircle2 className="h-4 w-4 mr-2" />
                        )}
                        Resolve
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1"
                        onClick={() =>
                          resolveAnomaly.mutate({
                            anomaly_id: selectedAnomaly,
                            resolution: 'false_positive',
                            notes: 'Marked as false positive',
                          })
                        }
                        disabled={resolveAnomaly.isPending}
                      >
                        <XCircle className="h-4 w-4 mr-2" />
                        False Positive
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-500">
              Select an anomaly to view details
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
