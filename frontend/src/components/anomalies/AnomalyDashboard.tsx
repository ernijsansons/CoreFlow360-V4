/**
 * Anomaly Dashboard Component
 * Real-time fraud detection and anomaly management
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  AlertTriangle,
  AlertCircle,
  AlertOctagon,
  Info,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  TrendingDown,
  DollarSign,
  Calendar,
  Building2,
  RefreshCw,
  Loader2,
  Shield,
  Sparkles
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface Anomaly {
  id: string;
  transaction_type: 'expense' | 'invoice' | 'payment';
  transaction_id: string;
  anomaly_type: 'duplicate' | 'outlier' | 'unusual_amount' | 'suspicious_vendor' | 'timing_anomaly';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  details: {
    transaction_amount?: number;
    vendor_name?: string;
    transaction_date?: string;
    duplicate_transaction_id?: string;
    average_amount?: number;
    standard_deviation?: number;
    [key: string]: any;
  };
  status: 'open' | 'resolved' | 'false_positive';
  created_at: string;
}

interface AnomalyStats {
  total_anomalies: number;
  open_count: number;
  resolved_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export function AnomalyDashboard() {
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('open');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');

  const queryClient = useQueryClient();

  const { data: anomaliesData, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['anomalies', statusFilter, severityFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter) params.append('status', statusFilter);
      if (severityFilter) params.append('severity', severityFilter);
      params.append('limit', '50');

      const response = await apiClient.get(`/api/anomalies?${params.toString()}`);
      if (!response.ok) throw new Error('Failed to fetch anomalies');
      return response.json();
    },
  });

  const { data: statsData } = useQuery({
    queryKey: ['anomaly-stats'],
    queryFn: async () => {
      const response = await apiClient.get('/api/anomalies/stats');
      if (!response.ok) throw new Error('Failed to fetch stats');
      return response.json();
    },
  });

  const scanMutation = useMutation({
    mutationFn: async (daysBack: number = 30) => {
      const response = await apiClient.post('/api/anomalies/scan', {
        json: { days_back: daysBack },
      });
      if (!response.ok) throw new Error('Scan failed');
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['anomalies'] });
      queryClient.invalidateQueries({ queryKey: ['anomaly-stats'] });
      const event = new CustomEvent('show-toast', {
        detail: {
          message: `Found ${data.data.anomalies_found} anomalies`,
          type: 'success'
        }
      });
      window.dispatchEvent(event);
    },
  });

  const resolveMutation = useMutation({
    mutationFn: async ({ anomalyId, resolution }: { anomalyId: string; resolution: 'resolved' | 'false_positive' }) => {
      const response = await apiClient.post(`/api/anomalies/${anomalyId}/resolve`, {
        json: { resolution },
      });
      if (!response.ok) throw new Error('Failed to resolve');
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['anomalies'] });
      queryClient.invalidateQueries({ queryKey: ['anomaly-stats'] });
      setSelectedAnomaly(null);
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Anomaly resolved', type: 'success' }
      });
      window.dispatchEvent(event);
    },
  });

  const anomalies = anomaliesData?.data?.anomalies || [];
  const stats: AnomalyStats = statsData?.data?.summary || {
    total_anomalies: 0,
    open_count: 0,
    resolved_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
  };

  const filteredAnomalies = anomalies.filter((anomaly: Anomaly) =>
    anomaly.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    anomaly.details.vendor_name?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertOctagon className="w-5 h-5" />;
      case 'high': return <AlertTriangle className="w-5 h-5" />;
      case 'medium': return <AlertCircle className="w-5 h-5" />;
      case 'low': return <Info className="w-5 h-5" />;
      default: return <Info className="w-5 h-5" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400 border-red-600';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400 border-orange-600';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400 border-yellow-600';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400 border-blue-600';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 border-gray-600';
    }
  };

  const getAnomalyTypeLabel = (type: string) => {
    const labels: Record<string, string> = {
      duplicate: 'Duplicate Transaction',
      outlier: 'Amount Outlier',
      unusual_amount: 'Unusual Amount',
      suspicious_vendor: 'Suspicious Vendor',
      timing_anomaly: 'Timing Anomaly',
    };
    return labels[type] || type;
  };

  const formatCurrency = (amount?: number) => {
    if (!amount) return 'N/A';
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  const handleResolve = (anomalyId: string, resolution: 'resolved' | 'false_positive') => {
    resolveMutation.mutate({ anomalyId, resolution });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-100 dark:bg-red-900/20 rounded-lg">
            <Shield className="w-6 h-6 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Anomaly Detection</h1>
            <p className="text-muted-foreground mt-1">{stats.open_count} open anomalies</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => scanMutation.mutate(30)}
            disabled={scanMutation.isPending}
          >
            {scanMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4 mr-2" />
            )}
            Scan for Anomalies
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Critical</p>
              <p className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.critical_count}</p>
            </div>
            <AlertOctagon className="w-8 h-8 text-red-600 dark:text-red-400" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">High</p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">{stats.high_count}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-600 dark:text-orange-400" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Medium</p>
              <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{stats.medium_count}</p>
            </div>
            <AlertCircle className="w-8 h-8 text-yellow-600 dark:text-yellow-400" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Low</p>
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{stats.low_count}</p>
            </div>
            <Info className="w-8 h-8 text-blue-600 dark:text-blue-400" />
          </div>
        </Card>
      </div>

      {/* Filters & Search */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Search */}
          <div className="md:col-span-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search anomalies..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full h-10 px-3 rounded-md border border-input bg-background"
            >
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positives</option>
              <option value="">All Statuses</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full h-10 px-3 rounded-md border border-input bg-background"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : error ? (
        <Card className="p-6">
          <div className="text-center text-destructive">
            <p className="font-semibold">Error loading anomalies</p>
            <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
            <Button onClick={() => refetch()} className="mt-4" size="sm">
              Try Again
            </Button>
          </div>
        </Card>
      ) : filteredAnomalies.length === 0 ? (
        <Card className="p-12">
          <div className="text-center">
            <CheckCircle2 className="mx-auto h-12 w-12 text-green-600 dark:text-green-400 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No anomalies found</h3>
            <p className="text-sm text-muted-foreground">
              {searchTerm || statusFilter || severityFilter
                ? 'Try adjusting your filters'
                : 'Everything looks good! Your transactions are clean.'}
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredAnomalies.map((anomaly: Anomaly) => (
            <Card
              key={anomaly.id}
              className={`p-5 border-l-4 ${getSeverityColor(anomaly.severity)} cursor-pointer hover:shadow-md transition-shadow`}
              onClick={() => setSelectedAnomaly(anomaly)}
            >
              <div className="flex items-start justify-between">
                {/* Left Side */}
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    {getSeverityIcon(anomaly.severity)}
                    <div>
                      <h3 className="font-semibold">{anomaly.description}</h3>
                      <p className="text-sm text-muted-foreground">{getAnomalyTypeLabel(anomaly.anomaly_type)}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-sm text-muted-foreground mt-3">
                    {anomaly.details.transaction_amount && (
                      <div className="flex items-center gap-1">
                        <DollarSign className="w-4 h-4" />
                        {formatCurrency(anomaly.details.transaction_amount)}
                      </div>
                    )}
                    {anomaly.details.vendor_name && (
                      <div className="flex items-center gap-1">
                        <Building2 className="w-4 h-4" />
                        {anomaly.details.vendor_name}
                      </div>
                    )}
                    {anomaly.details.transaction_date && (
                      <div className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {formatDate(anomaly.details.transaction_date)}
                      </div>
                    )}
                  </div>
                </div>

                {/* Right Side - Severity Badge */}
                <div className="flex flex-col items-end gap-2">
                  <span className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getSeverityColor(anomaly.severity)}`}>
                    {anomaly.severity}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(anomaly.created_at)}
                  </span>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Anomaly Detail Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedAnomaly(null)}>
          <Card className="max-w-2xl w-full p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-6">
              <div className="flex items-center gap-3">
                {getSeverityIcon(selectedAnomaly.severity)}
                <div>
                  <h2 className="text-xl font-semibold">{selectedAnomaly.description}</h2>
                  <p className="text-sm text-muted-foreground">{getAnomalyTypeLabel(selectedAnomaly.anomaly_type)}</p>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setSelectedAnomaly(null)}>
                <XCircle className="w-5 h-5" />
              </Button>
            </div>

            {/* Details */}
            <div className="space-y-4 mb-6">
              <div className="grid grid-cols-2 gap-4">
                {Object.entries(selectedAnomaly.details).map(([key, value]) => (
                  <div key={key}>
                    <p className="text-xs text-muted-foreground capitalize">{key.replace(/_/g, ' ')}</p>
                    <p className="font-semibold">
                      {typeof value === 'number' && key.includes('amount') ? formatCurrency(value) : String(value)}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            {selectedAnomaly.status === 'open' && (
              <div className="flex items-center gap-3 pt-4 border-t">
                <Button
                  onClick={() => handleResolve(selectedAnomaly.id, 'resolved')}
                  disabled={resolveMutation.isPending}
                  className="flex-1"
                >
                  <CheckCircle2 className="w-4 h-4 mr-2" />
                  Mark Resolved
                </Button>
                <Button
                  onClick={() => handleResolve(selectedAnomaly.id, 'false_positive')}
                  disabled={resolveMutation.isPending}
                  variant="outline"
                  className="flex-1"
                >
                  <XCircle className="w-4 h-4 mr-2" />
                  False Positive
                </Button>
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
