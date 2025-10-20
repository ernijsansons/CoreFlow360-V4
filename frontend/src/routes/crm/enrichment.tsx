/**
 * Lead Enrichment & Intelligence System
 * Automated data enrichment with AI-powered insights
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect, useCallback } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { enrichmentService, type EnrichmentResult } from '@/lib/api/services/enrichment.service';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Sparkles,
  Search,
  Building2,
  User,
  Globe,
  Linkedin,
  DollarSign,
  TrendingUp,
  CheckCircle,
  XCircle,
  Loader2,
  RefreshCw,
  Download,
  Filter,
  Database,
  Zap,
  AlertCircle,
  Clock,
  BarChart3,
  Users,
  Award,
  MapPin
} from 'lucide-react';

export const Route = createFileRoute('/crm/enrichment')({
  component: EnrichmentPage,
});

interface DataSource {
  source: string;
  name: string;
  description: string;
  supported_fields: string[];
  cost_per_enrichment: number;
  enabled: boolean;
}

interface BulkJobStatus {
  job_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: {
    total: number;
    completed: number;
    failed: number;
  };
  results?: EnrichmentResult[];
}

function EnrichmentPage() {
  const [dataSources, setDataSources] = useState<DataSource[]>([]);
  const [enrichmentHistory, setEnrichmentHistory] = useState<EnrichmentResult[]>([]);
  const [selectedLeads, setSelectedLeads] = useState<string[]>([]);
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [isEnriching, setIsEnriching] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeJobs, setActiveJobs] = useState<BulkJobStatus[]>([]);
  const [estimatedCost, setEstimatedCost] = useState<number | null>(null);

  // Mock leads for demonstration
  const [leads] = useState([
    {
      id: 'lead-1',
      name: 'Sarah Johnson',
      email: 'sarah.j@techcorp.com',
      company: 'TechCorp Inc',
      status: 'new',
      enriched: false,
    },
    {
      id: 'lead-2',
      name: 'Michael Chen',
      email: 'mchen@innovate.io',
      company: 'Innovate Solutions',
      status: 'new',
      enriched: false,
    },
    {
      id: 'lead-3',
      name: 'Emily Rodriguez',
      email: 'emily@startupxyz.com',
      company: 'StartupXYZ',
      status: 'enriched',
      enriched: true,
    },
  ]);

  const loadDataSources = useCallback(async () => {
    try {
      const response = await enrichmentService.listDataSources();
      setDataSources(response.data);
    } catch (error) {
      console.error('Failed to load data sources:', error);
    }
  }, []);

  const loadEnrichmentHistory = useCallback(async () => {
    try {
      const response = await enrichmentService.getEnrichmentHistory({ limit: 10 });
      setEnrichmentHistory(response.data);
    } catch (error) {
      console.error('Failed to load enrichment history:', error);
    }
  }, []);

  const estimateCost = useCallback(async () => {
    if (selectedLeads.length === 0) {
      setEstimatedCost(null);
      return;
    }
    try {
      const response = await enrichmentService.estimateEnrichmentCost(selectedLeads);
      setEstimatedCost(response.data.estimated_cost_usd);
    } catch (error) {
      console.error('Failed to estimate cost:', error);
    }
  }, [selectedLeads]);

  useEffect(() => {
    void loadDataSources();
    void loadEnrichmentHistory();
  }, [loadDataSources, loadEnrichmentHistory]);

  useEffect(() => {
    void estimateCost();
  }, [estimateCost]);

  const handleBulkEnrich = async () => {
    if (selectedLeads.length === 0) return;

    setIsEnriching(true);
    try {
      const response = await enrichmentService.bulkEnrichLeads(selectedLeads, {
        data_sources: selectedSources.length > 0 ? selectedSources : undefined,
      });

      const event = new CustomEvent('show-toast', {
        detail: { message: `Enrichment job started: ${response.data.job_id}`, type: 'success' }
      });
      window.dispatchEvent(event);

      // Poll for job status
      pollJobStatus(response.data.job_id);

      setSelectedLeads([]);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to start enrichment', type: 'error' }
      });
      window.dispatchEvent(event);
    } finally {
      setIsEnriching(false);
    }
  };

  const pollJobStatus = async (jobId: string) => {
    const interval = setInterval(async () => {
      try {
        const response = await enrichmentService.getBulkEnrichmentStatus(jobId);
        const job = response.data;

        setActiveJobs((prev) => {
          const existing = prev.find((j) => j.job_id === jobId);
          if (existing) {
            return prev.map((j) => (j.job_id === jobId ? job : j));
          }
          return [...prev, job];
        });

        if (job.status === 'completed' || job.status === 'failed') {
          clearInterval(interval);
          loadEnrichmentHistory();
        }
      } catch (error) {
        console.error('Failed to poll job status:', error);
        clearInterval(interval);
      }
    }, 3000);
  };

  const toggleLeadSelection = (leadId: string) => {
    setSelectedLeads((prev) =>
      prev.includes(leadId) ? prev.filter((id) => id !== leadId) : [...prev, leadId]
    );
  };

  const toggleSourceSelection = (source: string) => {
    setSelectedSources((prev) =>
      prev.includes(source) ? prev.filter((s) => s !== source) : [...prev, source]
    );
  };

  const filteredLeads = leads.filter(
    (lead) =>
      lead.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      lead.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      lead.company.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'processing':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'failed':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Sparkles className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Lead Enrichment</h1>
              <p className="text-muted-foreground mt-1">
                Automatically enrich leads with AI-powered data intelligence
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" onClick={loadEnrichmentHistory}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={handleBulkEnrich}
              disabled={selectedLeads.length === 0 || isEnriching}
            >
              {isEnriching ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Zap className="w-4 h-4 mr-2" />
              )}
              Enrich Selected ({selectedLeads.length})
            </Button>
          </div>
        </div>

        {/* Data Sources Selection */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Database className="w-5 h-5 text-primary" />
            Data Sources
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {dataSources.map((source) => (
              <button
                key={source.source}
                onClick={() => toggleSourceSelection(source.source)}
                disabled={!source.enabled}
                className={`p-4 border-2 rounded-lg text-left transition-all ${
                  selectedSources.includes(source.source)
                    ? 'border-primary bg-primary/5'
                    : 'border-border hover:border-primary/50'
                } ${!source.enabled ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold">{source.name}</span>
                  {selectedSources.includes(source.source) && (
                    <CheckCircle className="w-4 h-4 text-primary" />
                  )}
                </div>
                <p className="text-xs text-muted-foreground mb-2">{source.description}</p>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <DollarSign className="w-3 h-3" />
                  <span>${source.cost_per_enrichment} per lead</span>
                </div>
              </button>
            ))}
          </div>
          {selectedSources.length === 0 && (
            <p className="text-sm text-muted-foreground mt-3">
              No sources selected - all available sources will be used
            </p>
          )}
        </Card>

        {/* Cost Estimate */}
        {estimatedCost !== null && selectedLeads.length > 0 && (
          <Card className="p-4 bg-blue-50 dark:bg-blue-900/10 border-blue-200 dark:border-blue-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <BarChart3 className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <div>
                  <p className="font-semibold text-blue-900 dark:text-blue-100">
                    Estimated Cost
                  </p>
                  <p className="text-sm text-blue-700 dark:text-blue-300">
                    {selectedLeads.length} leads × {selectedSources.length || 'all'} sources
                  </p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold text-blue-900 dark:text-blue-100">
                  ${estimatedCost.toFixed(2)}
                </p>
                <p className="text-xs text-blue-700 dark:text-blue-300">Total cost</p>
              </div>
            </div>
          </Card>
        )}

        {/* Active Jobs */}
        {activeJobs.length > 0 && (
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5 text-primary" />
              Active Enrichment Jobs
            </h3>
            <div className="space-y-3">
              {activeJobs.map((job) => (
                <div key={job.job_id} className="p-4 border border-border rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">Job {job.job_id.slice(0, 8)}</span>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(job.status)}`}>
                      {job.status}
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm text-muted-foreground">
                      <span>Progress</span>
                      <span>
                        {job.progress.completed} / {job.progress.total} completed
                      </span>
                    </div>
                    <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all duration-300"
                        style={{
                          width: `${(job.progress.completed / job.progress.total) * 100}%`,
                        }}
                      />
                    </div>
                    {job.progress.failed > 0 && (
                      <p className="text-xs text-red-600 dark:text-red-400">
                        {job.progress.failed} failed
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Leads List */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <Users className="w-5 h-5 text-primary" />
              Leads
            </h3>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search leads..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>

          <div className="space-y-2">
            {filteredLeads.map((lead) => (
              <div
                key={lead.id}
                className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                  selectedLeads.includes(lead.id)
                    ? 'border-primary bg-primary/5'
                    : 'border-border hover:border-primary/50'
                }`}
                onClick={() => toggleLeadSelection(lead.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                      <User className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-semibold">{lead.name}</h4>
                        {lead.enriched && (
                          <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400">
                            Enriched
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">{lead.email}</p>
                      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                        <Building2 className="w-3 h-3" />
                        <span>{lead.company}</span>
                      </div>
                    </div>
                  </div>
                  {selectedLeads.includes(lead.id) && (
                    <CheckCircle className="w-5 h-5 text-primary" />
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Enrichment History */}
        {enrichmentHistory.length > 0 && (
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Award className="w-5 h-5 text-primary" />
              Recent Enrichments
            </h3>
            <div className="space-y-4">
              {enrichmentHistory.map((result) => (
                <div key={result.lead_id} className="p-4 border border-border rounded-lg">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1">
                      <h4 className="font-semibold mb-1">
                        {result.enriched_data.contact?.full_name || 'Unknown'}
                      </h4>
                      <p className="text-sm text-muted-foreground">
                        {result.enriched_data.contact?.email}
                      </p>
                    </div>
                    <div className="text-right">
                      <div className="flex items-center gap-1 text-sm font-semibold">
                        <Award className="w-4 h-4 text-yellow-500" />
                        <span>{result.confidence_score}% match</span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {result.cost_credits} credits
                      </p>
                    </div>
                  </div>

                  {result.enriched_data.company && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-3 bg-muted/50 rounded-lg">
                      <div>
                        <p className="text-xs text-muted-foreground mb-1">Company</p>
                        <p className="text-sm font-medium flex items-center gap-1">
                          <Building2 className="w-3 h-3" />
                          {result.enriched_data.company.name}
                        </p>
                      </div>
                      {result.enriched_data.company.industry && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-1">Industry</p>
                          <p className="text-sm font-medium">{result.enriched_data.company.industry}</p>
                        </div>
                      )}
                      {result.enriched_data.company.employee_count && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-1">Employees</p>
                          <p className="text-sm font-medium flex items-center gap-1">
                            <Users className="w-3 h-3" />
                            {result.enriched_data.company.employee_count.toLocaleString()}
                          </p>
                        </div>
                      )}
                      {result.enriched_data.company.annual_revenue && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-1">Revenue</p>
                          <p className="text-sm font-medium flex items-center gap-1">
                            <DollarSign className="w-3 h-3" />
                            {(result.enriched_data.company.annual_revenue / 1000000).toFixed(1)}M
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="flex items-center gap-2 mt-3 flex-wrap">
                    <span className="text-xs text-muted-foreground">Sources:</span>
                    {result.data_sources.map((source) => (
                      <span
                        key={source}
                        className="px-2 py-0.5 rounded-full text-xs bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400"
                      >
                        {source}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
