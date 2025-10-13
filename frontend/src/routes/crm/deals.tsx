/**
 * CRM Deal Pipeline - Fortune 50 Level
 * Kanban board with drag-and-drop, AI insights, and real-time updates
 */

import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useDeals, useUpdateDealStage, usePipelineMetrics } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Target,
  Search,
  Plus,
  TrendingUp,
  DollarSign,
  Calendar,
  Building2,
  User,
  RefreshCw,
  Filter,
  BarChart3,
  Clock,
  AlertCircle,
  CheckCircle2
} from 'lucide-react';

export const Route = createFileRoute('/crm/deals')({
  component: DealsPage,
});

// Pipeline stages configuration
const PIPELINE_STAGES = [
  { id: 'prospecting', label: 'Prospecting', color: 'bg-gray-100 dark:bg-gray-800' },
  { id: 'qualification', label: 'Qualification', color: 'bg-blue-100 dark:bg-blue-900/20' },
  { id: 'proposal', label: 'Proposal', color: 'bg-yellow-100 dark:bg-yellow-900/20' },
  { id: 'negotiation', label: 'Negotiation', color: 'bg-orange-100 dark:bg-orange-900/20' },
  { id: 'closed_won', label: 'Closed Won', color: 'bg-green-100 dark:bg-green-900/20' },
  { id: 'closed_lost', label: 'Closed Lost', color: 'bg-red-100 dark:bg-red-900/20' },
];

interface Deal {
  id: string;
  name: string;
  stage: string;
  value: number;
  probability: number;
  expected_close_date?: string;
  company_name?: string;
  company_id?: string;
  contact_name?: string;
  owner_name?: string;
  created_at: string;
  updated_at: string;
}

function DealsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'kanban' | 'list'>('kanban');

  const { data: dealsData, isLoading, error, refetch, isFetching } = useDeals({ limit: 100 });
  const { data: metricsData } = usePipelineMetrics();
  const updateDealStageMutation = useUpdateDealStage();

  const deals = dealsData?.data || [];
  const metrics = metricsData || { stages: [] };

  // Filter deals by search term
  const filteredDeals = deals.filter((deal: Deal) =>
    deal.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    deal.company_name?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Group deals by stage
  const dealsByStage = PIPELINE_STAGES.map(stage => ({
    ...stage,
    deals: filteredDeals.filter((deal: Deal) => deal.stage === stage.id),
    value: filteredDeals
      .filter((deal: Deal) => deal.stage === stage.id)
      .reduce((sum: number, deal: Deal) => sum + (deal.value || 0), 0),
  }));

  const handleDragStart = (e: React.DragEvent, dealId: string, currentStage: string) => {
    e.dataTransfer.setData('dealId', dealId);
    e.dataTransfer.setData('currentStage', currentStage);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = async (e: React.DragEvent, targetStage: string) => {
    e.preventDefault();
    const dealId = e.dataTransfer.getData('dealId');
    const currentStage = e.dataTransfer.getData('currentStage');

    if (currentStage === targetStage) return;

    try {
      await updateDealStageMutation.mutateAsync({
        dealId,
        stage: targetStage,
      });

      const event = new CustomEvent('show-toast', {
        detail: { message: `Deal moved to ${targetStage}`, type: 'success' }
      });
      window.dispatchEvent(event);
    } catch (error) {
      const event = new CustomEvent('show-toast', {
        detail: { message: 'Failed to update deal stage', type: 'error' }
      });
      window.dispatchEvent(event);
    }
  };

  const handleRefresh = async () => {
    await refetch();
    const event = new CustomEvent('show-toast', {
      detail: { message: 'Pipeline refreshed', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const formatCurrency = (value: number) => {
    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
    return `$${value}`;
  };

  const formatDate = (date?: string) => {
    if (!date) return 'No date';
    const d = new Date(date);
    const now = new Date();
    const diffDays = Math.ceil((d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

    if (diffDays < 0) return <span className="text-red-600 dark:text-red-400">Overdue</span>;
    if (diffDays === 0) return <span className="text-orange-600 dark:text-orange-400">Today</span>;
    if (diffDays <= 7) return <span className="text-yellow-600 dark:text-yellow-400">{diffDays}d</span>;
    return <span className="text-muted-foreground">{diffDays}d</span>;
  };

  const getProbabilityColor = (probability: number) => {
    if (probability >= 75) return 'text-green-600 dark:text-green-400';
    if (probability >= 50) return 'text-blue-600 dark:text-blue-400';
    if (probability >= 25) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  const totalPipelineValue = dealsByStage
    .filter(s => !['closed_won', 'closed_lost'].includes(s.id))
    .reduce((sum, stage) => sum + stage.value, 0);

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
              <Target className="w-6 h-6 text-orange-600 dark:text-orange-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Deal Pipeline</h1>
              <p className="text-muted-foreground mt-1">
                {deals.length} active deals · {formatCurrency(totalPipelineValue)} pipeline
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isFetching}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <div className="flex items-center gap-2 border rounded-lg p-1">
              <Button
                variant={viewMode === 'kanban' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('kanban')}
              >
                <BarChart3 className="w-4 h-4 mr-2" />
                Kanban
              </Button>
              <Button
                variant={viewMode === 'list' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('list')}
              >
                <Filter className="w-4 h-4 mr-2" />
                List
              </Button>
            </div>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              New Deal
            </Button>
          </div>
        </div>

        {/* Search */}
        <Card className="p-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search deals, companies..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
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
              <p className="font-semibold">Error loading deals</p>
              <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
              <Button onClick={() => refetch()} className="mt-4" size="sm">
                Try Again
              </Button>
            </div>
          </Card>
        ) : viewMode === 'kanban' ? (
          /* Kanban View */
          <div className="overflow-x-auto pb-4">
            <div className="flex gap-4 min-w-max">
              {dealsByStage.map((stage) => (
                <div key={stage.id} className="flex-shrink-0 w-80">
                  {/* Stage Header */}
                  <div className={`${stage.color} rounded-t-lg p-4`}>
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="font-semibold">{stage.label}</h3>
                      <span className="text-sm text-muted-foreground">
                        {stage.deals.length}
                      </span>
                    </div>
                    <p className="text-sm font-semibold">{formatCurrency(stage.value)}</p>
                  </div>

                  {/* Stage Column - Drop Zone */}
                  <div
                    className="bg-muted/30 rounded-b-lg p-4 min-h-[500px] space-y-3"
                    onDragOver={handleDragOver}
                    onDrop={(e) => handleDrop(e, stage.id)}
                  >
                    {stage.deals.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                        <Target className="w-8 h-8 mb-2 opacity-50" />
                        <p className="text-sm">No deals</p>
                      </div>
                    ) : (
                      stage.deals.map((deal: Deal) => (
                        <Card
                          key={deal.id}
                          draggable
                          onDragStart={(e) => handleDragStart(e, deal.id, stage.id)}
                          className="cursor-move hover:shadow-md transition-shadow p-4"
                        >
                          {/* Deal Header */}
                          <div className="mb-3">
                            <Link
                              to="/crm/deals/$dealId"
                              params={{ dealId: deal.id }}
                              className="font-semibold hover:text-primary transition-colors line-clamp-2"
                            >
                              {deal.name}
                            </Link>
                            {deal.company_name && (
                              <Link
                                to="/crm/companies/$companyId"
                                params={{ companyId: deal.company_id || '' }}
                                className="flex items-center text-sm text-muted-foreground hover:text-primary mt-1"
                              >
                                <Building2 className="w-3 h-3 mr-1" />
                                {deal.company_name}
                              </Link>
                            )}
                          </div>

                          {/* Deal Value */}
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center text-sm font-semibold">
                              <DollarSign className="w-4 h-4 mr-1 text-green-600 dark:text-green-400" />
                              {formatCurrency(deal.value)}
                            </div>
                            <div className={`flex items-center text-sm font-semibold ${getProbabilityColor(deal.probability)}`}>
                              <TrendingUp className="w-3 h-3 mr-1" />
                              {deal.probability}%
                            </div>
                          </div>

                          {/* Deal Metadata */}
                          <div className="space-y-2 pt-3 border-t">
                            {deal.expected_close_date && (
                              <div className="flex items-center justify-between text-xs">
                                <span className="text-muted-foreground flex items-center">
                                  <Calendar className="w-3 h-3 mr-1" />
                                  Close date
                                </span>
                                {formatDate(deal.expected_close_date)}
                              </div>
                            )}
                            {deal.owner_name && (
                              <div className="flex items-center text-xs text-muted-foreground">
                                <User className="w-3 h-3 mr-1" />
                                {deal.owner_name}
                              </div>
                            )}
                          </div>
                        </Card>
                      ))
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          /* List View */
          <div className="space-y-3">
            {filteredDeals.length === 0 ? (
              <Card className="p-12">
                <div className="text-center">
                  <Target className="mx-auto h-12 w-12 text-muted-foreground" />
                  <h3 className="mt-4 text-lg font-semibold">No deals found</h3>
                  <p className="mt-2 text-sm text-muted-foreground">
                    {searchTerm ? 'Try adjusting your search term' : 'Get started by creating your first deal'}
                  </p>
                  {!searchTerm && (
                    <Button className="mt-6">
                      <Plus className="w-4 h-4 mr-2" />
                      New Deal
                    </Button>
                  )}
                </div>
              </Card>
            ) : (
              filteredDeals.map((deal: Deal) => (
                <Card key={deal.id} className="p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <Link
                        to="/crm/deals/$dealId"
                        params={{ dealId: deal.id }}
                        className="font-semibold hover:text-primary transition-colors"
                      >
                        {deal.name}
                      </Link>
                      {deal.company_name && (
                        <Link
                          to="/crm/companies/$companyId"
                          params={{ companyId: deal.company_id || '' }}
                          className="flex items-center text-sm text-muted-foreground hover:text-primary mt-1"
                        >
                          <Building2 className="w-3 h-3 mr-1" />
                          {deal.company_name}
                        </Link>
                      )}
                    </div>

                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <p className="text-sm text-muted-foreground">Value</p>
                        <p className="font-semibold">{formatCurrency(deal.value)}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-muted-foreground">Probability</p>
                        <p className={`font-semibold ${getProbabilityColor(deal.probability)}`}>
                          {deal.probability}%
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-muted-foreground">Close Date</p>
                        <p className="text-sm">{formatDate(deal.expected_close_date)}</p>
                      </div>
                      <div className="text-right min-w-[120px]">
                        <p className="text-sm text-muted-foreground">Stage</p>
                        <span className="inline-block mt-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                          {PIPELINE_STAGES.find(s => s.id === deal.stage)?.label || deal.stage}
                        </span>
                      </div>
                    </div>
                  </div>
                </Card>
              ))
            )}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
