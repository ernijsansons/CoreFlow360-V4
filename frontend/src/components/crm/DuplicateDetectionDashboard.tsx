/**
 * Duplicate Detection Dashboard
 * Real-time duplicate management with side-by-side comparison and merge capabilities
 */

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Users, Building2, AlertTriangle, CheckCircle, XCircle,
  Merge, Eye, Trash2, Search, Filter
} from 'lucide-react';
import apiClient from '@/lib/api/client';
import type { DuplicateMatch } from '@/types/crm';

interface DuplicateDashboardStats {
  total_matches: number;
  high_confidence: number;
  auto_merge_eligible: number;
  pending_review: number;
  contacts: number;
  companies: number;
}

export function DuplicateDetectionDashboard() {
  const [selectedTab, setSelectedTab] = useState<'contact' | 'company'>('contact');
  const [confidenceFilter, setConfidenceFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [selectedMatches, setSelectedMatches] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  // Fetch duplicate summary
  const { data: summary } = useQuery({
    queryKey: ['crm', 'duplicates', 'summary'],
    queryFn: async () => {
      const response = await apiClient.get('/api/v1/crm/data-quality/duplicates/pending');
      const results = response.data.data;

      // Calculate stats
      const stats: DuplicateDashboardStats = {
        total_matches: results.length,
        high_confidence: results.filter((m: any) => m.confidence === 'high').length,
        auto_merge_eligible: results.filter((m: any) => m.auto_merge_eligible).length,
        pending_review: results.filter((m: any) => m.status === 'pending').length,
        contacts: results.filter((m: any) => m.entity_type === 'contact').length,
        companies: results.filter((m: any) => m.entity_type === 'company').length,
      };

      return stats;
    },
    refetchInterval: 30000 // Refresh every 30 seconds
  });

  // Fetch duplicate matches
  const { data: matches, isLoading } = useQuery({
    queryKey: ['crm', 'duplicates', selectedTab, confidenceFilter],
    queryFn: async () => {
      const params = new URLSearchParams({
        entity_type: selectedTab
      });

      if (confidenceFilter !== 'all') {
        params.append('confidence', confidenceFilter);
      }

      const response = await apiClient.get(`/api/v1/crm/data-quality/duplicates/pending?${params}`);
      return response.data.data as DuplicateMatch[];
    }
  });

  // Scan for duplicates mutation
  const scanMutation = useMutation({
    mutationFn: async (entityType: 'contact' | 'company') => {
      const response = await apiClient.post('/api/v1/crm/data-quality/duplicates/scan', {
        entity_type: entityType
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'duplicates'] });
    }
  });

  // Dismiss duplicate mutation
  const dismissMutation = useMutation({
    mutationFn: async (matchId: string) => {
      await apiClient.post(`/api/v1/crm/data-quality/duplicates/${matchId}/dismiss`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'duplicates'] });
    }
  });

  // Bulk dismiss mutation
  const bulkDismissMutation = useMutation({
    mutationFn: async (matchIds: string[]) => {
      await Promise.all(
        matchIds.map(id => apiClient.post(`/api/v1/crm/data-quality/duplicates/${id}/dismiss`))
      );
    },
    onSuccess: () => {
      setSelectedMatches(new Set());
      queryClient.invalidateQueries({ queryKey: ['crm', 'duplicates'] });
    }
  });

  const handleScan = () => {
    scanMutation.mutate(selectedTab);
  };

  const handleDismiss = (matchId: string) => {
    dismissMutation.mutate(matchId);
  };

  const handleBulkDismiss = () => {
    if (selectedMatches.size > 0) {
      bulkDismissMutation.mutate(Array.from(selectedMatches));
    }
  };

  const toggleMatchSelection = (matchId: string) => {
    const newSelection = new Set(selectedMatches);
    if (newSelection.has(matchId)) {
      newSelection.delete(matchId);
    } else {
      newSelection.add(matchId);
    }
    setSelectedMatches(newSelection);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Duplicate Detection</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            AI-powered duplicate detection and merge management
          </p>
        </div>
        <Button
          onClick={handleScan}
          disabled={scanMutation.isPending}
          className="bg-brand-primary hover:bg-brand-primary/90"
        >
          <Search className="w-4 h-4 mr-2" />
          {scanMutation.isPending ? 'Scanning...' : 'Scan for Duplicates'}
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-6 border-brand-primary/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Matches</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">
                {summary?.total_matches || 0}
              </p>
            </div>
            <AlertTriangle className="w-8 h-8 text-brand-accent" />
          </div>
        </Card>

        <Card className="p-6 border-green-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">High Confidence</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">
                {summary?.high_confidence || 0}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
        </Card>

        <Card className="p-6 border-blue-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Auto-Merge Ready</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-1">
                {summary?.auto_merge_eligible || 0}
              </p>
            </div>
            <Merge className="w-8 h-8 text-blue-500" />
          </div>
        </Card>

        <Card className="p-6 border-yellow-500/20">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Needs Review</p>
              <p className="text-3xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
                {summary?.pending_review || 0}
              </p>
            </div>
            <Eye className="w-8 h-8 text-yellow-500" />
          </div>
        </Card>
      </div>

      {/* Main Content */}
      <Card className="p-6">
        <Tabs value={selectedTab} onValueChange={(v) => setSelectedTab(v as any)}>
          <div className="flex items-center justify-between mb-6">
            <TabsList>
              <TabsTrigger value="contact" className="flex items-center gap-2">
                <Users className="w-4 h-4" />
                Contacts ({summary?.contacts || 0})
              </TabsTrigger>
              <TabsTrigger value="company" className="flex items-center gap-2">
                <Building2 className="w-4 h-4" />
                Companies ({summary?.companies || 0})
              </TabsTrigger>
            </TabsList>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-gray-500" />
                <select
                  value={confidenceFilter}
                  onChange={(e) => setConfidenceFilter(e.target.value as any)}
                  className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm"
                >
                  <option value="all">All Confidence</option>
                  <option value="high">High Only</option>
                  <option value="medium">Medium Only</option>
                  <option value="low">Low Only</option>
                </select>
              </div>

              {selectedMatches.size > 0 && (
                <Button
                  variant="outline"
                  onClick={handleBulkDismiss}
                  className="border-red-500 text-red-500 hover:bg-red-50"
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Dismiss Selected ({selectedMatches.size})
                </Button>
              )}
            </div>
          </div>

          <TabsContent value="contact">
            <DuplicateMatchList
              matches={matches || []}
              isLoading={isLoading}
              selectedMatches={selectedMatches}
              onToggleSelection={toggleMatchSelection}
              onDismiss={handleDismiss}
              entityType="contact"
            />
          </TabsContent>

          <TabsContent value="company">
            <DuplicateMatchList
              matches={matches || []}
              isLoading={isLoading}
              selectedMatches={selectedMatches}
              onToggleSelection={toggleMatchSelection}
              onDismiss={handleDismiss}
              entityType="company"
            />
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
}

interface DuplicateMatchListProps {
  matches: DuplicateMatch[];
  isLoading: boolean;
  selectedMatches: Set<string>;
  onToggleSelection: (id: string) => void;
  onDismiss: (id: string) => void;
  entityType: 'contact' | 'company';
}

function DuplicateMatchList({
  matches,
  isLoading,
  selectedMatches,
  onToggleSelection,
  onDismiss,
  entityType
}: DuplicateMatchListProps) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary"></div>
      </div>
    );
  }

  if (!matches || matches.length === 0) {
    return (
      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          No duplicate {entityType}s found! Your data is clean.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-4">
      {matches.map((match) => (
        <DuplicateMatchCard
          key={match.duplicate_id}
          match={match}
          isSelected={selectedMatches.has(match.duplicate_id)}
          onToggleSelection={onToggleSelection}
          onDismiss={onDismiss}
        />
      ))}
    </div>
  );
}

interface DuplicateMatchCardProps {
  match: DuplicateMatch;
  isSelected: boolean;
  onToggleSelection: (id: string) => void;
  onDismiss: (id: string) => void;
}

function DuplicateMatchCard({ match, isSelected, onToggleSelection, onDismiss }: DuplicateMatchCardProps) {
  const [showDetails, setShowDetails] = useState(false);

  const confidenceColor = {
    high: 'bg-green-100 text-green-800 border-green-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-orange-100 text-orange-800 border-orange-200'
  }[match.confidence];

  return (
    <Card className={`p-4 transition-all ${isSelected ? 'ring-2 ring-brand-primary' : ''}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3 flex-1">
          <input
            type="checkbox"
            checked={isSelected}
            onChange={() => onToggleSelection(match.duplicate_id)}
            className="mt-1 w-4 h-4 rounded border-gray-300"
          />

          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <Badge className={confidenceColor}>
                {match.confidence} confidence
              </Badge>
              <Badge variant="outline">
                {match.match_score}% match
              </Badge>
              {match.auto_merge_eligible && (
                <Badge className="bg-blue-100 text-blue-800 border-blue-200">
                  Auto-merge eligible
                </Badge>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4 mb-3">
              <div>
                <p className="text-xs text-gray-500 mb-1">Primary Record</p>
                <p className="font-medium text-gray-900 dark:text-white">
                  ID: {match.primary_id.slice(0, 8)}...
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Duplicate Record</p>
                <p className="font-medium text-gray-900 dark:text-white">
                  ID: {match.duplicate_id.slice(0, 8)}...
                </p>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 mb-3">
              {match.match_reasons.map((reason, idx) => (
                <Badge key={idx} variant="secondary" className="text-xs">
                  {reason.field}: {Math.round(reason.similarity * 100)}% ({reason.method})
                </Badge>
              ))}
            </div>

            {showDetails && (
              <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Match reasoning and additional details would go here...
                </p>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setShowDetails(!showDetails)}
          >
            <Eye className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => onDismiss(match.duplicate_id)}
            className="border-red-500 text-red-500 hover:bg-red-50"
          >
            <XCircle className="w-4 h-4" />
          </Button>
          <Button
            size="sm"
            className="bg-brand-primary hover:bg-brand-primary/90"
          >
            <Merge className="w-4 h-4 mr-2" />
            Merge
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default DuplicateDetectionDashboard;
