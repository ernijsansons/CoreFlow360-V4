/**
 * Entity Merge Conflict Resolution UI
 * Side-by-side comparison with field-level merge strategy selection
 */

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Label } from '@/components/ui/label';
import {
  Merge, AlertTriangle, CheckCircle, ArrowRight, Users, Building2,
  Calendar, Mail, Phone, Globe, DollarSign, Tag
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface MergeConflictResolverProps {
  entityType: 'contact' | 'company';
  primaryId: string;
  duplicateId: string;
  onComplete?: () => void;
  onCancel?: () => void;
}

interface EntityData {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  company?: string;
  title?: string;
  website?: string;
  address?: string;
  revenue?: number;
  employees?: number;
  industry?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
  last_activity_at?: string;
  [key: string]: any;
}

interface FieldComparison {
  field: string;
  label: string;
  primaryValue: any;
  duplicateValue: any;
  isDifferent: boolean;
  icon: React.ComponentType<{ className?: string }>;
}

export function MergeConflictResolver({
  entityType,
  primaryId,
  duplicateId,
  onComplete,
  onCancel
}: MergeConflictResolverProps) {
  const [primaryData, setPrimaryData] = useState<EntityData | null>(null);
  const [duplicateData, setDuplicateData] = useState<EntityData | null>(null);
  const [fieldSelections, setFieldSelections] = useState<Record<string, 'primary' | 'duplicate' | 'both'>>({});
  const [isLoading, setIsLoading] = useState(true);
  const queryClient = useQueryClient();

  // Fetch entity data
  useState(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);

        const [primaryRes, duplicateRes] = await Promise.all([
          apiClient.get(`/api/v1/crm/${entityType}s/${primaryId}`),
          apiClient.get(`/api/v1/crm/${entityType}s/${duplicateId}`)
        ]);

        setPrimaryData(primaryRes.data.data);
        setDuplicateData(duplicateRes.data.data);

        // Initialize field selections to 'primary' by default
        const fields = getComparisonFields(primaryRes.data.data, duplicateRes.data.data);
        const initialSelections: Record<string, 'primary' | 'duplicate' | 'both'> = {};
        fields.forEach(field => {
          initialSelections[field.field] = 'primary';
        });
        setFieldSelections(initialSelections);
      } catch (error) {
        console.error('Failed to fetch entity data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  });

  // Merge mutation
  const mergeMutation = useMutation({
    mutationFn: async () => {
      const mergeStrategy: any = {
        primary_id: primaryId,
        duplicate_id: duplicateId,
        field_strategies: {}
      };

      // Build field strategies
      Object.keys(fieldSelections).forEach(field => {
        const selection = fieldSelections[field];
        if (selection === 'primary') {
          mergeStrategy.field_strategies[field] = { source: 'primary' };
        } else if (selection === 'duplicate') {
          mergeStrategy.field_strategies[field] = { source: 'duplicate' };
        } else if (selection === 'both') {
          mergeStrategy.field_strategies[field] = { source: 'merge' };
        }
      });

      const response = await apiClient.post('/api/v1/crm/data-quality/duplicates/merge', {
        entity_type: entityType,
        strategy: mergeStrategy
      });

      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['crm', 'duplicates'] });
      queryClient.invalidateQueries({ queryKey: ['crm', entityType] });
      onComplete?.();
    }
  });

  const handleMerge = () => {
    mergeMutation.mutate();
  };

  if (isLoading || !primaryData || !duplicateData) {
    return (
      <Card className="p-8">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary"></div>
        </div>
      </Card>
    );
  }

  const comparisons = getComparisonFields(primaryData, duplicateData);
  const conflictCount = comparisons.filter(c => c.isDifferent).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="p-6 bg-gradient-to-br from-brand-primary/10 to-brand-accent/10 border-brand-primary/20">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
              Merge {entityType === 'contact' ? 'Contacts' : 'Companies'}
            </h2>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              {conflictCount} field{conflictCount !== 1 ? 's' : ''} with different values
            </p>
          </div>
          <Merge className="w-8 h-8 text-brand-primary" />
        </div>
      </Card>

      {/* Info Alert */}
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          Select which value to keep for each field. The duplicate record will be archived and all
          related activities will be transferred to the primary record.
        </AlertDescription>
      </Alert>

      {/* Side-by-Side Comparison */}
      <div className="grid grid-cols-2 gap-6">
        {/* Primary Record */}
        <Card className="p-6 border-2 border-green-500">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle className="w-5 h-5 text-green-600" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Primary Record
            </h3>
            <Badge className="bg-green-100 text-green-800 border-green-200">
              Keep
            </Badge>
          </div>
          <EntitySummary entity={primaryData} entityType={entityType} />
        </Card>

        {/* Duplicate Record */}
        <Card className="p-6 border-2 border-orange-500">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-orange-600" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Duplicate Record
            </h3>
            <Badge className="bg-orange-100 text-orange-800 border-orange-200">
              Archive
            </Badge>
          </div>
          <EntitySummary entity={duplicateData} entityType={entityType} />
        </Card>
      </div>

      {/* Field Comparisons */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Field-Level Merge Strategy
        </h3>
        <div className="space-y-4">
          {comparisons.map((comparison) => (
            <FieldComparisonRow
              key={comparison.field}
              comparison={comparison}
              selection={fieldSelections[comparison.field]}
              onSelectionChange={(value) =>
                setFieldSelections({ ...fieldSelections, [comparison.field]: value })
              }
            />
          ))}
        </div>
      </Card>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          onClick={onCancel}
          disabled={mergeMutation.isPending}
        >
          Cancel
        </Button>
        <div className="flex items-center gap-3">
          <div className="text-sm text-gray-600 dark:text-gray-400">
            {Object.values(fieldSelections).filter(s => s === 'duplicate').length} fields from duplicate
          </div>
          <Button
            onClick={handleMerge}
            disabled={mergeMutation.isPending}
            className="bg-green-600 hover:bg-green-700"
          >
            <Merge className="w-4 h-4 mr-2" />
            {mergeMutation.isPending ? 'Merging...' : 'Merge Records'}
          </Button>
        </div>
      </div>

      {/* Error Display */}
      {mergeMutation.isError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Failed to merge records. Please try again or contact support.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

interface EntitySummaryProps {
  entity: EntityData;
  entityType: 'contact' | 'company';
}

function EntitySummary({ entity, entityType }: EntitySummaryProps) {
  const Icon = entityType === 'contact' ? Users : Building2;

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3">
        <Icon className="w-5 h-5 text-gray-500 mt-1" />
        <div>
          <p className="font-medium text-gray-900 dark:text-white">{entity.name}</p>
          {entity.title && <p className="text-sm text-gray-600 dark:text-gray-400">{entity.title}</p>}
          {entity.company && <p className="text-sm text-gray-600 dark:text-gray-400">{entity.company}</p>}
        </div>
      </div>

      <div className="space-y-2 text-sm">
        {entity.email && (
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <Mail className="w-4 h-4" />
            {entity.email}
          </div>
        )}
        {entity.phone && (
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <Phone className="w-4 h-4" />
            {entity.phone}
          </div>
        )}
        {entity.website && (
          <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
            <Globe className="w-4 h-4" />
            {entity.website}
          </div>
        )}
      </div>

      <div className="pt-3 border-t border-gray-200 dark:border-gray-700 space-y-1 text-xs text-gray-500">
        <div>Created: {new Date(entity.created_at).toLocaleDateString()}</div>
        <div>Updated: {new Date(entity.updated_at).toLocaleDateString()}</div>
        {entity.last_activity_at && (
          <div>Last Activity: {new Date(entity.last_activity_at).toLocaleDateString()}</div>
        )}
      </div>
    </div>
  );
}

interface FieldComparisonRowProps {
  comparison: FieldComparison;
  selection: 'primary' | 'duplicate' | 'both';
  onSelectionChange: (value: 'primary' | 'duplicate' | 'both') => void;
}

function FieldComparisonRow({ comparison, selection, onSelectionChange }: FieldComparisonRowProps) {
  const Icon = comparison.icon;

  return (
    <div className={`p-4 rounded-lg border ${comparison.isDifferent ? 'border-orange-200 bg-orange-50 dark:bg-orange-900/10' : 'border-gray-200 bg-gray-50 dark:bg-gray-800'}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3 flex-1">
          <Icon className="w-5 h-5 text-gray-500 mt-1" />
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <p className="font-medium text-gray-900 dark:text-white">{comparison.label}</p>
              {comparison.isDifferent && (
                <Badge variant="outline" className="text-xs">
                  Different
                </Badge>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-gray-500 mb-1">Primary</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatFieldValue(comparison.primaryValue)}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Duplicate</p>
                <p className="text-sm text-gray-900 dark:text-white">
                  {formatFieldValue(comparison.duplicateValue)}
                </p>
              </div>
            </div>
          </div>
        </div>

        {comparison.isDifferent && (
          <RadioGroup value={selection} onValueChange={onSelectionChange} className="ml-4">
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="primary" id={`${comparison.field}-primary`} />
              <Label htmlFor={`${comparison.field}-primary`} className="text-xs cursor-pointer">
                Primary
              </Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="duplicate" id={`${comparison.field}-duplicate`} />
              <Label htmlFor={`${comparison.field}-duplicate`} className="text-xs cursor-pointer">
                Duplicate
              </Label>
            </div>
            {comparison.field === 'tags' && (
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="both" id={`${comparison.field}-both`} />
                <Label htmlFor={`${comparison.field}-both`} className="text-xs cursor-pointer">
                  Merge Both
                </Label>
              </div>
            )}
          </RadioGroup>
        )}
      </div>
    </div>
  );
}

function getComparisonFields(primary: EntityData, duplicate: EntityData): FieldComparison[] {
  const fields: Array<{
    field: string;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    { field: 'name', label: 'Name', icon: Users },
    { field: 'email', label: 'Email', icon: Mail },
    { field: 'phone', label: 'Phone', icon: Phone },
    { field: 'website', label: 'Website', icon: Globe },
    { field: 'company', label: 'Company', icon: Building2 },
    { field: 'title', label: 'Title', icon: Tag },
    { field: 'address', label: 'Address', icon: Globe },
    { field: 'revenue', label: 'Revenue', icon: DollarSign },
    { field: 'employees', label: 'Employees', icon: Users },
    { field: 'industry', label: 'Industry', icon: Tag },
    { field: 'tags', label: 'Tags', icon: Tag }
  ];

  return fields
    .filter(f => primary[f.field] !== undefined || duplicate[f.field] !== undefined)
    .map(f => ({
      ...f,
      primaryValue: primary[f.field],
      duplicateValue: duplicate[f.field],
      isDifferent: primary[f.field] !== duplicate[f.field]
    }));
}

function formatFieldValue(value: any): string {
  if (value === null || value === undefined) {
    return '(empty)';
  }
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  if (typeof value === 'number') {
    return value.toLocaleString();
  }
  return String(value);
}

export default MergeConflictResolver;
