/**
 * CRM Companies Page - Fortune 50 Level
 * Comprehensive company management with AI insights
 */

import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useCompanies } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Building2,
  Plus,
  Search,
  Filter,
  TrendingUp,
  Users,
  DollarSign,
  BarChart3,
  Download,
  RefreshCw,
  ExternalLink,
  Mail,
  Phone
} from 'lucide-react';

export const Route = createFileRoute('/crm/companies')({
  component: CompaniesPage,
});

function CompaniesPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string>('active');

  const { data, isLoading, error, refetch, isFetching } = useCompanies({
    lifecycle_stage: lifecycleFilter,
    status: statusFilter,
    limit: 50,
  });

  const companies = data?.data || [];
  const total = data?.total || 0;

  // Filter companies by search term (client-side)
  const filteredCompanies = companies.filter((company) =>
    company.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    company.domain?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    company.industry?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleRefresh = async () => {
    await refetch();
    const event = new CustomEvent('show-toast', {
      detail: { message: 'Companies refreshed', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const handleExportCSV = () => {
    const headers = ['Company', 'Industry', 'Size', 'Score', 'Stage', 'Pipeline'];
    const rows = filteredCompanies.map(c => [
      c.name,
      c.industry || '',
      c.company_size || '',
      c.lead_score,
      c.lifecycle_stage,
      c.pipeline_value || 0
    ]);

    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `companies-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    const event = new CustomEvent('show-toast', {
      detail: { message: `Exported ${filteredCompanies.length} companies`, type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const getLifecycleColor = (stage: string) => {
    const colors = {
      customer: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
      evangelist: 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400',
      opportunity: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
      sql: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
      mql: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
      lead: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
    };
    return colors[stage as keyof typeof colors] || colors.lead;
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <Building2 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Companies</h1>
              <p className="text-muted-foreground mt-1">{total} total companies</p>
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
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportCSV}
              disabled={filteredCompanies.length === 0}
            >
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              Add Company
            </Button>
          </div>
        </div>

        {/* Filters & Search */}
        <Card className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="md:col-span-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Search companies, domains, industries..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            {/* Lifecycle Filter */}
            <div>
              <select
                value={lifecycleFilter || ''}
                onChange={(e) => setLifecycleFilter(e.target.value || undefined)}
                className="w-full h-10 px-3 rounded-md border border-input bg-background"
              >
                <option value="">All Stages</option>
                <option value="lead">Lead</option>
                <option value="mql">MQL</option>
                <option value="sql">SQL</option>
                <option value="opportunity">Opportunity</option>
                <option value="customer">Customer</option>
                <option value="evangelist">Evangelist</option>
              </select>
            </div>

            {/* Status Filter */}
            <div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full h-10 px-3 rounded-md border border-input bg-background"
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="prospect">Prospect</option>
                <option value="customer">Customer</option>
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
              <p className="font-semibold">Error loading companies</p>
              <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
              <Button onClick={() => refetch()} className="mt-4" size="sm">
                Try Again
              </Button>
            </div>
          </Card>
        ) : (
          <>
            {/* Companies Grid */}
            {filteredCompanies.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredCompanies.map((company) => (
                  <Card key={company.id} className="hover:shadow-lg transition-shadow">
                    <div className="p-6">
                      {/* Company Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1 min-w-0">
                          <Link
                            to="/crm/companies/$companyId"
                            params={{ companyId: company.id }}
                            className="font-semibold text-lg hover:text-primary transition-colors block truncate"
                          >
                            {company.name}
                          </Link>
                          {company.industry && (
                            <p className="text-sm text-muted-foreground mt-1">
                              {company.industry}
                            </p>
                          )}
                          {company.website && (
                            <a
                              href={company.website}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-muted-foreground hover:text-primary flex items-center gap-1 mt-1"
                            >
                              {company.domain || company.website}
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </div>
                        <div className="flex items-center gap-1 ml-2">
                          <TrendingUp className="w-4 h-4 text-green-500" />
                          <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                            {company.lead_score}
                          </span>
                        </div>
                      </div>

                      {/* Lifecycle Stage Badge */}
                      <div className="mb-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getLifecycleColor(company.lifecycle_stage)}`}>
                          {company.lifecycle_stage.toUpperCase()}
                        </span>
                        {company.company_size && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            {company.company_size} employees
                          </span>
                        )}
                      </div>

                      {/* Metrics Grid */}
                      <div className="grid grid-cols-3 gap-4 pt-4 border-t">
                        <div>
                          <div className="flex items-center text-muted-foreground text-xs mb-1">
                            <Users className="w-3 h-3 mr-1" />
                            Contacts
                          </div>
                          <p className="font-semibold">
                            {company.total_contacts || 0}
                          </p>
                        </div>
                        <div>
                          <div className="flex items-center text-muted-foreground text-xs mb-1">
                            <BarChart3 className="w-3 h-3 mr-1" />
                            Deals
                          </div>
                          <p className="font-semibold">
                            {company.total_deals || 0}
                          </p>
                        </div>
                        <div>
                          <div className="flex items-center text-muted-foreground text-xs mb-1">
                            <DollarSign className="w-3 h-3 mr-1" />
                            Pipeline
                          </div>
                          <p className="font-semibold">
                            ${((company.pipeline_value || 0) / 1000).toFixed(0)}K
                          </p>
                        </div>
                      </div>

                      {/* Quick Actions */}
                      <div className="flex items-center gap-2 mt-4 pt-4 border-t">
                        <Button variant="ghost" size="sm" className="flex-1">
                          <Mail className="w-3 h-3 mr-1" />
                          Email
                        </Button>
                        <Button variant="ghost" size="sm" className="flex-1">
                          <Phone className="w-3 h-3 mr-1" />
                          Call
                        </Button>
                        <Link
                          to="/crm/companies/$companyId"
                          params={{ companyId: company.id }}
                        >
                          <Button variant="ghost" size="sm">
                            View
                          </Button>
                        </Link>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            ) : (
              /* Empty State */
              <Card className="p-12">
                <div className="text-center">
                  <Building2 className="mx-auto h-12 w-12 text-muted-foreground" />
                  <h3 className="mt-4 text-lg font-semibold">No companies found</h3>
                  <p className="mt-2 text-sm text-muted-foreground">
                    {searchTerm || lifecycleFilter
                      ? 'Try adjusting your filters or search term'
                      : 'Get started by creating your first company'}
                  </p>
                  {!searchTerm && !lifecycleFilter && (
                    <Button className="mt-6">
                      <Plus className="w-4 h-4 mr-2" />
                      Add Company
                    </Button>
                  )}
                </div>
              </Card>
            )}

            {/* Results Summary */}
            {filteredCompanies.length > 0 && (
              <div className="text-sm text-muted-foreground text-center">
                Showing {filteredCompanies.length} of {total} companies
              </div>
            )}
          </>
        )}
      </div>
    </MainLayout>
  );
}
