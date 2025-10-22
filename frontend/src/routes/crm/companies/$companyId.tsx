/**
 * Company Detail Page - Fortune 50 Level
 * 360° company view with contacts, deals, and analytics
 */

import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useCompany, useContacts, useDeals } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Building2,
  Globe,
  Users,
  DollarSign,
  TrendingUp,
  MapPin,
  Calendar,
  Target,
  Mail,
  Phone,
  Edit,
  MoreVertical,
  ArrowLeft,
  ExternalLink,
  Briefcase,
  Activity,
  BarChart3
} from 'lucide-react';

export const Route = createFileRoute('/crm/companies/$companyId')({
  component: CompanyDetailPage,
});

function CompanyDetailPage() {
  const { companyId } = Route.useParams();
  const [activeTab, setActiveTab] = useState<'overview' | 'contacts' | 'deals' | 'analytics'>('overview');

  const { data: companyData, isLoading, error } = useCompany(companyId);
  const { data: contactsData } = useContacts({ company_id: companyId, limit: 20 });
  const { data: dealsData } = useDeals({ company_id: companyId, limit: 20 });

  const company = companyData;
  const contacts = contactsData?.data || [];
  const deals = dealsData?.data || [];

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

  const formatCurrency = (value: number) => {
    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
    return `$${value}`;
  };

  const formatDate = (date: string) => {
    const d = new Date(date);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  if (isLoading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </MainLayout>
    );
  }

  if (error || !company) {
    return (
      <MainLayout>
        <Card className="p-6">
          <div className="text-center text-destructive">
            <p className="font-semibold">Error loading company</p>
            <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Company not found'}</p>
            <Link to="/crm/companies">
              <Button className="mt-4" size="sm">
                Back to Companies
              </Button>
            </Link>
          </div>
        </Card>
      </MainLayout>
    );
  }

  const totalPipelineValue = company.pipeline_value || 0;
  const totalWonValue = company.won_value || 0;
  const totalContacts = company.total_contacts || 0;
  const totalDeals = company.total_deals || 0;

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/crm/companies">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </Button>
            </Link>
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <Building2 className="w-8 h-8 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h1 className="text-3xl font-bold tracking-tight">{company.name}</h1>
                {company.website && (
                  <a
                    href={company.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-muted-foreground mt-1 hover:text-primary inline-flex items-center gap-1"
                  >
                    <Globe className="w-4 h-4" />
                    {company.domain || company.website}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm">
              <Edit className="w-4 h-4 mr-2" />
              Edit
            </Button>
            <Button variant="outline" size="sm">
              <MoreVertical className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Key Metrics Row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                <Users className="w-5 h-5 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Contacts</p>
                <p className="text-2xl font-bold">{totalContacts}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                <Target className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active Deals</p>
                <p className="text-2xl font-bold">{totalDeals}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <DollarSign className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Pipeline</p>
                <p className="text-2xl font-bold">{formatCurrency(totalPipelineValue)}</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                <TrendingUp className="w-5 h-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Won Value</p>
                <p className="text-2xl font-bold">{formatCurrency(totalWonValue)}</p>
              </div>
            </div>
          </Card>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Company Info */}
          <div className="space-y-6">
            {/* Company Information Card */}
            <Card className="p-6">
              <h3 className="font-semibold mb-4">Company Information</h3>
              <div className="space-y-4">
                {company.industry && (
                  <div>
                    <label className="text-sm text-muted-foreground">Industry</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <Briefcase className="w-4 h-4" />
                      {company.industry}
                    </div>
                  </div>
                )}

                {company.company_size && (
                  <div>
                    <label className="text-sm text-muted-foreground">Company Size</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <Users className="w-4 h-4" />
                      {company.company_size}
                    </div>
                  </div>
                )}

                {company.annual_revenue && (
                  <div>
                    <label className="text-sm text-muted-foreground">Annual Revenue</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <DollarSign className="w-4 h-4" />
                      {formatCurrency(company.annual_revenue)}
                    </div>
                  </div>
                )}

                {company.location && (
                  <div>
                    <label className="text-sm text-muted-foreground">Location</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <MapPin className="w-4 h-4" />
                      {company.location}
                    </div>
                  </div>
                )}

                {company.website && (
                  <div>
                    <label className="text-sm text-muted-foreground">Website</label>
                    <a
                      href={company.website}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm hover:text-primary mt-1"
                    >
                      <Globe className="w-4 h-4" />
                      {company.domain || 'Visit Website'}
                    </a>
                  </div>
                )}
              </div>
            </Card>

            {/* Company Stats Card */}
            <Card className="p-6">
              <h3 className="font-semibold mb-4">Company Score</h3>
              <div className="space-y-4">
                {/* Lead Score */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">Lead Score</span>
                    <div className="flex items-center gap-1">
                      <TrendingUp className="w-4 h-4 text-green-500" />
                      <span className="text-lg font-bold text-green-600 dark:text-green-400">
                        {company.lead_score}
                      </span>
                    </div>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div
                      className="bg-green-600 dark:bg-green-400 h-2 rounded-full transition-all"
                      style={{ width: `${company.lead_score}%` }}
                    />
                  </div>
                </div>

                {/* Health Score */}
                {company.health_score !== undefined && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground">Health Score</span>
                      <span className="text-lg font-bold text-blue-600 dark:text-blue-400">
                        {company.health_score}%
                      </span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all"
                        style={{ width: `${company.health_score}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Lifecycle Stage */}
                <div className="pt-4 border-t">
                  <label className="text-sm text-muted-foreground">Lifecycle Stage</label>
                  <div className="mt-2">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getLifecycleColor(company.lifecycle_stage)}`}>
                      {company.lifecycle_stage.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Status */}
                <div>
                  <label className="text-sm text-muted-foreground">Status</label>
                  <div className="mt-2">
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                      {company.status}
                    </span>
                  </div>
                </div>

                {/* Created Date */}
                <div className="pt-4 border-t">
                  <label className="text-sm text-muted-foreground">Created</label>
                  <div className="flex items-center gap-2 text-sm mt-1">
                    <Calendar className="w-4 h-4" />
                    {formatDate(company.created_at)}
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* Right Column - Tabs Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Tabs */}
            <Card className="p-1">
              <div className="flex items-center gap-2">
                <Button
                  variant={activeTab === 'overview' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('overview')}
                  className="flex-1"
                >
                  Overview
                </Button>
                <Button
                  variant={activeTab === 'contacts' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('contacts')}
                  className="flex-1"
                >
                  Contacts ({contacts.length})
                </Button>
                <Button
                  variant={activeTab === 'deals' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('deals')}
                  className="flex-1"
                >
                  Deals ({deals.length})
                </Button>
                <Button
                  variant={activeTab === 'analytics' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('analytics')}
                  className="flex-1"
                >
                  Analytics
                </Button>
              </div>
            </Card>

            {/* Tab Content */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Recent Activity Summary */}
                <Card className="p-6">
                  <h3 className="font-semibold mb-4">Recent Activity</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Last Contact</p>
                      <p className="text-lg font-semibold mt-1">
                        {company.last_contact_date ? formatDate(company.last_contact_date) : 'Never'}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Total Activities</p>
                      <p className="text-lg font-semibold mt-1">-</p>
                    </div>
                  </div>
                </Card>

                {/* Quick Stats */}
                <Card className="p-6">
                  <h3 className="font-semibold mb-4">Performance Summary</h3>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between py-3 border-b">
                      <span className="text-sm text-muted-foreground">Total Pipeline Value</span>
                      <span className="font-semibold">{formatCurrency(totalPipelineValue)}</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b">
                      <span className="text-sm text-muted-foreground">Total Won Value</span>
                      <span className="font-semibold text-green-600 dark:text-green-400">
                        {formatCurrency(totalWonValue)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between py-3">
                      <span className="text-sm text-muted-foreground">Win Rate</span>
                      <span className="font-semibold">
                        {totalDeals > 0 ? ((totalWonValue / (totalPipelineValue + totalWonValue)) * 100).toFixed(1) : 0}%
                      </span>
                    </div>
                  </div>
                </Card>
              </div>
            )}

            {activeTab === 'contacts' && (
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Company Contacts</h3>
                  <Button size="sm" variant="outline">
                    <Users className="w-4 h-4 mr-2" />
                    Add Contact
                  </Button>
                </div>

                {contacts.length > 0 ? (
                  <div className="space-y-3">
                    {contacts.map((contact: any) => (
                      <Link
                        key={contact.id}
                        to="/crm/contacts/$contactId"
                        params={{ contactId: contact.id }}
                      >
                        <Card className="p-4 hover:shadow-md transition-shadow">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="font-semibold">
                                {contact.first_name} {contact.last_name}
                              </p>
                              {contact.job_title && (
                                <p className="text-sm text-muted-foreground mt-1">{contact.job_title}</p>
                              )}
                              <div className="flex items-center gap-3 mt-2">
                                {contact.email && (
                                  <a
                                    href={`mailto:${contact.email}`}
                                    onClick={(e) => e.stopPropagation()}
                                    className="text-sm text-muted-foreground hover:text-primary inline-flex items-center gap-1"
                                  >
                                    <Mail className="w-3 h-3" />
                                    {contact.email}
                                  </a>
                                )}
                              </div>
                            </div>
                            <div className="flex items-center gap-1">
                              <TrendingUp className="w-4 h-4 text-green-500" />
                              <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                                {contact.lead_score}
                              </span>
                            </div>
                          </div>
                        </Card>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Users className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No contacts at this company yet</p>
                  </div>
                )}
              </Card>
            )}

            {activeTab === 'deals' && (
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Company Deals</h3>
                  <Button size="sm" variant="outline">
                    <Target className="w-4 h-4 mr-2" />
                    Create Deal
                  </Button>
                </div>

                {deals.length > 0 ? (
                  <div className="space-y-3">
                    {deals.map((deal: any) => (
                      <Link
                        key={deal.id}
                        to="/crm/deals/$dealId"
                        params={{ dealId: deal.id }}
                      >
                        <Card className="p-4 hover:shadow-md transition-shadow">
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <p className="font-semibold">{deal.name}</p>
                              <p className="text-sm text-muted-foreground mt-1 capitalize">
                                {deal.stage.replace(/_/g, ' ')}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="font-semibold text-lg">{formatCurrency(deal.value)}</p>
                              <p className="text-sm text-muted-foreground">{deal.probability}% prob.</p>
                            </div>
                          </div>
                        </Card>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No deals for this company yet</p>
                  </div>
                )}
              </Card>
            )}

            {activeTab === 'analytics' && (
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Company Analytics</h3>
                  <BarChart3 className="w-5 h-5 text-muted-foreground" />
                </div>

                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Engagement Trend</p>
                    <div className="h-32 flex items-end justify-between gap-2">
                      {[45, 52, 48, 61, 58, 67, 73].map((height, i) => (
                        <div
                          key={i}
                          className="flex-1 bg-blue-600 dark:bg-blue-400 rounded-t"
                          style={{ height: `${height}%` }}
                        />
                      ))}
                    </div>
                  </div>

                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Deal Progress</p>
                    <div className="h-32 flex items-end justify-between gap-2">
                      {[30, 42, 38, 55, 61, 58, 64].map((height, i) => (
                        <div
                          key={i}
                          className="flex-1 bg-green-600 dark:bg-green-400 rounded-t"
                          style={{ height: `${height}%` }}
                        />
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-8 pt-6 border-t">
                  <p className="text-sm text-muted-foreground text-center">
                    Detailed analytics coming soon
                  </p>
                </div>
              </Card>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
