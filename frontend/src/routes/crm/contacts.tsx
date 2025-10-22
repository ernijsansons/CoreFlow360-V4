/**
 * CRM Contacts Page - Fortune 50 Level
 * Comprehensive contact management with engagement tracking
 */

import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useContacts } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  UserPlus,
  Search,
  Filter,
  TrendingUp,
  Mail,
  Phone,
  Linkedin,
  Building2,
  Calendar,
  Download,
  RefreshCw,
  MapPin,
  Briefcase,
  Clock,
  Activity
} from 'lucide-react';

export const Route = createFileRoute('/crm/contacts')({
  component: ContactsPage,
});

function ContactsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string>('active');

  const { data, isLoading, error, refetch, isFetching } = useContacts({
    lifecycle_stage: lifecycleFilter,
    status: statusFilter,
    limit: 50,
  });

  const contacts = data?.data || [];
  const total = data?.total || 0;

  // Filter contacts by search term (client-side)
  const filteredContacts = contacts.filter((contact) =>
    contact.first_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contact.last_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contact.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contact.company_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    contact.job_title?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleRefresh = async () => {
    await refetch();
    const event = new CustomEvent('show-toast', {
      detail: { message: 'Contacts refreshed', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const handleExportCSV = () => {
    const headers = ['Name', 'Email', 'Phone', 'Company', 'Title', 'Score', 'Stage', 'Engagement'];
    const rows = filteredContacts.map(c => [
      `${c.first_name || ''} ${c.last_name || ''}`.trim(),
      c.email || '',
      c.phone || '',
      c.company_name || '',
      c.job_title || '',
      c.lead_score,
      c.lifecycle_stage,
      c.engagement_score || 0
    ]);

    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `contacts-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    const event = new CustomEvent('show-toast', {
      detail: { message: `Exported ${filteredContacts.length} contacts`, type: 'success' }
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

  const getEngagementColor = (score: number) => {
    if (score >= 80) return 'text-green-600 dark:text-green-400';
    if (score >= 60) return 'text-blue-600 dark:text-blue-400';
    if (score >= 40) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-gray-600 dark:text-gray-400';
  };

  const formatLastContact = (date?: string) => {
    if (!date) return 'Never';
    const d = new Date(date);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    return `${Math.floor(diffDays / 30)} months ago`;
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <UserPlus className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Contacts</h1>
              <p className="text-muted-foreground mt-1">{total} total contacts</p>
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
              disabled={filteredContacts.length === 0}
            >
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
            <Button size="sm">
              <UserPlus className="w-4 h-4 mr-2" />
              Add Contact
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
                  placeholder="Search contacts, emails, companies..."
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
                <option value="unqualified">Unqualified</option>
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
              <p className="font-semibold">Error loading contacts</p>
              <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
              <Button onClick={() => refetch()} className="mt-4" size="sm">
                Try Again
              </Button>
            </div>
          </Card>
        ) : (
          <>
            {/* Contacts Grid */}
            {filteredContacts.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredContacts.map((contact) => (
                  <Card key={contact.id} className="hover:shadow-lg transition-shadow">
                    <div className="p-6">
                      {/* Contact Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1 min-w-0">
                          <Link
                            to="/crm/contacts/$contactId"
                            params={{ contactId: contact.id }}
                            className="font-semibold text-lg hover:text-primary transition-colors block truncate"
                          >
                            {contact.first_name} {contact.last_name}
                          </Link>
                          {contact.job_title && (
                            <div className="flex items-center text-sm text-muted-foreground mt-1">
                              <Briefcase className="w-3 h-3 mr-1" />
                              {contact.job_title}
                            </div>
                          )}
                          {contact.company_name && (
                            <Link
                              to="/crm/companies/$companyId"
                              params={{ companyId: contact.company_id || '' }}
                              className="flex items-center text-sm text-muted-foreground hover:text-primary mt-1"
                            >
                              <Building2 className="w-3 h-3 mr-1" />
                              {contact.company_name}
                            </Link>
                          )}
                        </div>
                        <div className="flex items-center gap-1 ml-2">
                          <TrendingUp className="w-4 h-4 text-green-500" />
                          <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                            {contact.lead_score}
                          </span>
                        </div>
                      </div>

                      {/* Contact Info */}
                      <div className="space-y-2 mb-4">
                        {contact.email && (
                          <div className="flex items-center text-sm text-muted-foreground truncate">
                            <Mail className="w-3 h-3 mr-2 flex-shrink-0" />
                            <a href={`mailto:${contact.email}`} className="hover:text-primary truncate">
                              {contact.email}
                            </a>
                          </div>
                        )}
                        {contact.phone && (
                          <div className="flex items-center text-sm text-muted-foreground">
                            <Phone className="w-3 h-3 mr-2 flex-shrink-0" />
                            <a href={`tel:${contact.phone}`} className="hover:text-primary">
                              {contact.phone}
                            </a>
                          </div>
                        )}
                        {contact.location && (
                          <div className="flex items-center text-sm text-muted-foreground">
                            <MapPin className="w-3 h-3 mr-2 flex-shrink-0" />
                            {contact.location}
                          </div>
                        )}
                      </div>

                      {/* Lifecycle Stage & Status */}
                      <div className="flex items-center gap-2 mb-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getLifecycleColor(contact.lifecycle_stage)}`}>
                          {contact.lifecycle_stage.toUpperCase()}
                        </span>
                        {contact.status && (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                            {contact.status}
                          </span>
                        )}
                      </div>

                      {/* Engagement Metrics */}
                      <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                        <div>
                          <div className="flex items-center text-muted-foreground text-xs mb-1">
                            <Activity className="w-3 h-3 mr-1" />
                            Engagement
                          </div>
                          <p className={`font-semibold ${getEngagementColor(contact.engagement_score || 0)}`}>
                            {contact.engagement_score || 0}%
                          </p>
                        </div>
                        <div>
                          <div className="flex items-center text-muted-foreground text-xs mb-1">
                            <Clock className="w-3 h-3 mr-1" />
                            Last Contact
                          </div>
                          <p className="font-semibold text-sm">
                            {formatLastContact(contact.last_contact_date)}
                          </p>
                        </div>
                      </div>

                      {/* Quick Actions */}
                      <div className="flex items-center gap-2 mt-4 pt-4 border-t">
                        {contact.email && (
                          <Button variant="ghost" size="sm" className="flex-1" asChild>
                            <a href={`mailto:${contact.email}`}>
                              <Mail className="w-3 h-3 mr-1" />
                              Email
                            </a>
                          </Button>
                        )}
                        {contact.phone && (
                          <Button variant="ghost" size="sm" className="flex-1" asChild>
                            <a href={`tel:${contact.phone}`}>
                              <Phone className="w-3 h-3 mr-1" />
                              Call
                            </a>
                          </Button>
                        )}
                        {contact.linkedin_url && (
                          <Button variant="ghost" size="sm" className="flex-1" asChild>
                            <a href={contact.linkedin_url} target="_blank" rel="noopener noreferrer">
                              <Linkedin className="w-3 h-3 mr-1" />
                              LinkedIn
                            </a>
                          </Button>
                        )}
                        <Link
                          to="/crm/contacts/$contactId"
                          params={{ contactId: contact.id }}
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
                  <UserPlus className="mx-auto h-12 w-12 text-muted-foreground" />
                  <h3 className="mt-4 text-lg font-semibold">No contacts found</h3>
                  <p className="mt-2 text-sm text-muted-foreground">
                    {searchTerm || lifecycleFilter
                      ? 'Try adjusting your filters or search term'
                      : 'Get started by adding your first contact'}
                  </p>
                  {!searchTerm && !lifecycleFilter && (
                    <Button className="mt-6">
                      <UserPlus className="w-4 h-4 mr-2" />
                      Add Contact
                    </Button>
                  )}
                </div>
              </Card>
            )}

            {/* Results Summary */}
            {filteredContacts.length > 0 && (
              <div className="text-sm text-muted-foreground text-center">
                Showing {filteredContacts.length} of {total} contacts
              </div>
            )}
          </>
        )}
      </div>
    </MainLayout>
  );
}
