/**
 * CRM Leads Page - Fortune 50 Level
 * Lead management with AI-powered scoring and qualification
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Target,
  Plus,
  Search,
  TrendingUp,
  Mail,
  Phone,
  Calendar,
  Download,
  RefreshCw,
  CheckCircle,
  Clock,
  AlertCircle
} from 'lucide-react';

export const Route = createFileRoute('/crm/leads')({
  component: LeadsPage,
});

interface Lead {
  id: string;
  title: string;
  source: string;
  lead_score: number;
  qualification_status: string;
  estimated_budget: number;
  contact_name?: string;
  contact_email?: string;
  contact_phone?: string;
  company_name?: string;
  created_at: string;
}

function LeadsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Mock data - replace with actual API call
  const leads: Lead[] = [
    {
      id: '1',
      title: 'Enterprise Demo Request - Fortune 500',
      source: 'website',
      lead_score: 85,
      qualification_status: 'qualified',
      estimated_budget: 500000,
      contact_name: 'Sarah Johnson',
      contact_email: 'sarah.j@enterprise.com',
      contact_phone: '+1 (555) 123-4567',
      company_name: 'Enterprise Corp',
      created_at: '2025-10-10T10:00:00Z'
    },
    {
      id: '2',
      title: 'Interested in Analytics Platform',
      source: 'paid_ad',
      lead_score: 72,
      qualification_status: 'working',
      estimated_budget: 100000,
      contact_name: 'Michael Chen',
      contact_email: 'm.chen@techstart.io',
      company_name: 'TechStart Inc',
      created_at: '2025-10-11T14:30:00Z'
    },
    {
      id: '3',
      title: 'Conference Lead - Tech Summit 2025',
      source: 'event',
      lead_score: 58,
      qualification_status: 'new',
      estimated_budget: 75000,
      contact_name: 'Emma Davis',
      contact_email: 'emma.d@innovate.com',
      company_name: 'Innovate Solutions',
      created_at: '2025-10-12T09:15:00Z'
    }
  ];

  // Filter leads
  const filteredLeads = leads.filter(lead => {
    const matchesSearch =
      lead.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      lead.contact_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      lead.company_name?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSource = sourceFilter === 'all' || lead.source === sourceFilter;
    const matchesStatus = statusFilter === 'all' || lead.qualification_status === statusFilter;

    return matchesSearch && matchesSource && matchesStatus;
  });

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600 dark:text-green-400';
    if (score >= 60) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getScoreBgColor = (score: number) => {
    if (score >= 80) return 'bg-green-100 dark:bg-green-900/20';
    if (score >= 60) return 'bg-yellow-100 dark:bg-yellow-900/20';
    return 'bg-red-100 dark:bg-red-900/20';
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'qualified':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'working':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'new':
        return <AlertCircle className="w-4 h-4 text-blue-500" />;
      default:
        return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    const colors = {
      qualified: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
      working: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
      new: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
      unqualified: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
    };
    return colors[status as keyof typeof colors] || colors.new;
  };

  const getSourceBadgeColor = (source: string) => {
    const colors = {
      website: 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400',
      paid_ad: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
      event: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
      referral: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
      organic: 'bg-teal-100 text-teal-800 dark:bg-teal-900/20 dark:text-teal-400',
    };
    return colors[source as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Target className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Leads</h1>
              <p className="text-muted-foreground mt-1">{filteredLeads.length} active leads</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm">
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              Add Lead
            </Button>
          </div>
        </div>

        {/* Filters */}
        <Card className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="md:col-span-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Search leads, contacts, companies..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            {/* Source Filter */}
            <div>
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="w-full h-10 px-3 rounded-md border border-input bg-background"
              >
                <option value="all">All Sources</option>
                <option value="website">Website</option>
                <option value="paid_ad">Paid Ads</option>
                <option value="event">Events</option>
                <option value="referral">Referrals</option>
                <option value="organic">Organic</option>
              </select>
            </div>

            {/* Status Filter */}
            <div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full h-10 px-3 rounded-md border border-input bg-background"
              >
                <option value="all">All Status</option>
                <option value="new">New</option>
                <option value="working">Working</option>
                <option value="qualified">Qualified</option>
                <option value="unqualified">Unqualified</option>
              </select>
            </div>
          </div>
        </Card>

        {/* Leads List */}
        <div className="grid gap-4">
          {filteredLeads.map((lead) => (
            <Card key={lead.id} className="hover:shadow-lg transition-shadow">
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-lg">{lead.title}</h3>
                      {getStatusIcon(lead.qualification_status)}
                    </div>
                    {lead.company_name && (
                      <p className="text-sm text-muted-foreground">{lead.company_name}</p>
                    )}
                  </div>

                  {/* Lead Score */}
                  <div className={`flex items-center gap-2 px-3 py-1 rounded-full ${getScoreBgColor(lead.lead_score)}`}>
                    <TrendingUp className={`w-4 h-4 ${getScoreColor(lead.lead_score)}`} />
                    <span className={`font-semibold ${getScoreColor(lead.lead_score)}`}>
                      {lead.lead_score}
                    </span>
                  </div>
                </div>

                {/* Contact Info */}
                {lead.contact_name && (
                  <div className="mb-4">
                    <p className="font-medium">{lead.contact_name}</p>
                    <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                      {lead.contact_email && (
                        <div className="flex items-center gap-1">
                          <Mail className="w-3 h-3" />
                          {lead.contact_email}
                        </div>
                      )}
                      {lead.contact_phone && (
                        <div className="flex items-center gap-1">
                          <Phone className="w-3 h-3" />
                          {lead.contact_phone}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Badges & Metrics */}
                <div className="flex items-center gap-3 mb-4">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(lead.qualification_status)}`}>
                    {lead.qualification_status.toUpperCase()}
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSourceBadgeColor(lead.source)}`}>
                    {lead.source.replace('_', ' ').toUpperCase()}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    Budget: ${(lead.estimated_budget / 1000).toFixed(0)}K
                  </span>
                  <div className="flex items-center text-sm text-muted-foreground">
                    <Calendar className="w-3 h-3 mr-1" />
                    {new Date(lead.created_at).toLocaleDateString()}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 pt-4 border-t">
                  <Button variant="ghost" size="sm">
                    <Mail className="w-3 h-3 mr-1" />
                    Email
                  </Button>
                  <Button variant="ghost" size="sm">
                    <Phone className="w-3 h-3 mr-1" />
                    Call
                  </Button>
                  <Button variant="ghost" size="sm">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    Qualify
                  </Button>
                  <Button variant="outline" size="sm" className="ml-auto">
                    View Details
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>

        {/* Empty State */}
        {filteredLeads.length === 0 && (
          <Card className="p-12">
            <div className="text-center">
              <Target className="mx-auto h-12 w-12 text-muted-foreground" />
              <h3 className="mt-4 text-lg font-semibold">No leads found</h3>
              <p className="mt-2 text-sm text-muted-foreground">
                {searchTerm || sourceFilter !== 'all' || statusFilter !== 'all'
                  ? 'Try adjusting your filters'
                  : 'Get started by creating your first lead'}
              </p>
              <Button className="mt-6">
                <Plus className="w-4 h-4 mr-2" />
                Add Lead
              </Button>
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
