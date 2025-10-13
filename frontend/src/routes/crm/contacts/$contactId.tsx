/**
 * Contact Detail Page - Fortune 50 Level
 * 360° contact view with complete interaction history
 */

import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { useContact, useActivities } from '@/lib/api/hooks/useCRM';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Mail,
  Phone,
  Linkedin,
  MapPin,
  Building2,
  Briefcase,
  Calendar,
  Activity,
  TrendingUp,
  Clock,
  MessageSquare,
  Users,
  DollarSign,
  Edit,
  Trash2,
  MoreVertical,
  ArrowLeft,
  ExternalLink,
  Target
} from 'lucide-react';

export const Route = createFileRoute('/crm/contacts/$contactId')({
  component: ContactDetailPage,
});

function ContactDetailPage() {
  const { contactId } = Route.useParams();
  const [activeTab, setActiveTab] = useState<'overview' | 'activity' | 'deals'>('overview');

  const { data: contactData, isLoading, error } = useContact(contactId);
  const { data: activitiesData } = useActivities({ contact_id: contactId, limit: 20 });

  const contact = contactData;
  const activities = activitiesData?.data || [];

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

  const getActivityIcon = (type: string) => {
    const icons = {
      email: Mail,
      call: Phone,
      meeting: Users,
      note: MessageSquare,
      task: Target,
    };
    const Icon = icons[type as keyof typeof icons] || Activity;
    return <Icon className="w-4 h-4" />;
  };

  const formatDate = (date: string) => {
    const d = new Date(date);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
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

  if (error || !contact) {
    return (
      <MainLayout>
        <Card className="p-6">
          <div className="text-center text-destructive">
            <p className="font-semibold">Error loading contact</p>
            <p className="text-sm mt-1">{error instanceof Error ? error.message : 'Contact not found'}</p>
            <Link to="/crm/contacts">
              <Button className="mt-4" size="sm">
                Back to Contacts
              </Button>
            </Link>
          </div>
        </Card>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/crm/contacts">
              <Button variant="ghost" size="sm">
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </Button>
            </Link>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">
                {contact.first_name} {contact.last_name}
              </h1>
              {contact.job_title && (
                <p className="text-muted-foreground mt-1 flex items-center gap-2">
                  <Briefcase className="w-4 h-4" />
                  {contact.job_title}
                  {contact.company_name && (
                    <>
                      <span>at</span>
                      <Link
                        to="/crm/companies/$companyId"
                        params={{ companyId: contact.company_id || '' }}
                        className="hover:text-primary inline-flex items-center gap-1"
                      >
                        {contact.company_name}
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </>
                  )}
                </p>
              )}
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

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Contact Info & Stats */}
          <div className="space-y-6">
            {/* Contact Information Card */}
            <Card className="p-6">
              <h3 className="font-semibold mb-4">Contact Information</h3>
              <div className="space-y-4">
                {contact.email && (
                  <div>
                    <label className="text-sm text-muted-foreground">Email</label>
                    <a
                      href={`mailto:${contact.email}`}
                      className="flex items-center gap-2 text-sm hover:text-primary mt-1"
                    >
                      <Mail className="w-4 h-4" />
                      {contact.email}
                    </a>
                  </div>
                )}

                {contact.phone && (
                  <div>
                    <label className="text-sm text-muted-foreground">Phone</label>
                    <a
                      href={`tel:${contact.phone}`}
                      className="flex items-center gap-2 text-sm hover:text-primary mt-1"
                    >
                      <Phone className="w-4 h-4" />
                      {contact.phone}
                    </a>
                  </div>
                )}

                {contact.location && (
                  <div>
                    <label className="text-sm text-muted-foreground">Location</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <MapPin className="w-4 h-4" />
                      {contact.location}
                    </div>
                  </div>
                )}

                {contact.linkedin_url && (
                  <div>
                    <label className="text-sm text-muted-foreground">LinkedIn</label>
                    <a
                      href={contact.linkedin_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm hover:text-primary mt-1"
                    >
                      <Linkedin className="w-4 h-4" />
                      View Profile
                    </a>
                  </div>
                )}
              </div>

              {/* Quick Actions */}
              <div className="grid grid-cols-2 gap-2 mt-6 pt-6 border-t">
                {contact.email && (
                  <Button variant="outline" size="sm" asChild>
                    <a href={`mailto:${contact.email}`}>
                      <Mail className="w-4 h-4 mr-2" />
                      Email
                    </a>
                  </Button>
                )}
                {contact.phone && (
                  <Button variant="outline" size="sm" asChild>
                    <a href={`tel:${contact.phone}`}>
                      <Phone className="w-4 h-4 mr-2" />
                      Call
                    </a>
                  </Button>
                )}
              </div>
            </Card>

            {/* Stats Card */}
            <Card className="p-6">
              <h3 className="font-semibold mb-4">Contact Stats</h3>
              <div className="space-y-4">
                {/* Lead Score */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">Lead Score</span>
                    <div className="flex items-center gap-1">
                      <TrendingUp className="w-4 h-4 text-green-500" />
                      <span className="text-lg font-bold text-green-600 dark:text-green-400">
                        {contact.lead_score}
                      </span>
                    </div>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div
                      className="bg-green-600 dark:bg-green-400 h-2 rounded-full transition-all"
                      style={{ width: `${contact.lead_score}%` }}
                    />
                  </div>
                </div>

                {/* Engagement Score */}
                {contact.engagement_score !== undefined && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground">Engagement</span>
                      <span className={`text-lg font-bold ${getEngagementColor(contact.engagement_score)}`}>
                        {contact.engagement_score}%
                      </span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all"
                        style={{ width: `${contact.engagement_score}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Lifecycle Stage */}
                <div className="pt-4 border-t">
                  <label className="text-sm text-muted-foreground">Lifecycle Stage</label>
                  <div className="mt-2">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getLifecycleColor(contact.lifecycle_stage)}`}>
                      {contact.lifecycle_stage.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Status */}
                {contact.status && (
                  <div>
                    <label className="text-sm text-muted-foreground">Status</label>
                    <div className="mt-2">
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                        {contact.status}
                      </span>
                    </div>
                  </div>
                )}

                {/* Last Contact */}
                {contact.last_contact_date && (
                  <div>
                    <label className="text-sm text-muted-foreground">Last Contact</label>
                    <div className="flex items-center gap-2 text-sm mt-1">
                      <Clock className="w-4 h-4" />
                      {formatDate(contact.last_contact_date)}
                    </div>
                  </div>
                )}

                {/* Created Date */}
                <div>
                  <label className="text-sm text-muted-foreground">Created</label>
                  <div className="flex items-center gap-2 text-sm mt-1">
                    <Calendar className="w-4 h-4" />
                    {formatDate(contact.created_at)}
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
                  variant={activeTab === 'activity' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('activity')}
                  className="flex-1"
                >
                  Activity ({activities.length})
                </Button>
                <Button
                  variant={activeTab === 'deals' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('deals')}
                  className="flex-1"
                >
                  Deals
                </Button>
              </div>
            </Card>

            {/* Tab Content */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Company Information */}
                {contact.company_name && (
                  <Card className="p-6">
                    <h3 className="font-semibold mb-4">Company Information</h3>
                    <div className="flex items-start gap-4">
                      <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                        <Building2 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                      </div>
                      <div className="flex-1">
                        <Link
                          to="/crm/companies/$companyId"
                          params={{ companyId: contact.company_id || '' }}
                          className="font-semibold text-lg hover:text-primary inline-flex items-center gap-2"
                        >
                          {contact.company_name}
                          <ExternalLink className="w-4 h-4" />
                        </Link>
                        {contact.job_title && (
                          <p className="text-sm text-muted-foreground mt-1">{contact.job_title}</p>
                        )}
                      </div>
                    </div>
                  </Card>
                )}

                {/* Notes Section */}
                <Card className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Notes</h3>
                    <Button size="sm" variant="outline">
                      <MessageSquare className="w-4 h-4 mr-2" />
                      Add Note
                    </Button>
                  </div>
                  <div className="text-center py-8 text-muted-foreground">
                    <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No notes yet</p>
                  </div>
                </Card>
              </div>
            )}

            {activeTab === 'activity' && (
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Recent Activity</h3>
                  <Button size="sm" variant="outline">
                    <Activity className="w-4 h-4 mr-2" />
                    Log Activity
                  </Button>
                </div>

                {activities.length > 0 ? (
                  <div className="space-y-4">
                    {activities.map((activity: any) => (
                      <div key={activity.id} className="flex gap-4 pb-4 border-b last:border-b-0">
                        <div className="p-2 bg-muted rounded-lg h-fit">
                          {getActivityIcon(activity.type)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="font-medium capitalize">{activity.type}</p>
                              <p className="text-sm text-muted-foreground mt-1">{activity.subject}</p>
                              {activity.description && (
                                <p className="text-sm mt-2">{activity.description}</p>
                              )}
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {formatDate(activity.created_at)}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No activities recorded yet</p>
                  </div>
                )}
              </Card>
            )}

            {activeTab === 'deals' && (
              <Card className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-semibold">Associated Deals</h3>
                  <Button size="sm" variant="outline">
                    <DollarSign className="w-4 h-4 mr-2" />
                    Create Deal
                  </Button>
                </div>
                <div className="text-center py-8 text-muted-foreground">
                  <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No deals associated with this contact</p>
                </div>
              </Card>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
