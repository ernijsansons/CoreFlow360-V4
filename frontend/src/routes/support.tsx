/**
 * Community & Support Center
 * Help resources, community forums, and support tickets
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  HelpCircle,
  MessageSquare,
  Book,
  Video,
  Users,
  Ticket,
  Search,
  ThumbsUp,
  MessageCircle,
  Send,
  FileText,
  Zap,
  Shield,
  TrendingUp,
  Award,
  ExternalLink,
  ChevronRight,
  Clock,
  CheckCircle,
  AlertCircle,
  Mail,
  Phone,
  Globe
} from 'lucide-react';

export const Route = createFileRoute('/support')({
  component: SupportPage,
});

interface SupportArticle {
  id: string;
  title: string;
  category: string;
  views: number;
  helpful: number;
  content: string;
}

interface ForumThread {
  id: string;
  title: string;
  author: string;
  replies: number;
  views: number;
  lastActivity: string;
  status: 'open' | 'answered' | 'closed';
  tags: string[];
}

interface Ticket {
  id: string;
  subject: string;
  status: 'open' | 'in_progress' | 'resolved' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  created_at: string;
  updated_at: string;
}

function SupportPage() {
  const [selectedTab, setSelectedTab] = useState<'help' | 'community' | 'tickets' | 'contact'>('help');
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewTicket, setShowNewTicket] = useState(false);

  const categories = [
    { id: 'getting-started', name: 'Getting Started', icon: Zap, count: 12 },
    { id: 'crm', name: 'CRM & Sales', icon: TrendingUp, count: 24 },
    { id: 'finance', name: 'Finance & Accounting', icon: FileText, count: 18 },
    { id: 'ai-agents', name: 'AI Agents', icon: MessageSquare, count: 15 },
    { id: 'security', name: 'Security & Privacy', icon: Shield, count: 8 },
    { id: 'api', name: 'API & Integration', icon: Globe, count: 20 },
  ];

  const popularArticles: SupportArticle[] = [
    {
      id: '1',
      title: 'Getting Started with CoreFlow360 V4',
      category: 'Getting Started',
      views: 1234,
      helpful: 89,
      content: 'Learn the basics...',
    },
    {
      id: '2',
      title: 'Setting Up AI Agents for Automation',
      category: 'AI Agents',
      views: 987,
      helpful: 76,
      content: 'Configure autonomous AI...',
    },
    {
      id: '3',
      title: 'Managing Multi-Business Portfolios',
      category: 'CRM & Sales',
      views: 856,
      helpful: 64,
      content: 'How to manage multiple...',
    },
  ];

  const forumThreads: ForumThread[] = [
    {
      id: '1',
      title: 'Best practices for AI agent configuration?',
      author: 'Sarah Chen',
      replies: 12,
      views: 234,
      lastActivity: '2 hours ago',
      status: 'answered',
      tags: ['ai-agents', 'best-practices'],
    },
    {
      id: '2',
      title: 'How to integrate with Salesforce?',
      author: 'Mike Johnson',
      replies: 5,
      views: 156,
      lastActivity: '4 hours ago',
      status: 'open',
      tags: ['integration', 'salesforce'],
    },
    {
      id: '3',
      title: 'Multi-currency setup guide',
      author: 'Emily Rodriguez',
      replies: 8,
      views: 198,
      lastActivity: '1 day ago',
      status: 'answered',
      tags: ['finance', 'multi-currency'],
    },
  ];

  const myTickets: Ticket[] = [
    {
      id: 'TICK-001',
      subject: 'API rate limit issue',
      status: 'in_progress',
      priority: 'high',
      created_at: '2025-01-10T10:00:00Z',
      updated_at: '2025-01-10T14:30:00Z',
    },
    {
      id: 'TICK-002',
      subject: 'Question about data migration',
      status: 'resolved',
      priority: 'medium',
      created_at: '2025-01-09T09:00:00Z',
      updated_at: '2025-01-09T16:00:00Z',
    },
  ];

  const videos = [
    { id: '1', title: 'CoreFlow360 V4 Overview', duration: '5:24', views: 2341 },
    { id: '2', title: 'AI Agents Setup Tutorial', duration: '8:15', views: 1876 },
    { id: '3', title: 'Advanced CRM Features', duration: '12:03', views: 1543 },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'answered':
      case 'resolved':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'in_progress':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      case 'open':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'closed':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'urgent':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
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
            <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <HelpCircle className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Support Center</h1>
              <p className="text-muted-foreground mt-1">
                Get help, connect with community, and access resources
              </p>
            </div>
          </div>
        </div>

        {/* Search Bar */}
        <Card className="p-4">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search for help articles, questions, or guides..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-12 h-12 text-base"
            />
          </div>
        </Card>

        {/* Tabs */}
        <div className="border-b">
          <div className="flex gap-6">
            {[
              { id: 'help', label: 'Help Center', icon: Book },
              { id: 'community', label: 'Community', icon: Users },
              { id: 'tickets', label: 'My Tickets', icon: Ticket, badge: myTickets.filter(t => t.status !== 'resolved' && t.status !== 'closed').length },
              { id: 'contact', label: 'Contact Us', icon: Mail },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id as any)}
                className={`flex items-center gap-2 pb-3 border-b-2 transition-colors ${
                  selectedTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span className="font-medium">{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="bg-primary text-primary-foreground text-xs rounded-full px-2 py-0.5">
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Help Center Tab */}
        {selectedTab === 'help' && (
          <>
            {/* Categories */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categories.map((category) => (
                <Card key={category.id} className="p-6 hover:shadow-lg transition-shadow cursor-pointer">
                  <div className="flex items-start justify-between mb-3">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      <category.icon className="w-5 h-5 text-primary" />
                    </div>
                    <span className="text-sm text-muted-foreground">{category.count} articles</span>
                  </div>
                  <h3 className="font-semibold mb-1">{category.name}</h3>
                  <p className="text-sm text-muted-foreground">Browse guides and tutorials</p>
                </Card>
              ))}
            </div>

            {/* Popular Articles */}
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-primary" />
                Popular Articles
              </h3>
              <div className="space-y-3">
                {popularArticles.map((article) => (
                  <div key={article.id} className="p-4 border border-border rounded-lg hover:bg-muted/50 cursor-pointer transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">{article.title}</h4>
                        <p className="text-sm text-muted-foreground mb-2">{article.category}</p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>{article.views} views</span>
                          <span className="flex items-center gap-1">
                            <ThumbsUp className="w-3 h-3" />
                            {article.helpful} found helpful
                          </span>
                        </div>
                      </div>
                      <ChevronRight className="w-5 h-5 text-muted-foreground" />
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Video Tutorials */}
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Video className="w-5 h-5 text-primary" />
                Video Tutorials
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {videos.map((video) => (
                  <div key={video.id} className="border border-border rounded-lg overflow-hidden hover:shadow-md transition-shadow cursor-pointer">
                    <div className="aspect-video bg-muted flex items-center justify-center">
                      <Video className="w-12 h-12 text-muted-foreground" />
                    </div>
                    <div className="p-3">
                      <h4 className="font-semibold text-sm mb-1">{video.title}</h4>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        <span>{video.duration}</span>
                        <span>•</span>
                        <span>{video.views} views</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </>
        )}

        {/* Community Tab */}
        {selectedTab === 'community' && (
          <>
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Community Forum</h3>
                <Button size="sm">
                  <MessageCircle className="w-4 h-4 mr-2" />
                  New Discussion
                </Button>
              </div>
              <div className="space-y-3">
                {forumThreads.map((thread) => (
                  <div key={thread.id} className="p-4 border border-border rounded-lg hover:bg-muted/50 cursor-pointer transition-colors">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-semibold">{thread.title}</h4>
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(thread.status)}`}>
                            {thread.status}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">
                          Started by {thread.author} • {thread.lastActivity}
                        </p>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <MessageCircle className="w-4 h-4" />
                            {thread.replies} replies
                          </span>
                          <span>{thread.views} views</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2 mt-3">
                      {thread.tags.map((tag) => (
                        <span key={tag} className="px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="p-6 bg-blue-50 dark:bg-blue-900/10 border-blue-200 dark:border-blue-800">
              <div className="flex items-start gap-4">
                <Award className="w-8 h-8 text-blue-600 dark:text-blue-400" />
                <div>
                  <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-1">
                    Join Our Community
                  </h3>
                  <p className="text-sm text-blue-700 dark:text-blue-300 mb-3">
                    Connect with other entrepreneurs, share insights, and learn from the best practices
                  </p>
                  <Button size="sm" variant="outline">
                    <Users className="w-4 h-4 mr-2" />
                    Join Community
                  </Button>
                </div>
              </div>
            </Card>
          </>
        )}

        {/* Tickets Tab */}
        {selectedTab === 'tickets' && (
          <>
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">My Support Tickets</h3>
                <Button size="sm" onClick={() => setShowNewTicket(!showNewTicket)}>
                  <Send className="w-4 h-4 mr-2" />
                  New Ticket
                </Button>
              </div>

              {showNewTicket && (
                <Card className="p-4 mb-4 border-2 border-primary">
                  <h4 className="font-semibold mb-3">Create Support Ticket</h4>
                  <div className="space-y-3">
                    <Input placeholder="Subject" />
                    <select className="w-full h-10 px-3 rounded-md border border-input bg-background">
                      <option value="low">Low Priority</option>
                      <option value="medium">Medium Priority</option>
                      <option value="high">High Priority</option>
                      <option value="urgent">Urgent</option>
                    </select>
                    <textarea
                      className="w-full min-h-[120px] p-3 rounded-md border border-input bg-background resize-none"
                      placeholder="Describe your issue..."
                    />
                    <div className="flex gap-2">
                      <Button size="sm">Submit Ticket</Button>
                      <Button size="sm" variant="outline" onClick={() => setShowNewTicket(false)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                </Card>
              )}

              <div className="space-y-3">
                {myTickets.map((ticket) => (
                  <div key={ticket.id} className="p-4 border border-border rounded-lg hover:bg-muted/50 cursor-pointer transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-mono text-muted-foreground">{ticket.id}</span>
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(ticket.status)}`}>
                            {ticket.status.replace('_', ' ')}
                          </span>
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getPriorityColor(ticket.priority)}`}>
                            {ticket.priority}
                          </span>
                        </div>
                        <h4 className="font-semibold mb-2">{ticket.subject}</h4>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Created: {new Date(ticket.created_at).toLocaleDateString()}</span>
                          <span>Updated: {new Date(ticket.updated_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-5 h-5 text-muted-foreground" />
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </>
        )}

        {/* Contact Tab */}
        {selectedTab === 'contact' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Contact Support</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <Mail className="w-5 h-5 text-primary mt-1" />
                  <div>
                    <h4 className="font-semibold mb-1">Email Support</h4>
                    <p className="text-sm text-muted-foreground mb-2">
                      Get help via email within 24 hours
                    </p>
                    <a href="mailto:support@coreflow360.com" className="text-sm text-primary hover:underline flex items-center gap-1">
                      support@coreflow360.com
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Phone className="w-5 h-5 text-primary mt-1" />
                  <div>
                    <h4 className="font-semibold mb-1">Phone Support</h4>
                    <p className="text-sm text-muted-foreground mb-2">
                      Enterprise customers: Mon-Fri 9AM-5PM PST
                    </p>
                    <a href="tel:+1234567890" className="text-sm text-primary hover:underline">
                      +1 (234) 567-890
                    </a>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <MessageSquare className="w-5 h-5 text-primary mt-1" />
                  <div>
                    <h4 className="font-semibold mb-1">Live Chat</h4>
                    <p className="text-sm text-muted-foreground mb-2">
                      Chat with our support team in real-time
                    </p>
                    <Button size="sm" variant="outline">
                      Start Chat
                    </Button>
                  </div>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Additional Resources</h3>
              <div className="space-y-3">
                <a href="#" className="flex items-center justify-between p-3 border border-border rounded-lg hover:bg-muted/50 transition-colors">
                  <div className="flex items-center gap-3">
                    <Book className="w-5 h-5 text-primary" />
                    <span className="font-medium">Documentation</span>
                  </div>
                  <ExternalLink className="w-4 h-4 text-muted-foreground" />
                </a>
                <a href="#" className="flex items-center justify-between p-3 border border-border rounded-lg hover:bg-muted/50 transition-colors">
                  <div className="flex items-center gap-3">
                    <Globe className="w-5 h-5 text-primary" />
                    <span className="font-medium">API Reference</span>
                  </div>
                  <ExternalLink className="w-4 h-4 text-muted-foreground" />
                </a>
                <a href="#" className="flex items-center justify-between p-3 border border-border rounded-lg hover:bg-muted/50 transition-colors">
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-primary" />
                    <span className="font-medium">System Status</span>
                  </div>
                  <ExternalLink className="w-4 h-4 text-muted-foreground" />
                </a>
              </div>
            </Card>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
