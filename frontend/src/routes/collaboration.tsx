/**
 * Real-time Collaboration Dashboard
 * Live presence, activity feeds, and team collaboration features
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState, useEffect } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Users,
  Activity,
  Eye,
  Edit,
  MessageSquare,
  Bell,
  Clock,
  Circle,
  Video,
  UserPlus,
  Share2,
  GitBranch,
  FileText,
  DollarSign,
  Building2,
  Target,
  Zap,
  TrendingUp,
  CheckCircle,
  AlertCircle,
  Settings,
  Filter
} from 'lucide-react';

export const Route = createFileRoute('/collaboration')({
  component: CollaborationPage,
});

interface ActiveUser {
  id: string;
  name: string;
  avatar?: string;
  status: 'online' | 'away' | 'busy' | 'offline';
  currentPage?: string;
  lastActivity: string;
  activeDocument?: {
    type: 'deal' | 'contact' | 'invoice' | 'report';
    id: string;
    name: string;
  };
}

interface ActivityEvent {
  id: string;
  type: 'created' | 'updated' | 'deleted' | 'commented' | 'shared';
  user: {
    id: string;
    name: string;
    avatar?: string;
  };
  entity: {
    type: 'deal' | 'contact' | 'company' | 'invoice' | 'document';
    id: string;
    name: string;
  };
  timestamp: string;
  changes?: string[];
}

interface Notification {
  id: string;
  type: 'mention' | 'assignment' | 'comment' | 'update' | 'alert';
  message: string;
  from: {
    id: string;
    name: string;
  };
  timestamp: string;
  read: boolean;
  link?: string;
}

function CollaborationPage() {
  const [activeUsers, setActiveUsers] = useState<ActiveUser[]>([
    {
      id: 'u1',
      name: 'Sarah Chen',
      status: 'online',
      currentPage: 'Deals Pipeline',
      lastActivity: new Date(Date.now() - 120000).toISOString(),
      activeDocument: {
        type: 'deal',
        id: 'd1',
        name: 'Enterprise SaaS Deal',
      },
    },
    {
      id: 'u2',
      name: 'Mike Johnson',
      status: 'online',
      currentPage: 'Analytics Dashboard',
      lastActivity: new Date(Date.now() - 300000).toISOString(),
    },
    {
      id: 'u3',
      name: 'Emily Rodriguez',
      status: 'away',
      currentPage: 'Financial Reports',
      lastActivity: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'u4',
      name: 'David Kim',
      status: 'busy',
      currentPage: 'Client Meeting',
      lastActivity: new Date(Date.now() - 600000).toISOString(),
    },
  ]);

  const [activities, setActivities] = useState<ActivityEvent[]>([
    {
      id: 'a1',
      type: 'created',
      user: { id: 'u1', name: 'Sarah Chen' },
      entity: { type: 'deal', id: 'd1', name: 'Enterprise SaaS Deal' },
      timestamp: new Date(Date.now() - 300000).toISOString(),
    },
    {
      id: 'a2',
      type: 'updated',
      user: { id: 'u2', name: 'Mike Johnson' },
      entity: { type: 'contact', id: 'c1', name: 'John Smith' },
      timestamp: new Date(Date.now() - 600000).toISOString(),
      changes: ['email', 'phone'],
    },
    {
      id: 'a3',
      type: 'commented',
      user: { id: 'u3', name: 'Emily Rodriguez' },
      entity: { type: 'invoice', id: 'i1', name: 'INV-2025-001' },
      timestamp: new Date(Date.now() - 900000).toISOString(),
    },
    {
      id: 'a4',
      type: 'shared',
      user: { id: 'u4', name: 'David Kim' },
      entity: { type: 'document', id: 'doc1', name: 'Q1 Financial Report' },
      timestamp: new Date(Date.now() - 1800000).toISOString(),
    },
  ]);

  const [notifications, setNotifications] = useState<Notification[]>([
    {
      id: 'n1',
      type: 'mention',
      message: 'Sarah Chen mentioned you in a comment',
      from: { id: 'u1', name: 'Sarah Chen' },
      timestamp: new Date(Date.now() - 300000).toISOString(),
      read: false,
      link: '/deals/d1',
    },
    {
      id: 'n2',
      type: 'assignment',
      message: 'You were assigned to Enterprise SaaS Deal',
      from: { id: 'u2', name: 'Mike Johnson' },
      timestamp: new Date(Date.now() - 600000).toISOString(),
      read: false,
      link: '/deals/d1',
    },
    {
      id: 'n3',
      type: 'comment',
      message: 'New comment on your invoice',
      from: { id: 'u3', name: 'Emily Rodriguez' },
      timestamp: new Date(Date.now() - 900000).toISOString(),
      read: true,
      link: '/finance/invoices/i1',
    },
  ]);

  const [selectedFilter, setSelectedFilter] = useState<'all' | 'online' | 'active'>('all');

  useEffect(() => {
    // Simulate real-time updates
    const interval = setInterval(() => {
      // Update last activity times
      setActiveUsers((prev) =>
        prev.map((user) => ({
          ...user,
          lastActivity: user.status === 'online' ? new Date().toISOString() : user.lastActivity,
        }))
      );
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'bg-green-500';
      case 'away':
        return 'bg-yellow-500';
      case 'busy':
        return 'bg-red-500';
      case 'offline':
        return 'bg-gray-400';
      default:
        return 'bg-gray-400';
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'created':
        return <Zap className="w-4 h-4 text-green-500" />;
      case 'updated':
        return <Edit className="w-4 h-4 text-blue-500" />;
      case 'deleted':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      case 'commented':
        return <MessageSquare className="w-4 h-4 text-purple-500" />;
      case 'shared':
        return <Share2 className="w-4 h-4 text-orange-500" />;
      default:
        return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  const getEntityIcon = (type: string) => {
    switch (type) {
      case 'deal':
        return <Target className="w-4 h-4" />;
      case 'contact':
        return <Users className="w-4 h-4" />;
      case 'company':
        return <Building2 className="w-4 h-4" />;
      case 'invoice':
        return <DollarSign className="w-4 h-4" />;
      case 'document':
        return <FileText className="w-4 h-4" />;
      default:
        return <FileText className="w-4 h-4" />;
    }
  };

  const formatTime = (timestamp: string) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffMs = now.getTime() - time.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return time.toLocaleDateString();
  };

  const filteredUsers = activeUsers.filter((user) => {
    if (selectedFilter === 'online') return user.status === 'online';
    if (selectedFilter === 'active') return user.status === 'online' || user.status === 'busy';
    return true;
  });

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAsRead = (notificationId: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === notificationId ? { ...n, read: true } : n))
    );
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
              <Users className="w-6 h-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Team Collaboration</h1>
              <p className="text-muted-foreground mt-1">
                Real-time presence, activity tracking, and team updates
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm">
              <Video className="w-4 h-4 mr-2" />
              Start Meeting
            </Button>
            <Button variant="outline" size="sm">
              <UserPlus className="w-4 h-4 mr-2" />
              Invite Team
            </Button>
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 dark:bg-green-900/20 rounded-lg">
                <Circle className="w-5 h-5 text-green-600 dark:text-green-400 fill-green-600 dark:fill-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {activeUsers.filter((u) => u.status === 'online').length}
                </p>
                <p className="text-sm text-muted-foreground">Online Now</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                <Activity className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{activities.length}</p>
                <p className="text-sm text-muted-foreground">Recent Activities</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
                <Bell className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{unreadCount}</p>
                <p className="text-sm text-muted-foreground">Unread Notifications</p>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                <Eye className="w-5 h-5 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {activeUsers.filter((u) => u.activeDocument).length}
                </p>
                <p className="text-sm text-muted-foreground">Active Documents</p>
              </div>
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Active Users */}
          <div className="lg:col-span-2">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Users className="w-5 h-5 text-primary" />
                  Team Presence
                </h3>
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-muted-foreground" />
                  <select
                    value={selectedFilter}
                    onChange={(e) => setSelectedFilter(e.target.value as any)}
                    className="h-8 px-2 rounded-md border border-input bg-background text-sm"
                  >
                    <option value="all">All ({activeUsers.length})</option>
                    <option value="online">
                      Online ({activeUsers.filter((u) => u.status === 'online').length})
                    </option>
                    <option value="active">
                      Active (
                      {
                        activeUsers.filter((u) => u.status === 'online' || u.status === 'busy')
                          .length
                      }
                      )
                    </option>
                  </select>
                </div>
              </div>

              <div className="space-y-3">
                {filteredUsers.map((user) => (
                  <div
                    key={user.id}
                    className="p-4 border border-border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <div className="relative">
                        <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                          <span className="text-sm font-semibold text-primary">
                            {user.name.charAt(0)}
                          </span>
                        </div>
                        <div
                          className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-background ${getStatusColor(user.status)}`}
                        />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-semibold">{user.name}</h4>
                          <span
                            className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${
                              user.status === 'online'
                                ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
                                : user.status === 'away'
                                ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400'
                                : user.status === 'busy'
                                ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
                                : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                            }`}
                          >
                            {user.status}
                          </span>
                        </div>

                        {user.currentPage && (
                          <p className="text-sm text-muted-foreground mb-1 flex items-center gap-1">
                            <Eye className="w-3 h-3" />
                            Viewing: {user.currentPage}
                          </p>
                        )}

                        {user.activeDocument && (
                          <div className="flex items-center gap-2 mt-2 p-2 bg-muted/50 rounded">
                            {getEntityIcon(user.activeDocument.type)}
                            <span className="text-xs font-medium">
                              Editing: {user.activeDocument.name}
                            </span>
                          </div>
                        )}

                        <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Last activity: {formatTime(user.lastActivity)}
                        </p>
                      </div>

                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="sm">
                          <MessageSquare className="w-4 h-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Video className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Notifications */}
          <div>
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Bell className="w-5 h-5 text-primary" />
                  Notifications
                  {unreadCount > 0 && (
                    <span className="bg-red-500 text-white text-xs rounded-full px-2 py-0.5">
                      {unreadCount}
                    </span>
                  )}
                </h3>
                <Button variant="ghost" size="sm">
                  <Settings className="w-4 h-4" />
                </Button>
              </div>

              <div className="space-y-2">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                      !notification.read
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:bg-muted/50'
                    }`}
                    onClick={() => markAsRead(notification.id)}
                  >
                    <div className="flex items-start gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium mb-1">{notification.message}</p>
                        <p className="text-xs text-muted-foreground">
                          {formatTime(notification.timestamp)}
                        </p>
                      </div>
                      {!notification.read && (
                        <div className="w-2 h-2 rounded-full bg-primary mt-1" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        {/* Activity Feed */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Recent Activity
          </h3>
          <div className="space-y-3">
            {activities.map((activity) => (
              <div key={activity.id} className="flex items-start gap-3 p-3 hover:bg-muted/50 rounded-lg transition-colors">
                <div className="p-2 bg-muted rounded-lg">{getActivityIcon(activity.type)}</div>
                <div className="flex-1">
                  <p className="text-sm">
                    <span className="font-semibold">{activity.user.name}</span>
                    <span className="text-muted-foreground mx-1">{activity.type}</span>
                    <span className="font-medium">{activity.entity.name}</span>
                  </p>
                  {activity.changes && activity.changes.length > 0 && (
                    <p className="text-xs text-muted-foreground mt-1">
                      Updated: {activity.changes.join(', ')}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatTime(activity.timestamp)}
                  </p>
                </div>
                <div className="p-1.5 bg-muted rounded">
                  {getEntityIcon(activity.entity.type)}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </MainLayout>
  );
}
