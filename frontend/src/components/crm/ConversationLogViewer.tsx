/**
 * Conversation Log Viewer
 * View all captured interactions (emails, calls, SMS, chat, meetings)
 * with filtering, search, and detailed view
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Mail, Phone, MessageSquare, Video, Search, Filter, Calendar,
  User, Building2, Tag, ChevronDown, ChevronUp, ExternalLink,
  Clock, TrendingUp, TrendingDown, Minus
} from 'lucide-react';
import apiClient from '@/lib/api/client';

interface ConversationLog {
  id: string;
  source_type: 'email' | 'call' | 'sms' | 'chat' | 'meeting';
  external_id: string;
  subject: string;
  body: string;
  transcript?: string;
  participants: Array<{
    email?: string;
    name: string;
    role: string;
  }>;
  direction: 'inbound' | 'outbound';
  occurred_at: string;
  metadata: Record<string, any>;
  ai_extracted_data?: {
    sentiment?: 'positive' | 'neutral' | 'negative';
    intent?: string;
    entities?: string[];
    action_items?: string[];
    buying_signals?: string[];
    objections?: string[];
  };
  linked_contacts: string[];
  linked_companies: string[];
  linked_deals: string[];
  created_at: string;
}

const SOURCE_ICONS = {
  email: Mail,
  call: Phone,
  sms: MessageSquare,
  chat: MessageSquare,
  meeting: Video
};

const SOURCE_COLORS = {
  email: 'bg-blue-100 text-blue-800 border-blue-200',
  call: 'bg-purple-100 text-purple-800 border-purple-200',
  sms: 'bg-green-100 text-green-800 border-green-200',
  chat: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  meeting: 'bg-pink-100 text-pink-800 border-pink-200'
};

const SENTIMENT_ICONS = {
  positive: TrendingUp,
  neutral: Minus,
  negative: TrendingDown
};

const SENTIMENT_COLORS = {
  positive: 'text-green-600',
  neutral: 'text-gray-600',
  negative: 'text-red-600'
};

export function ConversationLogViewer() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const limit = 20;

  // Fetch conversation logs
  const { data, isLoading } = useQuery({
    queryKey: ['crm', 'conversation-logs', searchQuery, selectedType, page],
    queryFn: async () => {
      const params = new URLSearchParams({
        limit: limit.toString(),
        offset: ((page - 1) * limit).toString()
      });

      if (searchQuery) {
        params.append('search', searchQuery);
      }
      if (selectedType !== 'all') {
        params.append('source_type', selectedType);
      }

      const response = await apiClient.get(`/api/v1/crm/conversation-logs?${params}`);
      return response.data.data as {
        logs: ConversationLog[];
        total: number;
        has_more: boolean;
      };
    }
  });

  const logs = data?.logs || [];
  const total = data?.total || 0;

  const typeFilters = [
    { value: 'all', label: 'All', icon: Filter },
    { value: 'email', label: 'Email', icon: Mail },
    { value: 'call', label: 'Calls', icon: Phone },
    { value: 'sms', label: 'SMS', icon: MessageSquare },
    { value: 'chat', label: 'Chat', icon: MessageSquare },
    { value: 'meeting', label: 'Meetings', icon: Video }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Conversation Log
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          All captured customer interactions across channels
        </p>
      </div>

      {/* Filters & Search */}
      <Card className="p-4">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <Input
              type="text"
              placeholder="Search conversations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          {/* Type Filters */}
          <div className="flex gap-2 overflow-x-auto">
            {typeFilters.map((filter) => {
              const Icon = filter.icon;
              return (
                <Button
                  key={filter.value}
                  variant={selectedType === filter.value ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setSelectedType(filter.value)}
                  className="whitespace-nowrap"
                >
                  <Icon className="w-4 h-4 mr-2" />
                  {filter.label}
                </Button>
              );
            })}
          </div>
        </div>

        {/* Results Count */}
        <div className="mt-3 text-sm text-gray-600 dark:text-gray-400">
          Showing {logs.length} of {total} conversations
        </div>
      </Card>

      {/* Conversation List */}
      {isLoading ? (
        <Card className="p-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-primary"></div>
          </div>
        </Card>
      ) : logs.length === 0 ? (
        <Card className="p-12 text-center">
          <MessageSquare className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            No Conversations Found
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            {searchQuery
              ? 'Try adjusting your search or filters'
              : 'Connect integrations to start capturing conversations'}
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {logs.map((log) => (
            <ConversationCard
              key={log.id}
              log={log}
              isExpanded={expandedId === log.id}
              onToggle={() => setExpandedId(expandedId === log.id ? null : log.id)}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > limit && (
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <Button
              variant="outline"
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
            >
              Previous
            </Button>

            <span className="text-sm text-gray-600 dark:text-gray-400">
              Page {page} of {Math.ceil(total / limit)}
            </span>

            <Button
              variant="outline"
              onClick={() => setPage(page + 1)}
              disabled={!data?.has_more}
            >
              Next
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}

function ConversationCard({
  log,
  isExpanded,
  onToggle
}: {
  log: ConversationLog;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const Icon = SOURCE_ICONS[log.source_type];
  const colorClass = SOURCE_COLORS[log.source_type];

  const sentiment = log.ai_extracted_data?.sentiment;
  const SentimentIcon = sentiment ? SENTIMENT_ICONS[sentiment] : null;
  const sentimentColor = sentiment ? SENTIMENT_COLORS[sentiment] : '';

  return (
    <Card className="overflow-hidden hover:shadow-md transition-shadow">
      {/* Header */}
      <div
        className="p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50"
        onClick={onToggle}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3 flex-1">
            <div className={`p-2 rounded-lg ${colorClass}`}>
              <Icon className="w-5 h-5" />
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-semibold text-gray-900 dark:text-white truncate">
                  {log.subject}
                </h3>
                {sentiment && SentimentIcon && (
                  <SentimentIcon className={`w-4 h-4 ${sentimentColor}`} />
                )}
              </div>

              <div className="flex items-center gap-3 text-sm text-gray-600 dark:text-gray-400">
                <div className="flex items-center gap-1">
                  <User className="w-4 h-4" />
                  {log.participants[0]?.name || 'Unknown'}
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  {new Date(log.occurred_at).toLocaleString()}
                </div>
                {log.direction === 'inbound' && (
                  <Badge variant="outline" className="text-xs">Inbound</Badge>
                )}
                {log.direction === 'outbound' && (
                  <Badge variant="outline" className="text-xs">Outbound</Badge>
                )}
              </div>

              {!isExpanded && (
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-2 line-clamp-2">
                  {log.body || log.transcript}
                </p>
              )}
            </div>
          </div>

          <Button variant="ghost" size="sm">
            {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </Button>
        </div>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-800/50">
          {/* Body/Transcript */}
          <div className="mb-4">
            <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
              {log.transcript ? 'Transcript' : 'Content'}
            </h4>
            <div className="bg-white dark:bg-gray-900 p-3 rounded-lg text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
              {log.transcript || log.body}
            </div>
          </div>

          {/* Participants */}
          {log.participants.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                Participants
              </h4>
              <div className="flex flex-wrap gap-2">
                {log.participants.map((participant, index) => (
                  <Badge key={index} variant="outline">
                    {participant.name} ({participant.role})
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* AI Extracted Data */}
          {log.ai_extracted_data && (
            <div className="mb-4">
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                AI Insights
              </h4>
              <div className="space-y-2">
                {log.ai_extracted_data.intent && (
                  <div>
                    <span className="text-xs text-gray-500">Intent:</span>
                    <Badge variant="outline" className="ml-2">
                      {log.ai_extracted_data.intent}
                    </Badge>
                  </div>
                )}
                {log.ai_extracted_data.action_items && log.ai_extracted_data.action_items.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">Action Items:</span>
                    <ul className="ml-4 mt-1 text-sm text-gray-700 dark:text-gray-300 list-disc">
                      {log.ai_extracted_data.action_items.map((item, index) => (
                        <li key={index}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {log.ai_extracted_data.buying_signals && log.ai_extracted_data.buying_signals.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">Buying Signals:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {log.ai_extracted_data.buying_signals.map((signal, index) => (
                        <Badge key={index} className="bg-green-100 text-green-800 border-green-200">
                          {signal}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {log.ai_extracted_data.objections && log.ai_extracted_data.objections.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">Objections:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {log.ai_extracted_data.objections.map((objection, index) => (
                        <Badge key={index} className="bg-red-100 text-red-800 border-red-200">
                          {objection}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Linked Entities */}
          {(log.linked_contacts.length > 0 || log.linked_companies.length > 0 || log.linked_deals.length > 0) && (
            <div>
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                Linked Entities
              </h4>
              <div className="flex flex-wrap gap-2">
                {log.linked_contacts.map((id) => (
                  <Badge key={id} variant="outline" className="cursor-pointer hover:bg-gray-100">
                    <User className="w-3 h-3 mr-1" />
                    Contact
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </Badge>
                ))}
                {log.linked_companies.map((id) => (
                  <Badge key={id} variant="outline" className="cursor-pointer hover:bg-gray-100">
                    <Building2 className="w-3 h-3 mr-1" />
                    Company
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </Badge>
                ))}
                {log.linked_deals.map((id) => (
                  <Badge key={id} variant="outline" className="cursor-pointer hover:bg-gray-100">
                    <Tag className="w-3 h-3 mr-1" />
                    Deal
                    <ExternalLink className="w-3 h-3 ml-1" />
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export default ConversationLogViewer;
