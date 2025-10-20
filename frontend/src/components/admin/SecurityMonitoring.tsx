/**
 * Security Monitoring Component
 * Real-time security analytics and threat monitoring
 */

import { useQuery } from '@tanstack/react-query';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8790';

interface SecurityMetrics {
  failedLoginAttempts: number;
  revokedTokens: number;
  mfaAdoptionRate: number;
  sessionsByRole: Array<{ role: string; session_count: number }>;
}

interface SecurityEvent {
  action: string;
  status_code: number;
  ip_address: string;
  created_at: string;
}

export default function SecurityMonitoring() {
  const userId = localStorage.getItem('userId');
  const token = localStorage.getItem('token');

  // Fetch security analytics
  const { data: securityData, isLoading } = useQuery({
    queryKey: ['admin', 'security'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/admin/analytics/security`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-User-ID': userId || ''
        }
      });
      if (!response.ok) throw new Error('Failed to fetch security analytics');
      return response.json();
    },
    refetchInterval: 10000 // Refresh every 10 seconds
  });

  const security: SecurityMetrics | undefined = securityData?.data?.security;
  const events: SecurityEvent[] = securityData?.data?.recentEvents || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Security Monitoring
        </h2>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Real-time security analytics and threat detection
        </p>
      </div>

      {/* Security Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <SecurityMetricCard
          title="Failed Logins"
          value={security?.failedLoginAttempts || 0}
          subtitle="Last 24 hours"
          alert={security && security.failedLoginAttempts > 10}
          loading={isLoading}
        />
        <SecurityMetricCard
          title="Revoked Tokens"
          value={security?.revokedTokens || 0}
          subtitle="Last 24 hours"
          loading={isLoading}
        />
        <SecurityMetricCard
          title="MFA Adoption"
          value={`${security?.mfaAdoptionRate?.toFixed(1) || 0}%`}
          subtitle="All active users"
          alert={security && security.mfaAdoptionRate < 50}
          loading={isLoading}
        />
        <SecurityMetricCard
          title="Active Sessions"
          value={security?.sessionsByRole?.reduce((sum, r) => sum + r.session_count, 0) || 0}
          subtitle="Across all roles"
          loading={isLoading}
        />
      </div>

      {/* Sessions by Role */}
      {security?.sessionsByRole && security.sessionsByRole.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Sessions by Role
          </h3>
          <div className="space-y-3">
            {security.sessionsByRole.map((roleSession) => (
              <div
                key={roleSession.role}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded"
              >
                <div className="flex items-center space-x-3">
                  <div className="h-10 w-10 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                    <span className="text-blue-600 dark:text-blue-300 font-medium">
                      {roleSession.role[0].toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <div className="font-medium text-gray-900 dark:text-white capitalize">
                      {roleSession.role.replace('_', ' ')}
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                      {roleSession.session_count} active {roleSession.session_count === 1 ? 'session' : 'sessions'}
                    </div>
                  </div>
                </div>
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {roleSession.session_count}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Security Events */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Recent Security Events
          </h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Last 50 security-related events
          </p>
        </div>

        {isLoading ? (
          <div className="p-8 text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-blue-600 border-r-transparent"></div>
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">Loading events...</p>
          </div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-500 dark:text-gray-400">No recent security events</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Action
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    IP Address
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {events.map((event, idx) => (
                  <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {event.action}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                        event.status_code >= 400
                          ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
                          : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                      }`}>
                        {event.status_code}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {event.ip_address || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {new Date(event.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Security Recommendations */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
        <h3 className="text-lg font-medium text-blue-900 dark:text-blue-100 mb-3">
          🛡️ Security Recommendations
        </h3>
        <ul className="space-y-2 text-sm text-blue-800 dark:text-blue-200">
          {security && security.mfaAdoptionRate < 50 && (
            <li>• MFA adoption is below 50%. Consider enforcing MFA for all users.</li>
          )}
          {security && security.failedLoginAttempts > 10 && (
            <li>• High number of failed login attempts detected. Review for potential brute force attacks.</li>
          )}
          <li>• Regularly review active sessions and revoke suspicious ones.</li>
          <li>• Monitor IP addresses for patterns of suspicious activity.</li>
        </ul>
      </div>
    </div>
  );
}

// Security Metric Card Component
function SecurityMetricCard({ title, value, subtitle, alert, loading }: {
  title: string;
  value: number | string;
  subtitle: string;
  alert?: boolean;
  loading?: boolean;
}) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow p-6 ${alert ? 'ring-2 ring-red-500' : ''}`}>
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
          {title}
        </div>
        {alert && (
          <span className="text-red-500 text-xs font-medium px-2 py-1 bg-red-100 dark:bg-red-900 rounded">
            ALERT
          </span>
        )}
      </div>
      {loading ? (
        <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
      ) : (
        <>
          <div className={`text-3xl font-bold ${alert ? 'text-red-600' : 'text-gray-900 dark:text-white'}`}>
            {value}
          </div>
          <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {subtitle}
          </div>
        </>
      )}
    </div>
  );
}
