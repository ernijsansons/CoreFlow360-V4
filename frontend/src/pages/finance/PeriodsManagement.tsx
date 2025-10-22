import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { financeService } from '@/lib/api/services'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { toast } from '@/components/ui/toast'
import {
  Loader2,
  Lock,
  Unlock,
  AlertTriangle,
  Calendar,
} from 'lucide-react'

interface Period {
  id: string
  name: string
  status: 'open' | 'closed' | 'locked'
  startDate: string
  endDate: string
  closedAt?: string
}

interface CurrentPeriodData {
  id: string
  name: string
  status: string
  startDate: string
  endDate: string
}

export function PeriodsManagement() {
  const queryClient = useQueryClient()

  const { data: periods, isLoading } = useQuery({
    queryKey: ['finance-periods'],
    queryFn: () => financeService.getPeriods(),
    staleTime: 1000 * 60 * 5, // 5 minutes
  })

  const { data: currentPeriod } = useQuery({
    queryKey: ['finance-current-period'],
    queryFn: () => financeService.getCurrentPeriod(),
    staleTime: 1000 * 60 * 5,
  })

  const closePeriod = useMutation({
    mutationFn: (id: string) => financeService.closePeriod(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finance-periods'] })
      queryClient.invalidateQueries({ queryKey: ['finance-current-period'] })
      toast({
        title: 'Period closed',
        description: 'The accounting period has been successfully closed',
      })
    },
  })

  const reopenPeriod = useMutation({
    mutationFn: (id: string) => financeService.reopenPeriod(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finance-periods'] })
      queryClient.invalidateQueries({ queryKey: ['finance-current-period'] })
      toast({
        title: 'Period reopened',
        description: 'The accounting period has been reopened',
      })
    },
  })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'open':
        return <Badge className="bg-green-500">Open</Badge>
      case 'closed':
        return <Badge variant="secondary">Closed</Badge>
      case 'locked':
        return <Badge variant="destructive">Locked</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return <Unlock className="h-5 w-5 text-green-500" />
      case 'closed':
        return <Lock className="h-5 w-5 text-gray-500" />
      case 'locked':
        return <Lock className="h-5 w-5 text-red-500" />
      default:
        return <Calendar className="h-5 w-5 text-gray-500" />
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Accounting Periods
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Manage fiscal periods and period closing
        </p>
      </div>

      {/* Current Period */}
      {currentPeriod?.data && (
        <Card className="p-6 border-2 border-brand-primary">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-brand-primary/10 rounded-lg">
                <Calendar className="h-6 w-6 text-brand-primary" />
              </div>
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Current Period</p>
                <p className="text-2xl font-bold">
                  {(currentPeriod.data as CurrentPeriodData).name || 'Unknown Period'}
                </p>
                <p className="text-sm text-gray-500">
                  {new Date((currentPeriod.data as CurrentPeriodData).startDate).toLocaleDateString()} -{' '}
                  {new Date((currentPeriod.data as CurrentPeriodData).endDate).toLocaleDateString()}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              {getStatusIcon((currentPeriod.data as CurrentPeriodData).status)}
              {getStatusBadge((currentPeriod.data as CurrentPeriodData).status)}
            </div>
          </div>
        </Card>
      )}

      {/* Periods List */}
      <Card className="p-6">
        <h2 className="text-2xl font-bold mb-6">All Periods</h2>

        {periods?.data && periods.data.length > 0 ? (
          <div className="space-y-3">
            {(periods.data as Period[]).map((period) => (
              <div
                key={period.id}
                className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
              >
                <div className="flex items-center space-x-4 flex-1">
                  {getStatusIcon(period.status)}
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <p className="font-medium">{period.name}</p>
                      {period.id === (currentPeriod?.data as CurrentPeriodData)?.id && (
                        <Badge variant="outline" className="text-xs">
                          Current
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-gray-500">
                      {new Date(period.startDate).toLocaleDateString()} -{' '}
                      {new Date(period.endDate).toLocaleDateString()}
                    </p>
                    {period.closedAt && (
                      <p className="text-xs text-gray-500 mt-1">
                        Closed: {new Date(period.closedAt).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  {getStatusBadge(period.status)}

                  {period.status === 'open' && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => closePeriod.mutate(period.id)}
                      disabled={closePeriod.isPending}
                    >
                      {closePeriod.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Lock className="h-4 w-4 mr-2" />
                      )}
                      Close Period
                    </Button>
                  )}

                  {period.status === 'closed' && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => reopenPeriod.mutate(period.id)}
                      disabled={reopenPeriod.isPending}
                    >
                      {reopenPeriod.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Unlock className="h-4 w-4 mr-2" />
                      )}
                      Reopen
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">No periods found</div>
        )}
      </Card>

      {/* Period Closing Warning */}
      <Card className="p-6 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
          <div>
            <p className="font-medium text-yellow-900 dark:text-yellow-300">
              Period Closing Policy
            </p>
            <ul className="text-sm text-yellow-700 dark:text-yellow-400 mt-2 space-y-1 list-disc list-inside">
              <li>Closing a period prevents new transactions from being posted to that period</li>
              <li>Closed periods can be reopened by authorized users</li>
              <li>All journal entries must be posted before closing</li>
              <li>Bank reconciliations should be completed before closing</li>
              <li>Review all financial reports before finalizing the period</li>
            </ul>
          </div>
        </div>
      </Card>
    </div>
  )
}
