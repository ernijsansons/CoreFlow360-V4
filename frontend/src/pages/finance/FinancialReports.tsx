import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { financeService } from '@/lib/api/services'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Input } from '@/components/ui/input-refactored'
import {
  Loader2,
  FileText,
  Download,
  Calendar,
  TrendingUp,
  DollarSign,
} from 'lucide-react'

type ReportType = 'trial-balance' | 'income-statement' | 'balance-sheet' | 'cash-flow'

interface IncomeStatementData {
  totalRevenue?: number
  totalExpenses?: number
  netIncome?: number
}

interface BalanceSheetData {
  totalAssets?: number
  totalLiabilities?: number
  totalEquity?: number
}

export function FinancialReports() {
  const [selectedReport, setSelectedReport] = useState<ReportType>('income-statement')
  const [startDate, setStartDate] = useState(
    new Date(new Date().getFullYear(), 0, 1).toISOString().split('T')[0]
  )
  const [endDate, setEndDate] = useState(new Date().toISOString().split('T')[0])
  const [format, setFormat] = useState<'json' | 'pdf' | 'excel'>('json')

  const { data: report, isLoading, refetch } = useQuery({
    queryKey: ['financial-report', selectedReport, startDate, endDate, format],
    queryFn: async () => {
      const params = { startDate, endDate, format }

      switch (selectedReport) {
        case 'trial-balance':
          return financeService.getTrialBalance(params)
        case 'income-statement':
          return financeService.getIncomeStatement(params)
        case 'balance-sheet':
          return financeService.getBalanceSheet(params)
        case 'cash-flow':
          return financeService.getCashFlow(params)
        default:
          return financeService.getIncomeStatement(params)
      }
    },
    enabled: false, // Manual fetch with "Generate Report" button
  })

  const reports: Array<{
    value: ReportType
    label: string
    description: string
    icon: typeof FileText
  }> = [
    {
      value: 'income-statement',
      label: 'Income Statement',
      description: 'Profit & Loss report',
      icon: TrendingUp,
    },
    {
      value: 'balance-sheet',
      label: 'Balance Sheet',
      description: 'Assets, Liabilities & Equity',
      icon: DollarSign,
    },
    {
      value: 'cash-flow',
      label: 'Cash Flow Statement',
      description: 'Operating, Investing & Financing activities',
      icon: DollarSign,
    },
    {
      value: 'trial-balance',
      label: 'Trial Balance',
      description: 'Debit & Credit balances',
      icon: FileText,
    },
  ]

  const handleGenerateReport = () => {
    refetch()
  }

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(amount)
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Financial Reports
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Generate comprehensive financial statements and reports
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report Selection */}
        <Card className="p-6">
          <h2 className="text-xl font-bold mb-4">Report Type</h2>

          <div className="space-y-3 mb-6">
            {reports.map((report) => {
              const Icon = report.icon
              return (
                <button
                  key={report.value}
                  onClick={() => setSelectedReport(report.value)}
                  className={`w-full p-4 border-2 rounded-lg transition-all text-left ${
                    selectedReport === report.value
                      ? 'border-brand-primary bg-brand-primary/5'
                      : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    <Icon className="h-5 w-5 mt-1" />
                    <div>
                      <p className="font-medium">{report.label}</p>
                      <p className="text-sm text-gray-500">{report.description}</p>
                    </div>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Date Range */}
          <div className="space-y-4 pt-4 border-t">
            <h3 className="font-semibold flex items-center space-x-2">
              <Calendar className="h-4 w-4" />
              <span>Date Range</span>
            </h3>

            <div>
              <label className="block text-sm font-medium mb-2">Start Date</label>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">End Date</label>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>

            {/* Format Selection */}
            <div>
              <label className="block text-sm font-medium mb-2">Export Format</label>
              <div className="flex space-x-2">
                {(['json', 'pdf', 'excel'] as const).map((fmt) => (
                  <Button
                    key={fmt}
                    size="sm"
                    variant={format === fmt ? 'default' : 'outline'}
                    onClick={() => setFormat(fmt)}
                    className="flex-1"
                  >
                    {fmt.toUpperCase()}
                  </Button>
                ))}
              </div>
            </div>

            <Button
              className="w-full"
              onClick={handleGenerateReport}
              disabled={isLoading}
            >
              {isLoading ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <FileText className="h-4 w-4 mr-2" />
              )}
              Generate Report
            </Button>
          </div>
        </Card>

        {/* Report Preview */}
        <Card className="lg:col-span-2 p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-bold">
                {reports.find((r) => r.value === selectedReport)?.label}
              </h2>
              <p className="text-sm text-gray-500">
                {new Date(startDate).toLocaleDateString()} -{' '}
                {new Date(endDate).toLocaleDateString()}
              </p>
            </div>

            {report?.data && (
              <Button size="sm" variant="outline">
                <Download className="h-4 w-4 mr-2" />
                Download
              </Button>
            )}
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-96">
              <Loader2 className="h-8 w-8 animate-spin text-brand-primary" />
            </div>
          ) : report?.data ? (
            <div className="space-y-6">
              {/* Report Summary */}
              {selectedReport === 'income-statement' && (
                <div className="grid grid-cols-3 gap-4">
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Revenue</p>
                    <p className="text-2xl font-bold mt-1 text-green-600">
                      {formatCurrency((report.data as IncomeStatementData).totalRevenue || 0)}
                    </p>
                  </Card>
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Expenses</p>
                    <p className="text-2xl font-bold mt-1 text-red-600">
                      {formatCurrency((report.data as IncomeStatementData).totalExpenses || 0)}
                    </p>
                  </Card>
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Net Income</p>
                    <p
                      className={`text-2xl font-bold mt-1 ${
                        ((report.data as IncomeStatementData).netIncome || 0) >= 0
                          ? 'text-green-600'
                          : 'text-red-600'
                      }`}
                    >
                      {formatCurrency((report.data as IncomeStatementData).netIncome || 0)}
                    </p>
                  </Card>
                </div>
              )}

              {selectedReport === 'balance-sheet' && (
                <div className="grid grid-cols-3 gap-4">
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Assets</p>
                    <p className="text-2xl font-bold mt-1">
                      {formatCurrency((report.data as BalanceSheetData).totalAssets || 0)}
                    </p>
                  </Card>
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Liabilities</p>
                    <p className="text-2xl font-bold mt-1">
                      {formatCurrency((report.data as BalanceSheetData).totalLiabilities || 0)}
                    </p>
                  </Card>
                  <Card className="p-4">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Equity</p>
                    <p className="text-2xl font-bold mt-1 text-brand-primary">
                      {formatCurrency((report.data as BalanceSheetData).totalEquity || 0)}
                    </p>
                  </Card>
                </div>
              )}

              {/* Detailed Data */}
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6">
                <pre className="text-sm overflow-auto max-h-96">
                  {JSON.stringify(report.data, null, 2)}
                </pre>
              </div>

              <div className="flex items-center space-x-2 text-sm text-gray-500">
                <Badge variant="outline">Generated: {new Date().toLocaleString()}</Badge>
                <Badge variant="outline">Format: {format.toUpperCase()}</Badge>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-96 text-gray-500">
              <FileText className="h-16 w-16 mb-4" />
              <p className="text-lg font-medium mb-2">No Report Generated</p>
              <p className="text-sm">
                Select a report type, date range, and click "Generate Report"
              </p>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
