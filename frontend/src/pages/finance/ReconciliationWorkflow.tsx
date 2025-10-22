import { useState } from 'react'
import {
  useReconciliationAccounts,
  useCreateReconciliation,
  useReconciliation,
  useUploadStatement,
  useAutoMatch,
  useCompleteReconciliation,
} from '@/hooks/api'
import { Card } from '@/components/ui/card-refactored'
import { Button } from '@/components/ui/button-refactored'
import { Badge } from '@/components/ui/badge-refactored'
import { Input } from '@/components/ui/input-refactored'
import {
  Loader2,
  Plus,
  Upload,
  CheckCircle2,
  Link as LinkIcon,
  FileText,
} from 'lucide-react'
// import { useDropzone } from 'react-dropzone' // TODO: Install package
import { useCallback } from 'react'

export function ReconciliationWorkflow() {
  const [selectedAccount, setSelectedAccount] = useState<string | null>(null)
  const [selectedReconciliation, setSelectedReconciliation] = useState<string | null>(null)
  const [statementDate, setStatementDate] = useState('')
  const [statementBalance, setStatementBalance] = useState('')

  const { data: accounts, isLoading: accountsLoading } = useReconciliationAccounts()
  const { data: reconciliation } = useReconciliation(selectedReconciliation || '')

  const createReconciliation = useCreateReconciliation()
  const uploadStatement = useUploadStatement()
  const autoMatch = useAutoMatch()
  const completeReconciliation = useCompleteReconciliation()

  const onDrop = useCallback(
    (acceptedFiles: File[]) => {
      const file = acceptedFiles[0]
      if (file && selectedReconciliation) {
        uploadStatement.mutate({
          reconciliation_id: selectedReconciliation,
          file,
        })
      }
    },
    [selectedReconciliation, uploadStatement]
  )

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'application/pdf': ['.pdf'],
      'application/vnd.ms-excel': ['.xls'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    },
    maxSize: 10 * 1024 * 1024, // 10MB
    multiple: false,
    disabled: !selectedReconciliation,
  })

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(amount)
  }

  const handleCreateReconciliation = () => {
    if (selectedAccount && statementDate && statementBalance) {
      createReconciliation.mutate(
        {
          account_id: selectedAccount,
          statement_date: statementDate,
          statement_balance: parseFloat(statementBalance),
        },
        {
          onSuccess: (data) => {
            setSelectedReconciliation(data.data.id)
            setStatementDate('')
            setStatementBalance('')
          },
        }
      )
    }
  }

  if (accountsLoading) {
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
          Bank Reconciliation
        </h1>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Match bank statements with ledger transactions
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Accounts List */}
        <Card className="p-6">
          <h2 className="text-xl font-bold mb-4">Bank Accounts</h2>

          <div className="space-y-3">
            {accounts?.data && accounts.data.length > 0 ? (
              accounts.data.map((account) => (
                <div
                  key={account.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all ${
                    selectedAccount === account.id
                      ? 'border-brand-primary bg-brand-primary/5'
                      : 'border-gray-200 dark:border-gray-700 hover:border-brand-primary/50'
                  }`}
                  onClick={() => setSelectedAccount(account.id)}
                >
                  <p className="font-medium mb-1">{account.name}</p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {account.account_number}
                  </p>
                  <p className="text-lg font-semibold mt-2">
                    {formatCurrency(account.balance)}
                  </p>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">No bank accounts found</div>
            )}
          </div>

          {/* Create Reconciliation Form */}
          {selectedAccount && (
            <div className="mt-6 pt-6 border-t space-y-3">
              <h3 className="font-semibold">New Reconciliation</h3>

              <div>
                <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Statement Date
                </label>
                <Input
                  type="date"
                  value={statementDate}
                  onChange={(e) => setStatementDate(e.target.value)}
                  className="mt-1"
                />
              </div>

              <div>
                <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Statement Balance
                </label>
                <Input
                  type="number"
                  step="0.01"
                  value={statementBalance}
                  onChange={(e) => setStatementBalance(e.target.value)}
                  placeholder="0.00"
                  className="mt-1"
                />
              </div>

              <Button
                size="sm"
                className="w-full"
                onClick={handleCreateReconciliation}
                disabled={
                  !statementDate || !statementBalance || createReconciliation.isPending
                }
              >
                {createReconciliation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                Start Reconciliation
              </Button>
            </div>
          )}
        </Card>

        {/* Reconciliation Workflow */}
        <Card className="lg:col-span-2 p-6">
          {selectedReconciliation && reconciliation?.data ? (
            <>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-2xl font-bold">Reconciliation</h2>
                  <p className="text-sm text-gray-500">
                    Statement Date: {new Date(reconciliation.data.statement_date).toLocaleDateString()}
                  </p>
                </div>
                <Badge
                  variant={
                    reconciliation.data.status === 'completed'
                      ? 'default'
                      : reconciliation.data.status === 'in_progress'
                      ? 'secondary'
                      : 'outline'
                  }
                >
                  {reconciliation.data.status}
                </Badge>
              </div>

              {/* Upload Statement */}
              {reconciliation.data.status === 'pending' && (
                <div className="mb-6">
                  <div
                    {...getRootProps()}
                    className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                      isDragActive
                        ? 'border-brand-primary bg-brand-primary/5'
                        : 'border-gray-300 dark:border-gray-700 hover:border-brand-primary'
                    }`}
                  >
                    <input {...getInputProps()} />

                    {uploadStatement.isPending ? (
                      <div className="flex flex-col items-center space-y-3">
                        <Loader2 className="h-12 w-12 animate-spin text-brand-primary" />
                        <p className="text-sm">Parsing bank statement...</p>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center space-y-3">
                        <Upload className="h-12 w-12 text-gray-400" />
                        <div>
                          <p className="font-medium">
                            {isDragActive ? 'Drop statement here' : 'Upload bank statement'}
                          </p>
                          <p className="text-sm text-gray-500 mt-1">
                            Supports CSV, Excel, PDF (max 10MB)
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <Card className="p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Statement Balance</p>
                  <p className="text-2xl font-bold mt-1">
                    {formatCurrency(reconciliation.data.statement_balance)}
                  </p>
                </Card>
                <Card className="p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Ledger Balance</p>
                  <p className="text-2xl font-bold mt-1">
                    {formatCurrency(reconciliation.data.ledger_balance)}
                  </p>
                </Card>
                <Card className="p-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Difference</p>
                  <p
                    className={`text-2xl font-bold mt-1 ${
                      Math.abs(reconciliation.data.difference) < 0.01
                        ? 'text-green-600'
                        : 'text-red-600'
                    }`}
                  >
                    {formatCurrency(Math.abs(reconciliation.data.difference))}
                  </p>
                </Card>
              </div>

              {/* Matching Progress */}
              {reconciliation.data.total_transactions > 0 && (
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Matching Progress</span>
                    <span className="text-sm text-gray-500">
                      {reconciliation.data.matched_transactions} of{' '}
                      {reconciliation.data.total_transactions} matched
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-brand-primary h-2 rounded-full transition-all"
                      style={{
                        width: `${
                          (reconciliation.data.matched_transactions /
                            reconciliation.data.total_transactions) *
                          100
                        }%`,
                      }}
                    />
                  </div>
                </div>
              )}

              {/* Actions */}
              {reconciliation.data.status === 'in_progress' && (
                <div className="flex space-x-3">
                  <Button
                    onClick={() => autoMatch.mutate(selectedReconciliation)}
                    disabled={autoMatch.isPending}
                  >
                    {autoMatch.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <LinkIcon className="h-4 w-4 mr-2" />
                    )}
                    Auto-Match Transactions
                  </Button>

                  {Math.abs(reconciliation.data.difference) < 0.01 && (
                    <Button
                      variant="default"
                      onClick={() => completeReconciliation.mutate(selectedReconciliation)}
                      disabled={completeReconciliation.isPending}
                    >
                      {completeReconciliation.isPending ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4 mr-2" />
                      )}
                      Complete Reconciliation
                    </Button>
                  )}
                </div>
              )}

              {reconciliation.data.status === 'completed' && (
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 flex items-start space-x-3">
                  <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5" />
                  <div>
                    <p className="font-medium text-green-900 dark:text-green-300">
                      Reconciliation Complete
                    </p>
                    <p className="text-sm text-green-700 dark:text-green-400 mt-1">
                      All transactions have been matched and the reconciliation is finalized
                    </p>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-96 text-gray-500">
              <FileText className="h-16 w-16 mb-4" />
              <p className="text-lg font-medium mb-2">No Reconciliation Selected</p>
              <p className="text-sm">
                Select an account and start a new reconciliation to begin
              </p>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
