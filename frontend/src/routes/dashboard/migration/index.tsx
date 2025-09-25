import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { MainLayout } from '@/layouts/main-layout'
import { ImportWizard } from '@/components/dashboard/ImportWizard'
import { ExportPanel } from '@/components/dashboard/ExportPanel'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Upload,
  Download,
  Database,
  FileText,
  CheckCircle2,
  AlertCircle,
  Clock,
  RefreshCw,
  Play,
  Pause,
  X,
  ArrowRight,
  History,
  Settings,
  Info
} from 'lucide-react'
import { useUIStore } from '@/stores'

export const Route = createFileRoute('/dashboard/migration/')({
  component: MigrationDashboard,
  beforeLoad: () => {
    useUIStore.getState().setBreadcrumbs([
      { label: 'Dashboard', href: '/dashboard' },
      { label: 'Migration Tools' }
    ])
  },
})

function MigrationDashboard() {
  const [activeTab, setActiveTab] = React.useState('import')
  const [isImporting, setIsImporting] = React.useState(false)
  const [isExporting, setIsExporting] = React.useState(false)

  const migrationJobs = [
    {
      id: '1',
      name: 'Customer Data Import',
      type: 'import',
      status: 'completed',
      progress: 100,
      records: 12847,
      duration: '2m 34s',
      date: '2024-02-01 10:30:00',
      source: 'CSV File'
    },
    {
      id: '2',
      name: 'Product Catalog Export',
      type: 'export',
      status: 'in_progress',
      progress: 65,
      records: 3421,
      duration: '45s',
      date: '2024-02-01 14:15:00',
      source: 'Database'
    },
    {
      id: '3',
      name: 'Order History Migration',
      type: 'import',
      status: 'failed',
      progress: 32,
      records: 0,
      duration: '1m 12s',
      date: '2024-01-31 09:45:00',
      source: 'API'
    },
    {
      id: '4',
      name: 'User Analytics Export',
      type: 'export',
      status: 'queued',
      progress: 0,
      records: 0,
      duration: '-',
      date: '2024-02-01 15:00:00',
      source: 'Database'
    }
  ]

  const dataSources = [
    { name: 'MySQL Database', status: 'connected', records: 248592, lastSync: '2 hours ago' },
    { name: 'PostgreSQL', status: 'connected', records: 145231, lastSync: '1 hour ago' },
    { name: 'MongoDB', status: 'disconnected', records: 0, lastSync: 'Never' },
    { name: 'Salesforce CRM', status: 'connected', records: 89234, lastSync: '3 hours ago' },
    { name: 'Google Sheets', status: 'connected', records: 12847, lastSync: '30 minutes ago' }
  ]

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge variant="success">Completed</Badge>
      case 'in_progress':
        return <Badge variant="default">In Progress</Badge>
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>
      case 'queued':
        return <Badge variant="secondary">Queued</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'in_progress':
        return <RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />
      case 'failed':
        return <X className="h-4 w-4 text-red-500" />
      case 'queued':
        return <Clock className="h-4 w-4 text-gray-500" />
      default:
        return null
    }
  }

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Migration Tools
            </h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Import and export data between systems and platforms
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Button variant="outline">
              <History className="h-4 w-4 mr-2" />
              Migration History
            </Button>
            <Button variant="outline">
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
          </div>
        </div>

        {/* Alert */}
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Migration Best Practices</AlertTitle>
          <AlertDescription>
            Always backup your data before performing migrations. Test imports with small datasets first.
            For large migrations, schedule during off-peak hours.
          </AlertDescription>
        </Alert>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Total Migrations</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">147</p>
              <p className="text-xs text-gray-500">Last 30 days</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Records Processed</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">1.2M</p>
              <p className="text-xs text-gray-500">Total records</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Success Rate</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold text-green-600">94.8%</p>
              <p className="text-xs text-gray-500">Average</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Active Jobs</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">2</p>
              <p className="text-xs text-gray-500">Running now</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList>
            <TabsTrigger value="import">Import Data</TabsTrigger>
            <TabsTrigger value="export">Export Data</TabsTrigger>
            <TabsTrigger value="jobs">Migration Jobs</TabsTrigger>
            <TabsTrigger value="sources">Data Sources</TabsTrigger>
          </TabsList>

          <TabsContent value="import" className="space-y-6">
            <ImportWizard />
          </TabsContent>

          <TabsContent value="export" className="space-y-6">
            <ExportPanel />
          </TabsContent>

          <TabsContent value="jobs" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle>Migration Jobs</CardTitle>
                    <CardDescription>Monitor and manage data migration tasks</CardDescription>
                  </div>
                  <Button size="sm">
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {migrationJobs.map((job) => (
                    <div key={job.id} className="p-4 border rounded-lg space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          {getStatusIcon(job.status)}
                          <div>
                            <p className="font-medium">{job.name}</p>
                            <div className="flex items-center space-x-4 text-xs text-gray-500">
                              <span>{job.type === 'import' ? 'Import' : 'Export'}</span>
                              <span>{job.source}</span>
                              <span>{job.date}</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {getStatusBadge(job.status)}
                          {job.status === 'in_progress' && (
                            <Button variant="ghost" size="sm">
                              <Pause className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                      
                      {job.status === 'in_progress' && (
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span>Progress</span>
                            <span>{job.progress}%</span>
                          </div>
                          <Progress value={job.progress} />
                          <div className="flex justify-between text-xs text-gray-500">
                            <span>{job.records.toLocaleString()} records processed</span>
                            <span>Duration: {job.duration}</span>
                          </div>
                        </div>
                      )}

                      {job.status === 'completed' && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-500">
                            {job.records.toLocaleString()} records in {job.duration}
                          </span>
                          <Button variant="outline" size="sm">
                            View Details
                          </Button>
                        </div>
                      )}

                      {job.status === 'failed' && (
                        <Alert variant="destructive" className="mt-2">
                          <AlertCircle className="h-4 w-4" />
                          <AlertDescription>
                            Migration failed at {job.progress}%. Check error logs for details.
                          </AlertDescription>
                        </Alert>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="sources" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle>Data Sources</CardTitle>
                    <CardDescription>Connected databases and external systems</CardDescription>
                  </div>
                  <Button>
                    <Database className="h-4 w-4 mr-2" />
                    Add Source
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {dataSources.map((source, index) => (
                    <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center space-x-4">
                        <Database className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="font-medium">{source.name}</p>
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>{source.records.toLocaleString()} records</span>
                            <span>Last sync: {source.lastSync}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge 
                          variant={source.status === 'connected' ? 'success' : 'secondary'}
                        >
                          {source.status}
                        </Badge>
                        <Button variant="outline" size="sm">Configure</Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-2 gap-4">
                <Button variant="outline" className="justify-start">
                  <Database className="h-4 w-4 mr-2" />
                  Test All Connections
                </Button>
                <Button variant="outline" className="justify-start">
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Sync All Sources
                </Button>
                <Button variant="outline" className="justify-start">
                  <Download className="h-4 w-4 mr-2" />
                  Backup Configurations
                </Button>
                <Button variant="outline" className="justify-start">
                  <FileText className="h-4 w-4 mr-2" />
                  View Logs
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  )
}