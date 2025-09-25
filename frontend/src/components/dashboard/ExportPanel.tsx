import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Download,
  FileText,
  FileSpreadsheet,
  FileJson,
  Database,
  Calendar,
  Filter,
  CheckCircle2,
  AlertCircle,
  Clock,
  Send,
  Archive
} from 'lucide-react'

interface ExportPreset {
  id: string
  name: string
  description: string
  format: string
  filters: number
  lastUsed: string
  icon: any
}

export function ExportPanel() {
  const [exportFormat, setExportFormat] = React.useState('csv')
  const [selectedTables, setSelectedTables] = React.useState<string[]>(['customers'])
  const [isExporting, setIsExporting] = React.useState(false)
  const [exportProgress, setExportProgress] = React.useState(0)

  const exportPresets: ExportPreset[] = [
    {
      id: '1',
      name: 'Customer Report',
      description: 'All customer data with contact info',
      format: 'Excel',
      filters: 3,
      lastUsed: '2 days ago',
      icon: FileSpreadsheet
    },
    {
      id: '2',
      name: 'Financial Summary',
      description: 'Revenue and transaction data',
      format: 'CSV',
      filters: 5,
      lastUsed: '1 week ago',
      icon: FileText
    },
    {
      id: '3',
      name: 'Product Catalog',
      description: 'Complete product inventory',
      format: 'JSON',
      filters: 2,
      lastUsed: '3 days ago',
      icon: FileJson
    },
    {
      id: '4',
      name: 'Analytics Backup',
      description: 'Full analytics data export',
      format: 'SQL',
      filters: 0,
      lastUsed: '1 month ago',
      icon: Database
    }
  ]

  const availableTables = [
    { name: 'customers', records: 12847, size: '24.5 MB' },
    { name: 'orders', records: 48293, size: '156.3 MB' },
    { name: 'products', records: 3421, size: '12.8 MB' },
    { name: 'transactions', records: 89234, size: '342.1 MB' },
    { name: 'analytics', records: 248592, size: '1.2 GB' },
    { name: 'users', records: 1284, size: '4.2 MB' }
  ]

  const handleTableToggle = (tableName: string) => {
    if (selectedTables.includes(tableName)) {
      setSelectedTables(selectedTables.filter(t => t !== tableName))
    } else {
      setSelectedTables([...selectedTables, tableName])
    }
  }

  const startExport = () => {
    setIsExporting(true)
    setExportProgress(0)
    
    const interval = setInterval(() => {
      setExportProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsExporting(false)
          return 100
        }
        return prev + 20
      })
    }, 800)
  }

  const getTotalSize = () => {
    const selected = availableTables.filter(t => selectedTables.includes(t.name))
    const totalMB = selected.reduce((sum, table) => {
      const size = parseFloat(table.size)
      const multiplier = table.size.includes('GB') ? 1024 : 1
      return sum + (size * multiplier)
    }, 0)
    return totalMB > 1024 ? `${(totalMB / 1024).toFixed(1)} GB` : `${totalMB.toFixed(1)} MB`
  }

  const getTotalRecords = () => {
    return availableTables
      .filter(t => selectedTables.includes(t.name))
      .reduce((sum, table) => sum + table.records, 0)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Main Export Panel */}
      <div className="lg:col-span-2 space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Export Configuration</CardTitle>
            <CardDescription>Select data and format for export</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Format Selection */}
            <div className="space-y-3">
              <Label>Export Format</Label>
              <RadioGroup value={exportFormat} onValueChange={setExportFormat}>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { value: 'csv', label: 'CSV', icon: FileText },
                    { value: 'excel', label: 'Excel', icon: FileSpreadsheet },
                    { value: 'json', label: 'JSON', icon: FileJson },
                    { value: 'sql', label: 'SQL', icon: Database }
                  ].map((format) => {
                    const Icon = format.icon
                    return (
                      <label
                        key={format.value}
                        htmlFor={format.value}
                        className={`flex items-center space-x-2 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                          exportFormat === format.value ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                        }`}
                      >
                        <RadioGroupItem value={format.value} id={format.value} />
                        <Icon className="h-4 w-4" />
                        <span className="text-sm">{format.label}</span>
                      </label>
                    )
                  })}
                </div>
              </RadioGroup>
            </div>

            {/* Table Selection */}
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <Label>Select Tables</Label>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedTables(selectedTables.length ? [] : availableTables.map(t => t.name))}
                >
                  {selectedTables.length ? 'Deselect All' : 'Select All'}
                </Button>
              </div>
              <div className="space-y-2">
                {availableTables.map((table) => (
                  <div
                    key={table.name}
                    className={`flex items-center justify-between p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                      selectedTables.includes(table.name) ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                    }`}
                    onClick={() => handleTableToggle(table.name)}
                  >
                    <div className="flex items-center space-x-3">
                      <Checkbox
                        checked={selectedTables.includes(table.name)}
                        onCheckedChange={() => handleTableToggle(table.name)}
                      />
                      <div>
                        <p className="font-medium">{table.name}</p>
                        <p className="text-xs text-gray-500">
                          {table.records.toLocaleString()} records • {table.size}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Export Options */}
            <div className="space-y-4">
              <Label>Export Options</Label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="date-range">Date Range</Label>
                  <Select defaultValue="all">
                    <SelectTrigger id="date-range">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Time</SelectItem>
                      <SelectItem value="today">Today</SelectItem>
                      <SelectItem value="week">This Week</SelectItem>
                      <SelectItem value="month">This Month</SelectItem>
                      <SelectItem value="year">This Year</SelectItem>
                      <SelectItem value="custom">Custom Range</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="compression">Compression</Label>
                  <Select defaultValue="none">
                    <SelectTrigger id="compression">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">None</SelectItem>
                      <SelectItem value="zip">ZIP</SelectItem>
                      <SelectItem value="gzip">GZIP</SelectItem>
                      <SelectItem value="tar">TAR</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <Checkbox id="include-headers" defaultChecked />
                  <label htmlFor="include-headers" className="text-sm">
                    Include column headers
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox id="include-metadata" />
                  <label htmlFor="include-metadata" className="text-sm">
                    Include metadata and relationships
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox id="encrypt" />
                  <label htmlFor="encrypt" className="text-sm">
                    Encrypt export file
                  </label>
                </div>
              </div>
            </div>

            {/* Export Summary */}
            {selectedTables.length > 0 && (
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  <div className="flex justify-between items-center">
                    <span>
                      Ready to export {selectedTables.length} table{selectedTables.length !== 1 ? 's' : ''} • 
                      {' '}{getTotalRecords().toLocaleString()} records • 
                      {' '}{getTotalSize()}
                    </span>
                    <Badge>Estimated time: 2-3 min</Badge>
                  </div>
                </AlertDescription>
              </Alert>
            )}

            {/* Export Progress */}
            {isExporting && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Exporting data...</span>
                  <span className="text-sm">{exportProgress}%</span>
                </div>
                <Progress value={exportProgress} />
              </div>
            )}

            {exportProgress === 100 && (
              <Alert className="bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <AlertDescription className="text-green-800 dark:text-green-200">
                  Export completed successfully! Your file is ready for download.
                  <Button variant="link" className="p-0 h-auto ml-2">
                    <Download className="h-3 w-3 mr-1" />
                    Download
                  </Button>
                </AlertDescription>
              </Alert>
            )}

            {/* Action Buttons */}
            <div className="flex justify-between">
              <div className="space-x-2">
                <Button variant="outline">
                  <Archive className="h-4 w-4 mr-2" />
                  Save as Preset
                </Button>
                <Button variant="outline">
                  <Clock className="h-4 w-4 mr-2" />
                  Schedule Export
                </Button>
              </div>
              <Button 
                onClick={startExport}
                disabled={selectedTables.length === 0 || isExporting}
              >
                {isExporting ? (
                  <>
                    <Download className="h-4 w-4 mr-2 animate-pulse" />
                    Exporting...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Export Data
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sidebar - Export Presets */}
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Export Presets</CardTitle>
            <CardDescription>Quick export configurations</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {exportPresets.map((preset) => {
              const Icon = preset.icon
              return (
                <div
                  key={preset.id}
                  className="p-3 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                >
                  <div className="flex items-start space-x-3">
                    <div className="p-2 bg-gray-100 dark:bg-gray-800 rounded-lg">
                      <Icon className="h-4 w-4 text-gray-600" />
                    </div>
                    <div className="flex-1">
                      <p className="font-medium text-sm">{preset.name}</p>
                      <p className="text-xs text-gray-500">{preset.description}</p>
                      <div className="flex items-center space-x-3 mt-2">
                        <Badge variant="outline" className="text-xs">
                          {preset.format}
                        </Badge>
                        {preset.filters > 0 && (
                          <span className="text-xs text-gray-500">
                            <Filter className="h-3 w-3 inline mr-1" />
                            {preset.filters} filters
                          </span>
                        )}
                        <span className="text-xs text-gray-400">
                          {preset.lastUsed}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Exports</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { name: 'customers_20240201.csv', size: '24.5 MB', time: '10 minutes ago' },
              { name: 'full_backup_20240201.sql', size: '1.8 GB', time: '2 hours ago' },
              { name: 'analytics_january.xlsx', size: '156 MB', time: '1 day ago' }
            ].map((file, index) => (
              <div key={index} className="flex items-center justify-between p-2">
                <div className="flex items-center space-x-2">
                  <FileText className="h-4 w-4 text-gray-400" />
                  <div>
                    <p className="text-sm font-medium">{file.name}</p>
                    <p className="text-xs text-gray-500">{file.size} • {file.time}</p>
                  </div>
                </div>
                <Button variant="ghost" size="sm">
                  <Download className="h-3 w-3" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}