import * as React from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Checkbox } from '@/components/ui/checkbox'
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
  Upload,
  FileText,
  Database,
  Globe,
  ChevronRight,
  ChevronLeft,
  CheckCircle2,
  AlertCircle,
  FileSpreadsheet,
  Code,
  Settings,
  Play,
  X
} from 'lucide-react'

interface ImportStep {
  id: number
  title: string
  description: string
}

export function ImportWizard() {
  const [currentStep, setCurrentStep] = React.useState(1)
  const [importType, setImportType] = React.useState('file')
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null)
  const [mapping, setMapping] = React.useState<Record<string, string>>({})
  const [isImporting, setIsImporting] = React.useState(false)
  const [importProgress, setImportProgress] = React.useState(0)

  const steps: ImportStep[] = [
    { id: 1, title: 'Source', description: 'Select data source' },
    { id: 2, title: 'Configure', description: 'Set import options' },
    { id: 3, title: 'Mapping', description: 'Map fields' },
    { id: 4, title: 'Review', description: 'Review & import' }
  ]

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedFile(file)
    }
  }

  const startImport = () => {
    setIsImporting(true)
    setImportProgress(0)
    
    const interval = setInterval(() => {
      setImportProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsImporting(false)
          return 100
        }
        return prev + 10
      })
    }, 500)
  }

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="space-y-6">
            <RadioGroup value={importType} onValueChange={setImportType}>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label
                  htmlFor="file"
                  className={`flex items-center space-x-3 p-4 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                    importType === 'file' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <RadioGroupItem value="file" id="file" />
                  <FileSpreadsheet className="h-5 w-5 text-gray-600" />
                  <div className="flex-1">
                    <p className="font-medium">File Upload</p>
                    <p className="text-xs text-gray-500">CSV, Excel, JSON</p>
                  </div>
                </label>

                <label
                  htmlFor="database"
                  className={`flex items-center space-x-3 p-4 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                    importType === 'database' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <RadioGroupItem value="database" id="database" />
                  <Database className="h-5 w-5 text-gray-600" />
                  <div className="flex-1">
                    <p className="font-medium">Database</p>
                    <p className="text-xs text-gray-500">MySQL, PostgreSQL</p>
                  </div>
                </label>

                <label
                  htmlFor="api"
                  className={`flex items-center space-x-3 p-4 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                    importType === 'api' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <RadioGroupItem value="api" id="api" />
                  <Globe className="h-5 w-5 text-gray-600" />
                  <div className="flex-1">
                    <p className="font-medium">API</p>
                    <p className="text-xs text-gray-500">REST, GraphQL</p>
                  </div>
                </label>

                <label
                  htmlFor="manual"
                  className={`flex items-center space-x-3 p-4 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 ${
                    importType === 'manual' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <RadioGroupItem value="manual" id="manual" />
                  <Code className="h-5 w-5 text-gray-600" />
                  <div className="flex-1">
                    <p className="font-medium">Manual Entry</p>
                    <p className="text-xs text-gray-500">Copy & paste</p>
                  </div>
                </label>
              </div>
            </RadioGroup>

            {importType === 'file' && (
              <div className="space-y-4">
                <div className="border-2 border-dashed rounded-lg p-8 text-center">
                  {selectedFile ? (
                    <div className="space-y-2">
                      <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto" />
                      <p className="font-medium">{selectedFile.name}</p>
                      <p className="text-sm text-gray-500">
                        {(selectedFile.size / 1024).toFixed(2)} KB
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedFile(null)}
                      >
                        Remove
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <Upload className="h-12 w-12 text-gray-400 mx-auto" />
                      <p className="font-medium">Drop files here or click to upload</p>
                      <p className="text-sm text-gray-500">Supports CSV, Excel, JSON (max 50MB)</p>
                      <input
                        type="file"
                        onChange={handleFileUpload}
                        accept=".csv,.xlsx,.json"
                        className="hidden"
                        id="file-upload"
                      />
                      <Button variant="outline" asChild>
                        <label htmlFor="file-upload">Choose File</label>
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )

      case 2:
        return (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Import Mode</Label>
                <Select defaultValue="append">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="append">Append to existing data</SelectItem>
                    <SelectItem value="replace">Replace existing data</SelectItem>
                    <SelectItem value="update">Update matching records</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Duplicate Handling</Label>
                <Select defaultValue="skip">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="skip">Skip duplicates</SelectItem>
                    <SelectItem value="update">Update duplicates</SelectItem>
                    <SelectItem value="error">Error on duplicates</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Date Format</Label>
                <Select defaultValue="auto">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">Auto-detect</SelectItem>
                    <SelectItem value="mm/dd/yyyy">MM/DD/YYYY</SelectItem>
                    <SelectItem value="dd/mm/yyyy">DD/MM/YYYY</SelectItem>
                    <SelectItem value="yyyy-mm-dd">YYYY-MM-DD</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Batch Size</Label>
                <Input type="number" defaultValue="1000" />
              </div>
            </div>

            <div className="space-y-4">
              <Label>Import Options</Label>
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <Checkbox id="validate" defaultChecked />
                  <label htmlFor="validate" className="text-sm">
                    Validate data before import
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox id="backup" defaultChecked />
                  <label htmlFor="backup" className="text-sm">
                    Create backup before import
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox id="notifications" />
                  <label htmlFor="notifications" className="text-sm">
                    Send email notification when complete
                  </label>
                </div>
              </div>
            </div>
          </div>
        )

      case 3:
        return (
          <div className="space-y-6">
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                Map your source fields to destination fields. Required fields are marked with an asterisk.
              </AlertDescription>
            </Alert>

            <div className="space-y-4">
              {[
                { source: 'customer_name', dest: 'name', required: true },
                { source: 'email_address', dest: 'email', required: true },
                { source: 'phone_number', dest: 'phone', required: false },
                { source: 'company', dest: 'organization', required: false },
                { source: 'created_date', dest: 'createdAt', required: false }
              ].map((field, index) => (
                <div key={index} className="flex items-center space-x-4">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <FileText className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-medium">{field.source}</span>
                    </div>
                  </div>
                  <ChevronRight className="h-4 w-4 text-gray-400" />
                  <div className="flex-1">
                    <Select defaultValue={field.dest}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={field.dest}>
                          {field.dest} {field.required && '*'}
                        </SelectItem>
                        <SelectItem value="skip">Skip this field</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ))}
            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <p className="text-sm font-medium mb-2">Auto-detected mappings</p>
              <p className="text-xs text-gray-500">
                5 of 5 fields have been automatically mapped based on field names.
                Review and adjust as needed.
              </p>
            </div>
          </div>
        )

      case 4:
        return (
          <div className="space-y-6">
            {!isImporting && importProgress < 100 && (
              <>
                <Alert>
                  <CheckCircle2 className="h-4 w-4" />
                  <AlertDescription>
                    Ready to import! Review your settings below before starting the import.
                  </AlertDescription>
                </Alert>

                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 border rounded-lg">
                      <p className="text-sm text-gray-500">Source</p>
                      <p className="font-medium">
                        {selectedFile ? selectedFile.name : importType}
                      </p>
                    </div>
                    <div className="p-3 border rounded-lg">
                      <p className="text-sm text-gray-500">Records</p>
                      <p className="font-medium">~12,847</p>
                    </div>
                    <div className="p-3 border rounded-lg">
                      <p className="text-sm text-gray-500">Import Mode</p>
                      <p className="font-medium">Append</p>
                    </div>
                    <div className="p-3 border rounded-lg">
                      <p className="text-sm text-gray-500">Validation</p>
                      <p className="font-medium">Enabled</p>
                    </div>
                  </div>

                  <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                      Estimated import time: 2-3 minutes
                    </p>
                    <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1">
                      Large imports may affect system performance
                    </p>
                  </div>
                </div>
              </>
            )}

            {isImporting && (
              <div className="space-y-4">
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 dark:bg-blue-900/20 rounded-full mb-4">
                    <Upload className="h-8 w-8 text-blue-600 animate-pulse" />
                  </div>
                  <p className="font-medium">Importing data...</p>
                  <p className="text-sm text-gray-500">Please don't close this window</p>
                </div>
                <Progress value={importProgress} className="h-2" />
                <div className="flex justify-between text-xs text-gray-500">
                  <span>Processing records...</span>
                  <span>{importProgress}%</span>
                </div>
              </div>
            )}

            {importProgress === 100 && (
              <div className="text-center space-y-4">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full">
                  <CheckCircle2 className="h-8 w-8 text-green-600" />
                </div>
                <div>
                  <p className="font-medium text-lg">Import completed successfully!</p>
                  <p className="text-sm text-gray-500 mt-1">12,847 records imported</p>
                </div>
                <div className="flex justify-center space-x-2">
                  <Button variant="outline">View Records</Button>
                  <Button>Start New Import</Button>
                </div>
              </div>
            )}
          </div>
        )

      default:
        return null
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Import Wizard</CardTitle>
        <CardDescription>
          Follow the steps to import your data
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Progress Steps */}
        <div className="flex items-center justify-between">
          {steps.map((step, index) => (
            <React.Fragment key={step.id}>
              <div className="flex flex-col items-center">
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    step.id <= currentStep
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-200 dark:bg-gray-700 text-gray-500'
                  }`}
                >
                  {step.id < currentStep ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : (
                    step.id
                  )}
                </div>
                <p className="text-xs mt-2">{step.title}</p>
              </div>
              {index < steps.length - 1 && (
                <div
                  className={`flex-1 h-0.5 mx-2 ${
                    step.id < currentStep
                      ? 'bg-blue-600'
                      : 'bg-gray-200 dark:bg-gray-700'
                  }`}
                />
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Step Content */}
        {renderStepContent()}

        {/* Navigation Buttons */}
        <div className="flex justify-between pt-4 border-t">
          <Button
            variant="outline"
            onClick={() => setCurrentStep(Math.max(1, currentStep - 1))}
            disabled={currentStep === 1 || isImporting}
          >
            <ChevronLeft className="h-4 w-4 mr-2" />
            Previous
          </Button>
          
          {currentStep < 4 ? (
            <Button
              onClick={() => setCurrentStep(Math.min(4, currentStep + 1))}
              disabled={currentStep === 1 && !selectedFile && importType === 'file'}
            >
              Next
              <ChevronRight className="h-4 w-4 ml-2" />
            </Button>
          ) : (
            <Button
              onClick={startImport}
              disabled={isImporting || importProgress === 100}
            >
              {isImporting ? (
                <>
                  <Settings className="h-4 w-4 mr-2 animate-spin" />
                  Importing...
                </>
              ) : importProgress === 100 ? (
                'Complete'
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Start Import
                </>
              )}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}