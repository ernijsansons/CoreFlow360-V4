import * as React from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import {
  User,
  Mail,
  Phone,
  Building2,
  Calendar,
  MoreHorizontal,
  Search,
  Filter,
  UserPlus,
  Star,
  Edit,
  Trash2,
  Eye,
  Loader2,
  AlertCircle,
  Download,
  Upload,
  Users,
  RefreshCw
} from 'lucide-react'
import { useLeads, useUpdateLead, useDeleteLead, useBulkUpdateLeads, useBulkDeleteLeads, useCreateLead } from '@/hooks/api/use-crm'
import { useToast } from '@/hooks/use-toast'
import { formatDistanceToNow } from 'date-fns'

interface Lead {
  id: string
  name: string
  email: string
  phone: string
  company: string
  status: 'new' | 'contacted' | 'qualified' | 'proposal' | 'negotiation' | 'won' | 'lost'
  value: number
  source: string
  owner: string
  createdAt: string
  lastContact: string
  score: number
  priority: 'low' | 'medium' | 'high'
}

export function LeadsTableEnhanced() {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [statusFilter, setStatusFilter] = React.useState('all')
  const [selectedLeads, setSelectedLeads] = React.useState<string[]>([])
  const [showCreateDialog, setShowCreateDialog] = React.useState(false)
  const { toast } = useToast()

  // Fetch leads using React Query
  const {
    data: leadsResponse,
    isLoading,
    isError,
    error,
    refetch,
    isFetching
  } = useLeads({
    status: statusFilter !== 'all' ? statusFilter : undefined,
    search: searchQuery || undefined,
  })

  // Mutations
  const updateLead = useUpdateLead()
  const deleteLead = useDeleteLead()
  const createLead = useCreateLead()
  const bulkUpdateLeads = useBulkUpdateLeads()
  const bulkDeleteLeads = useBulkDeleteLeads()

  // Use API data or fallback to mock data
  const apiLeads = leadsResponse?.data || []

  // Mock data for development/fallback
  const mockLeads: Lead[] = [
    {
      id: '1',
      name: 'John Smith',
      email: 'john.smith@acmecorp.com',
      phone: '+1 555-0123',
      company: 'Acme Corporation',
      status: 'qualified',
      value: 125000,
      source: 'Website',
      owner: 'Sarah Johnson',
      createdAt: '2024-01-15',
      lastContact: '2024-02-01',
      score: 85,
      priority: 'high'
    },
    {
      id: '2',
      name: 'Emily Brown',
      email: 'emily@techsolutions.io',
      phone: '+1 555-0124',
      company: 'Tech Solutions Inc',
      status: 'proposal',
      value: 89000,
      source: 'Referral',
      owner: 'Mike Davis',
      createdAt: '2024-01-18',
      lastContact: '2024-01-30',
      score: 72,
      priority: 'medium'
    },
  ]

  // Use API data if available, otherwise use mock data
  const leads = apiLeads.length > 0 ? apiLeads : (isError ? mockLeads : [])

  const filteredLeads = leads.filter(lead => {
    if (statusFilter !== 'all' && lead.status !== statusFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        lead.name.toLowerCase().includes(query) ||
        lead.email.toLowerCase().includes(query) ||
        lead.company.toLowerCase().includes(query)
      )
    }
    return true
  })

  const handleStatusChange = async (leadId: string, newStatus: string) => {
    try {
      await updateLead.mutateAsync({ id: leadId, data: { status: newStatus } })
      toast({
        title: 'Status updated',
        description: 'Lead status has been updated successfully.',
        variant: 'success',
      })
    } catch (error) {
      toast({
        title: 'Update failed',
        description: 'Failed to update lead status. Please try again.',
        variant: 'destructive',
      })
    }
  }

  const handleDeleteLead = async (leadId: string) => {
    if (confirm('Are you sure you want to delete this lead?')) {
      try {
        await deleteLead.mutateAsync(leadId)
        setSelectedLeads(prev => prev.filter(id => id !== leadId))
      } catch (error) {
        toast({
          title: 'Delete failed',
          description: 'Failed to delete lead. Please try again.',
          variant: 'destructive',
        })
      }
    }
  }

  const handleBulkAction = async (action: string) => {
    if (selectedLeads.length === 0) {
      toast({
        title: 'No leads selected',
        description: 'Please select at least one lead to perform this action.',
        variant: 'warning',
      })
      return
    }

    try {
      switch (action) {
        case 'delete':
          if (confirm(`Are you sure you want to delete ${selectedLeads.length} leads?`)) {
            await bulkDeleteLeads.mutateAsync(selectedLeads)
            setSelectedLeads([])
            toast({
              title: 'Leads deleted',
              description: `Successfully deleted ${selectedLeads.length} leads.`,
              variant: 'success',
            })
          }
          break
        case 'assign':
          // TODO: Open assignment dialog
          toast({
            title: 'Feature coming soon',
            description: 'Bulk assignment will be available in the next update.',
          })
          break
        case 'update-status':
          // TODO: Open status update dialog
          toast({
            title: 'Feature coming soon',
            description: 'Bulk status update will be available in the next update.',
          })
          break
        case 'export':
          // TODO: Implement export
          toast({
            title: 'Exporting leads',
            description: `Preparing to export ${selectedLeads.length} leads...`,
          })
          break
      }
    } catch (error) {
      toast({
        title: 'Action failed',
        description: `Failed to perform ${action}. Please try again.`,
        variant: 'destructive',
      })
    }
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedLeads(filteredLeads.map(lead => lead.id))
    } else {
      setSelectedLeads([])
    }
  }

  const handleSelectLead = (leadId: string, checked: boolean) => {
    if (checked) {
      setSelectedLeads(prev => [...prev, leadId])
    } else {
      setSelectedLeads(prev => prev.filter(id => id !== leadId))
    }
  }

  const getStatusColor = (status: Lead['status']) => {
    const colors = {
      new: 'bg-blue-100 text-blue-800',
      contacted: 'bg-yellow-100 text-yellow-800',
      qualified: 'bg-purple-100 text-purple-800',
      proposal: 'bg-orange-100 text-orange-800',
      negotiation: 'bg-indigo-100 text-indigo-800',
      won: 'bg-green-100 text-green-800',
      lost: 'bg-red-100 text-red-800',
    }
    return colors[status] || 'bg-gray-100 text-gray-800'
  }

  const getPriorityColor = (priority: Lead['priority']) => {
    const colors = {
      low: 'bg-gray-100 text-gray-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-red-100 text-red-800',
    }
    return colors[priority] || 'bg-gray-100 text-gray-800'
  }

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(value)
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="text-2xl">Leads Management</CardTitle>
            <CardDescription>
              {isLoading ? (
                'Loading leads...'
              ) : (
                <>
                  {filteredLeads.length} active leads
                  {selectedLeads.length > 0 && ` • ${selectedLeads.length} selected`}
                </>
              )}
            </CardDescription>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => refetch()}
              disabled={isFetching}
            >
              {isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>

            {selectedLeads.length > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    Bulk Actions ({selectedLeads.length})
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                  <DropdownMenuItem onClick={() => handleBulkAction('update-status')}>
                    <Edit className="h-4 w-4 mr-2" />
                    Update Status
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => handleBulkAction('assign')}>
                    <Users className="h-4 w-4 mr-2" />
                    Assign to User
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => handleBulkAction('export')}>
                    <Download className="h-4 w-4 mr-2" />
                    Export Selected
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={() => handleBulkAction('delete')}
                    className="text-red-600"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete Selected
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}

            <Button className="gap-2" onClick={() => setShowCreateDialog(true)}>
              <UserPlus className="h-4 w-4" />
              Add Lead
            </Button>
          </div>
        </div>

        <div className="flex gap-2 mt-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <Input
              placeholder="Search leads..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="contacted">Contacted</SelectItem>
              <SelectItem value="qualified">Qualified</SelectItem>
              <SelectItem value="proposal">Proposal</SelectItem>
              <SelectItem value="negotiation">Negotiation</SelectItem>
              <SelectItem value="won">Won</SelectItem>
              <SelectItem value="lost">Lost</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>

      <CardContent>
        {isError && !leads.length && (
          <div className="flex items-center gap-2 p-4 mb-4 bg-red-50 text-red-800 rounded-lg">
            <AlertCircle className="h-5 w-5" />
            <span>Failed to load leads. Error: {error?.message}</span>
          </div>
        )}

        {isLoading ? (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : filteredLeads.length === 0 ? (
          <div className="text-center py-12">
            <User className="h-12 w-12 mx-auto text-gray-400 mb-4" />
            <h3 className="text-lg font-semibold mb-2">No leads found</h3>
            <p className="text-gray-600 mb-4">
              {searchQuery || statusFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Start by adding your first lead'}
            </p>
            <Button onClick={() => setShowCreateDialog(true)}>
              <UserPlus className="h-4 w-4 mr-2" />
              Add Your First Lead
            </Button>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">
                  <Checkbox
                    checked={selectedLeads.length === filteredLeads.length && filteredLeads.length > 0}
                    onCheckedChange={handleSelectAll}
                  />
                </TableHead>
                <TableHead>Lead</TableHead>
                <TableHead>Company</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Last Contact</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLeads.map((lead) => (
                <TableRow key={lead.id}>
                  <TableCell>
                    <Checkbox
                      checked={selectedLeads.includes(lead.id)}
                      onCheckedChange={(checked) => handleSelectLead(lead.id, checked as boolean)}
                    />
                  </TableCell>
                  <TableCell>
                    <div>
                      <div className="font-medium">{lead.name}</div>
                      <div className="text-sm text-gray-500">{lead.email}</div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Building2 className="h-4 w-4 text-gray-400" />
                      {lead.company}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge className={getStatusColor(lead.status)}>
                      {lead.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-medium">
                    {formatCurrency(lead.value)}
                  </TableCell>
                  <TableCell>
                    <Badge className={getPriorityColor(lead.priority)}>
                      {lead.priority}
                    </Badge>
                  </TableCell>
                  <TableCell>{lead.owner}</TableCell>
                  <TableCell>
                    <div className="text-sm text-gray-500">
                      {formatDistanceToNow(new Date(lead.lastContact), { addSuffix: true })}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={updateLead.isPending || deleteLead.isPending}
                        >
                          {(updateLead.isPending || deleteLead.isPending) ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <MoreHorizontal className="h-4 w-4" />
                          )}
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuItem>
                          <Eye className="h-4 w-4 mr-2" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Edit className="h-4 w-4 mr-2" />
                          Edit Lead
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuLabel>Update Status</DropdownMenuLabel>
                        <DropdownMenuItem
                          onClick={() => handleStatusChange(lead.id, 'contacted')}
                        >
                          Mark as Contacted
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleStatusChange(lead.id, 'qualified')}
                        >
                          Mark as Qualified
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleStatusChange(lead.id, 'won')}
                          className="text-green-600"
                        >
                          <Star className="h-4 w-4 mr-2" />
                          Mark as Won
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => handleDeleteLead(lead.id)}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete Lead
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}