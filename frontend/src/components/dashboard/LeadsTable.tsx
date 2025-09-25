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
  Eye
} from 'lucide-react'

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

export function LeadsTable() {
  const [searchQuery, setSearchQuery] = React.useState('')
  const [statusFilter, setStatusFilter] = React.useState('all')
  const [selectedLeads, setSelectedLeads] = React.useState<string[]>([])

  const leads: Lead[] = [
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
    {
      id: '3',
      name: 'Michael Johnson',
      email: 'mjohnson@globalind.com',
      phone: '+1 555-0125',
      company: 'Global Industries',
      status: 'new',
      value: 67500,
      source: 'LinkedIn',
      owner: 'Sarah Johnson',
      createdAt: '2024-01-20',
      lastContact: '2024-01-28',
      score: 65,
      priority: 'medium'
    },
    {
      id: '4',
      name: 'Sarah Wilson',
      email: 'sarah.w@startuphub.com',
      phone: '+1 555-0126',
      company: 'StartupHub',
      status: 'contacted',
      value: 45000,
      source: 'Email Campaign',
      owner: 'John Anderson',
      createdAt: '2024-01-22',
      lastContact: '2024-01-29',
      score: 58,
      priority: 'low'
    },
    {
      id: '5',
      name: 'Robert Davis',
      email: 'rdavis@enterprise.com',
      phone: '+1 555-0127',
      company: 'Enterprise Co',
      status: 'negotiation',
      value: 38000,
      source: 'Trade Show',
      owner: 'Emily Chen',
      createdAt: '2024-01-25',
      lastContact: '2024-02-02',
      score: 78,
      priority: 'high'
    },
    {
      id: '6',
      name: 'Lisa Martinez',
      email: 'lisa@cloudservices.net',
      phone: '+1 555-0128',
      company: 'Cloud Services Ltd',
      status: 'qualified',
      value: 92000,
      source: 'Partner',
      owner: 'Mike Davis',
      createdAt: '2024-01-10',
      lastContact: '2024-01-25',
      score: 81,
      priority: 'high'
    },
    {
      id: '7',
      name: 'James Anderson',
      email: 'james@marketingpro.com',
      phone: '+1 555-0129',
      company: 'Marketing Pro Agency',
      status: 'won',
      value: 55000,
      source: 'Website',
      owner: 'Sarah Johnson',
      createdAt: '2024-01-05',
      lastContact: '2024-01-20',
      score: 90,
      priority: 'medium'
    },
    {
      id: '8',
      name: 'Patricia Lee',
      email: 'plee@dataanalytics.io',
      phone: '+1 555-0130',
      company: 'Data Analytics Inc',
      status: 'lost',
      value: 75000,
      source: 'Cold Call',
      owner: 'John Anderson',
      createdAt: '2024-01-08',
      lastContact: '2024-01-15',
      score: 45,
      priority: 'low'
    }
  ]

  const filteredLeads = leads.filter((lead) => {
    const matchesSearch = 
      lead.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lead.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lead.company.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesStatus = statusFilter === 'all' || lead.status === statusFilter
    
    return matchesSearch && matchesStatus
  })

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedLeads(filteredLeads.map(lead => lead.id))
    } else {
      setSelectedLeads([])
    }
  }

  const handleSelectLead = (leadId: string, checked: boolean) => {
    if (checked) {
      setSelectedLeads([...selectedLeads, leadId])
    } else {
      setSelectedLeads(selectedLeads.filter(id => id !== leadId))
    }
  }

  const getStatusBadge = (status: Lead['status']) => {
    const variants: Record<Lead['status'], any> = {
      new: { variant: 'secondary', label: 'New' },
      contacted: { variant: 'outline', label: 'Contacted' },
      qualified: { variant: 'default', label: 'Qualified' },
      proposal: { variant: 'default', label: 'Proposal' },
      negotiation: { variant: 'default', label: 'Negotiation' },
      won: { variant: 'success', label: 'Won' },
      lost: { variant: 'destructive', label: 'Lost' }
    }
    const config = variants[status]
    return <Badge variant={config.variant}>{config.label}</Badge>
  }

  const getPriorityIcon = (priority: Lead['priority']) => {
    const colors = {
      low: 'text-gray-400',
      medium: 'text-yellow-500',
      high: 'text-red-500'
    }
    return <Star className={`h-4 w-4 ${colors[priority]} fill-current`} />
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex justify-between items-center">
          <div>
            <CardTitle>Leads</CardTitle>
            <CardDescription>Manage and track your sales leads</CardDescription>
          </div>
          <Button>
            <UserPlus className="h-4 w-4 mr-2" />
            Add Lead
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {/* Filters */}
        <div className="flex items-center space-x-2 mb-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search leads..."
              className="pl-10"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-40">
              <Filter className="h-4 w-4 mr-2" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="contacted">Contacted</SelectItem>
              <SelectItem value="qualified">Qualified</SelectItem>
              <SelectItem value="proposal">Proposal</SelectItem>
              <SelectItem value="negotiation">Negotiation</SelectItem>
              <SelectItem value="won">Won</SelectItem>
              <SelectItem value="lost">Lost</SelectItem>
            </SelectContent>
          </Select>
          {selectedLeads.length > 0 && (
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-500">
                {selectedLeads.length} selected
              </span>
              <Button variant="outline" size="sm">
                Bulk Actions
              </Button>
            </div>
          )}
        </div>

        {/* Table */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">
                  <Checkbox
                    checked={selectedLeads.length === filteredLeads.length && filteredLeads.length > 0}
                    onCheckedChange={handleSelectAll}
                    aria-label="Select all"
                  />
                </TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Company</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Score</TableHead>
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
                      aria-label={`Select ${lead.name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      {getPriorityIcon(lead.priority)}
                      <div>
                        <p className="font-medium">{lead.name}</p>
                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                          <Mail className="h-3 w-3" />
                          <span>{lead.email}</span>
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium">{lead.company}</p>
                      <p className="text-xs text-gray-500">{lead.source}</p>
                    </div>
                  </TableCell>
                  <TableCell>{getStatusBadge(lead.status)}</TableCell>
                  <TableCell className="font-medium">
                    ${lead.value.toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-1">
                      <span className="font-medium">{lead.score}</span>
                      <span className="text-xs text-gray-500">/100</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <p className="text-sm">{lead.owner}</p>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-1 text-xs text-gray-500">
                      <Calendar className="h-3 w-3" />
                      <span>
                        {new Date(lead.lastContact).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric'
                        })}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0">
                          <span className="sr-only">Open menu</span>
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem>
                          <Eye className="h-4 w-4 mr-2" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Edit className="h-4 w-4 mr-2" />
                          Edit Lead
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Phone className="h-4 w-4 mr-2" />
                          Call Lead
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Mail className="h-4 w-4 mr-2" />
                          Send Email
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600">
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
        </div>

        {filteredLeads.length === 0 && (
          <div className="text-center py-12">
            <User className="h-12 w-12 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No leads found</p>
            <Button variant="outline" className="mt-4">
              <UserPlus className="h-4 w-4 mr-2" />
              Add your first lead
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}