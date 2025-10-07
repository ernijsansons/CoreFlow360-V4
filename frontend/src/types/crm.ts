/**
 * CRM Type Definitions
 * Comprehensive types for CRM functionality
 */

// Lead Types
export interface Lead {
  id: string
  name: string
  email: string
  phone?: string
  company?: string
  status: 'new' | 'contacted' | 'qualified' | 'unqualified'
  owner?: string
  source?: string
  priority?: 'low' | 'medium' | 'high'
  createdAt: string
  updatedAt: string
}

export interface LeadFormData {
  name: string
  email: string
  phone?: string
  company?: string
  status?: Lead['status']
  owner?: string
  source?: string
  priority?: Lead['priority']
}

export interface LeadUpdateData extends Partial<LeadFormData> {
  notes?: string
  tags?: string[]
}

// Contact Types
export interface Contact {
  id: string
  name: string
  email: string
  phone?: string
  company?: string
  position?: string
  createdAt: string
  updatedAt: string
}

export interface ContactFormData {
  name: string
  email: string
  phone?: string
  company?: string
  position?: string
}

// Company Types
export interface Company {
  id: string
  name: string
  industry?: string
  size?: string
  website?: string
  createdAt: string
  updatedAt: string
}

// Deal Types
export interface Deal {
  id: string
  title: string
  value: number
  stage: string
  status: 'open' | 'won' | 'lost'
  owner?: string
  companyId?: string
  expectedCloseDate?: string
  createdAt: string
  updatedAt: string
}

export interface DealFormData {
  title: string
  value: number
  stage: string
  status?: Deal['status']
  owner?: string
  companyId?: string
  expectedCloseDate?: string
}

export interface DealUpdateData extends Partial<DealFormData> {
  notes?: string
  tags?: string[]
}

// Pipeline Types
export interface PipelineStage {
  id: string
  name: string
  order: number
  probability: number
  deals: Deal[]
}

export interface Pipeline {
  id: string
  name: string
  stages: PipelineStage[]
}

// Activity Types
export interface Activity {
  id: string
  type: 'call' | 'email' | 'meeting' | 'task' | 'note'
  subject: string
  description?: string
  relatedTo?: {
    type: 'lead' | 'contact' | 'deal'
    id: string
  }
  dueDate?: string
  completed: boolean
  createdAt: string
  updatedAt: string
}

// CRM Metrics Types
export interface CRMMetrics {
  totalLeads: number
  qualifiedLeads: number
  conversionRate: number
  totalDeals: number
  dealValue: number
  wonDeals: number
  lostDeals: number
  averageDealSize: number
  averageSalesCycle: number
}

// Bulk Operation Types
export interface BulkLeadUpdate {
  ids: string[]
  updates: LeadUpdateData
}

export interface BulkLeadDelete {
  ids: string[]
}
