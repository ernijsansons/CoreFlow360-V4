/**
 * CRM V2 React Query Hooks
 * Fortune 50-level data fetching with caching and optimistic updates
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { crmV2Service } from '../services/crm-v2.service';
import type { Company, Contact, Deal, Activity } from '../services/crm-v2.service';

// ============================================================
// QUERY KEYS
// ============================================================

export const crmKeys = {
  all: ['crm-v2'] as const,
  companies: () => [...crmKeys.all, 'companies'] as const,
  companiesList: (filters?: any) => [...crmKeys.companies(), 'list', filters] as const,
  company: (id: string) => [...crmKeys.companies(), 'detail', id] as const,
  contacts: () => [...crmKeys.all, 'contacts'] as const,
  contactsList: (filters?: any) => [...crmKeys.contacts(), 'list', filters] as const,
  deals: () => [...crmKeys.all, 'deals'] as const,
  dealsList: (filters?: any) => [...crmKeys.deals(), 'list', filters] as const,
  activities: () => [...crmKeys.all, 'activities'] as const,
  activitiesList: (filters?: any) => [...crmKeys.activities(), 'list', filters] as const,
  pipeline: () => [...crmKeys.all, 'pipeline'] as const,
  dashboardStats: () => [...crmKeys.all, 'dashboard-stats'] as const,
};

// ============================================================
// COMPANIES HOOKS
// ============================================================

export function useCompanies(filters?: {
  lifecycle_stage?: string;
  status?: string;
  owner_id?: string;
  min_score?: number;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: crmKeys.companiesList(filters),
    queryFn: async () => {
      const response = await crmV2Service.getCompanies(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch companies');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 5, // 5 minutes
  });
}

export function useCompany(id: string, enabled = true) {
  return useQuery({
    queryKey: crmKeys.company(id),
    queryFn: async () => {
      const response = await crmV2Service.getCompanyById(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch company');
      }
      return response.data;
    },
    enabled: enabled && !!id,
    staleTime: 1000 * 60 * 5,
  });
}

export function useCreateCompany() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<Company>) => crmV2Service.createCompany(data),
    onSuccess: () => {
      // Invalidate companies list
      queryClient.invalidateQueries({ queryKey: crmKeys.companies() });
    },
  });
}

export function useUpdateCompany() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Company> }) =>
      crmV2Service.updateCompany(id, data),
    onSuccess: (_, variables) => {
      // Invalidate specific company and list
      queryClient.invalidateQueries({ queryKey: crmKeys.company(variables.id) });
      queryClient.invalidateQueries({ queryKey: crmKeys.companies() });
    },
  });
}

// ============================================================
// CONTACTS HOOKS
// ============================================================

export function useContacts(filters?: {
  company_id?: string;
  lifecycle_stage?: string;
  status?: string;
  min_score?: number;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: crmKeys.contactsList(filters),
    queryFn: async () => {
      const response = await crmV2Service.getContacts(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch contacts');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 5,
  });
}

export function useContact(id: string) {
  return useQuery({
    queryKey: [...crmKeys.contacts(), 'detail', id] as const,
    queryFn: async () => {
      const response = await crmV2Service.getContact(id);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch contact');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 5,
    enabled: !!id,
  });
}

export function useCreateContact() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<Contact>) => crmV2Service.createContact(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.contacts() });
    },
  });
}

// ============================================================
// DEALS HOOKS
// ============================================================

export function useDeals(filters?: {
  stage?: string;
  status?: string;
  owner_id?: string;
  company_id?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: crmKeys.dealsList(filters),
    queryFn: async () => {
      const response = await crmV2Service.getDeals(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch deals');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 2, // 2 minutes for more real-time feel
  });
}

export function useCreateDeal() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Partial<Deal>) => crmV2Service.createDeal(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.deals() });
      queryClient.invalidateQueries({ queryKey: crmKeys.pipeline() });
    },
  });
}

export function useUpdateDealStage() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, stage }: { id: string; stage: string }) =>
      crmV2Service.updateDealStage(id, stage),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.deals() });
      queryClient.invalidateQueries({ queryKey: crmKeys.pipeline() });
    },
  });
}

// ============================================================
// ACTIVITIES HOOKS
// ============================================================

export function useActivities(filters?: {
  type?: string;
  status?: string;
  owner_id?: string;
  company_id?: string;
  deal_id?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: crmKeys.activitiesList(filters),
    queryFn: async () => {
      const response = await crmV2Service.getActivities(filters);
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch activities');
      }
      return response.data;
    },
    staleTime: 1000 * 60, // 1 minute
  });
}

// ============================================================
// ANALYTICS HOOKS
// ============================================================

export function usePipelineMetrics() {
  return useQuery({
    queryKey: crmKeys.pipeline(),
    queryFn: async () => {
      const response = await crmV2Service.getPipelineMetrics();
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch pipeline metrics');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 2,
    refetchInterval: 1000 * 60 * 5, // Refetch every 5 minutes
  });
}

export function useCRMDashboardStats() {
  return useQuery({
    queryKey: crmKeys.dashboardStats(),
    queryFn: async () => {
      const response = await crmV2Service.getDashboardStats();
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Failed to fetch CRM dashboard stats');
      }
      return response.data;
    },
    staleTime: 1000 * 60 * 2,
    refetchInterval: 1000 * 60 * 5,
  });
}

// ============================================================
// AI FEATURES HOOKS
// ============================================================

export function useCalculateLeadScore() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (contactId: string) => crmV2Service.calculateLeadScore(contactId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: crmKeys.contacts() });
    },
  });
}
