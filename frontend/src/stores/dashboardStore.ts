import { create } from 'zustand';
import type {
  Customer,
  Lead,
  SalesData,
  RevenueData,
  DashboardMetrics,
} from '@/utils/dashboardMockData';
import { dashboardApi } from '@/utils/dashboardApi';

interface DashboardState {
  // Data
  metrics: DashboardMetrics | null;
  customers: Customer[];
  leads: Lead[];
  salesData: SalesData[];
  revenueData: RevenueData[];

  // UI State
  isLoading: boolean;
  error: string | null;
  sidebarOpen: boolean;

  // Actions
  fetchDashboardData: () => Promise<void>;
  fetchCustomers: () => Promise<void>;
  fetchLeads: () => Promise<void>;
  addLead: (lead: Omit<Lead, 'id' | 'createdAt'>) => Promise<void>;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
}

/**
 * Global dashboard state management with Zustand
 */
export const useDashboardStore = create<DashboardState>((set, get) => ({
  // Initial state
  metrics: null,
  customers: [],
  leads: [],
  salesData: [],
  revenueData: [],
  isLoading: false,
  error: null,
  sidebarOpen: true,

  /**
   * Fetch all dashboard data in parallel
   */
  fetchDashboardData: async () => {
    set({ isLoading: true, error: null });
    try {
      const [metrics, customers, leads, salesData, revenueData] =
        await Promise.all([
          dashboardApi.getDashboardMetrics(),
          dashboardApi.getCustomers(),
          dashboardApi.getLeads(),
          dashboardApi.getSalesData(),
          dashboardApi.getRevenueData(),
        ]);

      set({
        metrics,
        customers,
        leads,
        salesData,
        revenueData,
        isLoading: false,
      });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to fetch data',
        isLoading: false,
      });
    }
  },

  /**
   * Fetch customers only
   */
  fetchCustomers: async () => {
    try {
      const customers = await dashboardApi.getCustomers();
      set({ customers });
    } catch (error) {
      set({
        error:
          error instanceof Error ? error.message : 'Failed to fetch customers',
      });
    }
  },

  /**
   * Fetch leads only
   */
  fetchLeads: async () => {
    try {
      const leads = await dashboardApi.getLeads();
      set({ leads });
    } catch (error) {
      set({
        error:
          error instanceof Error ? error.message : 'Failed to fetch leads',
      });
    }
  },

  /**
   * Add new lead
   */
  addLead: async (leadData) => {
    try {
      const newLead = await dashboardApi.createLead(leadData);
      set({ leads: [...get().leads, newLead] });
    } catch (error) {
      set({
        error: error instanceof Error ? error.message : 'Failed to add lead',
      });
      throw error;
    }
  },

  /**
   * Toggle sidebar open/closed
   */
  toggleSidebar: () => {
    set({ sidebarOpen: !get().sidebarOpen });
  },

  /**
   * Set sidebar state directly
   */
  setSidebarOpen: (open) => {
    set({ sidebarOpen: open });
  },
}));
