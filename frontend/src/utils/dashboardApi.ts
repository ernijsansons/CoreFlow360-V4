import {
  mockCustomers,
  mockLeads,
  mockSalesData,
  mockRevenueData,
  mockDashboardMetrics,
  type Customer,
  type Lead,
  type SalesData,
  type RevenueData,
  type DashboardMetrics,
} from './dashboardMockData';

/**
 * Simulates network delay for realistic mock API
 */
const simulateDelay = (ms: number = 500): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Mock API client for dashboard data
 * Replace with real API calls (e.g., fetch, axios) in production
 */
export const dashboardApi = {
  /**
   * Fetch dashboard metrics
   */
  getDashboardMetrics: async (): Promise<DashboardMetrics> => {
    await simulateDelay(300);
    return mockDashboardMetrics;
  },

  /**
   * Fetch all customers
   */
  getCustomers: async (): Promise<Customer[]> => {
    await simulateDelay();
    return mockCustomers;
  },

  /**
   * Fetch all leads
   */
  getLeads: async (): Promise<Lead[]> => {
    await simulateDelay();
    return mockLeads;
  },

  /**
   * Fetch sales data for charts
   */
  getSalesData: async (): Promise<SalesData[]> => {
    await simulateDelay();
    return mockSalesData;
  },

  /**
   * Fetch revenue trend data
   */
  getRevenueData: async (): Promise<RevenueData[]> => {
    await simulateDelay();
    return mockRevenueData;
  },

  /**
   * Create new lead (mock)
   */
  createLead: async (lead: Omit<Lead, 'id' | 'createdAt'>): Promise<Lead> => {
    await simulateDelay(600);
    return {
      ...lead,
      id: Date.now(),
      createdAt: new Date().toISOString(),
    };
  },

  /**
   * Update customer status (mock)
   */
  updateCustomerStatus: async (
    id: number,
    status: Customer['status']
  ): Promise<Customer> => {
    await simulateDelay(400);
    const customer = mockCustomers.find((c) => c.id === id);
    if (!customer) throw new Error('Customer not found');
    return { ...customer, status };
  },
};
