/**
 * Mock data for CRM dashboard
 * Replace with real API calls in production
 */

export interface Customer {
  id: number;
  name: string;
  email: string;
  status: 'Active' | 'Inactive' | 'Pending';
  company: string;
  phone: string;
  createdAt: string;
  revenue: number;
}

export interface Lead {
  id: number;
  name: string;
  email: string;
  source: string;
  status: 'New' | 'Contacted' | 'Qualified' | 'Lost';
  value: number;
  createdAt: string;
}

export interface SalesData {
  quarter: string;
  leads: number;
  conversions: number;
  revenue: number;
}

export interface RevenueData {
  month: string;
  revenue: number;
  expenses: number;
  profit: number;
}

export const mockCustomers: Customer[] = [
  {
    id: 1,
    name: 'John Doe',
    email: 'john.doe@example.com',
    status: 'Active',
    company: 'Acme Corp',
    phone: '+1 (555) 123-4567',
    createdAt: '2024-01-15',
    revenue: 125000,
  },
  {
    id: 2,
    name: 'Jane Smith',
    email: 'jane.smith@techstart.io',
    status: 'Active',
    company: 'TechStart Inc',
    phone: '+1 (555) 987-6543',
    createdAt: '2024-02-20',
    revenue: 89000,
  },
  {
    id: 3,
    name: 'Bob Johnson',
    email: 'bob.j@globalventures.com',
    status: 'Pending',
    company: 'Global Ventures',
    phone: '+1 (555) 456-7890',
    createdAt: '2024-03-10',
    revenue: 45000,
  },
  {
    id: 4,
    name: 'Alice Williams',
    email: 'alice.w@innovate.com',
    status: 'Active',
    company: 'Innovate Solutions',
    phone: '+1 (555) 234-5678',
    createdAt: '2024-01-05',
    revenue: 210000,
  },
  {
    id: 5,
    name: 'Charlie Brown',
    email: 'charlie@startup.xyz',
    status: 'Inactive',
    company: 'Startup XYZ',
    phone: '+1 (555) 876-5432',
    createdAt: '2023-11-22',
    revenue: 12000,
  },
];

export const mockLeads: Lead[] = [
  {
    id: 1,
    name: 'Emma Davis',
    email: 'emma.d@prospect.com',
    source: 'Website',
    status: 'New',
    value: 25000,
    createdAt: '2024-03-15',
  },
  {
    id: 2,
    name: 'Michael Chen',
    email: 'm.chen@enterprise.net',
    source: 'Referral',
    status: 'Qualified',
    value: 75000,
    createdAt: '2024-03-12',
  },
  {
    id: 3,
    name: 'Sarah Martinez',
    email: 'sarah.m@bigcorp.com',
    source: 'LinkedIn',
    status: 'Contacted',
    value: 50000,
    createdAt: '2024-03-10',
  },
  {
    id: 4,
    name: 'David Lee',
    email: 'david.lee@smallbiz.org',
    source: 'Cold Email',
    status: 'Lost',
    value: 15000,
    createdAt: '2024-02-28',
  },
];

export const mockSalesData: SalesData[] = [
  { quarter: 'Q1 2024', leads: 450, conversions: 67, revenue: 1250000 },
  { quarter: 'Q2 2024', leads: 520, conversions: 89, revenue: 1680000 },
  { quarter: 'Q3 2024', leads: 610, conversions: 105, revenue: 2100000 },
  { quarter: 'Q4 2024', leads: 580, conversions: 92, revenue: 1890000 },
];

export const mockRevenueData: RevenueData[] = [
  { month: 'Jan', revenue: 420000, expenses: 280000, profit: 140000 },
  { month: 'Feb', revenue: 380000, expenses: 260000, profit: 120000 },
  { month: 'Mar', revenue: 450000, expenses: 290000, profit: 160000 },
  { month: 'Apr', revenue: 520000, expenses: 310000, profit: 210000 },
  { month: 'May', revenue: 580000, expenses: 340000, profit: 240000 },
  { month: 'Jun', revenue: 580000, expenses: 330000, profit: 250000 },
  { month: 'Jul', revenue: 670000, expenses: 380000, profit: 290000 },
  { month: 'Aug', revenue: 710000, expenses: 400000, profit: 310000 },
  { month: 'Sep', revenue: 720000, expenses: 390000, profit: 330000 },
  { month: 'Oct', revenue: 650000, expenses: 370000, profit: 280000 },
  { month: 'Nov', revenue: 620000, expenses: 360000, profit: 260000 },
  { month: 'Dec', revenue: 620000, expenses: 350000, profit: 270000 },
];

export interface DashboardMetrics {
  totalLeads: number;
  conversionRate: number;
  totalRevenue: number;
  activeCustomers: number;
}

export const mockDashboardMetrics: DashboardMetrics = {
  totalLeads: 1200,
  conversionRate: 15.2,
  totalRevenue: 6820000,
  activeCustomers: 342,
};
