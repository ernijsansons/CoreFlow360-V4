/**
 * Department Profiler
 * Analyzes department data to provide operational context and capabilities
 */
import type { D1Database } from '@cloudflare/workers-types';
import {
  DepartmentProfile,
  DepartmentCapabilities
} from './types';
import { Logger } from '../../shared/logger';

export class DepartmentProfiler {
  private logger: Logger;
  private db: D1Database;

  // Department-specific capability mappings
  private departmentCapabilities: Record<string, DepartmentCapabilities> = {
    finance: {
      allowedOperations: [
        'financial_analysis', 'budget_planning', 'cost_analysis', 'revenue_analysis',
        'cash_flow_management', 'financial_reporting', 'tax_planning', 'audit_support',
        'investment_analysis', 'risk_assessment', 'compliance_monitoring', 'invoice_processing'
      ],
      restrictedOperations: ['employee_management', 'marketing_campaigns', 'sales_operations'],
      dataAccess: {
        read: ['financial_data', 'budget_data', 'cost_centers', 'revenue_data', 'department_data'],
        write: ['financial_reports', 'budget_allocations', 'cost_analysis', 'financial_forecasts'],
        delete: ['financial_drafts', 'temp_calculations']
      },
      approvalRequired: [
        'budget_changes_over_10000', 'new_expense_categories', 'financial_policy_changes',
        'audit_requests', 'external_financial_reporting'
      ],
      costLimits: {
        daily: 1000,
        monthly: 25000,
        quarterly: 75000
      },
      escalationRules: []
    },

    hr: {
      allowedOperations: [
        'resume_analysis', 'employee_onboarding', 'performance_management', 'compensation_analysis',
        'benefits_administration', 'policy_development', 'compliance_monitoring', 'training_coordination',
        'employee_relations', 'recruitment_support', 'organizational_development'
      ],
      restrictedOperations: ['financial_analysis', 'sales_operations', 'technical_operations'],
      dataAccess: {
        read: ['employee_data', 'hr_policies', 'benefits_data', 'training_records', 'performance_data'],
        write: ['hr_reports', 'employee_records', 'policy_updates', 'training_plans'],
        delete: ['draft_policies', 'temp_employee_data']
      },
      approvalRequired: [
        'salary_changes', 'policy_changes', 'disciplinary_actions', 'hiring_decisions',
        'termination_requests', 'benefit_changes'
      ],
      costLimits: {
        daily: 500,
        monthly: 15000,
        quarterly: 45000
      },
      escalationRules: []
    },

    sales: {
      allowedOperations: [
        'lead_generation', 'prospect_qualification', 'sales_presentations', 'negotiation',
        'customer_relationship_management', 'sales_forecasting', 'market_analysis', 'competitive_intelligence',
        'pricing_strategy', 'contract_management', 'customer_success', 'sales_reporting'
      ],
      restrictedOperations: ['financial_analysis', 'hr_operations', 'technical_operations'],
      dataAccess: {
        read: ['customer_data', 'sales_data', 'market_data', 'competitor_data', 'product_data'],
        write: ['sales_reports', 'customer_notes', 'sales_forecasts', 'pricing_proposals'],
        delete: ['draft_proposals', 'temp_customer_data']
      },
      approvalRequired: [
        'pricing_changes_over_10_percent', 'contract_modifications', 'discount_approvals',
        'new_customer_terms', 'sales_policy_changes'
      ],
      costLimits: {
        daily: 2000,
        monthly: 50000,
        quarterly: 150000
      },
      escalationRules: []
    },

    marketing: {
      allowedOperations: [
        'brand_management', 'content_creation', 'digital_marketing', 'social_media_management',
        'email_marketing', 'seo_optimization', 'advertising', 'market_research',
        'campaign_management', 'analytics', 'customer_segmentation', 'lead_nurturing'
      ],
      restrictedOperations: ['financial_analysis', 'hr_operations', 'technical_operations'],
      dataAccess: {
        read: ['customer_data', 'marketing_data', 'campaign_data', 'analytics_data', 'content_data'],
        write: ['marketing_reports', 'campaign_plans', 'content_assets', 'analytics_dashboards'],
        delete: ['draft_content', 'temp_campaign_data']
      },
      approvalRequired: [
        'campaign_budget_over_5000', 'brand_changes', 'external_agency_contracts',
        'marketing_policy_changes', 'content_approval'
      ],
      costLimits: {
        daily: 1000,
        monthly: 30000,
        quarterly: 90000
      },
      escalationRules: []
    },

    operations: {
      allowedOperations: [
        'process_optimization', 'supply_chain_management', 'quality_control', 'inventory_management',
        'vendor_management', 'project_management', 'resource_planning', 'performance_metrics',
        'cost_reduction', 'risk_management', 'compliance_monitoring', 'workflow_automation'
      ],
      restrictedOperations: ['financial_analysis', 'hr_operations', 'sales_operations'],
      dataAccess: {
        read: ['operational_data', 'vendor_data', 'inventory_data', 'process_data', 'quality_data'],
        write: ['operational_reports', 'process_documentation', 'vendor_contracts', 'quality_reports'],
        delete: ['draft_processes', 'temp_operational_data']
      },
      approvalRequired: [
        'vendor_contracts_over_10000', 'process_changes', 'quality_standard_changes',
        'operational_policy_changes', 'resource_allocation'
      ],
      costLimits: {
        daily: 1500,
        monthly: 40000,
        quarterly: 120000
      },
      escalationRules: []
    },

    it: {
      allowedOperations: [
        'system_administration', 'software_development', 'cybersecurity', 'database_management',
        'network_management', 'cloud_computing', 'devops', 'technical_support',
        'project_management', 'technology_evaluation', 'compliance_monitoring', 'data_management'
      ],
      restrictedOperations: ['financial_analysis', 'hr_operations', 'sales_operations'],
      dataAccess: {
        read: ['system_data', 'user_data', 'security_data', 'infrastructure_data', 'application_data'],
        write: ['system_reports', 'security_reports', 'infrastructure_documentation', 'user_management'],
        delete: ['temp_system_data', 'draft_documentation']
      },
      approvalRequired: [
        'system_changes', 'security_policy_changes', 'infrastructure_investments',
        'data_access_changes', 'external_vendor_contracts'
      ],
      costLimits: {
        daily: 2000,
        monthly: 60000,
        quarterly: 180000
      },
      escalationRules: []
    }
  };

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Analyze department and generate comprehensive profile
   */
  async analyzeDepartment(
    businessId: string,
    departmentName: string
  ): Promise<DepartmentProfile> {
    try {
      this.logger.debug('Starting department analysis', {
        businessId,
        departmentName
      });

      // Get department data from database
      const departmentData = await this.getDepartmentData(businessId, departmentName);
      
      // Analyze department capabilities
      const capabilities = await this.analyzeCapabilities(departmentName, departmentData);
      
      // Generate department profile
      const profile: DepartmentProfile = {
        basic: {
          name: departmentName,
          code: departmentData.code || '',
          description: departmentData.description || '',
          type: departmentData.type || 'support',
        },
        team: {
          size: departmentData.teamSize || 0,
          roles: [],
          skills: [],
          averageExperience: 0,
        },
        operations: {
          primaryFunctions: await this.identifyResponsibilities(departmentName, departmentData),
          keyProcesses: [],
          tools: [],
          kpis: [],
          budget: {
            currency: 'USD',
            allocation: {},
          },
        },
        workflows: {
          approvalLevels: 0,
          automationLevel: 'low',
          commonTasks: [],
          painPoints: [],
          efficiency: {
            score: 0,
            bottlenecks: [],
            improvements: [],
          },
        },
        relationships: {
          upstreamDepartments: [],
          downstreamDepartments: [],
          externalPartners: [],
          collaborationStrength: {},
        },
      };

      this.logger.info('Department analysis completed', {
        businessId,
        departmentName,
        teamSize: profile.team.size,
      });

      return profile;

    } catch (error) {
      this.logger.error('Department analysis failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId,
        departmentName
      });
      throw error;
    }
  }

  /**
   * Get department capabilities based on name and data
   */
  async getDepartmentCapabilities(departmentName: string): Promise<DepartmentCapabilities> {
    const normalizedName = departmentName.toLowerCase();
    const capabilities = this.departmentCapabilities[normalizedName as keyof typeof this.departmentCapabilities];
    
    if (!capabilities) {
      // Return default capabilities for unknown departments
      return {
        allowedOperations: ['general_operations', 'reporting', 'data_analysis'],
        restrictedOperations: ['financial_analysis', 'hr_operations', 'technical_operations'],
        dataAccess: {
          read: ['department_data', 'general_data'],
          write: ['department_reports', 'general_reports'],
          delete: ['draft_data', 'temp_data']
        },
        approvalRequired: ['policy_changes', 'budget_changes', 'external_contracts'],
        costLimits: {
          daily: 500,
          monthly: 15000,
          quarterly: 45000
        },
        escalationRules: []
      };
    }

    return capabilities;
  }

  /**
   * Check if operation is allowed for department
   */
  async isOperationAllowed(
    departmentName: string,
    operation: string
  ): Promise<boolean> {
    const capabilities = await this.getDepartmentCapabilities(departmentName);
    return capabilities.allowedOperations.includes(operation);
  }

  /**
   * Check if data access is allowed for department
   */
  async isDataAccessAllowed(
    departmentName: string,
    dataType: string,
    accessType: 'read' | 'write' | 'delete'
  ): Promise<boolean> {
    const capabilities = await this.getDepartmentCapabilities(departmentName);
    return capabilities.dataAccess[accessType].includes(dataType);
  }

  /**
   * Check if operation requires approval
   */
  async requiresApproval(
    departmentName: string,
    operation: string
  ): Promise<boolean> {
    const capabilities = await this.getDepartmentCapabilities(departmentName);
    return capabilities.approvalRequired.includes(operation);
  }

  /**
   * Check if cost is within department limits
   */
  async isCostWithinLimits(
    departmentName: string,
    cost: number,
    period: 'daily' | 'monthly' | 'quarterly'
  ): Promise<boolean> {
    const capabilities = await this.getDepartmentCapabilities(departmentName);
    return cost <= capabilities.costLimits[period];
  }

  /**
   * Get department performance metrics
   */
  async getPerformanceMetrics(
    businessId: string,
    departmentName: string,
    period: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly' = 'monthly'
  ): Promise<Record<string, number>> {
    try {
      const metrics = await this.db.prepare(`
        SELECT 
          COUNT(*) as total_operations,
          AVG(completion_time) as avg_completion_time,
          SUM(success_count) as total_successes,
          SUM(error_count) as total_errors,
          AVG(efficiency_score) as avg_efficiency
        FROM department_metrics 
        WHERE business_id = ? 
        AND department = ? 
        AND period = ?
        AND created_at >= ?
      `).bind(
        businessId,
        departmentName,
        period,
        this.getPeriodStartDate(period)
      ).first() as { total_operations: number; avg_completion_time: number; total_successes: number; total_errors: number; avg_efficiency: number; } | null;

      if (!metrics) {
        return {
          totalOperations: 0,
          avgCompletionTime: 0,
          totalSuccesses: 0,
          totalErrors: 0,
          avgEfficiency: 0,
          successRate: 0
        };
      }

      return {
        totalOperations: metrics.total_operations || 0,
        avgCompletionTime: metrics.avg_completion_time || 0,
        totalSuccesses: metrics.total_successes || 0,
        totalErrors: metrics.total_errors || 0,
        avgEfficiency: metrics.avg_efficiency || 0,
        successRate: metrics.total_operations ? 
          (metrics.total_successes / metrics.total_operations) * 100 : 0
      };

    } catch (error) {
      this.logger.error('Failed to get performance metrics', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId,
        departmentName,
        period
      });
      return {};
    }
  }

  /**
   * Get department collaboration data
   */
  async getCollaborationData(
    businessId: string,
    departmentName: string
  ): Promise<Record<string, any>> {
    try {
      const data = await this.db.prepare(`
        SELECT 
          COUNT(DISTINCT user_id) as active_users,
          COUNT(*) as total_interactions,
          AVG(response_time) as avg_response_time,
          COUNT(DISTINCT project_id) as active_projects
        FROM collaboration_logs 
        WHERE business_id = ? 
        AND department = ?
        AND created_at >= ?
      `).bind(
        businessId,
        departmentName,
        new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() // Last 30 days
      ).first();

      return {
        activeUsers: data?.active_users || 0,
        totalInteractions: data?.total_interactions || 0,
        avgResponseTime: data?.avg_response_time || 0,
        activeProjects: data?.active_projects || 0
      };

    } catch (error) {
      this.logger.error('Failed to get collaboration data', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId,
        departmentName
      });
      return {};
    }
  }

  private async getDepartmentData(businessId: string, departmentName: string): Promise<any> {
    try {
      const data = await this.db.prepare(`
        SELECT * FROM departments 
        WHERE business_id = ? AND name = ?
      `).bind(businessId, departmentName).first();

      return data || {};

    } catch (error) {
      this.logger.error('Failed to get department data', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId,
        departmentName
      });
      return {};
    }
  }

  private async analyzeCapabilities(departmentName: string, departmentData: any): Promise<DepartmentCapabilities> {
    return await this.getDepartmentCapabilities(departmentName);
  }

  private async identifyResponsibilities(departmentName: string, departmentData: any): Promise<string[]> {
    const capabilities = await this.getDepartmentCapabilities(departmentName);
    return capabilities.allowedOperations;
  }

  private async identifyGoals(departmentName: string, departmentData: any): Promise<string[]> {
    // Mock implementation - in real scenario, this would analyze department data
    const goals: Record<string, string[]> = {
      finance: ['Improve financial accuracy', 'Reduce processing time', 'Enhance compliance'],
      hr: ['Improve employee satisfaction', 'Reduce turnover', 'Enhance training programs'],
      sales: ['Increase revenue', 'Improve customer satisfaction', 'Expand market reach'],
      marketing: ['Increase brand awareness', 'Generate more leads', 'Improve conversion rates'],
      operations: ['Improve efficiency', 'Reduce costs', 'Enhance quality'],
      it: ['Improve system reliability', 'Enhance security', 'Increase automation']
    };

    return goals[departmentName.toLowerCase() as keyof typeof goals] || ['Improve performance', 'Enhance efficiency'];
  }

  private async identifyChallenges(departmentName: string, departmentData: any): Promise<string[]> {
    // Mock implementation - in real scenario, this would analyze department data
    const challenges: Record<string, string[]> = {
      finance: ['Regulatory compliance', 'Data accuracy', 'Process automation'],
      hr: ['Talent retention', 'Skill gaps', 'Policy compliance'],
      sales: ['Market competition', 'Lead quality', 'Customer retention'],
      marketing: ['Budget constraints', 'ROI measurement', 'Content creation'],
      operations: ['Process optimization', 'Resource allocation', 'Quality control'],
      it: ['Security threats', 'System maintenance', 'Technology updates']
    };

    return challenges[departmentName.toLowerCase() as keyof typeof challenges] || ['Resource constraints', 'Process improvement'];
  }

  private async identifyMetrics(departmentName: string, departmentData: any): Promise<string[]> {
    // Mock implementation - in real scenario, this would analyze department data
    const metrics: Record<string, string[]> = {
      finance: ['Revenue growth', 'Cost reduction', 'Compliance rate'],
      hr: ['Employee satisfaction', 'Turnover rate', 'Training completion'],
      sales: ['Sales growth', 'Customer acquisition', 'Conversion rate'],
      marketing: ['Lead generation', 'Brand awareness', 'Campaign ROI'],
      operations: ['Efficiency rate', 'Quality score', 'Cost per unit'],
      it: ['System uptime', 'Security incidents', 'User satisfaction']
    };

    return metrics[departmentName.toLowerCase() as keyof typeof metrics] || ['Performance score', 'Efficiency rate'];
  }

  private async calculatePerformanceScore(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would calculate based on actual metrics
    return Math.floor(Math.random() * 40) + 60; // 60-100
  }

  private async calculateEfficiencyRating(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would calculate based on actual metrics
    return Math.floor(Math.random() * 30) + 70; // 70-100
  }

  private async assessCollaborationLevel(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would assess based on actual data
    return Math.floor(Math.random() * 40) + 60; // 60-100
  }

  private async calculateInnovationIndex(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would calculate based on actual data
    return Math.floor(Math.random() * 50) + 50; // 50-100
  }

  private async assessRiskLevel(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would assess based on actual data
    return Math.floor(Math.random() * 30) + 20; // 20-50
  }

  private async assessComplianceStatus(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would assess based on actual data
    return Math.floor(Math.random() * 20) + 80; // 80-100
  }

  private async assessTechnologyAdoption(departmentName: string, departmentData: any): Promise<number> {
    // Mock implementation - in real scenario, this would assess based on actual data
    return Math.floor(Math.random() * 40) + 60; // 60-100
  }

  private async identifyTrainingNeeds(departmentName: string, departmentData: any): Promise<string[]> {
    // Mock implementation - in real scenario, this would identify based on actual data
    return ['Technical skills', 'Soft skills', 'Industry knowledge'];
  }

  private async identifyImprovementOpportunities(departmentName: string, departmentData: any): Promise<string[]> {
    // Mock implementation - in real scenario, this would identify based on actual data
    return ['Process automation', 'Skill development', 'Technology adoption'];
  }

  private getPeriodStartDate(period: string): string {
    const now = new Date();
    let startDate: Date;

    switch (period) {
      case 'daily':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'weekly':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'monthly':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case 'quarterly':
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      case 'yearly':
        startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }

    return startDate.toISOString();
  }
}

