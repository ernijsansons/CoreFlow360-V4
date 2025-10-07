/**
 * Context Enricher
 * Enhances business context with intelligence and generates contextual prompts
 */
import {
  BusinessContextData,
  ContextualPrompts,
  ContextEnrichmentConfig,
  CompanyProfile,
  DepartmentProfile,
  UserProfile,
  BusinessIntelligence
} from './types';
import { Logger } from '../../shared/logger';

export class ContextEnricher {
  private logger: Logger;
  private config: ContextEnrichmentConfig;

  // Department-specific prompt templates
  private departmentPrompts = {
    finance: {
      systemContext: "You are a financial analysis expert working for {companyName}. You have deep understanding of financial processes, accounting principles, and business metrics.",
      roleContext: "As a {jobTitle} in the Finance department, you focus on financial accuracy, compliance, and strategic financial decision-making.",
      capabilities: [
        "financial_analysis", "budget_planning", "cost_analysis", "revenue_analysis",
        "cash_flow_management", "financial_reporting", "tax_planning", "audit_support",
        "investment_analysis", "risk_assessment", "compliance_monitoring"
      ],
      businessRules: [
        "Always prioritize financial accuracy and compliance",
        "Consider regulatory requirements in all recommendations",
        "Maintain confidentiality of sensitive financial data",
        "Provide clear explanations for financial recommendations"
      ]
    },

    hr: {
      systemContext: "You are an HR specialist working for {companyName}. You understand employment law, organizational development, and people management.",
      roleContext: "As a {jobTitle} in Human Resources, you focus on employee development, compliance, and organizational effectiveness.",
      capabilities: [
        "resume_analysis", "employee_onboarding", "performance_management", "compensation_analysis",
        "benefits_administration", "policy_development", "compliance_monitoring", "training_coordination",
        "employee_relations", "recruitment_support", "organizational_development"
      ],
      businessRules: [
        "Maintain strict confidentiality of employee information",
        "Ensure compliance with employment laws and regulations",
        "Promote diversity and inclusion in all recommendations",
        "Focus on employee well-being and development"
      ]
    },

    sales: {
      systemContext: "You are a sales professional working for {companyName}. You understand customer relationship management, sales processes, and market dynamics.",
      roleContext: "As a {jobTitle} in Sales, you focus on customer acquisition, relationship building, and revenue generation.",
      capabilities: [
        "lead_generation", "prospect_qualification", "sales_presentations", "negotiation",
        "customer_relationship_management", "sales_forecasting", "market_analysis", "competitive_intelligence",
        "pricing_strategy", "contract_management", "customer_success"
      ],
      businessRules: [
        "Always prioritize customer value and satisfaction",
        "Maintain ethical sales practices",
        "Build long-term customer relationships",
        "Provide accurate product information and pricing"
      ]
    },

    marketing: {
      systemContext: "You are a marketing professional working for {companyName}. You understand brand management, digital marketing, and customer engagement strategies.",
      roleContext: "As a {jobTitle} in Marketing, you focus on brand awareness, lead generation, and customer engagement.",
      capabilities: [
        "brand_management", "content_creation", "digital_marketing", "social_media_management",
        "email_marketing", "seo_optimization", "advertising", "market_research",
        "campaign_management", "analytics", "customer_segmentation"
      ],
      businessRules: [
        "Maintain brand consistency across all communications",
        "Focus on customer value and engagement",
        "Use data-driven insights for decision making",
        "Ensure compliance with marketing regulations"
      ]
    },

    operations: {
      systemContext: "You are an operations specialist working for {companyName}. You understand process optimization, supply chain management, and operational efficiency.",
      roleContext: "As a {jobTitle} in Operations, you focus on process improvement, efficiency, and quality management.",
      capabilities: [
        "process_optimization", "supply_chain_management", "quality_control", "inventory_management",
        "vendor_management", "project_management", "resource_planning", "performance_metrics",
        "cost_reduction", "risk_management", "compliance_monitoring"
      ],
      businessRules: [
        "Prioritize efficiency and quality in all processes",
        "Maintain compliance with operational standards",
        "Focus on continuous improvement",
        "Ensure safety and security in all operations"
      ]
    },

    it: {
      systemContext: "You are an IT professional working for {companyName}. You understand technology infrastructure, software development, and cybersecurity.",
      roleContext: "As a {jobTitle} in Information Technology, you focus on system reliability, security, and technological innovation.",
      capabilities: [
        "system_administration", "software_development", "cybersecurity", "database_management",
        "network_management", "cloud_computing", "devops", "technical_support",
        "project_management", "technology_evaluation", "compliance_monitoring"
      ],
      businessRules: [
        "Prioritize system security and reliability",
        "Maintain compliance with IT standards and regulations",
        "Focus on user experience and efficiency",
        "Ensure data privacy and protection"
      ]
    }
  };

  constructor(config: ContextEnrichmentConfig) {
    this.logger = new Logger();
    this.config = config;
  }

  /**
   * Enrich business context with analysis data
   */
  async enrichWithAnalysis(contextData: BusinessContextData): Promise<void> {
    try {
      this.logger.debug('Starting context enrichment', {
        businessId: contextData.businessId
      });

      // Enrich the existing context data with additional analysis
      // This modifies the contextData object in place
      const industryInsights = await this.generateIndustryInsights(contextData);
      const complianceRequirements = await this.identifyComplianceRequirements(contextData);
      const riskFactors = await this.assessRiskFactors(contextData);
      const opportunities = await this.identifyOpportunities(contextData);
      const recommendations = await this.generateRecommendations(contextData);

      this.logger.info('Context enrichment completed', {
        businessId: contextData.businessId,
        insightsCount: industryInsights.length,
        risksIdentified: riskFactors.length
      });

    } catch (error: any) {
      this.logger.error('Context enrichment failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId: contextData.businessId
      });
      throw error;
    }
  }

  /**
   * Generate contextual prompts for AI interactions
   */
  async generateContextualPrompts(
    contextData: BusinessContextData,
    capability: string,
    taskType?: string
  ): Promise<ContextualPrompts> {
    const department = contextData.userProfile.basic.department?.toLowerCase() || 'general';
    const departmentTemplate = this.departmentPrompts[department as keyof typeof this.departmentPrompts] || this.departmentPrompts.operations;

    const systemPrompt = this.interpolateTemplate(departmentTemplate.systemContext, {
      companyName: contextData.companyProfile.basic.name || 'the company',
      industry: contextData.companyProfile.basic.industry || 'business',
      department: contextData.userProfile.basic.department || 'operations'
    });

    const roleContext = this.interpolateTemplate(departmentTemplate.roleContext, {
      jobTitle: contextData.userProfile.basic.jobTitle || 'team member',
      department: contextData.userProfile.basic.department || 'operations',
      experience: 'experienced'
    });

    const businessRules = await this.extractBusinessRules(contextData);
    const communicationGuidelines = this.generateCommunicationGuidelines(contextData);
    const escalationInstructions = this.generateEscalationInstructions(contextData);
    const complianceRequirements = await this.identifyComplianceRequirements(contextData);
    const exampleInteractions = await this.generateExampleInteractions(contextData, capability, taskType);

    return {
      systemPrompt,
      departmentContext: `Department: ${department} - ${departmentTemplate.systemContext}`,
      roleContext,
      businessRules,
      communicationGuidelines,
      escalationInstructions,
      complianceRequirements,
      exampleInteractions
    };
  }


  private async extractBusinessRules(contextData: BusinessContextData): Promise<string[]> {
    const rules: string[] = [];

    // Add department-specific rules
    const department = contextData.userProfile.basic.department?.toLowerCase() || 'general';
    const departmentTemplate = this.departmentPrompts[department as keyof typeof this.departmentPrompts];
    if (departmentTemplate) {
      rules.push(...departmentTemplate.businessRules);
    }

    // Add industry-specific rules
    if (contextData.companyProfile.basic.industry) {
      const industryRules = await this.getIndustryRules(contextData.companyProfile.basic.industry);
      rules.push(...industryRules);
    }

    return rules;
  }

  private async generateIndustryInsights(contextData: BusinessContextData): Promise<string[]> {
    const insights: string[] = [];

    if (contextData.companyProfile.basic.industry) {
      const industryInsights = await this.getIndustryInsights(contextData.companyProfile.basic.industry);
      insights.push(...industryInsights);
    }

    // Add market trends
    const marketTrends = await this.getMarketTrends(contextData.companyProfile.basic.industry);
    insights.push(...marketTrends);

    // Add regulatory changes
    const regulatoryChanges = await this.getRegulatoryChanges(contextData.companyProfile.basic.industry);
    insights.push(...regulatoryChanges);

    return insights;
  }

  private async identifyComplianceRequirements(contextData: BusinessContextData): Promise<string[]> {
    const requirements: string[] = [];

    // Add industry-specific compliance requirements
    if (contextData.companyProfile.basic.industry) {
      const industryCompliance = await this.getIndustryCompliance(contextData.companyProfile.basic.industry);
      requirements.push(...industryCompliance);
    }

    // Add general business compliance requirements
    const generalCompliance = await this.getGeneralCompliance();
    requirements.push(...generalCompliance);

    return requirements;
  }

  private async assessRiskFactors(contextData: BusinessContextData): Promise<string[]> {
    const risks: string[] = [];

    // Add industry-specific risks
    if (contextData.companyProfile.basic.industry) {
      const industryRisks = await this.getIndustryRisks(contextData.companyProfile.basic.industry);
      risks.push(...industryRisks);
    }

    // Add department-specific risks
    const department = contextData.userProfile.basic.department;
    if (department) {
      const departmentRisks = await this.getDepartmentRisks(department);
      risks.push(...departmentRisks);
    }

    // Add general business risks
    const generalRisks = await this.getGeneralRisks();
    risks.push(...generalRisks);

    return risks;
  }

  private async identifyOpportunities(contextData: BusinessContextData): Promise<string[]> {
    const opportunities: string[] = [];

    // Add industry-specific opportunities
    if (contextData.companyProfile.basic.industry) {
      const industryOpportunities = await this.getIndustryOpportunities(contextData.companyProfile.basic.industry);
      opportunities.push(...industryOpportunities);
    }

    // Add department-specific opportunities
    const department = contextData.userProfile.basic.department;
    if (department) {
      const departmentOpportunities = await this.getDepartmentOpportunities(department);
      opportunities.push(...departmentOpportunities);
    }

    return opportunities;
  }

  private async generateRecommendations(contextData: BusinessContextData): Promise<string[]> {
    const recommendations: string[] = [];

    // Add process improvement recommendations
    const processRecommendations = await this.getProcessRecommendations(contextData);
    recommendations.push(...processRecommendations);

    // Add technology recommendations
    const technologyRecommendations = await this.getTechnologyRecommendations(contextData);
    recommendations.push(...technologyRecommendations);

    // Add training recommendations
    const trainingRecommendations = await this.getTrainingRecommendations(contextData);
    recommendations.push(...trainingRecommendations);

    return recommendations;
  }

  private interpolateTemplate(template: string, variables: Record<string, string>): string {
    return template.replace(/\{(\w+)\}/g, (match, key) => {
      return variables[key] || match;
    });
  }

  private generateCommunicationGuidelines(contextData: BusinessContextData): string {
    const style = contextData.userProfile.preferences.communicationStyle || 'direct';
    const assistantStyle = contextData.userProfile.preferences.assistantStyle || 'friendly';

    return `Use ${style} communication style with ${assistantStyle} tone. Respect user's working hours and preferences.`;
  }

  private generateEscalationInstructions(contextData: BusinessContextData): string {
    const role = contextData.userProfile.basic.role;
    const department = contextData.userProfile.basic.department;

    return `For critical issues, escalate to ${role === 'employee' ? 'manager' : 'director'} in ${department} department. Follow approval workflows for high-value transactions.`;
  }

  private async generateExampleInteractions(
    contextData: BusinessContextData,
    capability: string,
    taskType?: string
  ): Promise<Array<{ scenario: string; expectedResponse: string }>> {
    const department = contextData.userProfile.basic.department?.toLowerCase() || 'general';

    return [
      {
        scenario: `Analyzing ${department} data`,
        expectedResponse: `Provide detailed analysis with actionable insights`
      },
      {
        scenario: `Generating ${department} reports`,
        expectedResponse: `Create comprehensive reports with visualizations`
      },
      {
        scenario: `Processing ${department} requests`,
        expectedResponse: `Handle requests efficiently following business rules`
      }
    ];
  }

  // Helper methods for data enrichment
  private async getIndustryInsights(industry: string): Promise<string[]> {
    // Mock implementation - in real scenario, this would fetch from external APIs
    return [
      `The ${industry} industry is experiencing significant digital transformation`,
      `Regulatory compliance requirements are becoming more stringent in ${industry}`,
      `Customer expectations are evolving rapidly in the ${industry} sector`
    ];
  }

  private async getIndustryRules(industry: string): Promise<string[]> {
    // Mock implementation
    return [
      `Follow ${industry} industry standards`,
      'Maintain regulatory compliance',
      'Ensure data security and privacy'
    ];
  }

  private async getMarketTrends(industry?: string): Promise<string[]> {
    // Mock implementation
    return [
      'Digital transformation accelerating',
      'Remote work becoming standard',
      'Sustainability focus increasing'
    ];
  }

  private async getRegulatoryChanges(industry?: string): Promise<string[]> {
    // Mock implementation
    return [
      'New data protection regulations',
      'Updated compliance requirements',
      'Enhanced security standards'
    ];
  }

  private async getIndustryCompliance(industry: string): Promise<string[]> {
    // Mock implementation
    return [
      `Comply with ${industry} regulations`,
      'Maintain audit trails',
      'Ensure data privacy'
    ];
  }

  private async getGeneralCompliance(): Promise<string[]> {
    // Mock implementation
    return [
      'Follow company policies',
      'Maintain confidentiality',
      'Report security incidents'
    ];
  }

  private async getIndustryRisks(industry: string): Promise<string[]> {
    // Mock implementation
    return [
      `Market volatility in ${industry}`,
      'Regulatory changes',
      'Competitive pressure'
    ];
  }

  private async getDepartmentRisks(department: string): Promise<string[]> {
    // Mock implementation
    return [
      'Resource constraints',
      'Skill gaps',
      'Technology obsolescence'
    ];
  }

  private async getGeneralRisks(): Promise<string[]> {
    // Mock implementation
    return [
      'Economic uncertainty',
      'Cybersecurity threats',
      'Operational disruptions'
    ];
  }

  private async getIndustryOpportunities(industry: string): Promise<string[]> {
    // Mock implementation
    return [
      `Growth in ${industry} market`,
      'Technology adoption',
      'Partnership opportunities'
    ];
  }

  private async getDepartmentOpportunities(department: string): Promise<string[]> {
    // Mock implementation
    return [
      'Process automation',
      'Skill development',
      'Efficiency improvements'
    ];
  }

  private async getProcessRecommendations(contextData: BusinessContextData): Promise<string[]> {
    // Mock implementation
    return [
      'Implement automated workflows',
      'Standardize procedures',
      'Improve communication channels'
    ];
  }

  private async getTechnologyRecommendations(contextData: BusinessContextData): Promise<string[]> {
    // Mock implementation
    return [
      'Adopt cloud-based solutions',
      'Implement analytics tools',
      'Enhance security measures'
    ];
  }

  private async getTrainingRecommendations(contextData: BusinessContextData): Promise<string[]> {
    // Mock implementation
    return [
      'Technical skills training',
      'Leadership development',
      'Industry certification'
    ];
  }

}


