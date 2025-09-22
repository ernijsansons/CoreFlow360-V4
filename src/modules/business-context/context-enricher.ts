/**;
 * Context Enricher;
 * Enhances business context with intelligence and generates contextual prompts;/
 */
;
import {
  BusinessContextData,;
  ContextualPrompts,;
  ContextEnrichmentConfig,;
  CompanyProfile,;
  DepartmentProfile,;
  UserProfile,;
  BusinessIntelligence;/
} from './types';"/
import { Logger } from '../../shared/logger';

export class ContextEnricher {
  private logger: Logger;
  private config: ContextEnrichmentConfig;
/
  // Department-specific prompt templates;
  private departmentPrompts = {
    finance: {"
      systemContext: "You are a financial analysis expert working;"
  for {companyName}. You have deep understanding of financial processes, accounting principles, and business metrics.",;"
      roleContext: "As a {jobTitle} in the;"
  Finance department, you focus on financial accuracy, compliance, and strategic financial decision-making.",;
      capabilities: [;"
        "financial_analysis", "budget_planning", "cost_analysis", "revenue_analysis",;"
        "cash_flow_management", "financial_reporting", "tax_planning", "audit_support",;"
        "investment_analysis", "risk_assessment", "compliance_monitoring";
      ],;
      businessRules: [;"
        "Always prioritize financial accuracy and compliance",;"
        "Consider regulatory requirements in all recommendations",;"
        "Maintain confidentiality of sensitive financial data",;"
        "Provide clear explanations for financial recommendations";
      ];
    },
;
    hr: {"
      systemContext: "You are an HR specialist;"
  working for {companyName}. You understand employment law, organizational development, and people management.",;"
      roleContext: "As a {jobTitle} in;"
  Human Resources, you focus on employee development, compliance, and organizational effectiveness.",;
      capabilities: [;"
        "resume_analysis", "employee_onboarding", "performance_management", "compensation_analysis",;"
        "benefits_administration", "policy_development", "compliance_monitoring", "training_coordination",;"
        "employee_relations", "recruitment_support", "organizational_development";
      ],;
      businessRules: [;"
        "Maintain strict confidentiality of employee information",;"
        "Ensure compliance with employment laws and regulations",;"
        "Promote fair and equitable treatment of all employees",;"
        "Support organizational culture and values";
      ];
    },
;
    sales: {"
      systemContext: "You are a sales operations;"
  expert working for {companyName}. You understand sales processes, customer relationships, and revenue generation.",;"
      roleContext: "As a {jobTitle} in;"
  Sales, you focus on customer acquisition, relationship management, and revenue growth.",;
      capabilities: [;"
        "lead_qualification", "customer_analysis", "sales_forecasting", "proposal_generation",;"
        "crm_management", "pipeline_analysis", "competitor_analysis", "pricing_strategy",;"
        "contract_review", "revenue_tracking", "customer_segmentation";
      ],;
      businessRules: [;"
        "Always prioritize customer satisfaction and value delivery",;"
        "Maintain ethical sales practices and transparency",;"
        "Protect customer confidential information",;"
        "Focus on long-term relationship building";
      ];
    },
;
    marketing: {"
      systemContext: "You are a marketing strategist;"
  working for {companyName}. You understand brand management, customer acquisition, and market dynamics.",;"
      roleContext: "As a {jobTitle} in;"
  Marketing, you focus on brand building, customer engagement, and market expansion.",;
      capabilities: [;"
        "market_analysis", "campaign_planning", "content_strategy", "brand_management",;"
        "customer_segmentation", "competitive_analysis", "roi_analysis", "lead_generation",;"
        "social_media_strategy", "event_planning", "public_relations";
      ],;
      businessRules: [;"
        "Maintain consistent brand voice and messaging",;"
        "Ensure all marketing activities comply with regulations",;"
        "Focus on measurable results and ROI",;"
        "Protect customer privacy and data";
      ];
    },
;
    operations: {"
      systemContext: "You are an operations specialist;"
  working for {companyName}. You understand process optimization, quality management, and operational efficiency.",;"
      roleContext: "As a {jobTitle} in;"
  Operations, you focus on process improvement, quality assurance, and operational excellence.",;
      capabilities: [;"
        "process_optimization", "quality_management", "supply_chain_analysis", "inventory_management",;"
        "vendor_management", "cost_optimization", "efficiency_analysis", "project_management",;"
        "risk_management", "compliance_monitoring", "performance_metrics";
      ],;
      businessRules: [;"
        "Prioritize quality and customer satisfaction",;"
        "Focus on continuous improvement and efficiency",;"
        "Ensure compliance with operational standards",;"
        "Maintain cost-effectiveness without compromising quality";
      ];
    },
;
    it: {"
      systemContext: "You are an IT;"
  specialist working for {companyName}. You understand technology systems, cybersecurity, and digital transformation.",;"
      roleContext: "As a {jobTitle} in IT, you focus on system reliability, security, and technological innovation.",;
      capabilities: [;"
        "system_analysis", "security_assessment", "infrastructure_planning", "software_evaluation",;"
        "data_management", "cybersecurity", "backup_recovery", "user_support",;"
        "project_management", "vendor_management", "compliance_monitoring";
      ],;
      businessRules: [;"
        "Prioritize data security and privacy",;"
        "Ensure system reliability and availability",;"
        "Follow established IT governance and compliance requirements",;"
        "Support business objectives through technology solutions";
      ];
    },
;
    legal: {"
      systemContext: "You are a legal;"
  advisor working for {companyName}. You understand corporate law, compliance, and risk management.",;"
      roleContext: "As a {jobTitle} in Legal, you focus on legal compliance, risk mitigation, and contractual matters.",;
      capabilities: [;"
        "contract_review", "compliance_monitoring", "legal_research", "risk_assessment",;"
        "policy_development", "litigation_support", "regulatory_analysis", "intellectual_property",;"
        "employment_law", "corporate_governance", "dispute_resolution";
      ],;
      businessRules: [;"
        "Ensure strict compliance with all applicable laws and regulations",;"
        "Maintain attorney-client privilege and confidentiality",;"
        "Provide conservative legal advice to minimize risk",;"
        "Document all legal decisions and rationale";
      ];
    }
  };

  constructor(config: ContextEnrichmentConfig) {
    this.logger = new Logger();
    this.config = config;}
/
  /**;
   * Enrich context data with intelligence and analysis;/
   */;
  async enrichWithAnalysis(contextData: BusinessContextData): Promise<void> {
    try {
      if (!this.config.intelligence.analysisEnabled) {
        return;}
/
      // Enhance company profile with strategic insights;
      this.enrichCompanyProfile(contextData.companyProfile, contextData.businessIntelligence);
/
      // Enhance department profile with operational insights;
      if (contextData.departmentProfile) {
        this.enrichDepartmentProfile(contextData.departmentProfile, contextData.businessIntelligence);
      }
/
      // Enhance user profile with personalized insights;
      this.enrichUserProfile(contextData.userProfile, contextData.companyProfile);
/
      // Add confidence score adjustment based on enrichment;
      contextData.metadata.confidenceScore = Math.min(;
        1.0,;
        contextData.metadata.confidenceScore + 0.1;
      );
"
      this.logger.debug('Context enriched with analysis', {"
        businessId: "contextData.businessId",;"
        confidenceScore: "contextData.metadata.confidenceScore",;
      });

    } catch (error) {"
      this.logger.error('Failed to enrich context with analysis', error, {"
        businessId: "contextData.businessId",;
      });
    }
  }
/
  /**;
   * Generate contextual prompts for AI agents;/
   */;
  async generateContextualPrompts(;"
    contextData: "BusinessContextData",;"
    capability: "string",;
    taskType?: string;
  ): Promise<ContextualPrompts> {
    try {
      const department = contextData.userProfile.basic.department.toLowerCase();
      const departmentPrompt = this.departmentPrompts[department as keyof typeof this.departmentPrompts] ||;
                               this.departmentPrompts.operations;
/
      // Build system prompt with company context;
      const systemPrompt = this.buildSystemPrompt(contextData, departmentPrompt);
/
      // Build department-specific context;
      const departmentContext = this.buildDepartmentContext(contextData, departmentPrompt);
/
      // Build role-specific context;
      const roleContext = this.buildRoleContext(contextData, departmentPrompt);
/
      // Generate business rules;
      const businessRules = this.generateBusinessRules(contextData, departmentPrompt);
/
      // Generate communication guidelines;
      const communicationGuidelines = this.generateCommunicationGuidelines(contextData);
/
      // Generate escalation instructions;
      const escalationInstructions = this.generateEscalationInstructions(contextData);
/
      // Generate compliance requirements;
      const complianceRequirements = this.generateComplianceRequirements(contextData);
/
      // Generate example interactions;
      const exampleInteractions = this.generateExampleInteractions(contextData, capability, taskType);

      const prompts: ContextualPrompts = {
        systemPrompt,;
        departmentContext,;
        roleContext,;
        businessRules,;
        communicationGuidelines,;
        escalationInstructions,;
        complianceRequirements,;
        exampleInteractions,;
      };
"
      this.logger.debug('Contextual prompts generated', {"
        businessId: "contextData.businessId",;
        department,;
        capability,;"
        promptLength: "systemPrompt.length",;
      });

      return prompts;

    } catch (error) {"
      this.logger.error('Failed to generate contextual prompts', error, {"
        businessId: "contextData.businessId",;
        capability,;
      });
/
      // Return basic prompts as fallback;
      return this.generateFallbackPrompts(contextData);
    }
  }
/
  /**;
   * Private methods for enrichment;/
   */
;"
  private enrichCompanyProfile(companyProfile: "CompanyProfile", intelligence: BusinessIntelligence): void {/
    // Add strategic context based on business intelligence;/
    // This could include market position insights, competitive advantages, etc.;
  }
"
  private enrichDepartmentProfile(departmentProfile: "DepartmentProfile", intelligence: BusinessIntelligence): void {/
    // Add operational context based on business intelligence;/
    // This could include department performance insights, optimization opportunities, etc.;
  }
"
  private enrichUserProfile(userProfile: "UserProfile", companyProfile: CompanyProfile): void {/
    // Add personalized context based on role and company;/
    // This could include career development insights, skill recommendations, etc.;
  }
"
  private buildSystemPrompt(contextData: "BusinessContextData", departmentPrompt: any): string {
    const company = contextData.companyProfile.basic;
    const user = contextData.userProfile.basic;
    const intelligence = contextData.businessIntelligence;

    return `${departmentPrompt.systemContext}

COMPANY CONTEXT: ;
- Company: ${company.name} (${company.industry});
- Size: ${company.size} company with ${contextData.companyProfile.structure.employeeCount} employees;
- Business Model: ${contextData.companyProfile.business.model}
- Market Position: ${intelligence.market.position}
- Strategic Phase: ${intelligence.strategic.phase}
- Risk Tolerance: ${intelligence.strategic.riskTolerance}
"
Your responses should be tailored to ${company.name}'s specific;
  business context, ${user.department} department needs, and ${user.jobTitle} responsibilities.
;
Always consider: ;"
1. The company's ${intelligence.strategic.phase} phase and ${intelligence.strategic.riskTolerance} risk tolerance;
2. Current business priorities and constraints;
3. Department-specific workflows and requirements;
4. Compliance and regulatory considerations;
5. Cost-effectiveness and ROI implications
;`
Maintain a ${contextData.userProfile.preferences.assistantStyle} communication style while being professional and accurate.`;/
      .replace(/\{companyName\}/g, company.name);/
      .replace(/\{jobTitle\}/g, user.jobTitle);
  }
"
  private buildDepartmentContext(contextData: "BusinessContextData", departmentPrompt: any): string {
    const department = contextData.departmentProfile;
    if (!department) {
      return departmentPrompt.roleContext;}
`
    return `${departmentPrompt.roleContext}

DEPARTMENT CONTEXT: ;
- Department: ${department.basic.name} (${department.basic.type});
- Team Size: ${department.team.size} members;"
- Primary Functions: ${department.operations.primaryFunctions.join(', ')}"
- Key Tools: ${department.operations.tools.join(', ')}/
- Efficiency Score: ${department.workflows.efficiency.score}/100;"
- Current Priorities: ${department.operations.kpis.map(kpi => kpi.name).join(', ')}

Focus on tasks and solutions that align with;"`
  ${department.basic.name} objectives and support the department's primary functions.`;/
      .replace(/\{jobTitle\}/g, contextData.userProfile.basic.jobTitle);
  }
"
  private buildRoleContext(contextData: "BusinessContextData", departmentPrompt: any): string {
    const user = contextData.userProfile.basic;
    const permissions = contextData.userProfile.permissions;
`
    return `ROLE CONTEXT:;
- Position: ${user.jobTitle} (${user.role} level);
- Department: ${user.department}/
- Experience: ${Math.floor((Date.now() - user.startDate) / (365.25 * 24 * 60 * 60 * 1000))} years with company;
- Direct Reports: ${user.directReports || 0}"
- Capabilities: ${permissions.capabilities.slice(0, 5).join(', ')}"
- Approval Authority: ${Object.keys(permissions.approvalLimits).join(', ') || 'Standard operations'}

Your recommendations should be appropriate for a;`
  ${user.jobTitle} with ${user.role} level authority and responsibilities.`;
  }
"
  private generateBusinessRules(contextData: "BusinessContextData", departmentPrompt: any): string[] {
    const baseRules = [...departmentPrompt.businessRules];
    const intelligence = contextData.businessIntelligence;
/
    // Add company-specific rules based on business intelligence;
    if (intelligence.financial.constraints.budgetTight) {"
      baseRules.push("Consider cost implications and budget constraints in all recommendations");}
"
    if (intelligence.operational.riskLevel === 'high') {"
      baseRules.push("Apply extra scrutiny to risk assessment and mitigation strategies");
    }
"
    if (intelligence.strategic.phase === 'startup' || intelligence.strategic.phase === 'growth') {"
      baseRules.push("Balance speed and scalability in solution recommendations");
    }

    return baseRules;
  }

  private generateCommunicationGuidelines(contextData: BusinessContextData): string {
    const style = contextData.userProfile.preferences.communicationStyle;
    const assistantStyle = contextData.userProfile.preferences.assistantStyle;
    const culture = contextData.companyProfile.culture;
`
    let guidelines = `Communication should be ${assistantStyle} and ${style}.`;
"
    if (culture.communicationStyle === 'formal') {"
      guidelines += " Use professional language and formal business terminology.";"
    } else if (culture.communicationStyle === 'informal') {"
      guidelines += " Use conversational language while maintaining professionalism.";
    }
"
    if (culture.decisionMaking === 'collaborative') {"
      guidelines += " Encourage input from relevant stakeholders and team members.";
    }

    return guidelines;
  }

  private generateEscalationInstructions(contextData: BusinessContextData): string {
    const user = contextData.userProfile.basic;
    const capabilities = contextData.departmentCapabilities;
`
    let instructions = `For issues requiring escalation:\n`;

    if (capabilities.escalationRules.length > 0) {
      instructions += capabilities.escalationRules;`
        .map(rule => `- ${rule.condition}: ${rule.action}`);"
        .join('\n');
    } else {`
      instructions += `- High-cost decisions (>${capabilities.costLimits.daily || 1000}): Escalate to manager\n`;"`
      instructions += `- Cross-departmental issues: "Involve relevant department leads\n`;`/
      instructions += `- Compliance concerns: Escalate to legal/compliance team\n`;"`
      instructions += `- Technical issues: Escalate to IT department`;"}

    return instructions;
  }

  private generateComplianceRequirements(contextData: BusinessContextData): string[] {
    const industry = contextData.companyProfile.basic.industry;
    const size = contextData.companyProfile.basic.size;
    const requirements: string[] = [];
/
    // Add industry-specific compliance requirements;"
    if (industry.toLowerCase().includes('financial') || industry.toLowerCase().includes('bank')) {"
      requirements.push("Adhere to financial regulations and data protection standards");"
      requirements.push("Maintain audit trails for all financial transactions");}
"
    if (industry.toLowerCase().includes('healthcare')) {"
      requirements.push("Comply with HIPAA and patient privacy regulations");"
      requirements.push("Ensure medical data confidentiality");
    }
/
    // Add size-based requirements;"
    if (size === 'enterprise' || size === 'large') {"
      requirements.push("Follow corporate governance and SOX compliance requirements");
    }
/
    // Default requirements;"
    requirements.push("Protect sensitive business and customer information");"
    requirements.push("Follow company policies and procedures");

    return requirements;
  }

  private generateExampleInteractions(;"
    contextData: "BusinessContextData",;"
    capability: "string",;
    taskType?: string;"
  ): Array<{ scenario: "string; expectedResponse: string"}> {
    const department = contextData.userProfile.basic.department.toLowerCase();
    const examples: Array<{ scenario: string; expectedResponse: string}> = [];
/
    // Generate department and capability-specific examples;"
    if (department === 'finance' && capability.includes('analysis')) {
      examples.push({"
        scenario: "User asks for monthly revenue analysis",;"
        expectedResponse: "I'll analyze the monthly revenue data, breaking down by;"
  product lines, regions, and comparing to previous periods. I'll also identify trends and provide actionable insights for leadership.";
      });
    }
"
    if (department === 'hr' && capability.includes('employee')) {
      examples.push({"
        scenario: "User needs help with performance review process",;"
        expectedResponse: "I'll guide you through our performance;"
  review framework, ensuring compliance with company policies and providing templates that align with our competency model.";
      });
    }
/
    // Add more examples based on capability and task type;
    if (examples.length === 0) {
      examples.push({`
        scenario: `User requests ${capability} assistance`,;"`
        expectedResponse: `I'll help you;"`
  with ${capability} while ensuring compliance with ${contextData.companyProfile.basic.name}'s policies and ${contextData.userProfile.basic.department} department requirements.`;
      });
    }

    return examples;
  }

  private generateFallbackPrompts(contextData: BusinessContextData): ContextualPrompts {
    return {`
      systemPrompt: `You;`
  are an AI assistant helping ${contextData.userProfile.basic.firstName} at ${contextData.companyProfile.basic.name}.`,;`
      departmentContext: `Working in the ${contextData.userProfile.basic.department} department.`,;`
      roleContext: `Acting as a ${contextData.userProfile.basic.jobTitle}.`,;"
      businessRules: ["Follow company policies", "Maintain professional standards"],;"
      communicationGuidelines: "Be helpful and professional.",;"
      escalationInstructions: "Escalate complex issues to appropriate managers.",;"
      complianceRequirements: ["Protect sensitive information"],;
      exampleInteractions: [];};
  }
}"`/