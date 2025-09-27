/**
 * Company Analyzer
 * Analyzes company data to provide business intelligence and strategic context
 */

import type { D1Database } from '@cloudflare/workers-types';
import {
  CompanyProfile,
  BusinessIntelligence,
  CompanyMetrics
} from './types';
import { Logger } from '../../shared/logger';

export class CompanyAnalyzer {
  private logger: Logger;
  private db: D1Database;

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Analyze company to build comprehensive business intelligence
   */
  async analyzeCompany(businessId: string): Promise<{
    businessModel: CompanyProfile['business'];
    organizationalStructure: CompanyProfile['structure'];
    technologyProfile: CompanyProfile['technology'];
    culturalProfile: CompanyProfile['culture'];
  }> {
    try {
      const [
        businessModel,
        organizationalStructure,
        technologyProfile,
        culturalProfile
      ] = await Promise.all([
        this.analyzeBusinessModel(businessId),
        this.analyzeOrganizationalStructure(businessId),
        this.analyzeTechnologyProfile(businessId),
        this.analyzeCulturalProfile(businessId)
      ]);

      return {
        businessModel,
        organizationalStructure,
        technologyProfile,
        culturalProfile
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze company', error, { businessId });
      return this.getDefaultAnalysis();
    }
  }

  /**
   * Get comprehensive business intelligence
   */
  async getBusinessIntelligence(businessId: string): Promise<BusinessIntelligence> {
    try {
      const [
        financial,
        market,
        operational,
        strategic
      ] = await Promise.all([
        this.analyzeFinancialIntelligence(businessId),
        this.analyzeMarketIntelligence(businessId),
        this.analyzeOperationalIntelligence(businessId),
        this.analyzeStrategicIntelligence(businessId)
      ]);

      return {
        financial,
        market,
        operational,
        strategic
      };

    } catch (error: any) {
      this.logger.error('Failed to get business intelligence', error, { businessId });
      return this.getDefaultBusinessIntelligence();
    }
  }

  /**
   * Analyze business model and revenue structure
   */
  private async analyzeBusinessModel(businessId: string): Promise<CompanyProfile['business']> {
    try {
      // Get business settings and financial data
      const businessData = await this.db.prepare(`
        SELECT
          business_model,
          target_market,
          revenue_streams,
          customer_segments,
          settings
        FROM businesses
        WHERE id = ?
      `).bind(businessId).first();

      if (!businessData) {
        return this.getDefaultBusinessModel();
      }

      const settings = JSON.parse(businessData.settings || '{}');

      // Analyze revenue patterns
      const revenueAnalysis = await this.analyzeRevenuePatterns(businessId);

      // Analyze customer base
      const customerAnalysis = await this.analyzeCustomerBase(businessId);

      return {
        model: businessData.business_model || 'b2b',
        revenue: {
          annual: revenueAnalysis.annual,
          currency: settings.currency || 'USD',
          growthRate: revenueAnalysis.growthRate,
          stage: revenueAnalysis.stage,
        },
        customers: {
          count: customerAnalysis.count,
          segments: customerAnalysis.segments,
          avgLifetimeValue: customerAnalysis.avgLifetimeValue,
          churnRate: customerAnalysis.churnRate,
        },
        marketPosition: this.determineMarketPosition(businessId, revenueAnalysis, customerAnalysis),
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze business model', error, { businessId });
      return this.getDefaultBusinessModel();
    }
  }

  /**
   * Analyze organizational structure
   */
  private async analyzeOrganizationalStructure(businessId: string): Promise<CompanyProfile['structure']> {
    try {
      // Get employee and department data
      const [employeeCount, departments, locations] = await Promise.all([
        this.getEmployeeCount(businessId),
        this.getDepartments(businessId),
        this.getLocations(businessId)
      ]);

      return {
        employeeCount,
        departments: departments.map((d: any) => d.name),
        locations,
        hierarchy: this.determineHierarchyType(employeeCount, departments.length),
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze organizational structure', error, { businessId });
      return {
        employeeCount: 0,
        departments: [],
        locations: [],
        hierarchy: 'flat',
      };
    }
  }

  /**
   * Analyze technology profile
   */
  private async analyzeTechnologyProfile(businessId: string): Promise<CompanyProfile['technology']> {
    try {
      // This would integrate with system inventory, integrations, etc.
      // For now, return a basic profile
      return {
        primarySystems: ['CRM', 'ERP', 'Email'],
        integrations: [],
        maturityLevel: 'intermediate',
        digitalTransformation: 'in-progress',
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze technology profile', error, { businessId });
      return {
        primarySystems: [],
        integrations: [],
        maturityLevel: 'basic',
        digitalTransformation: 'planning',
      };
    }
  }

  /**
   * Analyze cultural profile
   */
  private async analyzeCulturalProfile(businessId: string): Promise<CompanyProfile['culture']> {
    try {
      const businessData = await this.db.prepare(`
        SELECT settings
        FROM businesses
        WHERE id = ?
      `).bind(businessId).first();

      const settings = JSON.parse(businessData?.settings || '{}');
      const culture = settings.culture || {};

      return {
        values: culture.values || [],
        workStyle: culture.workStyle || 'hybrid',
        decisionMaking: culture.decisionMaking || 'collaborative',
        communicationStyle: culture.communicationStyle || 'mixed',
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze cultural profile', error, { businessId });
      return {
        values: [],
        workStyle: 'traditional',
        decisionMaking: 'centralized',
        communicationStyle: 'formal',
      };
    }
  }

  /**
   * Analyze financial intelligence
   */
  private async analyzeFinancialIntelligence(businessId: string): Promise<BusinessIntelligence['financial']> {
    try {
      // In production, this would analyze actual financial data
      // For now, return intelligent defaults based on company size/industry

      const businessData = await this.db.prepare(`
        SELECT size, industry, settings
        FROM businesses
        WHERE id = ?
      `).bind(businessId).first();

      const size = businessData?.size || 'small';
      const industry = businessData?.industry || 'general';

      // Determine financial performance based on size and industry
      const performance = this.inferFinancialPerformance(size, industry);
      const constraints = this.inferFinancialConstraints(size, performance);

      return {
        performance,
        constraints,
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze financial intelligence', error, { businessId });
      return {
        performance: {
          profitability: 'medium',
          cashFlow: 'neutral',
          growth: 'steady',
        },
        constraints: {
          budgetTight: false,
          cashFlowConcerns: false,
          investmentFocus: [],
        },
      };
    }
  }

  /**
   * Analyze market intelligence
   */
  private async analyzeMarketIntelligence(businessId: string): Promise<BusinessIntelligence['market']> {
    try {
      const businessData = await this.db.prepare(`
        SELECT industry, size, settings
        FROM businesses
        WHERE id = ?
      `).bind(businessId).first();

      const industry = businessData?.industry || 'general';
      const size = businessData?.size || 'small';

      return {
        position: size === 'startup' ? 'growing' : 'stable',
        competition: this.inferCompetitionLevel(industry),
        opportunities: this.inferMarketOpportunities(industry, size),
        threats: this.inferMarketThreats(industry, size),
        trends: this.inferIndustryTrends(industry),
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze market intelligence', error, { businessId });
      return {
        position: 'stable',
        competition: 'moderate',
        opportunities: [],
        threats: [],
        trends: [],
      };
    }
  }

  /**
   * Analyze operational intelligence
   */
  private async analyzeOperationalIntelligence(businessId: string): Promise<BusinessIntelligence['operational']> {
    try {
      const employeeCount = await this.getEmployeeCount(businessId);
      const departmentCount = (await this.getDepartments(businessId)).length;

      // Infer operational metrics based on size and structure
      const efficiency = this.inferOperationalEfficiency(employeeCount, departmentCount);
      const scalability = this.inferScalability(employeeCount);
      const riskLevel = this.inferRiskLevel(employeeCount, efficiency);

      return {
        efficiency,
        scalability,
        riskLevel,
        priorities: this.inferOperationalPriorities(efficiency, scalability, riskLevel),
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze operational intelligence', error, { businessId });
      return {
        efficiency: 70,
        scalability: 'good',
        riskLevel: 'medium',
        priorities: [],
      };
    }
  }

  /**
   * Analyze strategic intelligence
   */
  private async analyzeStrategicIntelligence(businessId: string): Promise<BusinessIntelligence['strategic']> {
    try {
      const businessData = await this.db.prepare(`
        SELECT size, industry, created_at, settings
        FROM businesses
        WHERE id = ?
      `).bind(businessId).first();

      const size = businessData?.size || 'small';
      const createdAt = new Date(businessData?.created_at || Date.now());
      const age = (Date.now() - createdAt.getTime()) / (365.25 * 24 * 60 * 60 * 1000); // Years

      const phase = this.inferBusinessPhase(size, age);
      const focus = this.inferStrategicFocus(phase, size);
      const timeHorizon = this.inferTimeHorizon(phase);
      const riskTolerance = this.inferRiskTolerance(phase, size);

      return {
        phase,
        focus,
        timeHorizon,
        riskTolerance,
      };

    } catch (error: any) {
      this.logger.error('Failed to analyze strategic intelligence', error, { businessId });
      return {
        phase: 'growth',
        focus: [],
        timeHorizon: 'medium',
        riskTolerance: 'moderate',
      };
    }
  }

  /**
   * Helper methods for data analysis
   */

  private async getEmployeeCount(businessId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM business_memberships
      WHERE business_id = ? AND status = 'active'
    `).bind(businessId).first();

    return result?.count || 0;
  }

  private async getDepartments(businessId: string): Promise<Array<{ name: string; code: string }>> {
    const result = await this.db.prepare(`
      SELECT DISTINCT department as name, department as code
      FROM business_memberships
      WHERE business_id = ? AND status = 'active' AND department IS NOT NULL
    `).bind(businessId).all();

    return result.results?.map((row: any) => ({
      name: row.name,
      code: row.code
    })) || [];
  }

  private async getLocations(businessId: string): Promise<CompanyProfile['structure']['locations']> {
    // In production, this would query actual location data
    return [{
      type: 'headquarters',
      country: 'US',
      city: 'Unknown',
      employeeCount: await this.getEmployeeCount(businessId),
    }];
  }

  private async analyzeRevenuePatterns(businessId: string): Promise<{
    annual?: number;
    growthRate?: number;
    stage: CompanyProfile['business']['revenue']['stage'];
  }> {
    // In production, this would analyze actual revenue data
    return {
      stage: 'growth',
      growthRate: 15,
    };
  }

  private async analyzeCustomerBase(businessId: string): Promise<{
    count?: number;
    segments: string[];
    avgLifetimeValue?: number;
    churnRate?: number;
  }> {
    // In production, this would analyze customer data
    return {
      segments: ['Enterprise', 'SMB'],
      churnRate: 5,
    };
  }

  private determineMarketPosition(businessId: string,
  revenue: any, customers: any): CompanyProfile['business']['marketPosition'] {
    // Simple heuristic based on available data
    return 'challenger';
  }

  private determineHierarchyType(employeeCount: number, departmentCount: number): CompanyProfile['structure']['hierarchy'] {
    if (employeeCount < 20) return 'flat';
    if (employeeCount < 100) return 'traditional';
    if (departmentCount > 10) return 'matrix';
    return 'traditional';
  }

  private inferFinancialPerformance(size: string, industry: string): BusinessIntelligence['financial']['performance'] {
    return {
      profitability: size === 'startup' ? 'low' : 'medium',
      cashFlow: size === 'startup' ? 'negative' : 'positive',
      growth: size === 'startup' ? 'accelerating' : 'steady',
    };
  }

  private inferFinancialConstraints(size: string, performance: any): BusinessIntelligence['financial']['constraints'] {
    return {
      budgetTight: size === 'startup' || performance.profitability === 'low',
      cashFlowConcerns: performance.cashFlow === 'negative',
      investmentFocus: size === 'startup' ? ['growth', 'product'] : ['efficiency', 'expansion'],
    };
  }

  private inferCompetitionLevel(industry: string): BusinessIntelligence['market']['competition'] {
    const highCompetitionIndustries = ['technology', 'retail', 'financial', 'consulting'];
    return highCompetitionIndustries.some(i => industry.toLowerCase().includes(i)) ? 'intense' : 'moderate';
  }

  private inferMarketOpportunities(industry: string, size: string): string[] {
    const opportunities = ['digital transformation', 'market expansion'];
    if (size === 'startup') opportunities.push('product-market fit');
    return opportunities;
  }

  private inferMarketThreats(industry: string, size: string): string[] {
    const threats = ['economic downturn', 'increased competition'];
    if (size === 'startup') threats.push('funding challenges');
    return threats;
  }

  private inferIndustryTrends(industry: string): string[] {
    return ['automation', 'sustainability', 'remote work'];
  }

  private inferOperationalEfficiency(employeeCount: number, departmentCount: number): number {
    // Simple heuristic
    const ratio = employeeCount / Math.max(departmentCount, 1);
    if (ratio > 20) return 60; // Too many people per department
    if (ratio < 3) return 65;  // Too many departments
    return 75; // Good balance
  }

  private inferScalability(employeeCount: number): BusinessIntelligence['operational']['scalability'] {
    if (employeeCount < 10) return 'excellent';
    if (employeeCount < 50) return 'good';
    if (employeeCount < 200) return 'limited';
    return 'poor';
  }

  private inferRiskLevel(employeeCount: number, efficiency: number): BusinessIntelligence['operational']['riskLevel'] {
    if (efficiency < 60 || employeeCount < 5) return 'high';
    if (efficiency > 80 && employeeCount > 20) return 'low';
    return 'medium';
  }

  private inferOperationalPriorities(
    efficiency: number,
    scalability: string,
    riskLevel: string
  ): BusinessIntelligence['operational']['priorities'] {
    const priorities: BusinessIntelligence['operational']['priorities'] = [];

    if (efficiency < 70) {
      priorities.push({ area: 'Process Optimization', urgency: 'high', impact: 'high' });
    }

    if (scalability === 'limited' || scalability === 'poor') {
      priorities.push({ area: 'Infrastructure Scaling', urgency: 'medium', impact: 'high' });
    }

    if (riskLevel === 'high') {
      priorities.push({ area: 'Risk Mitigation', urgency: 'critical', impact: 'high' });
    }

    return priorities;
  }

  private inferBusinessPhase(size: string, age: number): BusinessIntelligence['strategic']['phase'] {
    if (size === 'startup' || age < 2) return 'startup';
    if (age < 5) return 'growth';
    if (age < 15) return 'expansion';
    return 'maturity';
  }

  private inferStrategicFocus(phase: string, size: string): string[] {
    switch (phase) {
      case 'startup':
        return ['product development', 'market validation', 'funding'];
      case 'growth':
        return ['scaling operations', 'customer acquisition', 'team building'];
      case 'expansion':
        return ['market expansion', 'new products', 'partnerships'];
      default:
        return ['optimization', 'innovation', 'sustainability'];
    }
  }

  private inferTimeHorizon(phase: string): BusinessIntelligence['strategic']['timeHorizon'] {
    switch (phase) {
      case 'startup':
        return 'immediate';
      case 'growth':
        return 'short';
      case 'expansion':
        return 'medium';
      default:
        return 'long';
    }
  }

  private inferRiskTolerance(phase: string, size: string): BusinessIntelligence['strategic']['riskTolerance'] {
    if (phase === 'startup') return 'aggressive';
    if (size === 'enterprise') return 'conservative';
    return 'moderate';
  }

  /**
   * Default values
   */

  private getDefaultAnalysis() {
    return {
      businessModel: this.getDefaultBusinessModel(),
      organizationalStructure: {
        employeeCount: 0,
        departments: [],
        locations: [],
        hierarchy: 'flat' as const,
      },
      technologyProfile: {
        primarySystems: [],
        integrations: [],
        maturityLevel: 'basic' as const,
        digitalTransformation: 'planning' as const,
      },
      culturalProfile: {
        values: [],
        workStyle: 'traditional' as const,
        decisionMaking: 'centralized' as const,
        communicationStyle: 'formal' as const,
      },
    };
  }

  private getDefaultBusinessModel(): CompanyProfile['business'] {
    return {
      model: 'b2b',
      revenue: {
        currency: 'USD',
        stage: 'growth',
      },
      customers: {
        segments: [],
      },
      marketPosition: 'follower',
    };
  }

  private getDefaultBusinessIntelligence(): BusinessIntelligence {
    return {
      financial: {
        performance: {
          profitability: 'medium',
          cashFlow: 'neutral',
          growth: 'steady',
        },
        constraints: {
          budgetTight: false,
          cashFlowConcerns: false,
          investmentFocus: [],
        },
      },
      market: {
        position: 'stable',
        competition: 'moderate',
        opportunities: [],
        threats: [],
        trends: [],
      },
      operational: {
        efficiency: 70,
        scalability: 'good',
        riskLevel: 'medium',
        priorities: [],
      },
      strategic: {
        phase: 'growth',
        focus: [],
        timeHorizon: 'medium',
        riskTolerance: 'moderate',
      },
    };
  }
}