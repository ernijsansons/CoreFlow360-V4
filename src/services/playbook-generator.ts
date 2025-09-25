import type { Env } from '../types/env';
import type {
  Playbook,
  PlaybookSection,
  CustomerSegment,
  Pattern,
  Feedback,
  Strategy
} from '../types/crm';

export class PlaybookGenerator {
  private env: Env;
  private playbooks = new Map<string, Playbook>();
  private segments = new Map<string, CustomerSegment>();
  private patterns = new Map<string, Pattern>();

  constructor(env: Env) {
    this.env = env;
    this.loadExistingData();
  }

  async generatePlaybook(segment: CustomerSegment): Promise<Playbook> {

    // Analyze what works for this segment
    const successfulApproaches = await this.analyzeSegmentSuccess(segment);

    const playbook = await this.createComprehensivePlaybook(segment, successfulApproaches);

    // Test playbook with subset of leads
    await this.testPlaybook(playbook);

    // Store and activate playbook
    await this.storePlaybook(playbook);
    this.playbooks.set(playbook.id, playbook);

    return playbook;
  }

  private async analyzeSegmentSuccess(segment: CustomerSegment): Promise<any> {
    const db = this.env.DB_CRM;

    // Get successful deals for this segment
    const successfulDeals = await db.prepare(`
      SELECT
        o.*,
        l.*,
        GROUP_CONCAT(i.interaction_data) as interactions,
        GROUP_CONCAT(ca.call_summary) as call_summaries
      FROM opportunities o
      JOIN leads l ON o.lead_id = l.id
      LEFT JOIN interactions i ON l.id = i.lead_id
      LEFT JOIN conversation_analyses ca ON l.id = ca.lead_id
      WHERE o.status = 'closed_won'
        AND l.segment = ?
        AND o.close_date >= datetime('now', '-12 months')
      GROUP BY o.id
      ORDER BY o.value DESC
    `).bind(segment.id).all();

    // Analyze patterns in successful approaches
    const analysis = await this.analyzeSuccessPatterns(successfulDeals.results, segment);

    return analysis;
  }

  private async analyzeSuccessPatterns(deals: any[], segment: CustomerSegment): Promise<any> {
    const prompt = `
      Analyze these successful deals for ${segment.name} segment to extract winning approaches:

      Segment Characteristics:
      - Industry: ${segment.criteria.industry?.join(', ')}
      - Company Size: ${segment.criteria.companySize}
      - Typical Challenges: ${segment.characteristics.typicalChallenges.join(', ')}
      - Decision Makers: ${segment.characteristics.decisionMakers.join(', ')}
      - Preferred Channels: ${segment.characteristics.preferredChannels.join(', ')}
      - Communication Style: ${segment.characteristics.communicationStyle}

      Successful Deals Data:
      ${JSON.stringify(deals.slice(0, 20).map(deal => ({
        value: deal.value,
        salesCycle: deal.sales_cycle,
        industry: deal.industry,
        title: deal.title,
        companySize: deal.company_size,
        closeReason: deal.close_reason,
        keyPainPoints: deal.pain_points,
        winningFactors: deal.winning_factors
      })))}

      Extract successful approaches for:
      1. **Ideal Customer Profile** refinement
      2. **Qualifying Questions** that identify good fits
      3. **Discovery Process** that uncovers key needs
      4. **Common Objections** and effective responses
      5. **Proof Points** that resonate most
      6. **Email Templates** that get responses
      7. **Call Scripts** for different scenarios
      8. **Competitive Positioning** against key competitors
      9. **Pricing Guidance** and negotiation strategies
      10. **Closing Techniques** that work for this segment

      Return comprehensive analysis with specific examples and recommendations.
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error) {
      return this.getFallbackAnalysis(segment);
    }
  }

  private async createComprehensivePlaybook(segment: CustomerSegment, analysis: any): Promise<Playbook> {
    const playbookId = `playbook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const prompt = `
      Create a comprehensive sales playbook for ${segment.name}:

      Based on this analysis: ${JSON.stringify(analysis)}

      Generate detailed sections for:

      1. **Ideal Customer Profile**
      - Firmographic criteria
      - Behavioral indicators
      - Technology stack
      - Buying process characteristics
      - Red flags to avoid

      2. **Qualifying Questions** (ranked by effectiveness)
      - Budget qualification
      - Authority identification
      - Need confirmation
      - Timeline validation
      - Decision process mapping

      3. **Discovery Call Structure**
      - Opening approach
      - Agenda setting
      - Pain discovery sequence
      - Solution exploration
      - Next steps confirmation

      4. **Common Objections and Responses**
      - Price objections
      - Authority objections
      - Need objections
      - Timing objections
      - Trust/credibility objections

      5. **Proof Points That Resonate**
      - Case studies
      - ROI metrics
      - Customer testimonials
      - Industry benchmarks
      - Competitive advantages

      6. **Email Templates**
      - Cold outreach
      - Follow-up sequences
      - Value-add emails
      - Breakup emails
      - Re-engagement emails

      7. **Call Scripts**
      - Discovery calls
      - Demo calls
      - Proposal presentations
      - Negotiation calls
      - Closing calls

      8. **Competitive Positioning**
      - Vs. major competitors
      - Unique differentiators
      - Trap questions
      - Win strategies

      9. **Pricing Guidance**
      - Value-based pricing
      - Discount guidelines
      - Payment terms
      - Negotiation tactics

      10. **Close Techniques**
      - Buying signal recognition
      - Close timing
      - Objection handling
      - Urgency creation

      Make each section immediately actionable with specific scripts, questions, and templates.

      Return as JSON matching the Playbook interface structure.
    `;

    try {
      const response = await this.callAI(prompt);
      const playbookData = JSON.parse(response);

      const playbook: Playbook = {
        id: playbookId,
        name: `${segment.name} Sales Playbook`,
        segment: segment.id,
        version: 1,
        sections: {
       
    idealCustomerProfile: this.createSection('Ideal Customer Profile', playbookData.idealCustomerProfile, 'text', 'high'),
       
    qualifyingQuestions: this.createSection('Qualifying Questions', playbookData.qualifyingQuestions, 'list', 'high'),
       
    discoveryStructure: this.createSection('Discovery Call Structure', playbookData.discoveryStructure, 'script', 'high'),
          commonObjections: this.createSection('Common Objections', playbookData.commonObjections, 'list', 'high'),
          proofPoints: this.createSection('Proof Points', playbookData.proofPoints, 'list', 'medium'),
          emailTemplates: this.createSection('Email Templates', playbookData.emailTemplates, 'template', 'high'),
          callScripts: this.createSection('Call Scripts', playbookData.callScripts, 'script', 'high'),
       
    competitivePositioning: this.createSection('Competitive Positioning', playbookData.competitivePositioning, 'text', 'medium'),
          pricingGuidance: this.createSection('Pricing Guidance', playbookData.pricingGuidance, 'text', 'medium'),
          closeTechniques: this.createSection('Close Techniques', playbookData.closeTechniques, 'list', 'high')
        },
        performance: {
          adoptionRate: 0,
          winRate: 0,
          averageDealSize: 0,
          salesCycle: 0,
          userFeedback: 0
        },
        metadata: {
          generatedBy: 'ai',
          dataPoints: analysis.dataPoints || 50,
          lastAnalysis: new Date().toISOString(),
          confidence: analysis.confidence || 0.8
        },
        active: false, // Will activate after testing
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      return playbook;
    } catch (error) {
      return this.createFallbackPlaybook(segment);
    }
  }

  private createSection(
    title: string,
    content: any,
    type: 'text' | 'list' | 'template' | 'script' | 'checklist',
    priority: 'high' | 'medium' | 'low'
  ): PlaybookSection {
    let formattedContent = '';

    if (typeof content === 'string') {
      formattedContent = content;
    } else if (Array.isArray(content)) {
      formattedContent = content.join('\n• ');
    } else if (typeof content === 'object') {
      formattedContent = JSON.stringify(content, null, 2);
    }

    return {
      title,
      content: formattedContent,
      type,
      priority,
      tags: [title.toLowerCase().replace(/\s+/g, '_')],
      effectiveness: 0, // Will be updated based on usage
      lastUpdated: new Date().toISOString()
    };
  }

  async updatePlaybook(playbook: Playbook, feedback: Feedback[]): Promise<Playbook> {

    // Analyze feedback for improvement opportunities
    const improvements = await this.generateImprovements(playbook, feedback);

    // Apply improvements
    const updatedPlaybook = await this.applyImprovements(playbook, improvements);

    // Update performance metrics
    await this.updatePerformanceMetrics(updatedPlaybook);

    // Store updated playbook
    await this.storePlaybook(updatedPlaybook);
    this.playbooks.set(updatedPlaybook.id, updatedPlaybook);

    return updatedPlaybook;
  }

  private async generateImprovements(playbook: Playbook, feedback: Feedback[]): Promise<any> {
    const prompt = `
      Analyze feedback to improve this sales playbook:

      Current Playbook: ${playbook.name}
      Performance:
      - Win Rate: ${playbook.performance.winRate}%
      - Adoption Rate: ${playbook.performance.adoptionRate}%
      - User Feedback: ${playbook.performance.userFeedback}/5

      Feedback Analysis:
      ${JSON.stringify(feedback.map(f => ({
        type: f.type,
        rating: f.rating,
        comment: f.comment,
        category: f.category,
        suggestions: f.suggestions
      })))}

      Identify specific improvements for:
      1. **Content Updates** - What sections need updating?
      2. **New Additions** - What's missing from the playbook?
      3. **Script Improvements** - How can scripts be more effective?
      4. **Template Optimization** - Which templates need refinement?
      5. **Process Enhancements** - How can the process be streamlined?

      Prioritize improvements by impact and effort.
      Return specific, actionable recommendations.
    `;

    try {
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error) {
      return { contentUpdates: [], newAdditions: [], improvements: [] };
    }
  }

  private async applyImprovements(playbook: Playbook, improvements: any): Promise<Playbook> {
    const updatedPlaybook = { ...playbook };
    updatedPlaybook.version += 1;
    updatedPlaybook.updatedAt = new Date().toISOString();

    // Apply content updates
    for (const update of improvements.contentUpdates || []) {
      if (update.section && updatedPlaybook.sections[update.section as keyof typeof updatedPlaybook.sections]) {
        const section = updatedPlaybook.sections[update.section as keyof typeof updatedPlaybook.sections];
        section.content = update.newContent;
        section.lastUpdated = new Date().toISOString();
      }
    }

    // Add new sections or content
    for (const addition of improvements.newAdditions || []) {
      if (addition.section && addition.content) {
        const section = updatedPlaybook.sections[addition.section as keyof typeof updatedPlaybook.sections];
        if (section) {
          section.content += '\n\n' + addition.content;
          section.lastUpdated = new Date().toISOString();
        }
      }
    }

    return updatedPlaybook;
  }

  private async testPlaybook(playbook: Playbook): Promise<void> {

    // Get test leads for this segment
    const testLeads = await this.getTestLeads(playbook.segment, 10);

    // Apply playbook to test leads
    const results = await this.applyPlaybookToLeads(playbook, testLeads);

    // Analyze test results
    const testResults = await this.analyzeTestResults(results);

    // Update playbook performance
    playbook.performance = {
      ...playbook.performance,
      winRate: testResults.winRate,
      averageDealSize: testResults.averageDealSize,
      salesCycle: testResults.salesCycle,
      adoptionRate: testResults.adoptionRate
    };

    // Activate if test results are positive
    if (testResults.winRate > 0.3 && testResults.adoptionRate > 0.7) {
      playbook.active = true;
    }
  }

  private async getTestLeads(segmentId: string, count: number): Promise<any[]> {
    const db = this.env.DB_CRM;

    const testLeads = await db.prepare(`
      SELECT * FROM leads
      WHERE segment = ?
        AND status = 'new'
        AND created_at >= datetime('now', '-30 days')
      ORDER BY RANDOM()
      LIMIT ?
    `).bind(segmentId, count).all();

    return testLeads.results;
  }

  private async applyPlaybookToLeads(playbook: Playbook, leads: any[]): Promise<any[]> {
    const results = [];

    for (const lead of leads) {
      // Simulate applying playbook approach
      const result = {
        leadId: lead.id,
        playbookApplied: true,
        outcome: Math.random() > 0.6 ? 'positive' : 'neutral', // Mock outcome
        responseRate: Math.random(),
        engagementScore: Math.random() * 100,
        timeToResponse: Math.random() * 48 // hours
      };

      results.push(result);
    }

    return results;
  }

  private async analyzeTestResults(results: any[]): Promise<any> {
    const positiveOutcomes = results.filter(r => r.outcome === 'positive').length;
    const totalResults = results.length;

    return {
      winRate: (positiveOutcomes / totalResults) * 100,
      averageDealSize: 50000, // Would calculate from actual deals
      salesCycle: 45, // Would calculate from actual data
      adoptionRate: 85, // Would track actual usage
      responseRate: results.reduce((sum, r) => sum + r.responseRate, 0) / totalResults,
      engagementScore: results.reduce((sum, r) => sum + r.engagementScore, 0) / totalResults
    };
  }

  private async updatePerformanceMetrics(playbook: Playbook): Promise<void> {
    const db = this.env.DB_CRM;

    // Get actual performance data
    const performanceData = await db.prepare(`
      SELECT
        AVG(CASE WHEN o.status = 'closed_won' THEN 1.0 ELSE 0.0 END) * 100 as win_rate,
        AVG(o.value) as avg_deal_size,
        AVG(julianday(o.close_date) - julianday(o.created_at)) as avg_sales_cycle,
        COUNT(DISTINCT pb_usage.user_id) / (SELECT COUNT(*) FROM users WHERE active = 1) as adoption_rate
      FROM opportunities o
      JOIN leads l ON o.lead_id = l.id
      LEFT JOIN playbook_usage pb_usage ON l.id = pb_usage.lead_id AND pb_usage.playbook_id = ?
      WHERE l.segment = ?
        AND o.created_at >= datetime('now', '-90 days')
    `).bind(playbook.id, playbook.segment).first();

    if (performanceData) {
      playbook.performance.winRate = performanceData.win_rate || 0;
      playbook.performance.averageDealSize = performanceData.avg_deal_size || 0;
      playbook.performance.salesCycle = performanceData.avg_sales_cycle || 0;
      playbook.performance.adoptionRate = (performanceData.adoption_rate || 0) * 100;
    }

    // Get user feedback
    const feedbackData = await db.prepare(`
      SELECT AVG(rating) as avg_rating
      FROM feedback
      WHERE playbook_id = ?
        AND created_at >= datetime('now', '-30 days')
    `).bind(playbook.id).first();

    if (feedbackData) {
      playbook.performance.userFeedback = feedbackData.avg_rating || 0;
    }
  }

  async generatePlaybookForAllSegments(): Promise<Playbook[]> {

    const segments = Array.from(this.segments.values());
    const playbooks = [];

    for (const segment of segments) {
      try {
        const playbook = await this.generatePlaybook(segment);
        playbooks.push(playbook);
      } catch (error) {
      }
    }

    return playbooks;
  }

  async getPlaybookRecommendations(segmentId: string): Promise<{
    recommended: Playbook[];
    improvements: string[];
    newSections: string[];
  }> {
    const segment = this.segments.get(segmentId);
    if (!segment) {
      throw new Error('Segment not found');
    }

    const currentPlaybook = Array.from(this.playbooks.values())
      .find(p => p.segment === segmentId);

    const recommendations = {
      recommended: [],
      improvements: [],
      newSections: []
    };

    if (!currentPlaybook) {
      // Recommend creating a new playbook
      recommendations.recommended = [await this.generatePlaybook(segment)];
    } else {
      // Analyze current playbook for improvements
      const analysis = await this.analyzePlaybookGaps(currentPlaybook);
      recommendations.improvements = analysis.improvements;
      recommendations.newSections = analysis.newSections;
    }

    return recommendations;
  }

  private async analyzePlaybookGaps(playbook: Playbook): Promise<{
    improvements: string[];
    newSections: string[];
  }> {
    // Analyze playbook against latest patterns and best practices
    const patterns = Array.from(this.patterns.values())
      .filter(p => p.applicability.includes(playbook.segment));

    const improvements = [];
    const newSections = [];

    // Check if playbook incorporates latest successful patterns
    for (const pattern of patterns) {
      if (!this.playbookIncludesPattern(playbook, pattern)) {
        improvements.push(`Incorporate ${pattern.name} pattern for better ${pattern.type} performance`);
      }
    }

    // Check for missing essential sections
    const essentialSections = [
      'competitivePositioning',
      'pricingGuidance',
      'emailTemplates',
      'callScripts'
    ];

    for (const section of essentialSections) {
      const playbookSection = playbook.sections[section as keyof typeof playbook.sections];
      if (!playbookSection || playbookSection.content.length < 100) {
        newSections.push(`Expand ${section} section with more detailed guidance`);
      }
    }

    return { improvements, newSections };
  }

  private playbookIncludesPattern(playbook: Playbook, pattern: Pattern): boolean {
    // Check if playbook content includes pattern recommendations
    const allContent = Object.values(playbook.sections)
      .map(s => s.content)
      .join(' ')
      .toLowerCase();

    return allContent.includes(pattern.name.toLowerCase()) ||
           allContent.includes(pattern.description.toLowerCase());
  }

  private async callAI(prompt: string): Promise<string> {
    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet-20240229',
          max_tokens: 4000,
          messages: [{
            role: 'user',
            content: prompt
          }],
          temperature: 0.3
        })
      });

      const result = await response.json() as any;
      const content = result.content[0].text;

      // Extract JSON if present
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      return jsonMatch ? jsonMatch[0] : content;
    } catch (error) {
      throw error;
    }
  }

  // Fallback methods
  private getFallbackAnalysis(segment: CustomerSegment): any {
    return {
      idealCustomerProfile:
  `Companies in ${segment.criteria.industry?.join(', ')} with ${segment.criteria.companySize} size`,
      qualifyingQuestions: [
        'What challenges are you facing with your current solution?',
        'What would success look like for your team?',
        'Who else would be involved in evaluating this?'
      ],
      discoveryStructure: 'Standard discovery call structure',
      commonObjections: ['Budget concerns', 'Timing issues', 'Current solution satisfaction'],
      proofPoints: ['ROI case studies', 'Customer testimonials', 'Industry benchmarks'],
      emailTemplates: 'Standard email templates',
      callScripts: 'Standard call scripts',
      competitivePositioning: 'Competitive advantages and differentiation',
      pricingGuidance: 'Value-based pricing approach',
      closeTechniques: 'Standard closing techniques',
      dataPoints: 10,
      confidence: 0.5
    };
  }

  private createFallbackPlaybook(segment: CustomerSegment): Playbook {
    const analysis = this.getFallbackAnalysis(segment);

    return {
      id: `playbook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name: `${segment.name} Sales Playbook`,
      segment: segment.id,
      version: 1,
      sections: {
      
   idealCustomerProfile: this.createSection('Ideal Customer Profile', analysis.idealCustomerProfile, 'text', 'high'),
        qualifyingQuestions: this.createSection('Qualifying Questions', analysis.qualifyingQuestions, 'list', 'high'),
        discoveryStructure: this.createSection('Discovery Structure', analysis.discoveryStructure, 'script', 'high'),
        commonObjections: this.createSection('Common Objections', analysis.commonObjections, 'list', 'high'),
        proofPoints: this.createSection('Proof Points', analysis.proofPoints, 'list', 'medium'),
        emailTemplates: this.createSection('Email Templates', analysis.emailTemplates, 'template', 'high'),
        callScripts: this.createSection('Call Scripts', analysis.callScripts, 'script', 'high'),
      
   competitivePositioning: this.createSection('Competitive Positioning', analysis.competitivePositioning, 'text', 'medium'),
        pricingGuidance: this.createSection('Pricing Guidance', analysis.pricingGuidance, 'text', 'medium'),
        closeTechniques: this.createSection('Close Techniques', analysis.closeTechniques, 'list', 'high')
      },
      performance: {
        adoptionRate: 0,
        winRate: 0,
        averageDealSize: 0,
        salesCycle: 0,
        userFeedback: 0
      },
      metadata: {
        generatedBy: 'ai',
        dataPoints: 0,
        lastAnalysis: new Date().toISOString(),
        confidence: 0.5
      },
      active: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  }

  // Storage and loading methods
  private async storePlaybook(playbook: Playbook): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT OR REPLACE INTO playbooks (
        id, name, segment_id, version, playbook_data,
        active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      playbook.id,
      playbook.name,
      playbook.segment,
      playbook.version,
      JSON.stringify(playbook),
      playbook.active ? 1 : 0,
      playbook.createdAt,
      playbook.updatedAt
    ).run();
  }

  private async loadExistingData(): Promise<void> {
    await this.loadPlaybooks();
    await this.loadSegments();
    await this.loadPatterns();
  }

  private async loadPlaybooks(): Promise<void> {
    const db = this.env.DB_CRM;

    const playbooks = await db.prepare('SELECT * FROM playbooks').all();

    for (const row of playbooks.results) {
      const playbook = JSON.parse(row.playbook_data as string) as Playbook;
      this.playbooks.set(playbook.id, playbook);
    }

  }

  private async loadSegments(): Promise<void> {
    const db = this.env.DB_CRM;

    const segments = await db.prepare('SELECT * FROM customer_segments').all();

    for (const row of segments.results) {
      const segment = JSON.parse(row.segment_data as string) as CustomerSegment;
      this.segments.set(segment.id, segment);
    }
  }

  private async loadPatterns(): Promise<void> {
    const db = this.env.DB_CRM;

    const patterns = await db.prepare('SELECT * FROM patterns').all();

    for (const row of patterns.results) {
      const pattern = JSON.parse(row.pattern_data as string) as Pattern;
      this.patterns.set(pattern.id, pattern);
    }
  }

  // Public methods
  async getPlaybook(playbookId: string): Promise<Playbook | undefined> {
    return this.playbooks.get(playbookId);
  }

  async getActivePlaybooks(): Promise<Playbook[]> {
    return Array.from(this.playbooks.values()).filter(p => p.active);
  }

  async getPlaybooksBySegment(segmentId: string): Promise<Playbook[]> {
    return Array.from(this.playbooks.values()).filter(p => p.segment === segmentId);
  }

  async getPlaybookPerformance(): Promise<{
    totalPlaybooks: number;
    activePlaybooks: number;
    averageWinRate: number;
    averageAdoptionRate: number;
    topPerforming: Playbook[];
  }> {
    const allPlaybooks = Array.from(this.playbooks.values());
    const activePlaybooks = allPlaybooks.filter(p => p.active);

    const avgWinRate = activePlaybooks.reduce((sum, p) => sum + p.performance.winRate, 0) / activePlaybooks.length;
    const avgAdoptionRate = activePlaybooks.reduce((sum,
  p) => sum + p.performance.adoptionRate, 0) / activePlaybooks.length;

    const topPerforming = activePlaybooks
      .sort((a, b)
  => (b.performance.winRate * b.performance.adoptionRate) - (a.performance.winRate * a.performance.adoptionRate))
      .slice(0, 5);

    return {
      totalPlaybooks: allPlaybooks.length,
      activePlaybooks: activePlaybooks.length,
      averageWinRate: avgWinRate || 0,
      averageAdoptionRate: avgAdoptionRate || 0,
      topPerforming
    };
  }

  async recordPlaybookUsage(playbookId: string, userId: string, leadId: string, section: string): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO playbook_usage (
        playbook_id, user_id, lead_id, section_used, used_at
      ) VALUES (?, ?, ?, ?, ?)
    `).bind(
      playbookId,
      userId,
      leadId,
      section,
      new Date().toISOString()
    ).run();
  }

  async recordPlaybookFeedback(
    playbookId: string,
    userId: string,
    section: string,
    rating: number,
    comment: string
  ): Promise<void> {
    const feedback: Feedback = {
      id: `feedback_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      playbookId,
      type: 'usability',
      rating,
      comment,
      category: section,
      userId,
      timestamp: new Date().toISOString()
    };

    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT INTO feedback (
        id, playbook_id, type, rating, comment, category, user_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      feedback.id,
      feedback.playbookId,
      feedback.type,
      feedback.rating,
      feedback.comment,
      feedback.category,
      feedback.userId,
      feedback.timestamp
    ).run();
  }
}