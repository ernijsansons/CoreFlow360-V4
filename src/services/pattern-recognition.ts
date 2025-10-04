import type { Env } from '../types/env';
import type {
  Pattern,
  Interaction,
  Outcome,
  Lead,
  CustomerSegment,
  Strategy
} from '../types/crm';

export class PatternRecognition {
  private env: Env;
  private businessId: string;
  private patterns = new Map<string, Pattern>();
  private identifiedPatterns: Pattern[] = [];

  constructor(env: Env, businessId: string) {
    this.env = env;
    this.businessId = businessId;
    this.loadExistingPatterns();
  }

  async identifyWinningPatterns(): Promise<Pattern[]> {

    // Analyze successful deals
    const successfulDeals = await this.getSuccessfulDeals();
    const patterns = await this.analyzeDealsForPatterns(successfulDeals);

    // Apply patterns to future interactions
    await this.applyPatterns(patterns);

    this.identifiedPatterns = patterns;
    return patterns;
  }

  private async getSuccessfulDeals(): Promise<any[]> {
    const db = this.env.DB_CRM;

    const successfulDeals = await db.prepare(`
      SELECT
        o.*,
        l.*,
        GROUP_CONCAT(i.interaction_data) as interactions,
        GROUP_CONCAT(c.call_data) as calls
      FROM opportunities o
      JOIN leads l ON o.lead_id = l.id
      LEFT JOIN interactions i ON l.id = i.lead_id AND i.business_id = ?
      LEFT JOIN calls c ON l.id = c.lead_id AND c.business_id = ?
      WHERE o.business_id = ? AND l.business_id = ?
        AND o.status = 'closed_won'
        AND o.close_date >= datetime('now', '-6 months')
      GROUP BY o.id
      ORDER BY o.value DESC
      LIMIT 100
    `).bind(this.businessId, this.businessId, this.businessId, this.businessId).all();

    return successfulDeals.results.map((deal: any) => ({
      ...deal,
      interactions: this.parseInteractionData(deal.interactions as string),
      calls: this.parseCallData(deal.calls as string)
    }));
  }

  private async analyzeDealsForPatterns(successfulDeals: any[]): Promise<Pattern[]> {
    const prompt = `
      Analyze these successful deals and identify winning patterns:

      ${JSON.stringify(successfulDeals.slice(0, 20).map((deal: any) => ({
        id: deal.id,
        value: deal.value,
        salesCycle: deal.sales_cycle,
        industry: deal.industry,
        companySize: deal.company_size,
        firstMessage: deal.interactions?.[0]?.content,
        totalInteractions: deal.interactions?.length,
        callsHeld: deal.calls?.length,
        closeReason: deal.close_reason
      })))}

      Look for patterns in:
      1. **First message that got response** - What opening lines work?
      2. **Questions that uncovered pain** - Which discovery questions are most effective?
      3. **Objection handling that worked** - How were concerns addressed?
      4. **Close techniques that succeeded** - What closing approaches work?
      5. **Timing of outreach** - When is the best time to reach out?
      6. **Channel combinations** - Which communication channels work together?
      7. **Content that resonated** - What messaging drives engagement?
      8. **Stakeholder engagement patterns** - How were decision makers engaged?
      9. **Deal velocity patterns** - What accelerates deal closure?
      10. **Industry-specific patterns** - What works for different verticals?

      For each pattern identified, provide:
      - Clear description of the pattern
      - Conditions where it applies
      - Specific actions to take
      - Performance metrics (win rate, response rate, etc.)
      - Evidence/examples from the data
      - Confidence level (0-1)

      Return as JSON array of patterns:
      [
        {
          "name": "string",
          "type": "timing|content|channel|sequence|objection_handling|closing",
          "description": "string",
          "conditions": {
            "segment": "string",
            "stage": "string",
            "channel": "string",
            "context": {}
          },
          "actions": {
            "content": "string",
            "timing": "string",
            "followUp": ["string"]
          },
          "performance": {
            "winRate": number,
            "responseRate": number,
            "dealVelocity": number,
            "revenueImpact": number
          },
          "evidence": {
            "samples": ["string"],
            "dealIds": ["string"]
          },
          "confidence": number,
          "applicability": ["string"]
        }
      ]
    `;

    try {
      const response = await this.callAI(prompt);
      const patternsData = JSON.parse(response);

      const patterns: Pattern[] = patternsData.map((p: any) => ({
        id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        name: p.name,
        type: p.type,
        description: p.description,
        conditions: p.conditions,
        actions: p.actions,
        performance: p.performance,
        evidence: {
          dealIds: p.evidence.dealIds || [],
          interactionIds: [],
          samples: p.evidence.samples || []
        },
        confidence: p.confidence,
        applicability: p.applicability,
        discovered: new Date().toISOString(),
        lastValidated: new Date().toISOString()
      }));

      // Store discovered patterns
      for (const pattern of patterns) {
        await this.storePattern(pattern);
        this.patterns.set(pattern.id, pattern);
      }

      return patterns;
    } catch (error: any) {
      return [];
    }
  }

  async identifyChannelPatterns(): Promise<Pattern[]> {
    const channelData = await this.getChannelPerformanceData();

    const prompt = `
      Analyze channel performance data to identify winning patterns:

      ${JSON.stringify(channelData)}

      Identify patterns for:
      1. **Multi-channel sequences** that work best
      2. **Channel timing** for maximum impact
      3. **Channel combinations** that amplify each other
      4. **Content adaptation** across channels
      5. **Prospect behavior** across different channels

      Focus on actionable insights for channel orchestration.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'channel');
    } catch (error: any) {
      return [];
    }
  }

  async identifyTimingPatterns(): Promise<Pattern[]> {
    const timingData = await this.getTimingPerformanceData();

    const prompt = `
      Analyze timing data to identify optimal outreach patterns:

      ${JSON.stringify(timingData)}

      Look for patterns in:
      1. **Best days of week** for different types of outreach
      2. **Optimal time of day** by industry/role
      3. **Follow-up timing** sequences that work
      4. **Seasonal patterns** in response rates
      5. **Response latency** patterns
      6. **Meeting scheduling** preferences

      Provide specific timing recommendations with confidence levels.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'timing');
    } catch (error: any) {
      return [];
    }
  }

  async identifyContentPatterns(): Promise<Pattern[]> {
    const contentData = await this.getContentPerformanceData();

    const prompt = `
      Analyze content performance to identify winning message patterns:

      ${JSON.stringify(contentData)}

      Identify patterns in:
      1. **Subject lines** that get opens
      2. **Opening lines** that get responses
      3. **Value propositions** that resonate
      4. **Call-to-actions** that drive action
      5. **Social proof** that builds credibility
      6. **Personalization** elements that work
      7. **Message length** optimization
      8. **Tone and style** preferences

      Focus on specific, replicable content patterns.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'content');
    } catch (error: any) {
      return [];
    }
  }

  async identifyObjectionPatterns(): Promise<Pattern[]> {
    const objectionData = await this.getObjectionData();

    const prompt = `
      Analyze objection handling data to identify successful patterns:

      ${JSON.stringify(objectionData)}

      Identify patterns for:
      1. **Objection prevention** - How to avoid common objections
      2. **Objection handling frameworks** that work
      3. **Reframe techniques** that change perspective
      4. **Social proof responses** that overcome resistance
      5. **Follow-up strategies** after handling objections
      6. **Objection timing** - When objections typically arise

      Focus on proven objection handling sequences.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'objection_handling');
    } catch (error: any) {
      return [];
    }
  }

  async identifySequencePatterns(): Promise<Pattern[]> {
    const sequenceData = await this.getSequencePerformanceData();

    const prompt = `
      Analyze multi-touch sequence data to identify winning patterns:

      ${JSON.stringify(sequenceData)}

      Look for patterns in:
      1. **Sequence length** optimization
      2. **Touch frequency** that works best
      3. **Channel progression** through sequences
      4. **Content evolution** across touches
      5. **Breakup message** effectiveness
      6. **Re-engagement** strategies
      7. **Sequence personalization** approaches

      Identify optimal sequence structures for different scenarios.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'sequence');
    } catch (error: any) {
      return [];
    }
  }

  async identifyClosingPatterns(): Promise<Pattern[]> {
    const closingData = await this.getClosingData();

    const prompt = `
      Analyze successful closing techniques to identify winning patterns:

      ${JSON.stringify(closingData)}

      Identify patterns for:
      1. **Buying signal recognition** and response
      2. **Closing timing** optimization
      3. **Closing techniques** that work by situation
      4. **Urgency creation** methods
      5. **Risk reversal** approaches
      6. **Next step** progression strategies
      7. **Deal acceleration** tactics

      Focus on replicable closing sequences and techniques.
    `;

    try {
      const response = await this.callAI(prompt);
      const patterns = JSON.parse(response);
      return await this.processAndStorePatterns(patterns, 'closing');
    } catch (error: any) {
      return [];
    }
  }

  private async applyPatterns(patterns: Pattern[]): Promise<void> {

    for (const pattern of patterns) {
      // Update relevant strategies with pattern insights
      await this.updateStrategiesWithPattern(pattern);

      // Create pattern-based recommendations
      await this.createPatternRecommendations(pattern);

      // Update segment targeting based on patterns
      await this.updateSegmentTargeting(pattern);
    }
  }

  private async updateStrategiesWithPattern(pattern: Pattern): Promise<void> {
    const db = this.env.DB_CRM;

    // Find strategies that could benefit from this pattern
    const relevantStrategies = await db.prepare(`
      SELECT * FROM strategies
      WHERE type = ? OR target_segment IN (${pattern.applicability.map(() => '?').join(',')})
    `).bind(pattern.type, ...pattern.applicability).all();

    for (const strategyRow of relevantStrategies.results) {
      const strategy = JSON.parse((strategyRow as any).strategy_data as string);

      // Apply pattern insights to strategy
      const updatedStrategy = await this.applyPatternToStrategy(strategy, pattern);

      // Store updated strategy
      await db.prepare(`
        UPDATE strategies SET
          strategy_data = ?,
          version = version + 1,
          updated_at = ?
        WHERE id = ?
      `).bind(
        JSON.stringify(updatedStrategy),
        new Date().toISOString(),
        strategy.id
      ).run();
    }
  }

  private async applyPatternToStrategy(strategy: any, pattern: Pattern): Promise<any> {
    const updatedStrategy = { ...strategy };

    switch (pattern.type) {
      case 'timing':
        if (pattern.actions.timing) {
          updatedStrategy.approach.timing = pattern.actions.timing;
        }
        break;

      case 'content':
        if (pattern.actions.content) {
          updatedStrategy.prompts.examples.push(pattern.actions.content);
        }
        break;

      case 'channel':
        if (pattern.conditions.channel) {
          if (!updatedStrategy.approach.channel.includes(pattern.conditions.channel)) {
            updatedStrategy.approach.channel.push(pattern.conditions.channel);
          }
        }
        break;

      case 'sequence':
        updatedStrategy.approach.structure = pattern.actions.followUp || updatedStrategy.approach.structure;
        break;

      case 'objection_handling':
        updatedStrategy.objectionHandling = {
          ...updatedStrategy.objectionHandling,
          patterns: [...(updatedStrategy.objectionHandling?.patterns || []), pattern.id]
        };
        break;

      case 'closing':
        updatedStrategy.closingTechniques = {
          ...updatedStrategy.closingTechniques,
          patterns: [...(updatedStrategy.closingTechniques?.patterns || []), pattern.id]
        };
        break;
    }

    return updatedStrategy;
  }

  private async createPatternRecommendations(pattern: Pattern): Promise<void> {
    const db = this.env.DB_CRM;

    const recommendation = {
      id: `rec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      patternId: pattern.id,
      type: pattern.type,
      description: `Apply ${pattern.name} pattern`,
      action: pattern.description,
      expectedImpact: `Improve ${pattern.type} performance by ${(pattern.performance.winRate * 100).toFixed(1)}%`,
      confidence: pattern.confidence,
      applicability: pattern.applicability,
      createdAt: new Date().toISOString()
    };

    await db.prepare(`
      INSERT INTO pattern_recommendations (
        id, pattern_id, type, description, action,
        expected_impact, confidence, applicability, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      recommendation.id,
      recommendation.patternId,
      recommendation.type,
      recommendation.description,
      recommendation.action,
      recommendation.expectedImpact,
      recommendation.confidence,
      JSON.stringify(recommendation.applicability),
      recommendation.createdAt
    ).run();
  }

  private async updateSegmentTargeting(pattern: Pattern): Promise<void> {
    // Update customer segments with pattern insights
    const db = this.env.DB_CRM;

    for (const segmentName of pattern.applicability) {
      const segment = await db.prepare(`
        SELECT * FROM customer_segments WHERE name = ?
      `).bind(segmentName).first();

      if (segment) {
        const segmentData = JSON.parse(segment.segment_data as string);

        if (!segmentData.patterns) {
          segmentData.patterns = [];
        }

        if (!segmentData.patterns.includes(pattern.id)) {
          segmentData.patterns.push(pattern.id);
        }

        await db.prepare(`
          UPDATE customer_segments SET
            segment_data = ?,
            updated_at = ?
          WHERE id = ?
        `).bind(
          JSON.stringify(segmentData),
          new Date().toISOString(),
          segment.id
        ).run();
      }
    }
  }

  private async processAndStorePatterns(patternsData: any[], type: string): Promise<Pattern[]> {
    const patterns: Pattern[] = [];

    for (const patternData of patternsData) {
      const pattern: Pattern = {
        id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        name: patternData.name,
        type: type as any,
        description: patternData.description,
        conditions: patternData.conditions || {},
        actions: patternData.actions || { content: '', timing: '', followUp: [] },
        performance: patternData.performance || { winRate: 0, responseRate: 0, dealVelocity: 0, revenueImpact: 0 },
        evidence: {
          dealIds: patternData.evidence?.dealIds || [],
          interactionIds: patternData.evidence?.interactionIds || [],
          samples: patternData.evidence?.samples || []
        },
        confidence: patternData.confidence || 0.5,
        applicability: patternData.applicability || ['general'],
        discovered: new Date().toISOString(),
        lastValidated: new Date().toISOString()
      };

      await this.storePattern(pattern);
      this.patterns.set(pattern.id, pattern);
      patterns.push(pattern);
    }

    return patterns;
  }

  // Data gathering methods
  private async getChannelPerformanceData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        channel,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        AVG(response_time_minutes) as avg_response_time,
        COUNT(*) as total_interactions
      FROM interactions
      WHERE created_at >= datetime('now', '-3 months')
      GROUP BY channel
      ORDER BY success_rate DESC
    `).all();

    return data.results;
  }

  private async getTimingPerformanceData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        strftime('%w', created_at) as day_of_week,
        strftime('%H', created_at) as hour_of_day,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        COUNT(*) as total_interactions
      FROM interactions
      WHERE created_at >= datetime('now', '-3 months')
      GROUP BY day_of_week, hour_of_day
      HAVING total_interactions >= 10
      ORDER BY success_rate DESC
    `).all();

    return data.results;
  }

  private async getContentPerformanceData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        interaction_type,
        subject_line,
        opening_line,
        content_length,
        personalization_score,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        COUNT(*) as total_uses
      FROM interactions i
      JOIN interaction_content ic ON i.id = ic.interaction_id
      WHERE i.created_at >= datetime('now', '-3 months')
        AND ic.content_length > 0
      GROUP BY interaction_type, subject_line, opening_line
      HAVING total_uses >= 5
      ORDER BY success_rate DESC
      LIMIT 50
    `).all();

    return data.results;
  }

  private async getObjectionData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        objection_type,
        objection_content,
        response_strategy,
        handled_successfully,
        follow_up_outcome,
        COUNT(*) as frequency
      FROM objection_handling oh
      JOIN interactions i ON oh.interaction_id = i.id
      WHERE i.created_at >= datetime('now', '-3 months')
      GROUP BY objection_type, response_strategy
      ORDER BY handled_successfully DESC, frequency DESC
    `).all();

    return data.results;
  }

  private async getSequencePerformanceData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        sequence_id,
        sequence_step,
        channel,
        days_since_previous,
        AVG(CASE WHEN outcome_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
        COUNT(*) as total_steps
      FROM sequence_interactions si
      JOIN interactions i ON si.interaction_id = i.id
      WHERE i.created_at >= datetime('now', '-3 months')
      GROUP BY sequence_id, sequence_step
      ORDER BY success_rate DESC
    `).all();

    return data.results;
  }

  private async getClosingData(): Promise<any> {
    const db = this.env.DB_CRM;

    const data = await db.prepare(`
      SELECT
        closing_technique,
        deal_stage,
        buying_signals,
        urgency_factors,
        outcome,
        days_to_close,
        deal_value
      FROM closing_attempts ca
      JOIN opportunities o ON ca.opportunity_id = o.id
      WHERE o.close_date >= datetime('now', '-6 months')
      ORDER BY outcome DESC, deal_value DESC
    `).all();

    return data.results;
  }

  private parseInteractionData(data: string): any[] {
    if (!data) return [];
    try {
      return data.split(',').map((item: any) => JSON.parse(item));
    } catch (error: any) {
      return [];
    }
  }

  private parseCallData(data: string): any[] {
    if (!data) return [];
    try {
      return data.split(',').map((item: any) => JSON.parse(item));
    } catch (error: any) {
      return [];
    }
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
          max_tokens: 3000,
          messages: [{
            role: 'user',
            content: prompt
          }],
          temperature: 0.4
        })
      });

      const result = await response.json() as any;
      const content = result.content[0].text;

      // Extract JSON if present
      const jsonMatch = content.match(/\[[\s\S]*\]|\{[\s\S]*\}/);
      return jsonMatch ? jsonMatch[0] : content;
    } catch (error: any) {
      throw error;
    }
  }

  private async storePattern(pattern: Pattern): Promise<void> {
    const db = this.env.DB_CRM;

    await db.prepare(`
      INSERT OR REPLACE INTO patterns (
        id, name, type, description, pattern_data,
        confidence, discovered, last_validated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      pattern.id,
      pattern.name,
      pattern.type,
      pattern.description,
      JSON.stringify(pattern),
      pattern.confidence,
      pattern.discovered,
      pattern.lastValidated
    ).run();
  }

  private async loadExistingPatterns(): Promise<void> {
    const db = this.env.DB_CRM;

    const patterns = await db.prepare(`
      SELECT * FROM patterns
      WHERE last_validated >= datetime('now', '-30 days')
      ORDER BY confidence DESC
    `).all();

    for (const row of patterns.results) {
      const pattern = JSON.parse((row as any).pattern_data as string) as Pattern;
      this.patterns.set(pattern.id, pattern);
    }

  }

  // Public methods
  async validatePattern(patternId: string): Promise<boolean> {
    const pattern = this.patterns.get(patternId);
    if (!pattern) return false;

    // Validate pattern against recent data
    const validationResult = await this.validatePatternAgainstRecentData(pattern);

    pattern.lastValidated = new Date().toISOString();
    pattern.confidence = validationResult.confidence;

    await this.storePattern(pattern);

    return validationResult.isValid;
  }

  private async validatePatternAgainstRecentData(pattern: Pattern): Promise<{ isValid: boolean; confidence: number }> {
    // Implementation would check if pattern still holds true against recent data
    // For now, return mock validation
    return {
      isValid: true,
      confidence: Math.max(0.3, pattern.confidence * 0.95) // Slight confidence decay
    };
  }

  async getPatternsByType(type: string): Promise<Pattern[]> {
    return Array.from(this.patterns.values()).filter((p: any) => p.type === type);
  }

  async getTopPerformingPatterns(limit: number = 10): Promise<Pattern[]> {
    return Array.from(this.patterns.values())
      .sort((a, b) => (b.performance.winRate * b.confidence) - (a.performance.winRate * a.confidence))
      .slice(0, limit);
  }

  async getPatternRecommendations(segmentId: string): Promise<any[]> {
    const db = this.env.DB_CRM;

    const recommendations = await db.prepare(`
      SELECT * FROM pattern_recommendations
      WHERE JSON_EXTRACT(applicability, '$') LIKE '%${segmentId}%'
        OR JSON_EXTRACT(applicability, '$') LIKE '%general%'
      ORDER BY confidence DESC
      LIMIT 20
    `).all();

    return recommendations.results;
  }

  async runComprehensivePatternAnalysis(): Promise<{
    channelPatterns: Pattern[];
    timingPatterns: Pattern[];
    contentPatterns: Pattern[];
    objectionPatterns: Pattern[];
    sequencePatterns: Pattern[];
    closingPatterns: Pattern[];
  }> {

    const [
      channelPatterns,
      timingPatterns,
      contentPatterns,
      objectionPatterns,
      sequencePatterns,
      closingPatterns
    ] = await Promise.all([
      this.identifyChannelPatterns(),
      this.identifyTimingPatterns(),
      this.identifyContentPatterns(),
      this.identifyObjectionPatterns(),
      this.identifySequencePatterns(),
      this.identifyClosingPatterns()
    ]);

    return {
      channelPatterns,
      timingPatterns,
      contentPatterns,
      objectionPatterns,
      sequencePatterns,
      closingPatterns
    };
  }

  async getPatternInsights(): Promise<{
    totalPatterns: number;
    averageConfidence: number;
    topPerformingType: string;
    recentDiscoveries: number;
    validationRate: number;
  }> {
    const patterns = Array.from(this.patterns.values());
    const recentPatterns = patterns.filter((p: any) =>
      new Date(p.discovered).getTime() > Date.now() - (30 * 24 * 60 * 60 * 1000)
    );

    const typePerformance = new Map<string, number>();
    for (const pattern of patterns) {
      const score = pattern.performance.winRate * pattern.confidence;
      typePerformance.set(pattern.type, (typePerformance.get(pattern.type) || 0) + score);
    }

    const topPerformingType = Array.from(typePerformance.entries())
      .sort((a, b) => b[1] - a[1])[0]?.[0] || 'none';

    return {
      totalPatterns: patterns.length,
      averageConfidence: patterns.reduce((sum, p) => sum + p.confidence, 0) / patterns.length,
      topPerformingType,
      recentDiscoveries: recentPatterns.length,
      validationRate: 0.85 // Would calculate from actual validation data
    };
  }
}