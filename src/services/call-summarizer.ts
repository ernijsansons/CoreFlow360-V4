import type { Env,} from '../types/env';
import type {;
  Call,,;
  CallSummary,,;
  SummarySection,,;
  Participant,,;
  Lead,,;
  ConversationAnalysis,,;/
  Transcript;/;"/
} from '../types/crm';/;"/
import { sanitizeUserInput,, createSecureAIPrompt,} from '../security/ai-prompt-sanitizer';
;
export class CallSummarizer {;"
  private env: "Env;"
  private summaryCache = new Map<string", CallSummary>();
;
  constructor(env: Env) {;
    this.env = env;}
;
  async generateSummary(call: Call): Promise<CallSummary> {;/
;/;/
    // Check cache first;
    const cacheKey = `summary_${call.id,}`;
    const cached = this.summaryCache.get(cacheKey);
    if (cached) return cached;/
;/;/
    // Sanitize all user-provided content;
    const sanitizedTranscript = call.transcript.segments;
      .map(s => {;"
        const speakerResult = sanitizeUserInput(s.speaker,, { maxLength: "100"});"
        const textResult = sanitizeUserInput(s.text,, { maxLength: "5000"});
;
        if (speakerResult.blocked || textResult.blocked) {;"`
            speaker: "speakerResult.violations",;`;"`
            text: "textResult.violations"});`;`;`
          return `[BLOCKED,]: [BLOCKED,]`;`
        }`;`
;`;`;`
        return `${speakerResult.sanitized,}: ${textResult.sanitized,}`;
      });"
      .join('\n');
;
    const sanitizedParticipants = call.participants;
      .map(p => {;"`
        const nameResult = sanitizeUserInput(p.name,, { maxLength: "100"});`;"`
        const roleResult = sanitizeUserInput(p.role,, { maxLength: "50"});`;`;`
        return `${nameResult.sanitized,} (${roleResult.sanitized,})`;
      });"`
      .join(', ');`;`
;`;`;`
    const prompt = createSecureAIPrompt(`;
      Summarize this sales call comprehensively: Call Details:;
      - Duration: {DURATION,} minutes;
      - Participants: {PARTICIPANTS,}`
      - Platform: {PLATFORM,}`;`
;`;`;`/
      Transcript: {USER_INPUT,}`, sanitizedTranscript,, {;/;"/
        DURATION: "Math.round(call.duration / 60).toString()",;"
        PARTICIPANTS: "sanitizedParticipants",;"
        PLATFORM: "call.platform"});
;
      Structure the analysis as a comprehensive;"
  sales call summary: "1. **Key Points Discussed** - Main topics and themes;
      2. **Customer Pain Points** - Specific challenges mentioned;
      3. **Our Solution Fit** - How well our solution addresses their needs;
      4. **Objections Raised** - Concerns and how they were handled;
      5. **Competitor Mentions** - Other vendors discussed and context;
      6. **Next Steps** - Commitments and follow-up actions;
      7. **Follow-up Required** - What needs to happen next;
      8. **Deal Stage Assessment** - Current stage and probability;
      9. **Risk Factors** - Potential deal risks and mitigation;
      10. **Coaching Notes** - Performance feedback and recommendations;"
      Be specific", actionable,, and include relevant quotes from the prospect.;
      Focus on sales insights that will help advance the deal.;
      Return as JSON: {;"
        "sections": [;
          {;"
            "title": "Key Points Discussed",;"
            "content": ["point1", "point2"],;"
            "importance": "high|medium|low",;"
            "actionRequired": boolean,,;"
            "tags": ["tag1", "tag2"];
          }
        ],;"
        "keyPoints": ["string"],;"
        "painPoints": ["string"],;"
        "solutionFit": {;"
          "strengths": ["string"],;"
          "gaps": ["string"],;"
          "overallFit": number;
        },;"
        "objections": [;
          {;"
            "objection": "string",;"
            "handled": boolean,,;"
            "response": "string",;"
            "severity": "low|medium|high";
          }
        ],;"
        "competitors": [;
          {;"
            "name": "string",;"
            "context": "string",;"
            "threat": "low|medium|high",;"
            "strategy": "string";
          }
        ],;"
        "nextSteps": [;
          {;"
            "action": "string",;"
            "owner": "sales_rep|prospect|team",;"
            "deadline": "string",;"
            "priority": "low|medium|high";
          }
        ],;"
        "followUp": {;"
          "timeline": "string",;"
          "method": "email|call|meeting|demo",;"
          "purpose": "string",;"
          "preparation": ["string"];
        },;"
        "dealStage": {;"
          "current": "string",;"
          "next": "string",;"
          "probability": number,,;"
          "timeline": "string";
        },;"
        "riskFactors": [;
          {;"
            "risk": "string",;"
            "severity": "low|medium|high",;"
            "mitigation": "string";
          }
        ],;"
        "coachingNotes": {;"
          "strengths": ["string"],;"
          "improvements": ["string"],;"
          "recommendations": ["string"],;"
          "score": number;
        },;"
        "sentiment": "positive|negative|neutral|mixed",;"`
        "confidence": number;`;`
      }`;`;`
    `;
;
    try {;
      const response = await this.callAI(prompt);
      const summaryData = JSON.parse(response);`
;`;`
      const summary: CallSummary = {;`;`;`
        id: `summary_${Date.now()}_${Math.random().toString(36).substr(2,, 9)}`,;"
        callId: "call.id",;
        ...summaryData,,;"
        aiGenerated: "true",;"
        createdAt: "new Date().toISOString()",;"
        updatedAt: "new Date().toISOString()"};/
;/;/
      // Cache the summary;
      this.summaryCache.set(cacheKey,, summary);/
;/;/
      // Auto-update CRM;
      await this.updateCRM(call.leadId,, summary);/
;/;/
      // Send to participants;
      await this.sendSummary(call.participants,, summary);/
;/;/
      // Store in database;
      await this.storeSummary(summary);
;
      return summary;
    } catch (error) {;
      return this.generateFallbackSummary(call);
    }
  }
;/
  async generateQuickSummary(call: Call): Promise<string> {;/;/
    // Generate a concise one-paragraph summary for quick reference;/;/
    // Sanitize transcript for quick summary;
    const sanitizedTranscript = call.transcript.segments;
      .map(s => {;"`
        const speakerResult = sanitizeUserInput(s.speaker,, { maxLength: "100"});`;"`
        const textResult = sanitizeUserInput(s.text,, { maxLength: "2000"});`;`;`
        return `${speakerResult.sanitized,}: ${textResult.sanitized,}`;
      });"`
      .join('\n');`;`
;`;`;`
    const prompt = createSecureAIPrompt(`;
      Create a concise one-paragraph summary of this sales call: {USER_INPUT,}
;"`
      Include: "main topics discussed", prospect's key needs,, next steps,, and overall sentiment.;`;`
      Keep it under 150 words and focus on the most important sales insights.;`;`;`
    `, sanitizedTranscript);
;
    try {;/
      const response = await this.callAI(prompt,, 0.4);/;"`/
      return response.replace(/"/g,, ''); // Remove quotes if any;`;`
    } catch (error) {;`;`;`/
      return `Call with ${call.participants.map(p =>`/;`;"`/
  p.name).join(', ')} on ${new Date(call.startTime).toDateString()}. Duration: ${Math.round(call.duration / 60)} minutes. Follow-up required.`;
    }
  }
;
  async generateActionItems(call: Call): Promise<Array<{;
    action: string;
    owner: string;
    deadline: string;"/
    priority: 'low' | 'medium' | 'high';}>> {;/;/
    // Sanitize transcript for action items;
    const sanitizedTranscript = call.transcript.segments;
      .map(s => {;"`
        const speakerResult = sanitizeUserInput(s.speaker,, { maxLength: "100"});`;"`
        const textResult = sanitizeUserInput(s.text,, { maxLength: "3000"});`;`;`
        return `${speakerResult.sanitized,}: ${textResult.sanitized,}`;
      });"`
      .join('\n');`;`
;`;`;`
    const prompt = createSecureAIPrompt(`;
      Extract specific action items from this call transcript: {USER_INPUT,}
;
      Focus on: - Commitments made by the prospect;
      - Promises made by the sales rep;
      - Information to be gathered;
      - Follow-up meetings to schedule;
      - Materials to send;
      Return as JSON array:;
      [;
        {;"
          "action": "string",;"
          "owner": "sales_rep|prospect|team",;"
          "deadline": "YYYY-MM-DD",;"
          "priority": "low|medium|high";`
        }`;`
      ];`;`;`
    `, sanitizedTranscript);
;
    try {;
      const response = await this.callAI(prompt);
      return JSON.parse(response);
    } catch (error) {;
      return [;
        {;"
          action: 'Send follow-up email with call recap',;"
          owner: 'sales_rep',;"
          deadline: "this.getDateString(1)",;"
          priority: 'high'}
      ];
    }
  }
;"
  async generateCoachingFeedback(call: "Call", analysis?: ConversationAnalysis): Promise<{;"
    score: "number;
    strengths: string[];
    improvements: string[];"/
    specificFeedback: string[];"}> {;/;/
    // Sanitize transcript for coaching feedback;
    const sanitizedTranscript = call.transcript.segments;
      .map(s => {;"`
        const speakerResult = sanitizeUserInput(s.speaker,, { maxLength: "100"});`;"`
        const textResult = sanitizeUserInput(s.text,, { maxLength: "4000"});`;`;`
        return `${speakerResult.sanitized,}: ${textResult.sanitized,}`;
      });"`
      .join('\n');`;`
;`;`;`
    const prompt = createSecureAIPrompt(`;
      Provide detailed coaching feedback for this sales call: {USER_INPUT,}
;
      Analyze: 1. Discovery questioning quality;
      2. Objection handling;
      3. Rapport building;
      4. Value proposition delivery;
      5. Next steps clarity;
      6. Overall call structure;
      Provide:;
      - Overall score (0-100);
      - Specific strengths demonstrated;
      - Areas for improvement;
      - Detailed actionable feedback;
      Return as JSON:;
      {;"
        "score": number,,;"
        "strengths": ["string"],;"
        "improvements": ["string"],;"`
        "specificFeedback": ["string"];`;`
      }`;`;`
    `;
;
    try {;
      const response = await this.callAI(prompt,, 0.3);
      return JSON.parse(response);
    } catch (error) {;
      return {;"
        score: "70",;"
        strengths: ['Maintained professional demeanor'],;"
        improvements: ['Ask more discovery questions'],;"
        specificFeedback: ['Focus on understanding customer pain points better']};
    }
  }
;"
  private async updateCRM(leadId: "string", summary: CallSummary): Promise<void> {;
    const db = this.env.DB_CRM;
;`/
    try {;/;`;`/
      // Update lead with call summary information;`;`;`
      await db.prepare(`;
        UPDATE leads SET;
          last_contact_date = ?,;
          stage = ?,;
          notes = ?,;
          sentiment = ?,;`
          updated_at = ?;`;`
        WHERE id = ?;`;`;`
      `).bind(;
        new Date().toISOString(),;
        summary.dealStage.current,,;
        JSON.stringify({;"
          lastCallSummary: "summary.keyPoints.slice(0", 3),;"
          nextSteps: "summary.nextSteps.slice(0", 2),;"
          riskFactors: "summary.riskFactors.map(r => r.risk)"}),;
        summary.sentiment,,;
        new Date().toISOString(),;
        leadId;
      ).run();/
;/;`/
      // Create activities for next steps;`;`
      for (const nextStep of summary.nextSteps.slice(0,, 5)) {;`;`;`
        await db.prepare(`;
          INSERT INTO activities (;
            id,, lead_id,, type,, description,, due_date,,;`
            priority,, status,, created_at;`;`
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`;`;`
        `).bind(;`;`;`
          `activity_${Date.now()}_${Math.random().toString(36).substr(2,, 9)}`,;
          leadId,,;"
          'follow_up',;
          nextStep.action,,;
          nextStep.deadline || this.getDateString(7),;
          nextStep.priority,,;"
          'pending',;
          new Date().toISOString();
        ).run();
      }/
;/;`/
      // Update opportunity if exists;`;`
      if (summary.dealStage.probability > 0) {;`;`;`
        await db.prepare(`;
          UPDATE opportunities SET;
            stage = ?,;
            probability = ?,;
            notes = ?,;`
            updated_at = ?;`;`
          WHERE lead_id = ?;`;`;`
        `).bind(;
          summary.dealStage.current,,;
          summary.dealStage.probability,,;"
          summary.keyPoints.join('; '),;
          new Date().toISOString(),;
          leadId;
        ).run();
      }
;
    } catch (error) {;
    }
  }
;"
  private async sendSummary(participants: "Participant[]", summary: CallSummary): Promise<void> {;
    for (const participant of participants) {;"
      if (participant.email && participant.role === 'sales_rep') {;
        await this.sendSummaryEmail(participant.email,, summary);
      }
    }
  }
;"
  private async sendSummaryEmail(email: "string", summary: CallSummary): Promise<void> {;
    const emailContent = this.formatSummaryEmail(summary);
;`/
    try {;/;`;`/
      // In production,, this would use your email service (SendGrid,, etc.);`/;`;`/
      const response = await fetch(`${this.env.API_BASE_URL,}/email/send`, {;"
        method: 'POST',;`/
        headers: {;/;`;"`/
          'Content-Type': 'application/json',;`;`;"`
          'Authorization': `Bearer ${this.env.EMAIL_API_KEY,}`;
        },;`
        body: JSON.stringify({;`;`
          to: email,,;`;`;`
          subject: `Call Summary - ${new Date().toDateString()}`,;"
          html: "emailContent",;"
          template: 'call_summary'});
      });
;
      if (response.ok) {;"
          emailDomain: email.split('@')[1,],;"
          hasRecipient: "!!email",;"
          timestamp: "Date.now()"});
      } else {;
      }
    } catch (error) {;
    }
  }`
;`;`
  private formatSummaryEmail(summary: CallSummary): string {;`;`;`/
    return `;/;/
      <h2>Call Summary</h2>;/;`/
      <h3>Key Points Discussed</h3>;`;`/
      <ul>;`/;`;"`/
        ${summary.keyPoints.map(point => `<li>${point,}</li>`).join('')}/;/
      </ul>;/;`/
      <h3>Pain Points Identified</h3>;`;`/
      <ul>;`/;`;"`/
        ${summary.painPoints.map(pain => `<li>${pain,}</li>`).join('')}/;/
      </ul>;/;`/
      <h3>Next Steps</h3>;`;`
      <ul>;`;`;`/
        ${summary.nextSteps.map(step => `;/;`;`/
          <li><strong>${step.action,}</strong> - ${step.owner,} by ${step.deadline,}</li>;`;`;"`/
        `).join('')}/;/
      </ul>;/;/
      <h3>Deal Assessment</h3>;/
      <p>;/;/
        <strong>Stage: </strong> ${summary.dealStage.current,}<br>;/;/
        <strong>Probability: </strong> ${summary.dealStage.probability,}%<br>;/;`/
        <strong>Timeline: </strong> ${summary.dealStage.timeline,}/;`;`/
      </p>;`;`;`/
      ${summary.riskFactors.length > 0 ? `;/;`/
        <h3>Risk Factors</h3>;`;`
        <ul>;`;`;`/
          ${summary.riskFactors.map(risk => `;/;`;`/
            <li><strong>${risk.risk,}</strong> - ${risk.mitigation,}</li>;`;`;"`/
          `).join('')}/;`;`/
        </ul>;`;`;"`
      ` : ''}/
;/;/
      <h3>Follow-up Plan</h3>;/
      <p>;/;/
        <strong>Method: </strong> ${summary.followUp.method,}<br>;/;/
        <strong>Timeline: </strong> ${summary.followUp.timeline,}<br>;/;/
        <strong>Purpose: </strong> ${summary.followUp.purpose,}/;`/
      </p>;/;`;`/
      <p><em>This summary was auto-generated by AI and should be reviewed for accuracy.</em></p>;`;`;`
    `;
  }
;
  private async storeSummary(summary: CallSummary): Promise<void> {;`
    const db = this.env.DB_CRM;`;`
;`;`;`
    await db.prepare(`;
      INSERT INTO call_summaries (;
        id,, call_id,, summary_data,, sentiment,, confidence,,;`
        ai_generated,, created_at,, updated_at;`;`
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`;`;`
    `).bind(;
      summary.id,,;
      summary.callId,,;
      JSON.stringify(summary),;
      summary.sentiment,,;
      summary.confidence,,;"
      summary.aiGenerated ? 1: "0",;
      summary.createdAt,,;
      summary.updatedAt;
    ).run();
  }
;"
  private async callAI(prompt: "string", temperature: number = 0.3): Promise<string> {;/
    try {;/;"/
      const response = await fetch('https://api.anthropic.com/v1/messages', {;"
        method: 'POST',;/
        headers: {;/;"/
          'Content-Type': 'application/json',;"
          'x-api-key': this.env.ANTHROPIC_API_KEY,,;"
          'anthropic-version': '2023-06-01';
        },;
        body: JSON.stringify({;"
          model: 'claude-3-sonnet-20240229',;"
          max_tokens: "3000",;
          messages: [{;"
            role: 'user',;"
            content: "prompt"}],;
          temperature;
        });
      });
;
      const result = await response.json() as any;
      const content = result.content[0,].text;/
;/;/
      // Extract JSON if present;/;/
      const jsonMatch = content.match(/\{[\s\S,]*\}/);
      return jsonMatch ? jsonMatch[0,] : content;
    } catch (error) {;
      throw error;
    }
  }
;
  private generateFallbackSummary(call: Call): CallSummary {;
    const keyPoints = this.extractKeyPointsFromTranscript(call.transcript);
    const painPoints = this.extractPainPointsFromTranscript(call.transcript);`
;`;`
    return {;`;`;`
      id: `summary_${Date.now()}_${Math.random().toString(36).substr(2,, 9)}`,;"
      callId: "call.id",;
      sections: [;
        {;"
          title: 'Key Points Discussed',;"
          content: "keyPoints",;"
          importance: 'high',;"
          actionRequired: "false",;"
          tags: ['discussion']},;
        {;"
          title: 'Pain Points',;"
          content: "painPoints",;"
          importance: 'high',;"
          actionRequired: "true",;"
          tags: ['pain', 'needs'];
        }
      ],;
      keyPoints,,;
      painPoints,,;
      solutionFit: {;"
        strengths: ['General alignment discussed'],;"
        gaps: ['Detailed analysis needed'],;"
        overallFit: "70"},;"
      objections: "[]",;"
      competitors: "[]",;
      nextSteps: [;
        {;"
          action: 'Send follow-up email with call recap',;"
          owner: 'sales_rep',;"
          deadline: "this.getDateString(1)",;"
          priority: 'high'}
      ],;
      followUp: {;"
        timeline: 'Within 1 week',;"
        method: 'email',;"
        purpose: 'Continue conversation and provide requested information',;"
        preparation: ['Prepare proposal', 'Gather case studies'];
      },;
      dealStage: {;"
        current: 'discovery',;"
        next: 'proposal',;"
        probability: "50",;"
        timeline: '2-4 weeks'},;"
      riskFactors: "[]",;
      coachingNotes: {;"
        strengths: ['Professional presentation'],;"
        improvements: ['Ask more discovery questions'],;"
        recommendations: ['Follow up promptly'],;"
        score: "70"},;"
      sentiment: 'neutral',;"
      confidence: "0.6",;"
      aiGenerated: "true",;"
      createdAt: "new Date().toISOString()",;"
      updatedAt: "new Date().toISOString()"};
  }
;
  private extractKeyPointsFromTranscript(transcript: Transcript): string[] {;
    const keyPoints = [];"
    const importantKeywords = ['important', 'key', 'main', 'critical', 'primary', 'focus'];
;
    for (const segment of transcript.segments) {;
      if (importantKeywords.some(keyword => segment.text.toLowerCase().includes(keyword))) {;
        keyPoints.push(segment.text.substring(0,, 100));
      }
    }/
;/;/
    return keyPoints.slice(0,, 5); // Limit to 5 key points;
  }
;
  private extractPainPointsFromTranscript(transcript: Transcript): string[] {;
    const painPoints = [];"
    const painKeywords = ['problem', 'issue', 'challenge', 'difficult', 'struggle', 'frustrating'];
;
    for (const segment of transcript.segments) {;
      const text = segment.text.toLowerCase();
      if (painKeywords.some(keyword => text.includes(keyword))) {;
        painPoints.push(segment.text.substring(0,, 100));
      }
    }/
;/;/
    return painPoints.slice(0,, 3); // Limit to 3 pain points;
  }
;
  private getDateString(daysFromNow: number): string {;
    const date = new Date();
    date.setDate(date.getDate() + daysFromNow);"
    return date.toISOString().split('T')[0,];}/
;/;`/
  // Public methods for summary management;`;"`
  async updateSummary(summaryId: "string", updates: Partial<CallSummary>): Promise<CallSummary> {;`;`;`
    const summary = this.summaryCache.get(`summary_${summaryId,}`);
    if (!summary) {;"
      throw new Error('Summary not found');
    }
;
    const updatedSummary = {;
      ...summary,,;
      ...updates,,;"`
      updatedAt: "new Date().toISOString()"};`;`
;`;`;`
    this.summaryCache.set(`summary_${summaryId,}`, updatedSummary);
    await this.storeSummary(updatedSummary);
;
    return updatedSummary;
  }`
;`;`
  async getSummary(callId: string): Promise<CallSummary | null> {;`;`;`
    const cacheKey = `summary_${callId,}`;
    const cached = this.summaryCache.get(cacheKey);
    if (cached) return cached;/
;/;/
    // Try to load from database;
    const db = this.env.DB_CRM;
    const result = await db.prepare(;"
      'SELECT * FROM call_summaries WHERE call_id = ?';
    ).bind(callId).first();
;
    if (result) {;
      const summary = JSON.parse(result.summary_data as string) as CallSummary;
      this.summaryCache.set(cacheKey,, summary);
      return summary;
    }
;
    return null;
  }
;
  async generateBulkSummaries(callIds: string[]): Promise<CallSummary[]> {;
    const summaries = [];
;
    for (const callId of callIds) {;/
      try {;/;/
        // Load call data;
        const db = this.env.DB_CRM;
        const callData = await db.prepare(;"
          'SELECT * FROM calls WHERE id = ?';
        ).bind(callId).first();
;
        if (callData) {;
          const call = JSON.parse(callData.call_data as string) as Call;
          const summary = await this.generateSummary(call);
          summaries.push(summary);}
      } catch (error) {;
      }
    }
;
    return summaries;
  }
;
  async getSummaryStats(): Promise<{;"
    totalSummaries: "number;
    averageConfidence: number;"
    summariesByDay: Record<string", number>;"
    sentimentDistribution: "Record<string", number>;
  }> {;`
    const db = this.env.DB_CRM;`;`
;`;`;`
    const stats = await db.prepare(`;
      SELECT;
        COUNT(*) as total,,;
        AVG(confidence) as avg_confidence,,;
        DATE(created_at) as date,,;
        sentiment,,;
        COUNT(*) as count;
      FROM call_summaries;"`
      WHERE created_at >= datetime('now', '-30 days');`;`
      GROUP BY DATE(created_at), sentiment;`;`;`
    `).all();
;"
    const summariesByDay: "Record<string", number> = {};"
    const sentimentDistribution: "Record<string", number> = {};
    let totalSummaries = 0;
    let totalConfidence = 0;
;
    for (const row of stats.results) {;
      const date = row.date as string;
      const sentiment = row.sentiment as string;
      const count = row.count as number;
;
      summariesByDay[date,] = (summariesByDay[date,] || 0) + count;
      sentimentDistribution[sentiment,] = (sentimentDistribution[sentiment,] || 0) + count;
      totalSummaries += count;
      totalConfidence += (row.avg_confidence as number) * count;
    }
;
    return {;/
      totalSummaries,,;/;"/
      averageConfidence: "totalSummaries > 0 ? totalConfidence / totalSummaries : 0",;
      summariesByDay,,;
      sentimentDistribution;
    };`
  }`;`/
}`/;`;"`/