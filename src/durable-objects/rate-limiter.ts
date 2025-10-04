/**
 * Rate Limiter Durable Object
 * Provides distributed rate limiting coordination across edge locations
 *
 * Features:
 * - Distributed request tracking
 * - Global rate limit coordination
 * - Real-time threat detection
 * - Automatic pattern analysis
 */

export interface RateLimitRequest {
  fingerprint: string;
  ip: string;
  userId?: string;
  businessId?: string;
  endpoint: string;
  timestamp: number;
  headers: Record<string, string>;
}

export interface DistributedRateLimit {
  requests: RateLimitRequest[];
  blocks: Map<string, BlockInfo>;
  threatIndicators: Map<string, ThreatPattern>;
}

export interface BlockInfo {
  fingerprint: string;
  reason: string;
  blockedAt: number;
  blockedUntil: number;
  severity: 'temporary' | 'permanent';
  violations: number;
}

export interface ThreatPattern {
  type: string;
  firstSeen: number;
  lastSeen: number;
  count: number;
  confidence: number;
  sources: Set<string>;
}

export class RateLimiterDurableObject {
  private state: DurableObjectState;
  private env: any;

  // In-memory state for performance
  private requests: RateLimitRequest[] = [];
  private blocks: Map<string, BlockInfo> = new Map();
  private threatPatterns: Map<string, ThreatPattern> = new Map();

  // Configuration
  private readonly windowSize = 60000; // 1 minute sliding window
  private readonly maxRequests = 10000; // Global limit
  private readonly cleanupInterval = 5000; // Cleanup every 5 seconds
  private cleanupTimer?: number;

  constructor(state: DurableObjectState, env: any) {
    this.state = state;
    this.env = env;

    // Initialize from storage
    this.state.blockConcurrencyWhile(async () => {
      await this.loadState();
      this.startCleanupTimer();
    });
  }

  /**
   * Handle incoming requests
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/check':
          return this.handleRateLimitCheck(request);
        case '/record':
          return this.handleRequestRecord(request);
        case '/block':
          return this.handleBlock(request);
        case '/unblock':
          return this.handleUnblock(request);
        case '/stats':
          return this.handleStats();
        case '/threats':
          return this.handleThreatAnalysis();
        case '/fingerprint':
          return this.handleFingerprintAnalysis(request);
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('Rate limiter error:', error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  /**
   * Check rate limit for a request
   */
  private async handleRateLimitCheck(request: Request): Promise<Response> {
    const data = await request.json() as RateLimitRequest;

    // Check if blocked
    const blockInfo = this.blocks.get(data.fingerprint);
    if (blockInfo && blockInfo.blockedUntil > Date.now()) {
      return new Response(JSON.stringify({
        allowed: false,
        blocked: true,
        blockInfo,
        reason: blockInfo.reason
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Clean old requests
    this.cleanupRequests();

    // Count requests in window
    const now = Date.now();
    const windowStart = now - this.windowSize;
    const recentRequests = this.requests.filter(r => r.timestamp > windowStart);

    // Check global limit
    if (recentRequests.length >= this.maxRequests) {
      await this.autoBlock(data.fingerprint, 'global_limit_exceeded', 300000); // 5 min block
      return new Response(JSON.stringify({
        allowed: false,
        reason: 'Global rate limit exceeded',
        current: recentRequests.length,
        limit: this.maxRequests
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check fingerprint-specific patterns
    const fingerprintRequests = recentRequests.filter(r => r.fingerprint === data.fingerprint);
    const threatLevel = this.analyzeThreatLevel(data, fingerprintRequests);

    if (threatLevel > 0.8) {
      await this.autoBlock(data.fingerprint, 'high_threat_level', 3600000); // 1 hour block
      return new Response(JSON.stringify({
        allowed: false,
        reason: 'Suspicious activity detected',
        threatLevel
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Record the request
    await this.recordRequest(data);

    return new Response(JSON.stringify({
      allowed: true,
      current: recentRequests.length,
      limit: this.maxRequests,
      remaining: this.maxRequests - recentRequests.length,
      threatLevel
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Record a request
   */
  private async handleRequestRecord(request: Request): Promise<Response> {
    const data = await request.json() as RateLimitRequest;
    await this.recordRequest(data);

    return new Response(JSON.stringify({ recorded: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Block a fingerprint
   */
  private async handleBlock(request: Request): Promise<Response> {
    const { fingerprint, reason, duration } = await request.json() as {
      fingerprint: string;
      reason: string;
      duration: number;
    };

    await this.autoBlock(fingerprint, reason, duration);

    return new Response(JSON.stringify({ blocked: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Unblock a fingerprint
   */
  private async handleUnblock(request: Request): Promise<Response> {
    const { fingerprint } = await request.json() as { fingerprint: string };

    this.blocks.delete(fingerprint);
    await this.saveState();

    return new Response(JSON.stringify({ unblocked: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Get statistics
   */
  private async handleStats(): Promise<Response> {
    this.cleanupRequests();

    const now = Date.now();
    const windowStart = now - this.windowSize;
    const recentRequests = this.requests.filter(r => r.timestamp > windowStart);

    const stats = {
      totalRequests: recentRequests.length,
      uniqueFingerprints: new Set(recentRequests.map(r => r.fingerprint)).size,
      uniqueIPs: new Set(recentRequests.map(r => r.ip)).size,
      blockedFingerprints: this.blocks.size,
      threatPatterns: this.threatPatterns.size,
      requestsPerSecond: recentRequests.length / (this.windowSize / 1000),
      topEndpoints: this.getTopEndpoints(recentRequests),
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(stats), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Analyze threats
   */
  private async handleThreatAnalysis(): Promise<Response> {
    const threats = Array.from(this.threatPatterns.values()).map(pattern => ({
      ...pattern,
      sources: Array.from(pattern.sources)
    }));

    return new Response(JSON.stringify({ threats }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Analyze specific fingerprint
   */
  private async handleFingerprintAnalysis(request: Request): Promise<Response> {
    const { fingerprint } = await request.json() as { fingerprint: string };

    const fingerprintRequests = this.requests.filter(r => r.fingerprint === fingerprint);
    const blockInfo = this.blocks.get(fingerprint);
    const patterns = this.detectPatterns(fingerprintRequests);

    const analysis = {
      fingerprint,
      totalRequests: fingerprintRequests.length,
      firstSeen: fingerprintRequests[0]?.timestamp,
      lastSeen: fingerprintRequests[fingerprintRequests.length - 1]?.timestamp,
      blocked: !!blockInfo,
      blockInfo,
      patterns,
      endpoints: this.getTopEndpoints(fingerprintRequests),
      requestRate: this.calculateRequestRate(fingerprintRequests)
    };

    return new Response(JSON.stringify(analysis), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  /**
   * Record a request
   */
  private async recordRequest(data: RateLimitRequest): Promise<void> {
    this.requests.push(data);

    // Update threat patterns
    this.updateThreatPatterns(data);

    // Trigger save periodically
    if (this.requests.length % 100 === 0) {
      await this.saveState();
    }
  }

  /**
   * Auto-block a fingerprint
   */
  private async autoBlock(fingerprint: string, reason: string, duration: number): Promise<void> {
    const existingBlock = this.blocks.get(fingerprint);

    const blockInfo: BlockInfo = {
      fingerprint,
      reason,
      blockedAt: Date.now(),
      blockedUntil: Date.now() + duration,
      severity: duration > 3600000 ? 'permanent' : 'temporary',
      violations: (existingBlock?.violations || 0) + 1
    };

    this.blocks.set(fingerprint, blockInfo);
    await this.saveState();

    console.warn(`Auto-blocked ${fingerprint} for ${reason}. Duration: ${duration}ms`);
  }

  /**
   * Analyze threat level
   */
  private analyzeThreatLevel(request: RateLimitRequest, recentRequests: RateLimitRequest[]): number {
    let threatScore = 0;
    let factors = 0;

    // Rapid fire detection
    const oneSecondAgo = Date.now() - 1000;
    const rapidRequests = recentRequests.filter(r => r.timestamp > oneSecondAgo);
    if (rapidRequests.length > 10) {
      threatScore += 0.4;
      factors++;
    }

    // Endpoint scanning
    const uniqueEndpoints = new Set(recentRequests.map(r => r.endpoint));
    if (uniqueEndpoints.size > 20) {
      threatScore += 0.3;
      factors++;
    }

    // User agent anomalies
    const userAgent = request.headers['user-agent'];
    if (userAgent && /bot|crawler|spider|scraper/i.test(userAgent)) {
      threatScore += 0.2;
      factors++;
    }

    // Previous violations
    const blockInfo = this.blocks.get(request.fingerprint);
    if (blockInfo && blockInfo.violations > 0) {
      threatScore += Math.min(0.5, blockInfo.violations * 0.1);
      factors++;
    }

    return factors > 0 ? Math.min(1, threatScore) : 0;
  }

  /**
   * Update threat patterns
   */
  private updateThreatPatterns(request: RateLimitRequest): void {
    const patterns = this.detectPatterns([request]);

    patterns.forEach(pattern => {
      const key = `${pattern.type}:${pattern.identifier}`;
      const existing = this.threatPatterns.get(key);

      if (existing) {
        existing.lastSeen = Date.now();
        existing.count++;
        existing.sources.add(request.fingerprint);
        existing.confidence = Math.min(1, existing.confidence + 0.1);
      } else {
        this.threatPatterns.set(key, {
          type: pattern.type,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          count: 1,
          confidence: pattern.confidence,
          sources: new Set([request.fingerprint])
        });
      }
    });
  }

  /**
   * Detect patterns in requests
   */
  private detectPatterns(requests: RateLimitRequest[]): Array<{ type: string; identifier: string; confidence: number }> {
    const patterns: Array<{ type: string; identifier: string; confidence: number }> = [];

    if (requests.length === 0) return patterns;

    // Rapid fire pattern
    const timeSpan = requests[requests.length - 1].timestamp - requests[0].timestamp;
    const requestRate = requests.length / (timeSpan / 1000);
    if (requestRate > 10) {
      patterns.push({
        type: 'rapid_fire',
        identifier: requests[0].fingerprint,
        confidence: Math.min(1, requestRate / 20)
      });
    }

    // Scanning pattern
    const uniqueEndpoints = new Set(requests.map(r => r.endpoint));
    if (uniqueEndpoints.size > 10) {
      patterns.push({
        type: 'endpoint_scanning',
        identifier: requests[0].fingerprint,
        confidence: Math.min(1, uniqueEndpoints.size / 20)
      });
    }

    // Distributed attack pattern
    const uniqueIPs = new Set(requests.map(r => r.ip));
    if (uniqueIPs.size > 10 && requests.length > 50) {
      patterns.push({
        type: 'distributed_attack',
        identifier: 'global',
        confidence: Math.min(1, uniqueIPs.size / 20)
      });
    }

    return patterns;
  }

  /**
   * Get top endpoints
   */
  private getTopEndpoints(requests: RateLimitRequest[]): Array<{ endpoint: string; count: number }> {
    const endpointCounts = new Map<string, number>();

    requests.forEach(r => {
      endpointCounts.set(r.endpoint, (endpointCounts.get(r.endpoint) || 0) + 1);
    });

    return Array.from(endpointCounts.entries())
      .map(([endpoint, count]) => ({ endpoint, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  /**
   * Calculate request rate
   */
  private calculateRequestRate(requests: RateLimitRequest[]): number {
    if (requests.length < 2) return 0;

    const timeSpan = requests[requests.length - 1].timestamp - requests[0].timestamp;
    return requests.length / (timeSpan / 1000);
  }

  /**
   * Cleanup old requests
   */
  private cleanupRequests(): void {
    const cutoff = Date.now() - this.windowSize * 2; // Keep 2x window for analysis
    this.requests = this.requests.filter(r => r.timestamp > cutoff);

    // Cleanup expired blocks
    for (const [fingerprint, block] of this.blocks.entries()) {
      if (block.blockedUntil < Date.now()) {
        this.blocks.delete(fingerprint);
      }
    }

    // Cleanup old threat patterns
    const threatCutoff = Date.now() - 3600000; // 1 hour
    for (const [key, pattern] of this.threatPatterns.entries()) {
      if (pattern.lastSeen < threatCutoff) {
        this.threatPatterns.delete(key);
      }
    }
  }

  /**
   * Start cleanup timer
   */
  private startCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }

    this.cleanupTimer = setInterval(() => {
      this.cleanupRequests();
      this.saveState().catch(console.error);
    }, this.cleanupInterval) as unknown as number;
  }

  /**
   * Load state from storage
   */
  private async loadState(): Promise<void> {
    const [requests, blocks, patterns] = await Promise.all([
      this.state.storage.get<RateLimitRequest[]>('requests'),
      this.state.storage.get<[string, BlockInfo][]>('blocks'),
      this.state.storage.get<[string, ThreatPattern][]>('threatPatterns')
    ]);

    this.requests = requests || [];
    this.blocks = new Map(blocks || []);
    this.threatPatterns = new Map(patterns || []);

    // Clean up on load
    this.cleanupRequests();
  }

  /**
   * Save state to storage
   */
  private async saveState(): Promise<void> {
    await Promise.all([
      this.state.storage.put('requests', this.requests),
      this.state.storage.put('blocks', Array.from(this.blocks.entries())),
      this.state.storage.put('threatPatterns', Array.from(this.threatPatterns.entries()))
    ]);
  }
}