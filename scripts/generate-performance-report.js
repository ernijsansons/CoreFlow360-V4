#!/usr/bin/env node

/**
 * Performance Report Generator
 * Creates comprehensive performance reports for CI/CD and monitoring
 */

const fs = require('fs');
const path = require('path');

class PerformanceReportGenerator {
  constructor() {
    this.metrics = {};
    this.lighthouse = {};
    this.bundleAnalysis = {};
    this.apiMetrics = {};
    this.regressions = [];
    this.improvements = [];
  }

  /**
   * Parse command line arguments
   */
  parseArgs() {
    const args = process.argv.slice(2);
    const options = {};
    
    for (let i = 0; i < args.length; i += 2) {
      const key = args[i].replace('--', '');
      const value = args[i + 1];
      options[key] = isNaN(value) ? value : parseFloat(value);
    }
    
    return options;
  }

  /**
   * Load additional metrics from files
   */
  loadMetricsFromFiles() {
    try {
      // Load Lighthouse detailed results
      const lighthousePath = '/tmp/lighthouse/lhr.json';
      if (fs.existsSync(lighthousePath)) {
        const lighthouseData = JSON.parse(fs.readFileSync(lighthousePath, 'utf8'));
        this.lighthouse = this.extractLighthouseMetrics(lighthouseData);
      }

      // Load Artillery load test results
      const artilleryPath = '/tmp/artillery-report.json';
      if (fs.existsSync(artilleryPath)) {
        const artilleryData = JSON.parse(fs.readFileSync(artilleryPath, 'utf8'));
        this.apiMetrics = this.extractArtilleryMetrics(artilleryData);
      }

      // Load bundle analyzer results
      const bundlePath = 'frontend/dist/stats.json';
      if (fs.existsSync(bundlePath)) {
        const bundleData = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
        this.bundleAnalysis = this.extractBundleMetrics(bundleData);
      }

      // Load regression analysis results
      const regressionPath = path.join(__dirname, '../performance-regression-report.json');
      if (fs.existsSync(regressionPath)) {
        const regressionData = JSON.parse(fs.readFileSync(regressionPath, 'utf8'));
        this.regressions = regressionData.regressions || [];
        this.improvements = regressionData.improvements || [];
      }

    } catch (error) {
      console.warn('⚠️ Warning: Could not load some metrics files:', error.message);
    }
  }

  /**
   * Extract relevant metrics from Lighthouse results
   */
  extractLighthouseMetrics(lighthouseData) {
    const audits = lighthouseData.audits || {};
    
    return {
      performanceScore: Math.round((lighthouseData.categories?.performance?.score || 0) * 100),
      coreWebVitals: {
        lcp: audits['largest-contentful-paint']?.numericValue || 0,
        fid: audits['first-input-delay']?.numericValue || 0,
        cls: audits['cumulative-layout-shift']?.numericValue || 0,
        fcp: audits['first-contentful-paint']?.numericValue || 0,
        speedIndex: audits['speed-index']?.numericValue || 0,
        tbt: audits['total-blocking-time']?.numericValue || 0
      },
      opportunities: {
        unusedJavaScript: Math.round((audits['unused-javascript']?.numericValue || 0) / 1024), // KB
        unusedCSS: Math.round((audits['unused-css-rules']?.numericValue || 0) / 1024), // KB
        renderBlockingResources: audits['render-blocking-resources']?.numericValue || 0,
        legacyJavaScript: Math.round((audits['legacy-javascript']?.numericValue || 0) / 1024) // KB
      },
      diagnostics: {
        mainThreadWork: audits['mainthread-work-breakdown']?.numericValue || 0,
        networkRequests: audits['network-requests']?.details?.items?.length || 0,
        domElements: audits['dom-size']?.numericValue || 0
      }
    };
  }

  /**
   * Extract metrics from Artillery load test results
   */
  extractArtilleryMetrics(artilleryData) {
    const aggregate = artilleryData.aggregate || {};
    
    return {
      requestsPerSecond: Math.round(aggregate.rates?.mean || 0),
      latency: {
        min: aggregate.latency?.min || 0,
        max: aggregate.latency?.max || 0,
        median: aggregate.latency?.median || 0,
        p95: aggregate.latency?.p95 || 0,
        p99: aggregate.latency?.p99 || 0
      },
      errorRate: Math.round(((aggregate.errors || 0) / (aggregate.requests || 1)) * 100 * 100) / 100,
      throughput: {
        requests: aggregate.requests || 0,
        responses: aggregate.responses || 0,
        errors: aggregate.errors || 0
      },
      scenarios: artilleryData.phases?.map(phase => ({
        duration: phase.duration,
        arrivalRate: phase.arrivalRate,
        requests: phase.requests || 0
      })) || []
    };
  }

  /**
   * Extract bundle analysis metrics
   */
  extractBundleMetrics(bundleData) {
    const assets = bundleData.assets || [];
    
    const jsAssets = assets.filter(asset => asset.name.endsWith('.js'));
    const cssAssets = assets.filter(asset => asset.name.endsWith('.css'));
    
    return {
      totalSize: Math.round(assets.reduce((sum, asset) => sum + asset.size, 0) / 1024), // KB
      jsSize: Math.round(jsAssets.reduce((sum, asset) => sum + asset.size, 0) / 1024), // KB
      cssSize: Math.round(cssAssets.reduce((sum, asset) => sum + asset.size, 0) / 1024), // KB
      chunkCount: assets.length,
      largestChunks: assets
        .sort((a, b) => b.size - a.size)
        .slice(0, 5)
        .map(asset => ({
          name: asset.name,
          size: Math.round(asset.size / 1024) // KB
        }))
    };
  }

  /**
   * Calculate performance grade
   */
  calculatePerformanceGrade() {
    const score = this.lighthouse.performanceScore || 0;
    
    if (score >= 90) return { grade: 'A', color: '🟢', status: 'Excellent' };
    if (score >= 80) return { grade: 'B', color: '🟡', status: 'Good' };
    if (score >= 70) return { grade: 'C', color: '🟠', status: 'Needs Improvement' };
    if (score >= 60) return { grade: 'D', color: '🔴', status: 'Poor' };
    return { grade: 'F', color: '🔴', status: 'Critical' };
  }

  /**
   * Generate Core Web Vitals assessment
   */
  assessCoreWebVitals() {
    const cwv = this.lighthouse.coreWebVitals || {};
    const assessments = [];

    // LCP Assessment
    if (cwv.lcp <= 2500) {
      assessments.push({ metric: 'LCP', value: `${Math.round(cwv.lcp)}ms`, status: '🟢 Good', threshold: '≤ 2.5s' });
    } else if (cwv.lcp <= 4000) {
      assessments.push({ metric: 'LCP', value: `${Math.round(cwv.lcp)}ms`, status: '🟡 Needs Improvement', threshold: '≤ 2.5s' });
    } else {
      assessments.push({ metric: 'LCP', value: `${Math.round(cwv.lcp)}ms`, status: '🔴 Poor', threshold: '≤ 2.5s' });
    }

    // FID Assessment
    if (cwv.fid <= 100) {
      assessments.push({ metric: 'FID', value: `${Math.round(cwv.fid)}ms`, status: '🟢 Good', threshold: '≤ 100ms' });
    } else if (cwv.fid <= 300) {
      assessments.push({ metric: 'FID', value: `${Math.round(cwv.fid)}ms`, status: '🟡 Needs Improvement', threshold: '≤ 100ms' });
    } else {
      assessments.push({ metric: 'FID', value: `${Math.round(cwv.fid)}ms`, status: '🔴 Poor', threshold: '≤ 100ms' });
    }

    // CLS Assessment
    if (cwv.cls <= 0.1) {
      assessments.push({ metric: 'CLS', value: cwv.cls.toFixed(3), status: '🟢 Good', threshold: '≤ 0.1' });
    } else if (cwv.cls <= 0.25) {
      assessments.push({ metric: 'CLS', value: cwv.cls.toFixed(3), status: '🟡 Needs Improvement', threshold: '≤ 0.1' });
    } else {
      assessments.push({ metric: 'CLS', value: cwv.cls.toFixed(3), status: '🔴 Poor', threshold: '≤ 0.1' });
    }

    return assessments;
  }

  /**
   * Generate optimization recommendations
   */
  generateRecommendations() {
    const recommendations = [];
    const opportunities = this.lighthouse.opportunities || {};

    // Bundle size recommendations
    if (this.bundleAnalysis.jsSize > 600) {
      recommendations.push({
        priority: 'High',
        category: 'Bundle Optimization',
        issue: `JavaScript bundle size is ${this.bundleAnalysis.jsSize}KB (target: <600KB)`,
        solution: 'Implement code splitting, tree shaking, and lazy loading for non-critical modules'
      });
    }

    // Unused JavaScript
    if (opportunities.unusedJavaScript > 100) {
      recommendations.push({
        priority: 'Medium',
        category: 'Code Optimization',
        issue: `${opportunities.unusedJavaScript}KB of unused JavaScript detected`,
        solution: 'Remove unused code, optimize imports, and implement dynamic imports'
      });
    }

    // API performance
    if (this.apiMetrics.latency?.p95 > 200) {
      recommendations.push({
        priority: 'High',
        category: 'API Performance',
        issue: `API P95 latency is ${this.apiMetrics.latency.p95}ms (target: <200ms)`,
        solution: 'Optimize database queries, implement caching, and use connection pooling'
      });
    }

    // Core Web Vitals recommendations
    const cwv = this.lighthouse.coreWebVitals || {};
    if (cwv.lcp > 2500) {
      recommendations.push({
        priority: 'Critical',
        category: 'Core Web Vitals',
        issue: `LCP is ${Math.round(cwv.lcp)}ms (target: ≤2500ms)`,
        solution: 'Optimize images, implement preloading for critical resources, and reduce render-blocking resources'
      });
    }

    return recommendations.length > 0 ? recommendations : [
      { priority: 'Info', category: 'Performance', issue: 'No critical optimizations needed', solution: 'Continue monitoring and maintaining current performance levels' }
    ];
  }

  /**
   * Generate markdown performance report
   */
  generateMarkdownReport(options) {
    const performanceGrade = this.calculatePerformanceGrade();
    const coreWebVitals = this.assessCoreWebVitals();
    const recommendations = this.generateRecommendations();

    let report = `# 📊 Performance Report

## Overall Performance ${performanceGrade.color}

**Grade: ${performanceGrade.grade}** - ${performanceGrade.status}  
**Lighthouse Score: ${this.lighthouse.performanceScore || 'N/A'}/100**

---

## 🎯 Core Web Vitals

| Metric | Value | Status | Threshold |
|--------|-------|--------|-----------|
`;

    coreWebVitals.forEach(cwv => {
      report += `| ${cwv.metric} | ${cwv.value} | ${cwv.status} | ${cwv.threshold} |\n`;
    });

    report += `
---

## 📦 Bundle Analysis

| Metric | Value |
|--------|-------|
| **Total Bundle Size** | ${this.bundleAnalysis.totalSize || 'N/A'}KB |
| **JavaScript Size** | ${this.bundleAnalysis.jsSize || 'N/A'}KB |
| **CSS Size** | ${this.bundleAnalysis.cssSize || 'N/A'}KB |
| **Number of Chunks** | ${this.bundleAnalysis.chunkCount || 'N/A'} |

`;

    if (this.bundleAnalysis.largestChunks && this.bundleAnalysis.largestChunks.length > 0) {
      report += `### Largest Chunks
`;
      this.bundleAnalysis.largestChunks.forEach(chunk => {
        report += `- **${chunk.name}**: ${chunk.size}KB\n`;
      });
    }

    report += `
---

## 🚀 API Performance

| Metric | Value |
|--------|-------|
| **Requests/sec** | ${this.apiMetrics.requestsPerSecond || 'N/A'} |
| **P95 Latency** | ${this.apiMetrics.latency?.p95 || 'N/A'}ms |
| **Error Rate** | ${this.apiMetrics.errorRate || 'N/A'}% |
| **Total Requests** | ${this.apiMetrics.throughput?.requests || 'N/A'} |

`;

    if (this.regressions.length > 0) {
      report += `
## 📉 Performance Regressions

`;
      this.regressions.forEach(regression => {
        const icon = regression.severity === 'critical' ? '🚨' : 
                    regression.severity === 'high' ? '⚠️' : '📊';
        report += `${icon} **${regression.metric}**: ${regression.changePercent}% worse (${regression.severity} severity)\n`;
      });
    }

    if (this.improvements.length > 0) {
      report += `
## 📈 Performance Improvements

`;
      this.improvements.forEach(improvement => {
        report += `✅ **${improvement.metric}**: ${Math.abs(improvement.changePercent)}% better\n`;
      });
    }

    report += `
---

## 💡 Optimization Recommendations

`;

    recommendations.forEach((rec, index) => {
      const icon = rec.priority === 'Critical' ? '🚨' : 
                  rec.priority === 'High' ? '⚠️' : 
                  rec.priority === 'Medium' ? '📊' : 'ℹ️';
      
      report += `### ${index + 1}. ${icon} ${rec.category} (${rec.priority} Priority)

**Issue**: ${rec.issue}  
**Solution**: ${rec.solution}

`;
    });

    report += `
---

## 📊 Additional Metrics

### Frontend Metrics
- **Speed Index**: ${Math.round(this.lighthouse.coreWebVitals?.speedIndex || 0)}ms
- **Total Blocking Time**: ${Math.round(this.lighthouse.coreWebVitals?.tbt || 0)}ms
- **First Contentful Paint**: ${Math.round(this.lighthouse.coreWebVitals?.fcp || 0)}ms

### Resource Analysis
- **Unused JavaScript**: ${this.lighthouse.opportunities?.unusedJavaScript || 0}KB
- **Unused CSS**: ${this.lighthouse.opportunities?.unusedCSS || 0}KB
- **Legacy JavaScript**: ${this.lighthouse.opportunities?.legacyJavaScript || 0}KB

### Load Test Details
- **Min Latency**: ${this.apiMetrics.latency?.min || 'N/A'}ms
- **Max Latency**: ${this.apiMetrics.latency?.max || 'N/A'}ms
- **Median Latency**: ${this.apiMetrics.latency?.median || 'N/A'}ms

---

*Report generated on ${new Date().toISOString()} by CoreFlow360 Performance CI*
`;

    return report;
  }

  /**
   * Main execution method
   */
  run() {
    console.log('📊 Generating performance report...');

    const options = this.parseArgs();
    
    // Set basic metrics from command line
    if (options['lighthouse-score']) this.lighthouse.performanceScore = options['lighthouse-score'];
    if (options['bundle-size']) this.bundleAnalysis.jsSize = options['bundle-size'];
    if (options['api-latency']) {
      this.apiMetrics.latency = { p95: options['api-latency'] };
    }

    // Load additional metrics from files
    this.loadMetricsFromFiles();

    // Generate markdown report
    const markdownReport = this.generateMarkdownReport(options);

    // Write report to file
    const outputPath = options.output || 'performance-report.md';
    fs.writeFileSync(outputPath, markdownReport);

    console.log(`✅ Performance report generated: ${outputPath}`);
    console.log(`📊 Report Summary:`);
    console.log(`   • Performance Score: ${this.lighthouse.performanceScore || 'N/A'}/100`);
    console.log(`   • Bundle Size: ${this.bundleAnalysis.jsSize || 'N/A'}KB`);
    console.log(`   • API P95 Latency: ${this.apiMetrics.latency?.p95 || 'N/A'}ms`);
    console.log(`   • Regressions: ${this.regressions.length}`);
    console.log(`   • Improvements: ${this.improvements.length}`);
  }
}

// Run the report generator
if (require.main === module) {
  const generator = new PerformanceReportGenerator();
  generator.run();
}

module.exports = PerformanceReportGenerator;