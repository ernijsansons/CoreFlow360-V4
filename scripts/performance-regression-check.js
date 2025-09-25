#!/usr/bin/env node

/**
 * Performance Regression Detection Script
 * Compares current performance metrics against baseline and detects regressions
 */

const fs = require('fs');
const path = require('path');

// Performance thresholds and tolerances
const PERFORMANCE_THRESHOLDS = {
  lcp: { threshold: 2500, tolerance: 0.1 }, // 10% tolerance
  fid: { threshold: 100, tolerance: 0.15 }, // 15% tolerance
  cls: { threshold: 0.1, tolerance: 0.2 }, // 20% tolerance
  bundleSize: { threshold: 800, tolerance: 0.05 }, // 5% tolerance (KB)
  apiLatency: { threshold: 200, tolerance: 0.1 } // 10% tolerance (ms)
};

// Baseline file path
const BASELINE_FILE = path.join(__dirname, '../.performance-baseline.json');

class PerformanceRegressionChecker {
  constructor() {
    this.currentMetrics = {};
    this.baseline = {};
    this.regressions = [];
    this.improvements = [];
  }

  /**
   * Parse command line arguments
   */
  parseArgs() {
    const args = process.argv.slice(2);
    const metrics = {};
    
    for (let i = 0; i < args.length; i += 2) {
      const key = args[i].replace('--current-', '').replace('--', '');
      const value = parseFloat(args[i + 1]);
      
      if (!isNaN(value)) {
        metrics[key] = value;
      }
    }
    
    return metrics;
  }

  /**
   * Load baseline performance metrics
   */
  loadBaseline() {
    try {
      if (fs.existsSync(BASELINE_FILE)) {
        const baselineData = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
        this.baseline = baselineData.metrics || {};
        console.log('✅ Baseline metrics loaded');
        console.log(`📊 Baseline from: ${new Date(baselineData.timestamp).toISOString()}`);
      } else {
        console.log('⚠️  No baseline found, creating new baseline');
        this.baseline = {};
      }
    } catch (error) {
      console.error('❌ Error loading baseline:', error.message);
      this.baseline = {};
    }
  }

  /**
   * Update baseline with current metrics if they're better
   */
  updateBaseline() {
    let baselineUpdated = false;
    const newBaseline = { ...this.baseline };

    // Update baseline if current metrics are significantly better
    Object.keys(this.currentMetrics).forEach(metric => {
      const current = this.currentMetrics[metric];
      const baseline = this.baseline[metric];
      
      if (!baseline || this.isSignificantImprovement(metric, current, baseline)) {
        newBaseline[metric] = current;
        baselineUpdated = true;
        console.log(`📈 Updated baseline for ${metric}: ${baseline || 'N/A'} → ${current}`);
      }
    });

    if (baselineUpdated || Object.keys(this.baseline).length === 0) {
      const baselineData = {
        metrics: newBaseline,
        timestamp: Date.now(),
        version: process.env.GITHUB_SHA || 'development',
        branch: process.env.GITHUB_REF_NAME || 'unknown'
      };

      fs.writeFileSync(BASELINE_FILE, JSON.stringify(baselineData, null, 2));
      console.log('💾 Baseline updated and saved');
    }
  }

  /**
   * Check if current metric represents significant improvement
   */
  isSignificantImprovement(metric, current, baseline) {
    const threshold = PERFORMANCE_THRESHOLDS[metric];
    if (!threshold) return false;

    // For metrics where lower is better (lcp, fid, bundleSize, apiLatency)
    const lowerIsBetter = ['lcp', 'fid', 'bundleSize', 'apiLatency'].includes(metric);
    
    if (lowerIsBetter) {
      const improvementThreshold = baseline * (1 - threshold.tolerance);
      return current <= improvementThreshold;
    } else {
      // For metrics where higher is better (currently none in our set)
      const improvementThreshold = baseline * (1 + threshold.tolerance);
      return current >= improvementThreshold;
    }
  }

  /**
   * Detect performance regressions
   */
  detectRegressions() {
    console.log('\n🔍 Checking for performance regressions...\n');

    Object.keys(this.currentMetrics).forEach(metric => {
      const current = this.currentMetrics[metric];
      const baseline = this.baseline[metric];
      const threshold = PERFORMANCE_THRESHOLDS[metric];

      if (!threshold) {
        console.log(`⚠️  No threshold defined for ${metric}, skipping`);
        return;
      }

      if (!baseline) {
        console.log(`ℹ️  No baseline for ${metric}, current value: ${current}`);
        return;
      }

      const regression = this.checkRegression(metric, current, baseline, threshold);
      
      if (regression.isRegression) {
        this.regressions.push(regression);
        console.log(`❌ REGRESSION detected in ${metric}:`);
        console.log(`   Current: ${current} | Baseline: ${baseline}`);
        console.log(`   Change: ${regression.changePercent}% (threshold: ${threshold.tolerance * 100}%)`);
        console.log(`   Severity: ${regression.severity}`);
      } else if (regression.isImprovement) {
        this.improvements.push(regression);
        console.log(`✅ IMPROVEMENT in ${metric}:`);
        console.log(`   Current: ${current} | Baseline: ${baseline}`);
        console.log(`   Change: ${regression.changePercent}%`);
      } else {
        console.log(`✅ ${metric} within acceptable range:`);
        console.log(`   Current: ${current} | Baseline: ${baseline}`);
        console.log(`   Change: ${regression.changePercent}%`);
      }
      console.log('');
    });
  }

  /**
   * Check if metric represents a regression
   */
  checkRegression(metric, current, baseline, threshold) {
    const lowerIsBetter = ['lcp', 'fid', 'bundleSize', 'apiLatency'].includes(metric);
    
    let changePercent, regressionThreshold, isRegression, isImprovement;
    
    if (lowerIsBetter) {
      changePercent = ((current - baseline) / baseline) * 100;
      regressionThreshold = baseline * (1 + threshold.tolerance);
      isRegression = current > regressionThreshold;
      isImprovement = current < baseline * (1 - threshold.tolerance * 0.5);
    } else {
      changePercent = ((baseline - current) / baseline) * 100;
      regressionThreshold = baseline * (1 - threshold.tolerance);
      isRegression = current < regressionThreshold;
      isImprovement = current > baseline * (1 + threshold.tolerance * 0.5);
    }

    // Determine severity
    let severity = 'low';
    if (Math.abs(changePercent) > threshold.tolerance * 200) { // 2x threshold
      severity = 'critical';
    } else if (Math.abs(changePercent) > threshold.tolerance * 150) { // 1.5x threshold
      severity = 'high';
    } else if (Math.abs(changePercent) > threshold.tolerance * 100) { // 1x threshold
      severity = 'medium';
    }

    return {
      metric,
      current,
      baseline,
      changePercent: Math.round(changePercent * 100) / 100,
      isRegression,
      isImprovement,
      severity
    };
  }

  /**
   * Generate performance report
   */
  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalMetrics: Object.keys(this.currentMetrics).length,
        regressions: this.regressions.length,
        improvements: this.improvements.length,
        status: this.regressions.length > 0 ? 'FAILED' : 'PASSED'
      },
      regressions: this.regressions,
      improvements: this.improvements,
      currentMetrics: this.currentMetrics,
      baseline: this.baseline
    };

    // Save detailed report
    const reportPath = path.join(__dirname, '../performance-regression-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    return report;
  }

  /**
   * Print summary and exit with appropriate code
   */
  printSummaryAndExit(report) {
    console.log('\n📊 PERFORMANCE REGRESSION CHECK SUMMARY\n');
    console.log('='.repeat(50));
    
    if (report.summary.regressions > 0) {
      console.log(`❌ Status: ${report.summary.status}`);
      console.log(`📉 Regressions detected: ${report.summary.regressions}`);
      
      // Group regressions by severity
      const criticalRegressions = this.regressions.filter(r => r.severity === 'critical');
      const highRegressions = this.regressions.filter(r => r.severity === 'high');
      
      if (criticalRegressions.length > 0) {
        console.log(`🚨 Critical regressions: ${criticalRegressions.length}`);
        criticalRegressions.forEach(r => {
          console.log(`   • ${r.metric}: ${r.changePercent}% worse`);
        });
      }
      
      if (highRegressions.length > 0) {
        console.log(`⚠️  High severity regressions: ${highRegressions.length}`);
        highRegressions.forEach(r => {
          console.log(`   • ${r.metric}: ${r.changePercent}% worse`);
        });
      }
      
    } else {
      console.log(`✅ Status: ${report.summary.status}`);
      console.log(`📊 All ${report.summary.totalMetrics} metrics within acceptable ranges`);
    }
    
    if (report.summary.improvements > 0) {
      console.log(`📈 Performance improvements: ${report.summary.improvements}`);
      this.improvements.forEach(imp => {
        console.log(`   • ${imp.metric}: ${Math.abs(imp.changePercent)}% better`);
      });
    }
    
    console.log('='.repeat(50));
    console.log(`📄 Detailed report saved to: performance-regression-report.json`);
    
    // Exit with error code if regressions found
    const hasRegressions = report.summary.regressions > 0;
    const hasCriticalRegressions = this.regressions.some(r => r.severity === 'critical');
    
    if (hasCriticalRegressions) {
      console.log('\n🚨 Critical performance regressions detected - failing build');
      process.exit(2);
    } else if (hasRegressions) {
      console.log('\n⚠️  Performance regressions detected - review required');
      process.exit(1);
    } else {
      console.log('\n✅ Performance check passed');
      process.exit(0);
    }
  }

  /**
   * Main execution method
   */
  run() {
    console.log('🔧 CoreFlow360 Performance Regression Checker\n');
    
    // Parse current metrics from command line
    this.currentMetrics = this.parseArgs();
    
    if (Object.keys(this.currentMetrics).length === 0) {
      console.error('❌ No performance metrics provided');
      console.log('Usage: node performance-regression-check.js --current-lcp 2000 --current-fid 50 ...');
      process.exit(1);
    }
    
    console.log('📊 Current performance metrics:');
    Object.entries(this.currentMetrics).forEach(([key, value]) => {
      console.log(`   ${key}: ${value}`);
    });
    console.log('');
    
    // Load baseline and detect regressions
    this.loadBaseline();
    this.detectRegressions();
    this.updateBaseline();
    
    // Generate report and exit
    const report = this.generateReport();
    this.printSummaryAndExit(report);
  }
}

// Run the regression checker
if (require.main === module) {
  const checker = new PerformanceRegressionChecker();
  checker.run();
}

module.exports = PerformanceRegressionChecker;