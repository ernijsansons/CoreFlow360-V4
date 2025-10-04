#!/usr/bin/env tsx
/**
 * SECURITY TEST VALIDATION RUNNER
 * CoreFlow360 V4 - Comprehensive Security Testing
 *
 * This script runs the security test suite 10 times to:
 * 1. Detect test flakes and ensure reliability
 * 2. Validate 98% minimum test coverage
 * 3. Generate comprehensive security test reports
 * 4. Validate performance benchmarks (p99 < 150ms)
 *
 * @reliability 100% flake-free requirement
 * @coverage-target 98% minimum
 * @performance p99 < 150ms
 */

import { execSync, spawn } from 'child_process';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

interface TestResult {
  run: number;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  coverage?: CoverageReport;
  failures: TestFailure[];
  performance: PerformanceMetrics;
}

interface CoverageReport {
  lines: { total: number; covered: number; pct: number };
  functions: { total: number; covered: number; pct: number };
  statements: { total: number; covered: number; pct: number };
  branches: { total: number; covered: number; pct: number };
  overall: number;
}

interface TestFailure {
  testName: string;
  error: string;
  stack?: string;
  run: number;
}

interface PerformanceMetrics {
  totalTime: number;
  averageTestTime: number;
  p50: number;
  p95: number;
  p99: number;
  slowestTests: Array<{ name: string; duration: number }>;
}

interface ValidationReport {
  totalRuns: number;
  overallSuccess: boolean;
  flakeDetected: boolean;
  coverageAchieved: boolean;
  performanceTarget: boolean;
  results: TestResult[];
  summary: {
    averageCoverage: number;
    minCoverage: number;
    maxCoverage: number;
    totalFailures: number;
    flakyTests: string[];
    performanceSummary: PerformanceMetrics;
  };
  recommendations: string[];
  securityIssues: string[];
}

class SecurityTestValidator {
  private results: TestResult[] = [];
  private readonly maxRuns = 10;
  private readonly minCoverage = 98; // 98% minimum coverage requirement
  private readonly maxP99Time = 150; // 150ms maximum p99 response time

  async runValidation(): Promise<ValidationReport> {
    console.log('🔒 Starting Security Test Validation Suite');
    console.log(`📊 Running ${this.maxRuns} iterations to detect flakes and validate coverage\n`);

    // Run tests multiple times
    for (let run = 1; run <= this.maxRuns; run++) {
      console.log(`\n🏃 Run ${run}/${this.maxRuns}`);
      const result = await this.runSingleTest(run);
      this.results.push(result);

      // Show progress
      const passRate = (result.passed / (result.passed + result.failed)) * 100;
      console.log(`✅ Passed: ${result.passed}, ❌ Failed: ${result.failed}, ⏱️  Duration: ${result.duration}ms, 📈 Pass Rate: ${passRate.toFixed(1)}%`);

      if (result.coverage) {
        console.log(`📊 Coverage: ${result.coverage.overall.toFixed(2)}%`);
      }
    }

    // Analyze results
    return this.analyzeResults();
  }

  private async runSingleTest(runNumber: number): Promise<TestResult> {
    const startTime = Date.now();
    const failures: TestFailure[] = [];
    let testOutput: string;

    try {
      // Run security tests with coverage
      testOutput = execSync(
        'npm run test:security -- --coverage --reporter=json --reporter=verbose',
        {
          encoding: 'utf-8',
          cwd: process.cwd(),
          timeout: 300000, // 5 minute timeout
          env: { ...process.env, NODE_ENV: 'test' }
        }
      );
    } catch (error: any) {
      testOutput = error.stdout || error.message;
    }

    const endTime = Date.now();
    const duration = endTime - startTime;

    // Parse test results
    const testResult = this.parseTestOutput(testOutput, runNumber, duration);

    // Get coverage report
    const coverage = this.parseCoverageReport();

    return {
      ...testResult,
      coverage,
      performance: this.calculatePerformanceMetrics(testOutput, duration)
    };
  }

  private parseTestOutput(output: string, runNumber: number, duration: number): Omit<TestResult, 'coverage' | 'performance'> {
    const failures: TestFailure[] = [];
    let passed = 0;
    let failed = 0;
    let skipped = 0;

    try {
      // Try to parse JSON output
      const lines = output.split('\n');
      const jsonLine = lines.find(line => line.trim().startsWith('{') && line.includes('testResults'));

      if (jsonLine) {
        const result = JSON.parse(jsonLine);

        if (result.testResults) {
          result.testResults.forEach((testFile: any) => {
            testFile.assertionResults?.forEach((test: any) => {
              switch (test.status) {
                case 'passed':
                  passed++;
                  break;
                case 'failed':
                  failed++;
                  failures.push({
                    testName: test.fullName || test.title,
                    error: test.failureMessages?.[0] || 'Unknown error',
                    run: runNumber
                  });
                  break;
                case 'skipped':
                case 'pending':
                  skipped++;
                  break;
              }
            });
          });
        }
      } else {
        // Fallback: parse text output
        const passMatches = output.match(/(\d+) passed/);
        const failMatches = output.match(/(\d+) failed/);
        const skipMatches = output.match(/(\d+) skipped/);

        passed = passMatches ? parseInt(passMatches[1]) : 0;
        failed = failMatches ? parseInt(failMatches[1]) : 0;
        skipped = skipMatches ? parseInt(skipMatches[1]) : 0;

        // Extract failure information
        const failurePattern = /FAIL\s+(.+?)\n([\s\S]*?)(?=\n\s*PASS|\n\s*FAIL|\n\s*Test Suites:|\n\s*$)/g;
        let match;
        while ((match = failurePattern.exec(output)) !== null) {
          failures.push({
            testName: match[1],
            error: match[2].trim(),
            run: runNumber
          });
        }
      }
    } catch (error) {
      console.warn(`⚠️  Failed to parse test output for run ${runNumber}:`, error);
    }

    return {
      run: runNumber,
      passed,
      failed,
      skipped,
      duration,
      failures
    };
  }

  private parseCoverageReport(): CoverageReport | undefined {
    try {
      const coveragePath = join(process.cwd(), 'coverage', 'coverage-summary.json');

      if (!existsSync(coveragePath)) {
        console.warn('⚠️  Coverage report not found');
        return undefined;
      }

      const coverageData = JSON.parse(readFileSync(coveragePath, 'utf-8'));
      const total = coverageData.total;

      return {
        lines: total.lines,
        functions: total.functions,
        statements: total.statements,
        branches: total.branches,
        overall: (total.lines.pct + total.functions.pct + total.statements.pct + total.branches.pct) / 4
      };
    } catch (error) {
      console.warn('⚠️  Failed to parse coverage report:', error);
      return undefined;
    }
  }

  private calculatePerformanceMetrics(output: string, totalTime: number): PerformanceMetrics {
    const testTimes: number[] = [];
    const slowestTests: Array<{ name: string; duration: number }> = [];

    // Extract test timing information from output
    const timePattern = /✓\s+(.+?)\s+\((\d+(?:\.\d+)?)\s*ms\)/g;
    let match;
    while ((match = timePattern.exec(output)) !== null) {
      const duration = parseFloat(match[2]);
      testTimes.push(duration);

      if (slowestTests.length < 10 || duration > slowestTests[slowestTests.length - 1].duration) {
        slowestTests.push({ name: match[1].trim(), duration });
        slowestTests.sort((a, b) => b.duration - a.duration);
        if (slowestTests.length > 10) {
          slowestTests.pop();
        }
      }
    }

    if (testTimes.length === 0) {
      return {
        totalTime,
        averageTestTime: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        slowestTests: []
      };
    }

    testTimes.sort((a, b) => a - b);

    return {
      totalTime,
      averageTestTime: testTimes.reduce((a, b) => a + b, 0) / testTimes.length,
      p50: this.percentile(testTimes, 50),
      p95: this.percentile(testTimes, 95),
      p99: this.percentile(testTimes, 99),
      slowestTests
    };
  }

  private percentile(arr: number[], p: number): number {
    if (arr.length === 0) return 0;
    const index = Math.ceil((p / 100) * arr.length) - 1;
    return arr[Math.max(0, Math.min(index, arr.length - 1))];
  }

  private analyzeResults(): ValidationReport {
    console.log('\n📊 Analyzing Test Results...\n');

    // Calculate overall metrics
    const totalFailures = this.results.reduce((sum, result) => sum + result.failures.length, 0);
    const coverages = this.results
      .map(r => r.coverage?.overall)
      .filter((c): c is number => c !== undefined);

    const averageCoverage = coverages.length > 0
      ? coverages.reduce((a, b) => a + b, 0) / coverages.length
      : 0;

    const minCoverage = coverages.length > 0 ? Math.min(...coverages) : 0;
    const maxCoverage = coverages.length > 0 ? Math.max(...coverages) : 0;

    // Detect flaky tests
    const flakyTests = this.detectFlakyTests();

    // Calculate performance summary
    const allPerformanceMetrics = this.results.map(r => r.performance);
    const performanceSummary = this.aggregatePerformanceMetrics(allPerformanceMetrics);

    // Determine success criteria
    const overallSuccess = totalFailures === 0;
    const flakeDetected = flakyTests.length > 0;
    const coverageAchieved = minCoverage >= this.minCoverage;
    const performanceTarget = performanceSummary.p99 <= this.maxP99Time;

    // Generate recommendations
    const recommendations = this.generateRecommendations({
      overallSuccess,
      flakeDetected,
      coverageAchieved,
      performanceTarget,
      minCoverage,
      flakyTests,
      performanceSummary
    });

    // Identify security issues
    const securityIssues = this.identifySecurityIssues();

    const report: ValidationReport = {
      totalRuns: this.maxRuns,
      overallSuccess,
      flakeDetected,
      coverageAchieved,
      performanceTarget,
      results: this.results,
      summary: {
        averageCoverage,
        minCoverage,
        maxCoverage,
        totalFailures,
        flakyTests,
        performanceSummary
      },
      recommendations,
      securityIssues
    };

    this.generateReport(report);
    return report;
  }

  private detectFlakyTests(): string[] {
    const testFailures = new Map<string, number>();
    const testRuns = new Map<string, number>();

    // Count failures per test across all runs
    this.results.forEach(result => {
      result.failures.forEach(failure => {
        const testName = failure.testName;
        testFailures.set(testName, (testFailures.get(testName) || 0) + 1);
        testRuns.set(testName, this.maxRuns);
      });
    });

    // Identify tests that failed in some runs but not others (flaky)
    const flakyTests: string[] = [];
    testFailures.forEach((failureCount, testName) => {
      const totalRuns = testRuns.get(testName) || this.maxRuns;
      if (failureCount > 0 && failureCount < totalRuns) {
        flakyTests.push(testName);
      }
    });

    return flakyTests;
  }

  private aggregatePerformanceMetrics(metrics: PerformanceMetrics[]): PerformanceMetrics {
    if (metrics.length === 0) {
      return {
        totalTime: 0,
        averageTestTime: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        slowestTests: []
      };
    }

    const allP99Values = metrics.map(m => m.p99);
    const allP95Values = metrics.map(m => m.p95);
    const allP50Values = metrics.map(m => m.p50);

    return {
      totalTime: metrics.reduce((sum, m) => sum + m.totalTime, 0),
      averageTestTime: metrics.reduce((sum, m) => sum + m.averageTestTime, 0) / metrics.length,
      p50: allP50Values.reduce((a, b) => a + b, 0) / allP50Values.length,
      p95: allP95Values.reduce((a, b) => a + b, 0) / allP95Values.length,
      p99: allP99Values.reduce((a, b) => a + b, 0) / allP99Values.length,
      slowestTests: metrics
        .flatMap(m => m.slowestTests)
        .sort((a, b) => b.duration - a.duration)
        .slice(0, 10)
    };
  }

  private generateRecommendations(data: {
    overallSuccess: boolean;
    flakeDetected: boolean;
    coverageAchieved: boolean;
    performanceTarget: boolean;
    minCoverage: number;
    flakyTests: string[];
    performanceSummary: PerformanceMetrics;
  }): string[] {
    const recommendations: string[] = [];

    if (!data.overallSuccess) {
      recommendations.push('❌ CRITICAL: Tests are failing. Review and fix failing tests before deployment.');
    }

    if (data.flakeDetected) {
      recommendations.push(`❌ FLAKY TESTS DETECTED: ${data.flakyTests.length} tests are inconsistent. Fix flaky tests: ${data.flakyTests.join(', ')}`);
    }

    if (!data.coverageAchieved) {
      recommendations.push(`❌ COVERAGE INSUFFICIENT: Current coverage ${data.minCoverage.toFixed(2)}% is below 98% requirement. Add tests for uncovered code paths.`);
    }

    if (!data.performanceTarget) {
      recommendations.push(`❌ PERFORMANCE TARGET MISSED: p99 response time ${data.performanceSummary.p99.toFixed(2)}ms exceeds 150ms limit. Optimize slow tests.`);
    }

    if (data.overallSuccess && !data.flakeDetected && data.coverageAchieved && data.performanceTarget) {
      recommendations.push('✅ EXCELLENT: All security tests pass reliability, coverage, and performance requirements!');
    }

    // Additional security-specific recommendations
    recommendations.push('🔒 Ensure all SQL injection prevention tests cover edge cases');
    recommendations.push('🛡️  Verify XSS protection handles all attack vectors');
    recommendations.push('🏢 Validate multi-tenant isolation is comprehensive');
    recommendations.push('⚡ Confirm rate limiting handles distributed attacks');

    return recommendations;
  }

  private identifySecurityIssues(): string[] {
    const issues: string[] = [];

    // Analyze test failures for security implications
    this.results.forEach(result => {
      result.failures.forEach(failure => {
        const testName = failure.testName.toLowerCase();
        const error = failure.error.toLowerCase();

        if (testName.includes('sql injection') || error.includes('sql')) {
          issues.push(`🚨 SQL Injection test failure: ${failure.testName}`);
        }

        if (testName.includes('xss') || error.includes('script')) {
          issues.push(`🚨 XSS protection test failure: ${failure.testName}`);
        }

        if (testName.includes('tenant') || error.includes('business_id')) {
          issues.push(`🚨 Multi-tenant isolation test failure: ${failure.testName}`);
        }

        if (testName.includes('rate limit') || error.includes('rate')) {
          issues.push(`🚨 Rate limiting test failure: ${failure.testName}`);
        }

        if (testName.includes('auth') || error.includes('jwt')) {
          issues.push(`🚨 Authentication test failure: ${failure.testName}`);
        }
      });
    });

    return [...new Set(issues)]; // Remove duplicates
  }

  private generateReport(report: ValidationReport): void {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = join(process.cwd(), `security-test-validation-${timestamp}.json`);

    // Generate detailed JSON report
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    // Generate human-readable summary
    const summaryPath = join(process.cwd(), `security-test-summary-${timestamp}.md`);
    const summary = this.generateSummaryMarkdown(report);
    writeFileSync(summaryPath, summary);

    console.log('\n📈 SECURITY TEST VALIDATION RESULTS');
    console.log('═'.repeat(50));
    console.log(`📊 Total Runs: ${report.totalRuns}`);
    console.log(`✅ Overall Success: ${report.overallSuccess ? 'PASS' : 'FAIL'}`);
    console.log(`🔄 Flakes Detected: ${report.flakeDetected ? 'YES' : 'NO'}`);
    console.log(`📈 Coverage Target: ${report.coverageAchieved ? 'ACHIEVED' : 'MISSED'} (${report.summary.minCoverage.toFixed(2)}% minimum)`);
    console.log(`⚡ Performance Target: ${report.performanceTarget ? 'ACHIEVED' : 'MISSED'} (${report.summary.performanceSummary.p99.toFixed(2)}ms p99)`);
    console.log(`❌ Total Failures: ${report.summary.totalFailures}`);

    if (report.summary.flakyTests.length > 0) {
      console.log(`🔄 Flaky Tests: ${report.summary.flakyTests.join(', ')}`);
    }

    console.log('\n🎯 RECOMMENDATIONS:');
    report.recommendations.forEach(rec => console.log(`  ${rec}`));

    if (report.securityIssues.length > 0) {
      console.log('\n🚨 SECURITY ISSUES:');
      report.securityIssues.forEach(issue => console.log(`  ${issue}`));
    }

    console.log(`\n📄 Detailed report: ${reportPath}`);
    console.log(`📋 Summary report: ${summaryPath}`);

    // Exit with appropriate code
    const exitCode = report.overallSuccess && !report.flakeDetected && report.coverageAchieved && report.performanceTarget ? 0 : 1;
    process.exit(exitCode);
  }

  private generateSummaryMarkdown(report: ValidationReport): string {
    return `# Security Test Validation Report

## Summary
- **Total Runs**: ${report.totalRuns}
- **Overall Success**: ${report.overallSuccess ? '✅ PASS' : '❌ FAIL'}
- **Flakes Detected**: ${report.flakeDetected ? '❌ YES' : '✅ NO'}
- **Coverage Target**: ${report.coverageAchieved ? '✅ ACHIEVED' : '❌ MISSED'} (${report.summary.minCoverage.toFixed(2)}% minimum)
- **Performance Target**: ${report.performanceTarget ? '✅ ACHIEVED' : '❌ MISSED'} (${report.summary.performanceSummary.p99.toFixed(2)}ms p99)

## Coverage Analysis
- **Average Coverage**: ${report.summary.averageCoverage.toFixed(2)}%
- **Minimum Coverage**: ${report.summary.minCoverage.toFixed(2)}%
- **Maximum Coverage**: ${report.summary.maxCoverage.toFixed(2)}%

## Performance Analysis
- **Average p99**: ${report.summary.performanceSummary.p99.toFixed(2)}ms
- **Average p95**: ${report.summary.performanceSummary.p95.toFixed(2)}ms
- **Average Test Time**: ${report.summary.performanceSummary.averageTestTime.toFixed(2)}ms

## Recommendations
${report.recommendations.map(r => `- ${r}`).join('\n')}

## Security Issues
${report.securityIssues.length > 0 ? report.securityIssues.map(i => `- ${i}`).join('\n') : '✅ No security issues detected'}

## Detailed Results
${report.results.map((r, i) => `
### Run ${r.run}
- **Passed**: ${r.passed}
- **Failed**: ${r.failed}
- **Duration**: ${r.duration}ms
- **Coverage**: ${r.coverage?.overall.toFixed(2)}%
`).join('')}
`;
  }
}

// Main execution
async function main() {
  const validator = new SecurityTestValidator();

  try {
    await validator.runValidation();
  } catch (error) {
    console.error('❌ Security test validation failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}