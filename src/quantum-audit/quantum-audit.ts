#!/usr/bin/env ts-node

import { QuantumMasterAuditor } from './auditors/QuantumMasterAuditor';

async function main() {
  try {

    const auditor = new QuantumMasterAuditor();
    const report = await auditor.executeCompleteAudit();


    if (report.summary.critical > 0) {
      report.recommendations.immediate.forEach((_issue, _index) => {
      });
    }

    if (report.nextSteps.immediate.length > 0) {
      report.nextSteps.immediate.forEach((_step, _index) => {
      });
    }


    // Exit with appropriate code
    process.exit(report.summary.critical > 0 ? 1 : 0);

  } catch (error: any) {
    process.exit(1);
  }
}

// Execute if run directly
main();

export { main as runQuantumAudit };