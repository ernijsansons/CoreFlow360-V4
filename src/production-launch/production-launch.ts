#!/usr/bin/env ts-node

import { ProductionLaunchOrchestrator } from './orchestrator/ProductionLaunchOrchestrator';

async function main() {
  try {

    const orchestrator = new ProductionLaunchOrchestrator();

    // Check command line arguments
    const args = process.argv.slice(2);
    const command = args[0];

    switch (command) {
      case 'status':
        await showLaunchStatus(orchestrator);
        break;
      case 'validate':
        await validateLaunchReadiness(orchestrator);
        break;
      case 'launch':
        await executeLaunch(orchestrator);
        break;
      case 'pause':
        await pauseLaunch(orchestrator);
        break;
      case 'resume':
        await resumeLaunch(orchestrator);
        break;
      case 'abort':
        await abortLaunch(orchestrator);
        break;
      case 'rollback':
        await testRollback(orchestrator);
        break;
      default:
        showUsage();
        break;
    }

  } catch (error: any) {
    process.exit(1);
  }
}

async function showLaunchStatus(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const status = await orchestrator.getCurrentLaunchStatus();

  if (!status) {
    return;
  }


  if (status.issues.length > 0) {
    status.issues.forEach((issue, index) => {
    });
  }
}

async function validateLaunchReadiness(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  // This would run pre-flight checks without starting the launch
  const validator = new (await import('./validators/PreFlightValidator.js')).PreFlightValidator();
  const checks = await validator.performPreFlightChecks();


  if (!checks.allPassed) {
    checks.failures.forEach((failure, index) => {
    });
  }

  process.exit(checks.allPassed ? 0 : 1);
}

async function executeLaunch(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const startTime = Date.now();

  try {
    const result = await orchestrator.initiateGoLive();

    const duration = (Date.now() - startTime) / 1000;


    process.exit(0);

  } catch (error: any) {
    const duration = (Date.now() - startTime) / 1000;


    process.exit(1);
  }
}

async function pauseLaunch(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const status = await orchestrator.getCurrentLaunchStatus();
  if (!status) {
    return;
  }

  await orchestrator.pauseLaunch();
}

async function resumeLaunch(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const status = await orchestrator.getCurrentLaunchStatus();
  if (!status) {
    return;
  }

  await orchestrator.resumeLaunch();
}

async function abortLaunch(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const status = await orchestrator.getCurrentLaunchStatus();
  if (!status) {
    return;
  }


  await orchestrator.abortLaunch();
}

async function testRollback(orchestrator: ProductionLaunchOrchestrator): Promise<void> {

  const rollbackManager = new (await import('./rollback/RollbackManager.js')).RollbackManager();

  // Test rollback readiness
  const readiness = await rollbackManager.validateRollbackReadiness();

  if (!readiness.ready) {
    readiness.issues.forEach((issue: any) => console.log(`  - ${issue}`));
  }

  // Test rollback procedure
  const testResult = await rollbackManager.testRollbackProcedure();

  if (testResult.issues.length > 0) {
    testResult.issues.forEach((issue: any) => console.log(`  - ${issue}`));
  }
}

function showUsage(): void {
}

// Execute if run directly
main();

export { main as runProductionLaunch };