import os from 'node:os';
import { loadApiEnvironment } from '../apps/api/src/env.js';
import { getDbPool, closeDbPool } from '../apps/api/src/db/connection.js';
import { AttackLabEngine, loadAttackLabConfig, type AttackLabRunRecord, type RunActor } from '../apps/api/src/attack-lab/index.js';

/** Shared bootstrap for the demo:* CLI commands. Uses the same engine and scenario catalog as the UI. */
export function createCliEngine(): { engine: AttackLabEngine; close: () => Promise<void> } {
  const env = loadApiEnvironment();
  const engine = new AttackLabEngine(loadAttackLabConfig(env), getDbPool());
  return {
    engine,
    close: async () => {
      await engine.close();
      await closeDbPool();
    },
  };
}

export function cliActor(): RunActor {
  let user = 'operator';
  try {
    user = os.userInfo().username;
  } catch {
    // keep default
  }
  return { userId: null, label: `CLI (${user})`, source: 'CLI' };
}

export function argValue(name: string): string | undefined {
  const args = process.argv.slice(2);
  const eq = args.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.slice(name.length + 3);
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && args[idx + 1] && !args[idx + 1]!.startsWith('--')) return args[idx + 1];
  return undefined;
}

export function hasFlag(name: string): boolean {
  return process.argv.slice(2).includes(`--${name}`);
}

const ICON: Record<string, string> = {
  PASSED: '✓',
  FAILED: '✗',
  INFO: '•',
  RUNNING: '…',
  SKIPPED: '-',
};

export function printRun(run: AttackLabRunRecord): void {
  console.log(`\n=== ${run.scenarioId} — run ${run.id}`);
  for (const step of run.steps) {
    console.log(`  ${ICON[step.status] ?? '?'} [${step.status}] ${step.title}`);
    for (const line of step.detail.split('\n')) console.log(`      ${line}`);
  }
  if (run.mlResult) {
    const ml = run.mlResult;
    console.log(
      `  ML: ${ml.status}${ml.anomalyScore !== undefined && ml.anomalyScore !== null ? ` score=${ml.anomalyScore} threshold=${ml.anomalyThreshold}` : ''}${ml.modelVersion ? ` model=${ml.modelVersion}` : ''}`
    );
  }
  console.log(`  OUTCOME: ${run.outcome} | ${run.classification} | expectation met: ${run.expectationMet}`);
  console.log(`  ${run.summary}`);
  if (run.error) console.log(`  ERROR: ${run.error}`);
}
