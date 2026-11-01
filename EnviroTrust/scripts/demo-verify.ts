import { verifyRecordedRun, type AttackLabRunRecord } from '../apps/api/src/attack-lab/index.js';
import { argValue, createCliEngine } from './demo-lib.js';

/**
 * npm run demo:verify                 — re-verify the latest completed run of every scenario
 * npm run demo:verify -- --run <id>   — re-verify one recorded run
 *
 * Re-checks recorded evidence against the live databases/services and re-runs the witness chain check.
 * Exit code 1 when any check fails.
 */
async function main(): Promise<number> {
  const { engine, close } = createCliEngine();
  let failures = 0;
  try {
    const runId = argValue('run');
    let runs: AttackLabRunRecord[];
    if (runId) {
      const run = await engine.runs.getRun(runId);
      if (!run) {
        console.error(`Run ${runId} not found`);
        return 1;
      }
      runs = [run];
    } else {
      runs = await engine.runs.latestCompletedPerScenario();
    }
    if (runs.length === 0) {
      console.log('No completed Attack Lab runs recorded yet. Run `npm run demo:attacks` first.');
      return 1;
    }

    for (const run of runs) {
      console.log(`\n=== ${run.scenarioId} — run ${run.id} (${run.startedAt})`);
      const checks = await verifyRecordedRun(engine, run);
      for (const c of checks) {
        console.log(`  ${c.ok ? '✓' : '✗'} ${c.label}`);
        if (!c.ok) failures++;
      }
    }

    // Independent witness chain recomputation via the witness's own verification API.
    const res = await fetch(`${engine.config.witnessBaseUrl}/witness/v1/verify/chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Witness-Token': engine.config.witnessServiceToken },
      body: JSON.stringify({ stationId: engine.config.stationCode }),
    }).catch(() => null);
    const body = res ? ((await res.json().catch(() => null)) as { valid?: boolean; eventCount?: number; headSequence?: number } | null) : null;
    const chainOk = body?.valid === true;
    console.log(`\n=== Witness chain recomputation (${engine.config.stationCode})`);
    console.log(`  ${chainOk ? '✓' : '✗'} valid=${String(body?.valid)} events=${body?.eventCount ?? 'n/a'} head=${body?.headSequence ?? 'n/a'}${res ? '' : ' (witness unreachable)'}`);
    if (!chainOk) failures++;
  } finally {
    await close();
  }
  console.log(failures === 0 ? '\nAll recorded evidence re-verified.' : `\n${failures} check(s) failed.`);
  return failures === 0 ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[demo:verify] fatal:', err);
    process.exit(1);
  });
