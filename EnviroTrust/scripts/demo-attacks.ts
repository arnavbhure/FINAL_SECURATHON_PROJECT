import { SCENARIO_CATALOG, isScenarioId, type AttackLabRunRecord } from '../apps/api/src/attack-lab/index.js';
import { argValue, cliActor, createCliEngine, hasFlag, printRun } from './demo-lib.js';

/**
 * npm run demo:attacks                                   — run every scenario A–I
 * npm run demo:attacks -- --scenario telemetry-tampering — run one scenario
 * npm run demo:attacks -- --json                         — machine-readable summary
 *
 * Invoking this command is the explicit confirmation for disruptive scenarios (H, I).
 * Exit code 1 when any scenario's expected outcome was not actually achieved.
 */
async function main(): Promise<number> {
  const requested = argValue('scenario');
  if (requested && !isScenarioId(requested)) {
    console.error(`Unknown scenario "${requested}". Known: ${SCENARIO_CATALOG.map((s) => s.id).join(', ')}`);
    return 2;
  }
  const scenarios = requested ? SCENARIO_CATALOG.filter((s) => s.id === requested) : SCENARIO_CATALOG;
  const { engine, close } = createCliEngine();
  const results: AttackLabRunRecord[] = [];
  try {
    const safety = await engine.safety();
    if (!safety.ok) {
      console.error('Attack Lab safety checks failed — refusing to run scenarios:');
      for (const c of safety.checks.filter((x) => !x.ok)) console.error(`  ✗ ${c.label}: ${c.detail}`);
      console.error('Run `npm run demo:doctor` for details.');
      return 1;
    }
    console.log('EnviroTrust Attack Simulation Lab — DEMO ENVIRONMENT');
    console.log(`Targets: Primary ${engine.config.primaryBaseUrl} | Witness ${engine.config.witnessBaseUrl}`);
    for (const s of scenarios) {
      console.log(`\n▶ ${s.letter} — ${s.name} (≈${s.estimatedDurationSeconds}s)`);
      try {
        const run = await engine.runScenario(s.id, cliActor(), { confirm: true });
        results.push(run);
        if (!hasFlag('json')) printRun(run);
      } catch (err) {
        console.error(`  ✗ could not start: ${(err as Error).message}`);
        return 1;
      }
    }
  } finally {
    await close();
  }

  if (hasFlag('json')) {
    console.log(
      JSON.stringify(
        results.map((r) => ({ runId: r.id, scenarioId: r.scenarioId, outcome: r.outcome, classification: r.classification, expectationMet: r.expectationMet, summary: r.summary, mlResult: r.mlResult })),
        null,
        2
      )
    );
  }
  console.log('\n=== Summary');
  for (const r of results) {
    console.log(`  ${r.expectationMet ? '✓' : '✗'} ${r.scenarioId.padEnd(30)} ${String(r.outcome).padEnd(20)} ${r.classification}`);
  }
  const failed = results.filter((r) => r.expectationMet !== true);
  if (failed.length > 0) {
    console.log(`\n${failed.length} scenario(s) did not achieve the expected outcome.`);
    return 1;
  }
  console.log('\nAll requested scenarios achieved their expected outcome.');
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[demo:attacks] fatal:', err);
    process.exit(1);
  });
