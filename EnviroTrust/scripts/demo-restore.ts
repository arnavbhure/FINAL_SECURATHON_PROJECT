import { restoreDemoEnvironment } from '../apps/api/src/attack-lab/index.js';
import { createCliEngine, hasFlag } from './demo-lib.js';

/**
 * npm run demo:restore -- --confirm
 *
 * Takes demo identities out of service, resolves incidents raised by recorded Attack Lab runs and clears
 * the lab's own outbox/temp exports. Never deletes telemetry, audit, witness, security-event or run evidence.
 */
async function main(): Promise<number> {
  if (!hasFlag('confirm')) {
    console.error('Refusing to restore without --confirm. Usage: npm run demo:restore -- --confirm');
    return 1;
  }
  const { engine, close } = createCliEngine();
  try {
    const { actions } = await restoreDemoEnvironment(engine, { confirm: true });
    console.log('Demo environment restored (no evidence deleted):');
    for (const a of actions) console.log(`  • ${a}`);
    return 0;
  } catch (err) {
    console.error(`Restore refused: ${(err as Error).message}`);
    return 1;
  } finally {
    await close();
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[demo:restore] fatal:', err);
    process.exit(1);
  });
