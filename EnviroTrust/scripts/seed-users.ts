import { seedDemoUsers } from '../apps/api/src/db/seed.js';
import { closeDbPool } from '../apps/api/src/db/connection.js';

console.log('[SEED] Starting demo user provisioning...');

seedDemoUsers()
  .then(async () => {
    console.log('[SEED] Demo users successfully provisioned.');
    await closeDbPool();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('[SEED] Error seeding users:', err);
    await closeDbPool();
    process.exit(1);
  });
