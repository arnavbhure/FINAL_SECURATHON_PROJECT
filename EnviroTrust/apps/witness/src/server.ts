import { createWitnessApp } from './app.js';
import { getSanitizedWitnessConfigSummary } from './env.js';

const { app, env } = createWitnessApp();

const server = app.listen(env.WITNESS_PORT, () => {
  console.log(`[envirotrust-witness] Simulated Witness running on port ${env.WITNESS_PORT}`);
  console.log('[envirotrust-witness] Configuration summary:', getSanitizedWitnessConfigSummary(env));
});

process.on('SIGTERM', () => {
  console.log('[envirotrust-witness] Received SIGTERM. Shutting down gracefully...');
  server.close(() => {
    process.exit(0);
  });
});
