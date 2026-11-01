import { createApiApp } from './app.js';
import { getSanitizedConfigSummary } from './env.js';

const { app, env, mlAssessmentService, alertService } = createApiApp();

// Start background availability evaluator for STALE/OFFLINE/RECOVERED alerts
alertService.startEvaluator(5000);

if (env.ML_ENABLED) {
  console.log('[envirotrust-api] ML_ENABLED is true. Starting background assessment worker...');
  mlAssessmentService.startWorker(2000);
} else {
  console.log('[envirotrust-api] ML_ENABLED is false. Background assessment worker is idle.');
}

const server = app.listen(env.API_PORT, () => {
  console.log(`[envirotrust-api] Primary API running on port ${env.API_PORT}`);
  console.log('[envirotrust-api] Configuration summary:', getSanitizedConfigSummary(env));
});

process.on('SIGTERM', () => {
  console.log('[envirotrust-api] Received SIGTERM. Shutting down gracefully...');
  alertService.stopEvaluator();
  mlAssessmentService.stopWorker();
  server.close(() => {
    process.exit(0);
  });
});
