import { runSensorStream } from '../apps/sensor-simulator/src/stream.js';
import { runOpsStream } from '../apps/ops-simulator/src/stream.js';

console.log('========================================================');
console.log('EnviroTrust Live Simulation Runner — Continuous Streaming');
console.log('Starting both Sensor Telemetry/Heartbeats and Ops Context...');
console.log('========================================================');

const p1 = runSensorStream().catch((err) => {
  console.error('[SENSOR STREAM ERROR]:', err);
});

const p2 = runOpsStream().catch((err) => {
  console.error('[OPS STREAM ERROR]:', err);
});

Promise.all([p1, p2]).then(() => {
  console.log('[ALL STREAMS TERMINATED CLEANLY]');
});

