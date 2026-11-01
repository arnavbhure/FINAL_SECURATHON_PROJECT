import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const requiredFiles = [
  path.join(rootDir, 'packages/contracts/dist/src/index.js'),
  path.join(rootDir, 'packages/crypto/dist/src/index.js'),
  path.join(rootDir, 'apps/sensor-simulator/dist/src/index.js'),
  path.join(rootDir, 'apps/ops-simulator/dist/src/index.js'),
];

const missing = requiredFiles.some((f) => !fs.existsSync(f));
const force = process.argv.includes('--force');

if (missing || force) {
  console.log('[envirotrust] Compiling workspace dependencies (contracts, crypto, simulators)...');
  execSync(
    'npm run build --workspace=@envirotrust/contracts --workspace=@envirotrust/crypto --workspace=@envirotrust/sensor-simulator --workspace=@envirotrust/ops-simulator',
    {
      cwd: rootDir,
      stdio: 'inherit',
    }
  );
  console.log('[envirotrust] Workspace dependencies compiled successfully.');
}

