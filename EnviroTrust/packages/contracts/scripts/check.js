import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Root paths
const rootDir = path.resolve(__dirname, '../../..');
const canonicalDir = path.join(rootDir, 'docs', 'contracts');
const runtimeDir = path.resolve(__dirname, '../src/schemas');

if (!fs.existsSync(canonicalDir)) {
  console.error(`[contracts:check] ERROR: Canonical schema directory not found at: ${canonicalDir}`);
  process.exit(1);
}

if (!fs.existsSync(runtimeDir)) {
  console.error(`[contracts:check] ERROR: Runtime schema directory not found at: ${runtimeDir}`);
  console.error(`Run 'npm run contracts:sync' to populate runtime schemas.`);
  process.exit(1);
}

const canonicalFiles = fs.readdirSync(canonicalDir).filter((file) => file.endsWith('.json')).sort();
const runtimeFiles = fs.readdirSync(runtimeDir).filter((file) => file.endsWith('.json')).sort();

let hasDrift = false;

// Check for missing files
for (const file of canonicalFiles) {
  if (!runtimeFiles.includes(file)) {
    console.error(`[contracts:check] DRIFT DETECTED: Missing in runtime schemas: ${file}`);
    hasDrift = true;
  }
}

// Check for extra files in runtime
for (const file of runtimeFiles) {
  if (!canonicalFiles.includes(file)) {
    console.error(`[contracts:check] DRIFT DETECTED: Extra schema in runtime not in canonical docs: ${file}`);
    hasDrift = true;
  }
}

// Check semantic content equivalence
for (const file of canonicalFiles) {
  if (!runtimeFiles.includes(file)) continue;

  const canonicalContent = fs.readFileSync(path.join(canonicalDir, file), 'utf-8');
  const runtimeContent = fs.readFileSync(path.join(runtimeDir, file), 'utf-8');

  try {
    const canonicalParsed = JSON.parse(canonicalContent);
    const runtimeParsed = JSON.parse(runtimeContent);

    const canonicalNorm = JSON.stringify(canonicalParsed);
    const runtimeNorm = JSON.stringify(runtimeParsed);

    if (canonicalNorm !== runtimeNorm) {
      console.error(`[contracts:check] DRIFT DETECTED: Content mismatch for schema: ${file}`);
      hasDrift = true;
    }
  } catch (err) {
    console.error(`[contracts:check] ERROR parsing JSON for schema: ${file}`, err);
    hasDrift = true;
  }
}

if (hasDrift) {
  console.error(`\n[contracts:check] FAILED: Runtime schemas have drifted from canonical docs/contracts/.`);
  console.error(`Run 'npm run contracts:sync' to synchronize runtime schemas from docs/contracts/.`);
  process.exit(1);
}

console.log(`[contracts:check] SUCCESS: All ${canonicalFiles.length} runtime schemas strictly match canonical docs/contracts/.`);
