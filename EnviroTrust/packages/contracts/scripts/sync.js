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
  console.error(`[contracts:sync] ERROR: Canonical schema directory not found at: ${canonicalDir}`);
  process.exit(1);
}

if (!fs.existsSync(runtimeDir)) {
  fs.mkdirSync(runtimeDir, { recursive: true });
}

const files = fs.readdirSync(canonicalDir).filter((file) => file.endsWith('.json'));

if (files.length === 0) {
  console.error(`[contracts:sync] ERROR: No JSON schemas found in ${canonicalDir}`);
  process.exit(1);
}

console.log(`[contracts:sync] Synchronizing ${files.length} schemas from docs/contracts to packages/contracts/src/schemas...`);

let syncedCount = 0;
for (const file of files) {
  const sourcePath = path.join(canonicalDir, file);
  const destPath = path.join(runtimeDir, file);

  const raw = fs.readFileSync(sourcePath, 'utf-8');
  // Validate that it parses as JSON
  try {
    JSON.parse(raw);
  } catch (err) {
    console.error(`[contracts:sync] ERROR: Invalid JSON in canonical schema ${file}:`, err);
    process.exit(1);
  }

  fs.writeFileSync(destPath, raw, 'utf-8');
  console.log(`  ✓ Synced ${file}`);
  syncedCount++;
}

console.log(`[contracts:sync] Successfully synced ${syncedCount} schemas.`);
