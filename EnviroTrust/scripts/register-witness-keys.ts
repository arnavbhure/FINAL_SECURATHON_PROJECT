import { registerWitnessKeys, findManifestPath } from '../apps/witness/src/services/witness-key-registry.service.js';

export { registerWitnessKeys, findManifestPath };

// Direct CLI invocation
if (process.argv[1] && process.argv[1].endsWith('register-witness-keys.ts')) {
  const manifestArg = process.argv.find((a) => a.startsWith('--manifest='));
  const manifestPath = manifestArg ? manifestArg.split('=')[1] : undefined;

  registerWitnessKeys(manifestPath)
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

