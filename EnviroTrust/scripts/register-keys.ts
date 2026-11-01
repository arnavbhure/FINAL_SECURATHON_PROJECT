import { registerKeysFromManifest, findManifestPath } from '../apps/api/src/services/key-registry.service.js';

export { registerKeysFromManifest as registerKeys, findManifestPath };

// Direct CLI invocation
if (process.argv[1] && process.argv[1].endsWith('register-keys.ts')) {
  const manifestArg = process.argv.find((a) => a.startsWith('--manifest='));
  const manifestPath = manifestArg ? manifestArg.split('=')[1] : undefined;

  registerKeysFromManifest(manifestPath)
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
