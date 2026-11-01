import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { canonicalizePayload, calculatePublicKeyFingerprint } from '@envirotrust/crypto';
import type { TelemetryPayload } from '@envirotrust/contracts';
import { summaryFor } from '../classify.js';
import { LAB_SENSOR_CODE } from '../config.js';
import type { ScenarioContext } from '../context.js';
import type { ScenarioResult } from '../types.js';
import { preflight } from './rejection.js';

interface ScriptResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

interface ExportedEvent {
  witnessSequence: number;
  messageId: string;
  eventHash: string;
  eventDataWithoutHash: { payloadHash: string; [key: string]: unknown };
}

interface ExportFile {
  checkpoints: Array<{ payload: { checkpointSequence: number; lastWitnessSequence: number }; events: ExportedEvent[] }>;
}

interface VerifierReport {
  overallStatus: 'PASS' | 'FAIL';
  totalCheckpoints: number;
  totalEventsVerified: number;
  discrepancies: Array<{ type: string; witnessSequence?: number; messageId?: string; reason: string; expected?: string; actual?: string }>;
}

function sha256File(filePath: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

/** Runs one of the repository's real operator scripts (the same commands judges run by hand). */
function runRepoScript(ctx: ScenarioContext, script: string, args: string[], timeoutMs = 120000): Promise<ScriptResult> {
  const tsxCli = path.join(ctx.config.repoRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [tsxCli, path.join(ctx.config.repoRoot, 'scripts', script), ...args], {
      cwd: ctx.config.repoRoot,
      env: { ...process.env, WITNESS_DATABASE_URL: ctx.config.witnessDatabaseUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code, stdout, stderr });
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ exitCode: null, stdout, stderr: `${stderr}\n${err.message}` });
    });
  });
}

function parseReport(result: ScriptResult): VerifierReport | null {
  const line = result.stdout.trim().split('\n').reverse().find((l) => l.trim().startsWith('{'));
  if (!line) return null;
  try {
    return JSON.parse(line) as VerifierReport;
  } catch {
    return null;
  }
}

/** The trusted witness fingerprint comes from configuration or the provisioned trust anchor — never from the export. */
function resolveTrustedFingerprint(ctx: ScenarioContext): { fingerprint: string | null; source: string } {
  if (ctx.config.trustedWitnessFingerprint) {
    return { fingerprint: ctx.config.trustedWitnessFingerprint, source: 'ATTACK_LAB_TRUSTED_WITNESS_FINGERPRINT' };
  }
  const dir = path.join(ctx.config.secretsDir, 'witness-keys');
  const pub = path.join(dir, 'public.pem');
  if (fs.existsSync(pub)) {
    return { fingerprint: calculatePublicKeyFingerprint(fs.readFileSync(pub, 'utf-8')), source: 'provisioned witness public key (local-secrets/witness-keys/public.pem)' };
  }
  return { fingerprint: null, source: 'none' };
}

/** G — modify one checkpoint-covered event in an exported copy and verify both copies offline. */
export async function runCheckpointHistoryTampering(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const inconclusive = (classification: string, evidence: Record<string, unknown>): ScenarioResult => ({
    outcome: 'INCONCLUSIVE',
    classification,
    summary: summaryFor('INCONCLUSIVE', 'evidence'),
    expectationMet: false,
    primaryOutcome: null,
    witnessOutcome: null,
    mlResult: null,
    alertIds: [],
    securityEventIds: { primary: [], witness: [] },
    verificationEvidence: evidence,
  });

  const idStep = await ctx.steps.begin('identity', `Load the Attack Lab demo sensor ${LAB_SENSOR_CODE}`);
  const identity = await ctx.labIdentityStatus(LAB_SENSOR_CODE);
  await ctx.steps.finish(idStep, identity.ready ? 'PASSED' : 'FAILED', identity.ready ? `${LAB_SENSOR_CODE} / ${identity.keyId} registered in both registries` : 'Not provisioned — run npm run demo:provision');
  if (!identity.ready) return inconclusive('DEMO_IDENTITY_MISSING', { identity });

  // 1. Genuine events until a signed checkpoint covers at least one of them
  const gen = await ctx.steps.begin('generate', 'Generate genuine witnessed readings until a signed checkpoint covers them');
  const device = ctx.labDevice(LAB_SENSOR_CODE, { bootId: `LAB-G-${ctx.runId.slice(0, 8)}`, initialTelemetrySequence: 1 });
  const ours: Array<{ messageId: string; witnessSequence: number; payload: TelemetryPayload }> = [];
  let covering: { checkpointSequence: number; lastWitnessSequence: number } | null = null;
  for (let i = 0; i < 15 && !covering; i++) {
    const env = device.generateReading();
    const { primary, witness } = await ctx.submitDual('telemetry', env);
    const wSeq = Number((witness.body as Record<string, unknown> | null)?.['witnessSequence']);
    if (primary.ok && witness.ok && Number.isFinite(wSeq)) {
      ours.push({ messageId: env.payload.messageId, witnessSequence: wSeq, payload: env.payload });
    }
    const latest = await ctx.witnessPool.query<{ checkpoint_sequence: string; last_witness_sequence: string }>(
      `SELECT checkpoint_sequence, last_witness_sequence FROM witness_checkpoints
       WHERE station_code = $1 ORDER BY checkpoint_sequence DESC LIMIT 1`,
      [ctx.config.stationCode]
    );
    const cp = latest.rows[0];
    if (cp && ours.some((o) => o.witnessSequence <= Number(cp.last_witness_sequence))) {
      covering = { checkpointSequence: Number(cp.checkpoint_sequence), lastWitnessSequence: Number(cp.last_witness_sequence) };
    }
  }
  const target = covering ? ours.filter((o) => o.witnessSequence <= covering!.lastWitnessSequence).at(-1) : undefined;
  await ctx.steps.finish(
    gen,
    target ? 'PASSED' : 'FAILED',
    target
      ? `${ours.length} genuine reading(s) witnessed; checkpoint #${covering!.checkpointSequence} covers witness sequences ≤ ${covering!.lastWitnessSequence}. Target event: witness sequence ${target.witnessSequence} (message ${target.messageId}, value ${target.payload.value} mg/L).`
      : `${ours.length} reading(s) witnessed but no checkpoint covered them yet`,
    { generated: ours.map((o) => ({ messageId: o.messageId, witnessSequence: o.witnessSequence })), checkpoint: covering }
  );
  if (!target || !covering) return inconclusive('NO_CHECKPOINT_COVERAGE', { generated: ours.length });

  // 2. Export the genuine checkpoint history with the real export tool
  const runDir = path.join(ctx.config.workDir, ctx.runId);
  fs.mkdirSync(runDir, { recursive: true });
  const originalPath = path.join(runDir, 'witness-export-original.json');
  const modifiedPath = path.join(runDir, 'witness-export-modified.json');
  const exp = await ctx.steps.begin('export', 'Export signed checkpoints + covered history (npm run witness:checkpoint:export)');
  const exported = await runRepoScript(ctx, 'export-checkpoints.ts', [`--station=${ctx.config.stationCode}`, `--output=${originalPath}`]);
  if (exported.exitCode !== 0 || !fs.existsSync(originalPath)) {
    await ctx.steps.finish(exp, 'FAILED', `Export failed (exit ${exported.exitCode}): ${exported.stderr.slice(-400)}`);
    return inconclusive('EXPORT_FAILED', { stderr: exported.stderr.slice(-1000) });
  }
  const originalHashBefore = sha256File(originalPath);
  const exportData = JSON.parse(fs.readFileSync(originalPath, 'utf-8')) as ExportFile;
  const lastCovered = exportData.checkpoints.at(-1)?.payload.lastWitnessSequence ?? 0;
  const cursor = await ctx.witnessPool.query<{ last_witness_sequence: string }>(
    'SELECT last_witness_sequence FROM witness_chain_cursors WHERE station_code = $1',
    [ctx.config.stationCode]
  );
  const chainHead = Number(cursor.rows[0]?.last_witness_sequence || 0);
  const notAnchored = Math.max(0, chainHead - lastCovered);
  await ctx.steps.finish(
    exp,
    'PASSED',
    `${exportData.checkpoints.length} checkpoint(s), events 1…${lastCovered}; file SHA-256 ${originalHashBefore.slice(0, 16)}…. ${notAnchored} newer witness event(s) are not yet covered by any checkpoint and are NOT checkpoint-anchored.`,
    { checkpoints: exportData.checkpoints.length, lastCoveredWitnessSequence: lastCovered, witnessChainHead: chainHead, notCheckpointAnchored: notAnchored, originalSha256: originalHashBefore }
  );

  // 3. Modify one covered event in a separate copy
  const mod = await ctx.steps.begin('modify', 'Modify one covered event in a separate temporary copy');
  const copy = JSON.parse(JSON.stringify(exportData)) as ExportFile;
  const ev = copy.checkpoints.flatMap((c) => c.events).find((e) => e.messageId === target.messageId);
  if (!ev) {
    await ctx.steps.finish(mod, 'FAILED', 'Target event not present in the export');
    return inconclusive('TARGET_NOT_EXPORTED', { targetMessageId: target.messageId });
  }
  const originalPayloadHash = ev.eventDataWithoutHash.payloadHash;
  const rewrittenPayload = { ...target.payload, value: '12.00' };
  const rewrittenHash = crypto.createHash('sha256').update(canonicalizePayload(rewrittenPayload), 'utf-8').digest('hex');
  ev.eventDataWithoutHash.payloadHash = rewrittenHash;
  fs.writeFileSync(modifiedPath, JSON.stringify(copy, null, 2), 'utf-8');
  await ctx.steps.finish(
    mod,
    'PASSED',
    `Witness sequence ${ev.witnessSequence}: reading value ${target.payload.value} → 12.00 mg/L, so payloadHash ${originalPayloadHash.slice(0, 12)}… → ${rewrittenHash.slice(0, 12)}…. Stored event hash left as-is (as an attacker editing history would).`,
    { witnessSequence: ev.witnessSequence, originalPayloadHash, rewrittenPayloadHash: rewrittenHash, modifiedSha256: sha256File(modifiedPath) }
  );

  // 4. Verify both copies with the real offline verifier against the independently pinned fingerprint
  const trust = resolveTrustedFingerprint(ctx);
  if (!trust.fingerprint) return inconclusive('NO_TRUSTED_WITNESS_FINGERPRINT', {});
  const v1 = await ctx.steps.begin('verify-original', 'Verify the untouched export (npm run witness:checkpoint:verify)');
  const origRun = await runRepoScript(ctx, 'verify-checkpoint.ts', [`--file=${originalPath}`, `--pinned-fingerprint=${trust.fingerprint}`, '--json']);
  const origReport = parseReport(origRun);
  await ctx.steps.finish(
    v1,
    origReport?.overallStatus === 'PASS' ? 'PASSED' : 'FAILED',
    origReport
      ? `${origReport.overallStatus} (exit ${origRun.exitCode}): ${origReport.totalCheckpoints} checkpoint signature(s) and ${origReport.totalEventsVerified} event hash(es) verified; ${origReport.discrepancies.length} discrepancy(ies). Trusted fingerprint ${trust.fingerprint.slice(0, 16)}… from ${trust.source}.`
      : `Verifier produced no report (exit ${origRun.exitCode}): ${origRun.stderr.slice(-300)}`,
    { report: origReport ? { ...origReport, discrepancies: origReport.discrepancies.slice(0, 10) } : null }
  );

  const v2 = await ctx.steps.begin('verify-modified', 'Verify the modified copy with the same verifier and pinned fingerprint');
  const modRun = await runRepoScript(ctx, 'verify-checkpoint.ts', [`--file=${modifiedPath}`, `--pinned-fingerprint=${trust.fingerprint}`, '--json']);
  const modReport = parseReport(modRun);
  const hit = modReport?.discrepancies.find((d) => d.type === 'EVENT_HASH_MISMATCH' && d.witnessSequence === ev.witnessSequence);
  await ctx.steps.finish(
    v2,
    modReport?.overallStatus === 'FAIL' && hit ? 'PASSED' : 'FAILED',
    modReport
      ? `${modReport.overallStatus} (exit ${modRun.exitCode}): ${modReport.discrepancies.map((d) => `[${d.type}] ${d.reason}`).slice(0, 3).join(' | ') || 'no discrepancies'}`
      : `Verifier produced no report (exit ${modRun.exitCode})`,
    { report: modReport ? { ...modReport, discrepancies: modReport.discrepancies.slice(0, 10) } : null }
  );

  // 5. Witness storage untouched
  const wStep = await ctx.steps.begin('witness-untouched', 'Confirm the witness database record was not modified');
  const live = await ctx.witnessEvent(target.messageId);
  const originalEvent = exportData.checkpoints.flatMap((c) => c.events).find((e) => e.messageId === target.messageId);
  const originalHashAfter = sha256File(originalPath);
  const untouched =
    Boolean(live.event && originalEvent) &&
    live.event!.eventHash === originalEvent!.eventHash &&
    live.event!.payloadHash === originalPayloadHash &&
    originalHashAfter === originalHashBefore;
  await ctx.steps.finish(
    wStep,
    untouched ? 'PASSED' : 'FAILED',
    `Witness record (sequence ${live.event?.witnessSequence ?? 'n/a'}) eventHash ${live.event?.eventHash.slice(0, 12) ?? 'n/a'}…, payloadHash ${live.event?.payloadHash.slice(0, 12) ?? 'n/a'}… — ${untouched ? 'matches the original export' : 'DOES NOT match'}; untouched export file hash unchanged: ${originalHashAfter === originalHashBefore}`
  );

  const originalPassed = origReport?.overallStatus === 'PASS';
  const detected = originalPassed && modReport?.overallStatus === 'FAIL' && Boolean(hit) && untouched;
  const outcome = detected ? 'DETECTED' : 'INCONCLUSIVE';
  return {
    outcome,
    classification: detected ? 'CHECKPOINT_VERIFICATION_FAILED' : originalPassed ? 'MODIFICATION_NOT_DETECTED' : 'BASELINE_EXPORT_DID_NOT_VERIFY',
    summary: detected
      ? `${summaryFor('DETECTED', 'evidence')}: the untouched export passed and the modified copy failed — ${hit!.reason}.`
      : `${summaryFor('INCONCLUSIVE', 'evidence')}: original=${origReport?.overallStatus ?? 'n/a'}, modified=${modReport?.overallStatus ?? 'n/a'}.`,
    expectationMet: detected,
    primaryOutcome: null,
    witnessOutcome: { recordUnchanged: untouched, witnessSequence: live.event?.witnessSequence ?? null, eventHash: live.event?.eventHash ?? null },
    mlResult: null,
    alertIds: [],
    securityEventIds: { primary: [], witness: [] },
    verificationEvidence: {
      targetMessageId: target.messageId,
      targetWitnessSequence: ev.witnessSequence,
      checkpointSequence: covering.checkpointSequence,
      trustedFingerprint: trust.fingerprint,
      trustedFingerprintSource: trust.source,
      originalExport: { path: originalPath, sha256: originalHashBefore, verdict: origReport?.overallStatus ?? null },
      modifiedExport: { path: modifiedPath, verdict: modReport?.overallStatus ?? null },
      failureReason: hit ? { type: hit.type, reason: hit.reason, expected: hit.expected ?? null, actual: hit.actual ?? null } : null,
      notCheckpointAnchored: notAnchored,
      witnessDatabaseUntouched: untouched,
    },
  };
}
