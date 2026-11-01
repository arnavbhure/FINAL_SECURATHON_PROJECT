import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import type { WitnessIngestionService } from '../services/witness-ingestion.service.js';
import { loadWitnessEnvironment, type WitnessEnvironment } from '../env.js';
import {
  computeWitnessEventHash,
  WITNESS_GENESIS_HASH,
  type WitnessEventDataWithoutHash,
} from '../repositories/witness-event.repository.js';
import {
  authenticateWitnessAccess,
  witnessVerificationRateLimiter,
  validateReconciliationInput,
} from '../middleware/witness-auth.middleware.js';

export function createWitnessRoutes(
  ingestionService: WitnessIngestionService,
  customEnv?: WitnessEnvironment
): Router {
  const router = Router();
  const env = customEnv || loadWitnessEnvironment();
  const eventRepo = ingestionService.getEventRepository();

  // Helper to extract witness ingestion token
  function extractWitnessToken(req: Request): string | undefined {
    const customHeader = req.headers['x-witness-token'];
    if (typeof customHeader === 'string') return customHeader;
    const authHeader = req.headers['authorization'];
    if (typeof authHeader === 'string') return authHeader;
    return undefined;
  }

  // =========================================================================
  // Machine Ingestion Routes (Authenticated via Ed25519 signatures & witness service token)
  // Human JWT authentication is NOT required.
  // =========================================================================

  // 1. Ingestion: Telemetry readings
  router.post('/ingestion/readings', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestTelemetry(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  // Alias for telemetry readings ingestion
  router.post('/ingestion/telemetry', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestTelemetry(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  // 2. Ingestion: Operations context
  router.post('/ingestion/operations-context', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestOpsContext(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  // 3. Ingestion: Signed heartbeats
  router.post('/ingestion/heartbeats', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestHeartbeat(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  // 4. Ingestion: Signed physical tamper events
  router.post('/tamper/events', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestTamper(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  router.post('/ingestion/tamper', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestTamper(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  router.post('/ingestion/tamper/events', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    const token = extractWitnessToken(req);
    const result = await ingestionService.ingestTamper(req.body, token, requestId);
    res.status(result.status).json(result.body);
  });

  // =========================================================================
  // Protected Read & Verification Routes (Require Authentication & Site-Scoped Authorization)
  // =========================================================================

  // 4. Read: Latest checkpoint for station (Protected)
  router.get(
    '/checkpoints/:stationId/latest',
    authenticateWitnessAccess(env),
    async (req: Request, res: Response) => {
      const stationId = typeof req.params['stationId'] === 'string' ? req.params['stationId'] : undefined;
      if (!stationId) {
        res.status(400).json({ success: false, code: 'BAD_REQUEST', message: 'stationId is required' });
        return;
      }

      try {
        const checkpoint = await eventRepo.getLatestCheckpoint(stationId);
        if (!checkpoint) {
          res.status(404).json({
            success: false,
            code: 'NOT_FOUND',
            message: `No checkpoint found for station ${stationId}`,
          });
          return;
        }

        // Enforce site-scoped authorization for human users
        const principal = req.witnessPrincipal;
        if (principal && principal.role !== 'PLATFORM_ADMIN') {
          if (!principal.sites.includes(checkpoint.siteCode)) {
            res.status(403).json({
              success: false,
              code: 'FORBIDDEN_SITE_ACCESS',
              message: `Access denied: witness records for station '${stationId}' belong to site '${checkpoint.siteCode}', not authorized site`,
            });
            return;
          }
        }

        res.status(200).json({
          success: true,
          checkpoint: {
            id: checkpoint.id,
            payload: JSON.parse(checkpoint.canonicalPayload),
            witnessId: checkpoint.witnessId,
            witnessKeyId: checkpoint.witnessKeyId,
            siteId: checkpoint.siteCode,
            stationId: checkpoint.stationCode,
            checkpointSequence: checkpoint.checkpointSequence,
            lastWitnessSequence: checkpoint.lastWitnessSequence,
            chainHeadHash: checkpoint.chainHeadHash,
            previousCheckpointHash: checkpoint.previousCheckpointHash,
            createdAt: checkpoint.createdAt.toISOString(),
            canonicalPayload: checkpoint.canonicalPayload,
            signature: checkpoint.signatureBase64,
            checkpointHash: checkpoint.checkpointHash,
            witnessPublicKeyFingerprint: checkpoint.witnessPublicKeyFingerprint,
          },
        });
      } catch (err: any) {
        res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: err.message });
      }
    }
  );

  // 5. Read: Witness event by messageId (Protected)
  router.get(
    '/events/:messageId',
    authenticateWitnessAccess(env),
    async (req: Request, res: Response) => {
      const messageId = typeof req.params['messageId'] === 'string' ? req.params['messageId'] : undefined;
      if (!messageId) {
        res.status(400).json({ success: false, code: 'BAD_REQUEST', message: 'messageId is required' });
        return;
      }

      try {
        const event = await eventRepo.getEventByMessageId(messageId);
        if (!event) {
          res.status(404).json({
            success: false,
            code: 'NOT_FOUND',
            message: `Witness event with messageId ${messageId} not found`,
          });
          return;
        }

        // Enforce site-scoped authorization for human users
        const principal = req.witnessPrincipal;
        if (principal && principal.role !== 'PLATFORM_ADMIN') {
          if (!principal.sites.includes(event.siteCode)) {
            res.status(403).json({
              success: false,
              code: 'FORBIDDEN_SITE_ACCESS',
              message: `Access denied: witness event belongs to site '${event.siteCode}', not authorized site`,
            });
            return;
          }
        }

        res.status(200).json({
          success: true,
          event: {
            id: event.id,
            witnessSequence: event.witnessSequence,
            eventType: event.eventType,
            messageId: event.messageId,
            siteCode: event.siteCode,
            stationCode: event.stationCode,
            identityType: event.identityType,
            identityCode: event.identityCode,
            keyId: event.keyId,
            bootId: event.bootId,
            sourceSequence: event.sourceSequence,
            sourceTimestamp: event.sourceTimestamp.toISOString(),
            payload: event.payload,
            signature: event.signatureBase64,
            payloadHash: event.payloadHash,
            signatureHash: event.signatureHash,
            witnessReceivedAt: event.witnessReceivedAt.toISOString(),
            previousHash: event.previousHash,
            eventHash: event.eventHash,
          },
        });
      } catch (err: any) {
        res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: err.message });
      }
    }
  );

  // 6. Verification: Independent chain recomputation & audit (Protected & Rate-limited)
  router.post(
    '/verify/chain',
    authenticateWitnessAccess(env),
    witnessVerificationRateLimiter(60, 60000),
    async (req: Request, res: Response) => {
      const { stationId, fromSequence = 1, toSequence } = req.body || {};
      if (!stationId || typeof stationId !== 'string') {
        res.status(400).json({ success: false, code: 'BAD_REQUEST', message: 'stationId string is required' });
        return;
      }

      try {
        // Enforce site authorization if station checkpoint exists
        const principal = req.witnessPrincipal;
        if (principal && principal.role !== 'PLATFORM_ADMIN') {
          const cp = await eventRepo.getLatestCheckpoint(stationId);
          if (cp && !principal.sites.includes(cp.siteCode)) {
            res.status(403).json({
              success: false,
              code: 'FORBIDDEN_SITE_ACCESS',
              message: `Access denied: station '${stationId}' belongs to site '${cp.siteCode}', not authorized site`,
            });
            return;
          }
        }

        const events = await eventRepo.getEventsForStation(stationId, fromSequence, toSequence);
        if (events.length === 0) {
          res.status(200).json({
            valid: true,
            stationId,
            eventCount: 0,
            headSequence: 0,
            headHash: WITNESS_GENESIS_HASH,
            discrepancies: [],
          });
          return;
        }

        const discrepancies: Array<{
          sequence: number;
          messageId: string;
          expectedHash: string;
          actualHash: string;
          reason: string;
        }> = [];

        let runningPrevHash = WITNESS_GENESIS_HASH;

        // If starting from seq > 1, lookup previous event to get runningPrevHash
        if (fromSequence > 1) {
          const prevRes = await eventRepo.getEventsForStation(stationId, fromSequence - 1, fromSequence - 1);
          if (prevRes.length > 0 && prevRes[0]) {
            runningPrevHash = prevRes[0].eventHash;
          } else {
            discrepancies.push({
              sequence: fromSequence,
              messageId: events[0]?.messageId || 'unknown',
              expectedHash: '',
              actualHash: events[0]?.previousHash || '',
              reason: `Missing predecessor event at sequence ${fromSequence - 1}`,
            });
          }
        }

        for (let i = 0; i < events.length; i++) {
          const event = events[i];
          if (!event) continue;

          // Sequence continuity check
          const expectedSeq = fromSequence + i;
          if (event.witnessSequence !== expectedSeq) {
            discrepancies.push({
              sequence: event.witnessSequence,
              messageId: event.messageId,
              expectedHash: '',
              actualHash: '',
              reason: `Sequence break: expected ${expectedSeq}, got ${event.witnessSequence}`,
            });
          }

          // Previous hash continuity check
          if (event.previousHash !== runningPrevHash) {
            discrepancies.push({
              sequence: event.witnessSequence,
              messageId: event.messageId,
              expectedHash: runningPrevHash,
              actualHash: event.previousHash,
              reason: `Previous hash mismatch at sequence ${event.witnessSequence}`,
            });
          }

          // Recompute hash
          const eventDataWithoutHash: WitnessEventDataWithoutHash = {
            schemaVersion: 1,
            stationCode: event.stationCode,
            siteCode: event.siteCode,
            witnessSequence: event.witnessSequence,
            eventType: event.eventType,
            identityType: event.identityType,
            identityCode: event.identityCode,
            keyId: event.keyId,
            bootId: event.bootId,
            sourceSequence: event.sourceSequence,
            sourceTimestamp: event.sourceTimestamp.toISOString(),
            messageId: event.messageId,
            payloadHash: event.payloadHash,
            signatureHash: event.signatureHash,
            witnessReceivedAt: event.witnessReceivedAt.toISOString(),
            previousHash: event.previousHash,
          };

          const recomputedHash = computeWitnessEventHash(event.previousHash, eventDataWithoutHash);
          if (recomputedHash !== event.eventHash) {
            discrepancies.push({
              sequence: event.witnessSequence,
              messageId: event.messageId,
              expectedHash: recomputedHash,
              actualHash: event.eventHash,
              reason: `Event hash mismatch at sequence ${event.witnessSequence}`,
            });
          }

          runningPrevHash = event.eventHash;
        }

        const lastEvent = events[events.length - 1];
        res.status(200).json({
          valid: discrepancies.length === 0,
          stationId,
          eventCount: events.length,
          headSequence: lastEvent?.witnessSequence || 0,
          headHash: lastEvent?.eventHash || WITNESS_GENESIS_HASH,
          discrepancies,
        });
      } catch (err: any) {
        res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: err.message });
      }
    }
  );

  // 7. Verification: Cross-check primary record against witness history (Protected, Rate-limited, Anti-SSRF)
  router.post(
    '/verify/primary-record',
    authenticateWitnessAccess(env),
    witnessVerificationRateLimiter(60, 60000),
    validateReconciliationInput,
    async (req: Request, res: Response) => {
      const { messageId, payloadHash, signature } = req.body || {};

      try {
        const event = await eventRepo.getEventByMessageId(messageId);
        if (!event) {
          res.status(200).json({
            status: 'MISSING_FROM_WITNESS',
            messageId,
            witnessObserved: false,
            reason: 'Message ID was never independently received by witness.',
          });
          return;
        }

        // Enforce site authorization if caller is site-scoped
        const principal = req.witnessPrincipal;
        if (principal && principal.role !== 'PLATFORM_ADMIN') {
          if (!principal.sites.includes(event.siteCode)) {
            res.status(403).json({
              success: false,
              code: 'FORBIDDEN_SITE_ACCESS',
              message: `Access denied: record belongs to site '${event.siteCode}', not authorized site`,
            });
            return;
          }
        }

        if (event.payloadHash !== payloadHash.toLowerCase()) {
          res.status(200).json({
            status: 'PAYLOAD_MISMATCH',
            messageId,
            witnessObserved: true,
            witnessPayloadHash: event.payloadHash,
            primaryPayloadHash: payloadHash,
            reason: 'Payload hash in primary does not match witness record.',
          });
          return;
        }

        if (event.signatureBase64 !== signature) {
          res.status(200).json({
            status: 'SIGNATURE_MISMATCH',
            messageId,
            witnessObserved: true,
            reason: 'Digital signature in primary does not match witness record.',
          });
          return;
        }

        res.status(200).json({
          status: 'MATCHED',
          messageId,
          witnessObserved: true,
          witnessSequence: event.witnessSequence,
          witnessReceivedAt: event.witnessReceivedAt.toISOString(),
          eventHash: event.eventHash,
        });
      } catch (err: any) {
        res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: err.message });
      }
    }
  );

  return router;
}
