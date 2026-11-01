import crypto from 'node:crypto';
import type { Pool } from 'pg';
import type { ApiEnvironment } from '../env.js';
import {
  MlAssessmentRepository,
  type MlAssessmentJobRow,
} from '../repositories/ml-assessment.repository.js';
import { AuditRepository } from '../repositories/audit.repository.js';
import { MlClient, MlClientError } from './ml-client.js';

export interface ProcessCycleSummary {
  jobsClaimed: number;
  completed: number;
  insufficientContext: number;
  retried: number;
  failed: number;
}

export class MlAssessmentService {
  private readonly mlRepo: MlAssessmentRepository;
  private readonly auditRepo: AuditRepository;
  private readonly mlClient: MlClient;
  private readonly contextWaitDeadlineSec: number;
  private workerTimer: NodeJS.Timeout | null = null;
  private isCycleRunning: boolean = false;

  constructor(
    private readonly pool: Pool,
    private readonly env: ApiEnvironment,
    customMlClient?: MlClient,
    customContextWaitDeadlineSec?: number
  ) {
    this.mlRepo = new MlAssessmentRepository(pool);
    this.auditRepo = new AuditRepository(pool);
    this.contextWaitDeadlineSec =
      customContextWaitDeadlineSec ?? env.ML_CONTEXT_WAIT_DEADLINE_SECONDS ?? 60;
    this.mlClient =
      customMlClient ||
      new MlClient({
        baseUrl: env.ML_BASE_URL,
        timeoutMs: env.ML_TIMEOUT_MS,
        serviceToken: env.ML_SERVICE_TOKEN,
      });
  }

  getMlClient(): MlClient {
    return this.mlClient;
  }

  getAssessmentRepo(): MlAssessmentRepository {
    return this.mlRepo;
  }

  /**
   * Health check for ML connectivity.
   */
  async checkHealth(): Promise<{
    enabled: boolean;
    baseUrl: string;
    reachable: boolean;
    ready?: boolean | undefined;
    modelVersion?: string | undefined;
    error?: string | undefined;
  }> {
    if (!this.env.ML_ENABLED) {
      return {
        enabled: false,
        baseUrl: this.env.ML_BASE_URL,
        reachable: false,
        error: 'ML service integration is disabled (ML_ENABLED=false)',
      };
    }

    const health = await this.mlClient.healthCheck();
    return {
      enabled: true,
      baseUrl: this.env.ML_BASE_URL,
      ...health,
    };
  }

  /**
   * Computes an operational severity level based on model status and residual ratio.
   */
  private determineSeverity(
    status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR',
    anomalyType: string | null,
    residual: number | null,
    threshold: number | null
  ): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (status === 'CONSISTENT' || status === 'NOT_EVALUATED') {
      return 'NONE';
    }
    if (status === 'ERROR') {
      return 'LOW';
    }

    // SUSPICIOUS cases
    if (anomalyType === 'FLATLINE') {
      return 'CRITICAL';
    }

    if (residual !== null && threshold !== null && threshold > 0) {
      const ratio = residual / threshold;
      if (ratio >= 3.0) return 'CRITICAL';
      if (ratio >= 2.0) return 'HIGH';
      if (ratio >= 1.0) return 'MEDIUM';
    }

    return 'LOW';
  }

  /**
   * Processes a single assessment job.
   */
  async processJob(
    job: MlAssessmentJobRow
  ): Promise<{ status: 'COMPLETED' | 'INSUFFICIENT_CONTEXT' | 'RETRIED' | 'FAILED' }> {
    // 1. Fetch reading details
    const reading = await this.mlRepo.getTelemetryReading(job.reading_id);
    if (!reading) {
      await this.mlRepo.failJob(job.id, 'Associated telemetry reading not found', false);
      return { status: 'FAILED' };
    }

    // Validate reading is COD and cryptographically verified
    if (reading.parameter !== 'COD' || reading.signature_status !== 'VALID') {
      await this.mlRepo.failJob(
        job.id,
        `Reading is not verified COD (param: ${reading.parameter}, sig: ${reading.signature_status})`,
        false
      );
      return { status: 'FAILED' };
    }

    // 2. Find matching verified operational context
    // Enforces: interval_start <= measured_at AND interval not older than 900s
    const context = await this.mlRepo.findMatchingOpsContext(
      reading.site_id,
      reading.measured_at,
      900,
      30
    );

    if (!context) {
      // 2a. Check if we are still within the context arrival wait deadline
      const jobCreatedAtMs = new Date(job.created_at).getTime();
      const elapsedSec = (Date.now() - jobCreatedAtMs) / 1000;
      const waitDeadlineSec = this.contextWaitDeadlineSec;

      if (elapsedSec < waitDeadlineSec) {
        // Still awaiting context arrival! Keep job PENDING and schedule retry
        const retryDelaySec = Math.min(2, Math.max(1, Math.ceil(waitDeadlineSec - elapsedSec)));
        await this.mlRepo.rescheduleJobWaitingForContext(
          job.id,
          `WAITING_FOR_CONTEXT: Operational context for measurement time (${reading.measured_at.toISOString()}) has not yet arrived (awaiting within ${waitDeadlineSec}s deadline)`,
          retryDelaySec
        );
        return { status: 'RETRIED' };
      }

      // 2b. Context wait deadline has expired: finalize as INSUFFICIENT_CONTEXT
      const evaluatedAt = new Date();
      await this.mlRepo.saveAssessmentResult({
        readingId: reading.id,
        siteId: reading.site_id,
        contextId: null,
        modelVersion: 'rules-engine-v1',
        status: 'NOT_EVALUATED',
        anomalyType: null,
        actualValue: Number(reading.value_numeric),
        predictedValue: null,
        residual: null,
        threshold: null,
        severity: 'NONE',
        reasons: [
          `INSUFFICIENT_CONTEXT: Operational context did not arrive within the ${waitDeadlineSec}s deadline for measurement time ${reading.measured_at.toISOString()}`,
        ],
        processingStatus: 'INSUFFICIENT_CONTEXT',
        evaluatedAt,
      });

      // Append primary audit event
      const auditClient = await this.pool.connect();
      try {
        await this.auditRepo.appendStationEvent(
          {
            stationId: reading.station_id,
            eventType: 'ML_ASSESSMENT_EVALUATED',
            entityId: reading.sensor_code,
            messageId: reading.message_id,
            payloadHash: crypto.createHash('sha256').update(reading.id).digest('hex'),
            eventPayload: {
              readingId: reading.id,
              siteCode: reading.site_code,
              status: 'NOT_EVALUATED',
              reason: 'INSUFFICIENT_CONTEXT',
              waitDeadlineSec,
              evaluatedAt: evaluatedAt.toISOString(),
            },
          },
          auditClient
        );
      } finally {
        auditClient.release();
      }

      await this.mlRepo.completeJob(job.id, 'INSUFFICIENT_CONTEXT');
      return { status: 'INSUFFICIENT_CONTEXT' };
    }

    // 3. Fetch recent COD readings for behaviour rules
    const recentCodReadings = await this.mlRepo.getRecentCodReadings(
      reading.sensor_id,
      reading.measured_at,
      50
    );

    // 4. Submit to ML FastAPI service
    try {
      const mlResult = await this.mlClient.analyzeCod({
        readingId: reading.message_id,
        siteId: reading.site_code,
        stationId: reading.station_code,
        sensorId: reading.sensor_code,
        actualCod: Number(reading.value_numeric),
        measuredAt: reading.measured_at.toISOString(),
        contextVerified: true,
        context: {
          productionRate: Number(context.production_rate),
          wastewaterFlow: Number(context.wastewater_flow),
          treatmentDose: Number(context.treatment_dose),
          energyConsumption: Number(context.energy_consumption),
          operatingMode: context.operating_mode,
        },
        recentCodReadings,
      });

      // 5. Compute severity
      const severity = this.determineSeverity(
        mlResult.status,
        mlResult.anomalyType,
        mlResult.absoluteResidual,
        mlResult.residualThreshold
      );

      const evaluatedAt = new Date(mlResult.evaluatedAt);

      // 6. Save derived assessment result
      await this.mlRepo.saveAssessmentResult({
        readingId: reading.id,
        siteId: reading.site_id,
        contextId: context.id,
        modelVersion: mlResult.modelVersion,
        status: mlResult.status,
        anomalyType: mlResult.anomalyType,
        actualValue: Number(reading.value_numeric),
        predictedValue: mlResult.predictedCod,
        residual: mlResult.absoluteResidual,
        threshold: mlResult.residualThreshold,
        severity,
        reasons: mlResult.reasons,
        processingStatus: 'COMPLETED',
        evaluatedAt,
        anomalyScore: mlResult.rawModelOutput?.anomalyScore ?? null,
        anomalyThreshold: mlResult.rawModelOutput?.anomalyThreshold ?? null,
        isAnomaly: mlResult.rawModelOutput?.isAnomaly ?? null,
        detectionSources: mlResult.rawModelOutput?.detectionSources ?? null,
      });

      // 7. Append primary audit event
      const auditClient = await this.pool.connect();
      try {
        await this.auditRepo.appendStationEvent(
          {
            stationId: reading.station_id,
            eventType: 'ML_ASSESSMENT_EVALUATED',
            entityId: reading.sensor_code,
            messageId: reading.message_id,
            payloadHash: crypto
              .createHash('sha256')
              .update(JSON.stringify({ readingId: reading.id, mlResult }))
              .digest('hex'),
            eventPayload: {
              readingId: reading.id,
              siteCode: reading.site_code,
              status: mlResult.status,
              anomalyType: mlResult.anomalyType,
              actualCod: Number(reading.value_numeric),
              predictedCod: mlResult.predictedCod,
              residual: mlResult.absoluteResidual,
              threshold: mlResult.residualThreshold,
              modelVersion: mlResult.modelVersion,
              contextId: context.id,
              evaluatedAt: evaluatedAt.toISOString(),
            },
          },
          auditClient
        );
      } finally {
        auditClient.release();
      }

      // 8. Mark job completed
      await this.mlRepo.completeJob(job.id, 'COMPLETED');
      return { status: 'COMPLETED' };
    } catch (err) {
      const errorMsg = (err as Error).message;
      const isClientError = err instanceof MlClientError && err.code === 'ML_INVALID_REQUEST';

      if (isClientError || job.attempts >= job.max_attempts) {
        // Permanent failure
        await this.mlRepo.failJob(job.id, errorMsg, false);

        // Record a FAILED assessment so it is visible as FAILED rather than missing
        await this.mlRepo.saveAssessmentResult({
          readingId: reading.id,
          siteId: reading.site_id,
          contextId: context.id,
          modelVersion: 'unavailable',
          status: 'ERROR',
          anomalyType: null,
          actualValue: Number(reading.value_numeric),
          predictedValue: null,
          residual: null,
          threshold: null,
          severity: 'LOW',
          reasons: [`ML_PROCESSING_FAILED: ${errorMsg}`],
          processingStatus: 'FAILED',
          evaluatedAt: new Date(),
        });

        return { status: 'FAILED' };
      }

      // Transient failure -> retry with exponential backoff
      const backoffSec = Math.min(Math.pow(2, job.attempts), 30);
      await this.mlRepo.failJob(job.id, errorMsg, true, backoffSec);
      return { status: 'RETRIED' };
    }
  }

  /**
   * Runs a single worker processing cycle for pending jobs.
   */
  async runWorkerCycle(batchSize: number = 10, workerId: string = 'worker-1'): Promise<ProcessCycleSummary> {
    if (!this.env.ML_ENABLED) {
      return { jobsClaimed: 0, completed: 0, insufficientContext: 0, retried: 0, failed: 0 };
    }

    const jobs = await this.mlRepo.claimNextJobs(batchSize, workerId);
    const summary: ProcessCycleSummary = {
      jobsClaimed: jobs.length,
      completed: 0,
      insufficientContext: 0,
      retried: 0,
      failed: 0,
    };

    for (const job of jobs) {
      const res = await this.processJob(job);
      if (res.status === 'COMPLETED') summary.completed++;
      else if (res.status === 'INSUFFICIENT_CONTEXT') summary.insufficientContext++;
      else if (res.status === 'RETRIED') summary.retried++;
      else if (res.status === 'FAILED') summary.failed++;
    }

    return summary;
  }

  /**
   * Starts the background job polling worker.
   */
  startWorker(intervalMs: number = 2000, workerId: string = 'background-worker'): void {
    if (this.workerTimer) return;

    this.workerTimer = setInterval(async () => {
      if (this.isCycleRunning) return;
      this.isCycleRunning = true;
      try {
        await this.runWorkerCycle(10, workerId);
      } catch (err) {
        console.error('[ML Worker] Error in cycle:', (err as Error).message);
      } finally {
        this.isCycleRunning = false;
      }
    }, intervalMs);

    // Unref so process can cleanly exit if no other tasks remain
    this.workerTimer.unref();
  }

  /**
   * Stops the background job polling worker.
   */
  stopWorker(): void {
    if (this.workerTimer) {
      clearInterval(this.workerTimer);
      this.workerTimer = null;
    }
  }
}
