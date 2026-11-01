import type { Pool } from 'pg';
import {
  AlertRepository,
  type AlertRow,
  type AlertSummaryData,
  type AlertFilters,
} from '../repositories/alert.repository.js';
import { SensorAvailabilityService } from './sensor-availability.service.js';

export interface AuthenticatedUserPrincipal {
  id: string;
  email: string;
  role: 'PLATFORM_ADMIN' | 'FACTORY_OPERATOR' | 'REGULATOR_AUDITOR';
  sites: string[];
}

export class AlertService {
  private readonly alertRepo: AlertRepository;
  private readonly availabilityService: SensorAvailabilityService;
  private evaluatorTimer: NodeJS.Timeout | null = null;
  private isEvaluating = false;

  constructor(pool: Pool) {
    this.alertRepo = new AlertRepository(pool);
    this.availabilityService = new SensorAvailabilityService(pool);
  }

  getAlertRepository(): AlertRepository {
    return this.alertRepo;
  }

  /**
   * List alerts with RBAC and site scoping.
   */
  async getAlerts(
    filters: Omit<AlertFilters, 'siteIds'> & { siteId?: string | undefined },
    user: AuthenticatedUserPrincipal
  ): Promise<{ alerts: AlertRow[]; total: number }> {
    let allowedSiteIds: string[] | undefined;

    if (user.role === 'PLATFORM_ADMIN') {
      if (filters.siteId) {
        allowedSiteIds = [filters.siteId];
      }
    } else {
      if (filters.siteId && !user.sites.includes(filters.siteId)) {
        const error = new Error('Forbidden: Site access denied');
        (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_SITE';
        (error as unknown as { code: string; status: number }).status = 403;
        throw error;
      }
      allowedSiteIds = filters.siteId ? [filters.siteId] : user.sites;
    }

    const queryFilters: AlertFilters = {
      siteIds: allowedSiteIds,
      sensorId: filters.sensorId,
      severity: filters.severity,
      status: filters.status,
      alertType: filters.alertType,
      limit: filters.limit,
      offset: filters.offset,
    };

    return this.alertRepo.getAlerts(queryFilters);
  }

  /**
   * Get summary counts with RBAC site scoping.
   */
  async getAlertSummary(user: AuthenticatedUserPrincipal): Promise<AlertSummaryData> {
    const siteIds = user.role === 'PLATFORM_ADMIN' ? undefined : user.sites;
    return this.alertRepo.getAlertSummary(siteIds);
  }

  /**
   * Get alert by ID with RBAC check.
   */
  async getAlertById(alertId: string, user: AuthenticatedUserPrincipal): Promise<AlertRow | null> {
    const alert = await this.alertRepo.getAlertById(alertId);
    if (!alert) return null;

    if (user.role !== 'PLATFORM_ADMIN') {
      const userHasAccess =
        user.sites.includes(alert.site_id) || (alert.site_code && user.sites.includes(alert.site_code));
      if (!userHasAccess) {
        const error = new Error('Forbidden: Site access denied');
        (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_SITE';
        (error as unknown as { code: string; status: number }).status = 403;
        throw error;
      }
    }

    return alert;
  }

  /**
   * Acknowledge an alert with RBAC enforcement.
   */
  async acknowledgeAlert(alertId: string, user: AuthenticatedUserPrincipal): Promise<AlertRow> {
    // 1. Auditor read-only restriction
    if (user.role === 'REGULATOR_AUDITOR') {
      const error = new Error('Forbidden: Auditor accounts have read-only access to alerts and incidents');
      (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_AUDITOR_READONLY';
      (error as unknown as { code: string; status: number }).status = 403;
      throw error;
    }

    // 2. Fetch alert and verify site scope
    const alert = await this.alertRepo.getAlertById(alertId);
    if (!alert) {
      const error = new Error('Alert not found');
      (error as unknown as { code: string; status: number }).code = 'NOT_FOUND';
      (error as unknown as { code: string; status: number }).status = 404;
      throw error;
    }

    if (user.role !== 'PLATFORM_ADMIN') {
      const hasSiteAccess =
        user.sites.includes(alert.site_id) || (alert.site_code && user.sites.includes(alert.site_code));
      if (!hasSiteAccess) {
        const error = new Error('Forbidden: Cannot acknowledge alert for an unassigned site');
        (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_SITE';
        (error as unknown as { code: string; status: number }).status = 403;
        throw error;
      }
    }

    const updated = await this.alertRepo.acknowledgeAlert(alertId, user.id);
    if (!updated) {
      const error = new Error('Alert is already acknowledged or resolved');
      (error as unknown as { code: string; status: number }).code = 'CONFLICT';
      (error as unknown as { code: string; status: number }).status = 409;
      throw error;
    }

    return (await this.alertRepo.getAlertById(alertId)) || updated;
  }

  /**
   * Resolve an alert with required resolution note and RBAC enforcement.
   */
  async resolveAlert(
    alertId: string,
    resolutionNote: string,
    user: AuthenticatedUserPrincipal
  ): Promise<AlertRow> {
    // 1. Auditor read-only restriction
    if (user.role === 'REGULATOR_AUDITOR') {
      const error = new Error('Forbidden: Auditor accounts have read-only access to alerts and incidents');
      (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_AUDITOR_READONLY';
      (error as unknown as { code: string; status: number }).status = 403;
      throw error;
    }

    if (!resolutionNote || resolutionNote.trim().length < 3) {
      const error = new Error('A valid resolution note of at least 3 characters is required');
      (error as unknown as { code: string; status: number }).code = 'INVALID_RESOLUTION_NOTE';
      (error as unknown as { code: string; status: number }).status = 400;
      throw error;
    }

    // 2. Fetch alert and verify site scope
    const alert = await this.alertRepo.getAlertById(alertId);
    if (!alert) {
      const error = new Error('Alert not found');
      (error as unknown as { code: string; status: number }).code = 'NOT_FOUND';
      (error as unknown as { code: string; status: number }).status = 404;
      throw error;
    }

    if (user.role !== 'PLATFORM_ADMIN') {
      const hasSiteAccess =
        user.sites.includes(alert.site_id) || (alert.site_code && user.sites.includes(alert.site_code));
      if (!hasSiteAccess) {
        const error = new Error('Forbidden: Cannot resolve alert for an unassigned site');
        (error as unknown as { code: string; status: number }).code = 'FORBIDDEN_SITE';
        (error as unknown as { code: string; status: number }).status = 403;
        throw error;
      }
    }

    const updated = await this.alertRepo.resolveAlert(alertId, user.id, resolutionNote.trim());
    if (!updated) {
      const error = new Error('Alert is already resolved');
      (error as unknown as { code: string; status: number }).code = 'CONFLICT';
      (error as unknown as { code: string; status: number }).status = 409;
      throw error;
    }

    return (await this.alertRepo.getAlertById(alertId)) || updated;
  }

  /**
   * Evaluate all registered sensors against the availability state machine
   * and synchronize alerts (STALE, OFFLINE, RECOVERED) with strict deduplication.
   */
  async evaluateSensorAvailabilityAndSyncAlerts(): Promise<{
    evaluated: number;
    staleAlertsCreated: number;
    offlineAlertsCreated: number;
    recoveredCount: number;
  }> {
    if (this.isEvaluating) {
      return { evaluated: 0, staleAlertsCreated: 0, offlineAlertsCreated: 0, recoveredCount: 0 };
    }

    this.isEvaluating = true;
    let staleAlertsCreated = 0;
    let offlineAlertsCreated = 0;
    let recoveredCount = 0;

    try {
      const summaries = await this.availabilityService.getAllSensorsAvailability();

      for (const summary of summaries) {
        // Sensors that are not in service (INACTIVE / REVOKED) are not monitored for communication loss.
        if (summary.sensorStatus !== 'ACTIVE') continue;

        const lastHb = summary.lastHeartbeatSentAt || 'none';

        if (summary.currentStatus === 'STALE') {
          // Check if sensor is already marked offline (offline takes precedence over stale)
          const activeOffline = await this.alertRepo.findActiveAlertForSensor(summary.sensorId, 'SENSOR_OFFLINE');
          if (!activeOffline) {
            const activeStale = await this.alertRepo.findActiveAlertForSensor(summary.sensorId, 'SENSOR_STALE');
            if (!activeStale) {
              const dedupKey = `stale:${summary.sensorId}:${lastHb}`;
              await this.alertRepo.createAlert({
                siteId: summary.siteId,
                sensorId: summary.sensorId,
                stationId: summary.stationId,
                alertType: 'SENSOR_STALE',
                severity: 'WARNING',
                title: 'SENSOR COMMUNICATION STALE',
                description: `Sensor ${summary.sensorCode} (${summary.parameter}) at station ${summary.stationCode} has missed ${summary.missedIntervals} heartbeat interval(s).`,
                detectionSource: 'AVAILABILITY_ENGINE',
                status: 'OPEN',
                recommendedAction:
                  'Check network connectivity, gateway status, and sensor power supply. Verify sensor heartbeat service is transmitting.',
                deduplicationKey: dedupKey,
                metadata: {
                  sensorCode: summary.sensorCode,
                  stationCode: summary.stationCode,
                  missedIntervals: summary.missedIntervals,
                  lastHeartbeatReceivedAt: summary.lastHeartbeatReceivedAt,
                  lastHeartbeatSequence: summary.lastHeartbeatSequence,
                },
              });
              staleAlertsCreated++;
            }
          }
        } else if (summary.currentStatus === 'OFFLINE') {
          // Auto-resolve any existing STALE alert since OFFLINE supersedes it
          await this.alertRepo.resolveActiveAlertsForSensor(
            summary.sensorId,
            ['SENSOR_STALE'],
            'Transitioned from STALE to OFFLINE'
          );

          // Check if already has active OFFLINE alert
          const activeOffline = await this.alertRepo.findActiveAlertForSensor(summary.sensorId, 'SENSOR_OFFLINE');
          if (!activeOffline) {
            const dedupKey = `offline:${summary.sensorId}:${lastHb}`;
            await this.alertRepo.createAlert({
              siteId: summary.siteId,
              sensorId: summary.sensorId,
              stationId: summary.stationId,
              alertType: 'SENSOR_OFFLINE',
              severity: 'HIGH',
              title: 'SENSOR OFFLINE - COMMUNICATION LOST',
              description: `Sensor ${summary.sensorCode} (${summary.parameter}) at station ${summary.stationCode} is offline (${summary.missedIntervals} missed intervals). Operational distinction: Communication loss does not imply physical tampering.`,
              detectionSource: 'AVAILABILITY_ENGINE',
              status: 'OPEN',
              recommendedAction:
                'Check power supply, inspect local network/gateway connections, and initiate physical equipment check if communication does not recover.',
              deduplicationKey: dedupKey,
              metadata: {
                sensorCode: summary.sensorCode,
                stationCode: summary.stationCode,
                missedIntervals: summary.missedIntervals,
                lastHeartbeatReceivedAt: summary.lastHeartbeatReceivedAt,
                lastHeartbeatSequence: summary.lastHeartbeatSequence,
              },
            });
            offlineAlertsCreated++;
          }
        } else if (summary.currentStatus === 'ONLINE') {
          // Fresh heartbeat recovery: check if there are active STALE or OFFLINE alerts
          const resolved = await this.alertRepo.resolveActiveAlertsForSensor(
            summary.sensorId,
            ['SENSOR_STALE', 'SENSOR_OFFLINE'],
            `Sensor communication recovered via verified heartbeat sequence ${summary.lastHeartbeatSequence || 1}.`
          );

          if (resolved.length > 0) {
            // Record SENSOR_RECOVERED event/alert
            // Keyed to the incident(s) this recovery resolves: heartbeat sequences restart after a reboot,
            // so a sequence-based key would collapse a new recovery into an old one.
            const dedupKey = `recovered:${summary.sensorId}:${resolved.map((r) => r.id).sort().join('+')}`;
            await this.alertRepo.createAlert({
              siteId: summary.siteId,
              sensorId: summary.sensorId,
              stationId: summary.stationId,
              alertType: 'SENSOR_RECOVERED',
              severity: 'INFO',
              title: 'SENSOR COMMUNICATION RECOVERED',
              description: `Sensor ${summary.sensorCode} (${summary.parameter}) at station ${summary.stationCode} has restored active communication (sequence ${summary.lastHeartbeatSequence}).`,
              detectionSource: 'AVAILABILITY_ENGINE',
              status: 'RESOLVED',
              recommendedAction: 'Verify normal operational parameters in the telemetry dashboard.',
              deduplicationKey: dedupKey,
              metadata: {
                sensorCode: summary.sensorCode,
                stationCode: summary.stationCode,
                recoveredSequence: summary.lastHeartbeatSequence,
                recoveredAt: summary.lastHeartbeatReceivedAt,
                priorIncidentsResolved: resolved.map((r) => r.id),
              },
            });
            recoveredCount++;
          }
        }
      }

      return {
        evaluated: summaries.length,
        staleAlertsCreated,
        offlineAlertsCreated,
        recoveredCount,
      };
    } finally {
      this.isEvaluating = false;
    }
  }

  /**
   * Start durable periodic background evaluator.
   */
  startEvaluator(intervalMs = 5000): void {
    if (this.evaluatorTimer) return;
    this.evaluatorTimer = setInterval(() => {
      this.evaluateSensorAvailabilityAndSyncAlerts().catch((err) => {
        console.error('[AlertService] Error during background availability evaluation:', (err as Error).message);
      });
    }, intervalMs);
    // Unref so it does not block process exit
    if (this.evaluatorTimer && typeof this.evaluatorTimer.unref === 'function') {
      this.evaluatorTimer.unref();
    }
  }

  /**
   * Stop background evaluator.
   */
  stopEvaluator(): void {
    if (this.evaluatorTimer) {
      clearInterval(this.evaluatorTimer);
      this.evaluatorTimer = null;
    }
  }
}
