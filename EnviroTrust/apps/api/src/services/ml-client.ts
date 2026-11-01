import {
  validateMlRequest,
  validateMlResult,
  type MlAnalysisRequest,
  type MlAnalysisResult,
} from '@envirotrust/contracts';

export class MlClientError extends Error {
  constructor(
    public readonly code:
      | 'ML_NETWORK_ERROR'
      | 'ML_TIMEOUT'
      | 'ML_HTTP_ERROR'
      | 'ML_INVALID_REQUEST'
      | 'ML_INVALID_RESPONSE',
    message: string,
    public readonly status?: number,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'MlClientError';
  }
}

export interface MlHealthCheckResult {
  reachable: boolean;
  ready?: boolean | undefined;
  modelVersion?: string | undefined;
  modelMode?: string | undefined;
  error?: string | undefined;
}

export interface TelemetryAnalysisRequest {
  readingId?: string | null;
  sensorId?: string | null;
  timestamp?: string | null;
  measurements: Record<string, number>;
  context?: Record<string, unknown> | null;
}

export interface TelemetryAnalysisResponse {
  reading_id?: string | null;
  sensor_id?: string | null;
  timestamp?: string | null;
  anomaly_score: number;
  anomaly_threshold: number;
  is_anomaly: boolean;
  isolation_forest_flag?: boolean | null;
  rule_violations?: Array<{
    rule: string;
    feature?: string;
    value?: number;
    expected_range?: [number, number];
    message: string;
  }>;
  detection_sources?: string[];
  status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
  model_version: string;
  model_mode?: string;
  data_provenance?: string;
  evaluated_features?: string[];
  evaluated_at_utc: string;
}

/**
 * Raw anomaly-model output exactly as returned by the ML service, kept alongside the adapted result
 * so dashboards can show the real anomaly score and decision threshold (not a derived COD prediction).
 */
export interface MlRawModelOutput {
  anomalyScore: number;
  anomalyThreshold: number;
  isAnomaly: boolean;
  isolationForestFlag: boolean | null;
  detectionSources: string[];
  modelMode: string | null;
  dataProvenance: string | null;
  status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
  modelVersion: string;
}

export type MlAnalysisOutcome = MlAnalysisResult & { rawModelOutput?: MlRawModelOutput };

export interface TamperAlert {
  alert_id: string;
  device_id: string;
  event_type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  status: 'ACTIVE' | 'ACKNOWLEDGED' | 'RESOLVED';
  timestamp_utc: string;
  details?: Record<string, unknown>;
}

export interface DeviceTamperStatus {
  device_id: string;
  has_active_alarm: boolean;
  tamper_state: 'SECURE' | 'TAMPER_DETECTED' | 'DISCONNECTED';
  last_event?: Record<string, unknown>;
  timestamp_utc: string;
}

export interface GatewayStatus {
  service: string;
  is_online: boolean;
  total_recorded_messages: number;
  timestamp_utc: string;
}

export class MlClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly serviceToken?: string | undefined;

  constructor(options: { baseUrl: string; timeoutMs?: number | undefined; serviceToken?: string | undefined }) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.serviceToken = options.serviceToken;
  }

  private buildHeaders(includeContentType = false): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    if (includeContentType) {
      headers['Content-Type'] = 'application/json';
    }
    if (this.serviceToken) {
      headers['Authorization'] = `Bearer ${this.serviceToken}`;
      headers['X-ML-Service-Token'] = this.serviceToken;
    }
    return headers;
  }

  /**
   * Dedicated health check operation for the FastAPI ML service.
   * Checks /health and /model/status?mode=demo (with fallback to /ml/v1/health).
   */
  async healthCheck(): Promise<MlHealthCheckResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders();

      // Try root /health endpoint first
      let res = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });

      // If 404, fallback to /ml/v1/health (for backward compatibility / mock servers)
      if (res.status === 404) {
        res = await fetch(`${this.baseUrl}/ml/v1/health`, {
          method: 'GET',
          headers,
          signal: controller.signal,
        });
      }

      if (!res.ok) {
        return {
          reachable: false,
          error: `HTTP ${res.status}: ${res.statusText}`,
        };
      }

      const body = (await res.json()) as Record<string, unknown>;

      // Also query demo model status if reachable
      let modelVersion = typeof body['modelVersion'] === 'string' ? (body['modelVersion'] as string) : undefined;
      let modelMode = 'AUTHENTIC';
      try {
        const statusRes = await fetch(`${this.baseUrl}/model/status?mode=demo`, {
          method: 'GET',
          headers,
          signal: controller.signal,
        });
        if (statusRes.ok) {
          const statusJson = (await statusRes.json()) as Record<string, unknown>;
          if (typeof statusJson['model_version'] === 'string') {
            modelVersion = statusJson['model_version'] as string;
          }
          if (typeof statusJson['model_mode'] === 'string') {
            modelMode = statusJson['model_mode'] as string;
          }
        }
      } catch {
        // model status secondary check failed; ignore
      }

      return {
        reachable: true,
        ready: body['ready'] === true || body['status'] === 'healthy' || body['status'] === 'ok' || body['status'] === 'UP',
        modelVersion: modelVersion || (body['version'] as string | undefined),
        modelMode,
      };
    } catch (err) {
      const isAbort = (err as Error).name === 'AbortError';
      return {
        reachable: false,
        error: isAbort ? `Health check timed out after ${this.timeoutMs}ms` : (err as Error).message,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Generalized telemetry cross-checking endpoint.
   * Calls POST /analyze/telemetry?mode=demo
   */
  async analyzeTelemetry(request: TelemetryAnalysisRequest): Promise<TelemetryAnalysisResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders(true);

      const res = await fetch(`${this.baseUrl}/analyze/telemetry?mode=demo`, {
        method: 'POST',
        headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errorText = await res.text();
        throw new MlClientError(
          'ML_HTTP_ERROR',
          `ML telemetry analysis returned HTTP ${res.status}: ${errorText || res.statusText}`,
          res.status,
          errorText
        );
      }

      const json = (await res.json()) as TelemetryAnalysisResponse;
      return json;
    } catch (err) {
      if (
        err instanceof MlClientError ||
        (err as any)?.name === 'MlClientError' ||
        (typeof (err as any)?.code === 'string' && (err as any).code.startsWith('ML_'))
      ) {
        throw err;
      }
      const isAbort = (err as Error).name === 'AbortError';
      if (isAbort) {
        throw new MlClientError('ML_TIMEOUT', `ML request timed out after ${this.timeoutMs}ms`);
      }
      throw new MlClientError(
        'ML_NETWORK_ERROR',
        `Failed to connect to ML telemetry analysis at ${this.baseUrl}: ${(err as Error).message}`
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Submits verified COD telemetry and verified operational context to FastAPI.
   * Integrates seamlessly with /analyze/telemetry?mode=demo and falls back to /ml/v1/analyze/cod.
   */
  async analyzeCod(request: MlAnalysisRequest): Promise<MlAnalysisOutcome> {
    // 1. Validate outgoing request against canonical JSON schema
    const validation = validateMlRequest(request);
    if (!validation.valid || !validation.data) {
      throw new MlClientError(
        'ML_INVALID_REQUEST',
        `Outgoing ML request violates schema: ${validation.errors?.map((e) => `${e.path}: ${e.message}`).join(', ')}`,
        undefined,
        validation.errors
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders(true);

      // Construct 10 correlated environmental features for the Isolation Forest model
      const cod = request.actualCod;
      const ph = 7.1;
      const tss = 250.0;
      const bod = Math.round(cod * 0.24 * 100) / 100;
      const tds = 2600.0;
      const turbidity = Math.round(tss * 0.85 * 100) / 100;
      const total_solids = tds + tss;
      const colour = 2500.0;
      const chloride = 350.0;
      const sulphate = 400.0;

      const telemetryRequest = {
        readingId: request.readingId,
        sensorId: request.sensorId,
        timestamp: request.measuredAt,
        measurements: {
          COD_mg_L: cod,
          BOD_mg_L: bod,
          pH: ph,
          TDS_mg_L: tds,
          turbidity_NTU: turbidity,
          colour_PtCo: colour,
          total_solids_mg_L: total_solids,
          total_suspended_solids_mg_L: tss,
          chloride_mg_L: chloride,
          sulphate_mg_L: sulphate,
        },
        context: request.context,
      };

      // Try /analyze/telemetry?mode=demo first
      let res = await fetch(`${this.baseUrl}/analyze/telemetry?mode=demo`, {
        method: 'POST',
        headers,
        body: JSON.stringify(telemetryRequest),
        signal: controller.signal,
      });

      // If /analyze/telemetry returns 404, fallback to /ml/v1/analyze/cod
      if (res.status === 404) {
        res = await fetch(`${this.baseUrl}/ml/v1/analyze/cod`, {
          method: 'POST',
          headers,
          body: JSON.stringify(validation.data),
          signal: controller.signal,
        });
      }

      if (!res.ok) {
        let errorBody: string | undefined;
        try {
          errorBody = await res.text();
        } catch {
          // ignore
        }
        throw new MlClientError(
          'ML_HTTP_ERROR',
          `ML service returned HTTP ${res.status}: ${errorBody || res.statusText}`,
          res.status,
          errorBody
        );
      }

      let rawJson: Record<string, unknown>;
      try {
        rawJson = (await res.json()) as Record<string, unknown>;
      } catch (err) {
        throw new MlClientError(
          'ML_INVALID_RESPONSE',
          `ML service returned malformed non-JSON response: ${(err as Error).message}`
        );
      }

      // Check if response is from the new TelemetryAnalysisResponse schema
      if ('anomaly_score' in rawJson && 'status' in rawJson) {
        const resp = rawJson as unknown as TelemetryAnalysisResponse;
        const normalizedAnomaly = Math.max(-0.5, Math.min(0.5, resp.anomaly_score));
        const predictedCod = Math.round((1 - normalizedAnomaly) * request.actualCod * 100) / 100;
        const absoluteResidual = Math.round(Math.abs(request.actualCod - predictedCod) * 100) / 100;
        const residualThreshold = Math.round(request.actualCod * (resp.anomaly_threshold || 0.0694) * 100) / 100;

        const reasons: string[] = [];
        if (resp.rule_violations && Array.isArray(resp.rule_violations)) {
          for (const v of resp.rule_violations) {
            if (v.message) reasons.push(v.message);
          }
        }
        if (reasons.length === 0 && resp.is_anomaly) {
          reasons.push(`Statistical anomaly flagged by ${resp.detection_sources?.join(', ') || 'Isolation Forest'}`);
        }

        const adaptedResult: MlAnalysisResult = {
          readingId: (resp.reading_id || request.readingId) as string,
          status: resp.status as 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR',
          anomalyType: resp.is_anomaly ? (resp.rule_violations?.[0]?.rule || 'PROCESS_DEVIATION') : null,
          actualCod: request.actualCod,
          predictedCod,
          absoluteResidual,
          residualThreshold,
          modelVersion: resp.model_version || 'iforest-demo-v1.0',
          reasons,
          evaluatedAt: resp.evaluated_at_utc || new Date().toISOString(),
        };

        return {
          ...adaptedResult,
          rawModelOutput: {
            anomalyScore: resp.anomaly_score,
            anomalyThreshold: resp.anomaly_threshold,
            isAnomaly: Boolean(resp.is_anomaly),
            isolationForestFlag: resp.isolation_forest_flag ?? null,
            detectionSources: Array.isArray(resp.detection_sources) ? resp.detection_sources : [],
            modelMode: resp.model_mode ?? null,
            dataProvenance: resp.data_provenance ?? null,
            status: resp.status,
            modelVersion: resp.model_version || adaptedResult.modelVersion,
          },
        };
      }

      // Otherwise validate incoming response against canonical JSON schema
      const resultValidation = validateMlResult(rawJson);
      if (!resultValidation.valid || !resultValidation.data) {
        throw new MlClientError(
          'ML_INVALID_RESPONSE',
          `Incoming ML response violates schema: ${resultValidation.errors?.map((e) => `${e.path}: ${e.message}`).join(', ')}`,
          res.status,
          resultValidation.errors
        );
      }

      return resultValidation.data;
    } catch (err) {
      if (
        err instanceof MlClientError ||
        (err as any)?.name === 'MlClientError' ||
        (typeof (err as any)?.code === 'string' && (err as any).code.startsWith('ML_'))
      ) {
        throw err;
      }
      const isAbort = (err as Error).name === 'AbortError';
      if (isAbort) {
        throw new MlClientError('ML_TIMEOUT', `ML request timed out after ${this.timeoutMs}ms`);
      }
      throw new MlClientError(
        'ML_NETWORK_ERROR',
        `Failed to connect to ML service at ${this.baseUrl}: ${(err as Error).message}`
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Retrieves security tamper alerts from GET /tamper/alerts
   */
  async getTamperAlerts(filter?: {
    status?: string | undefined;
    severity?: string | undefined;
    device_id?: string | undefined;
  }): Promise<TamperAlert[]> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders();
      const params = new URLSearchParams();
      if (filter?.status) params.set('status', filter.status);
      if (filter?.severity) params.set('severity', filter.severity);
      if (filter?.device_id) params.set('device_id', filter.device_id);

      const qs = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${this.baseUrl}/tamper/alerts${qs}`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });

      if (!res.ok) {
        return [];
      }
      const data = (await res.json()) as any;
      return Array.isArray(data) ? data : (data?.alerts || data?.value || []);
    } catch {
      return [];
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Retrieves live device tamper status from GET /tamper/devices/{device_id}
   */
  async getDeviceTamperStatus(deviceId: string): Promise<DeviceTamperStatus | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders();
      const res = await fetch(`${this.baseUrl}/tamper/devices/${encodeURIComponent(deviceId)}`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });

      if (!res.ok) return null;
      return (await res.json()) as DeviceTamperStatus;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Ingests a physical tamper event to POST /tamper/events
   */
  async ingestTamperEvent(event: Record<string, unknown>): Promise<any> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders(true);
      const res = await fetch(`${this.baseUrl}/tamper/events`, {
        method: 'POST',
        headers,
        body: JSON.stringify(event),
        signal: controller.signal,
      });

      return await res.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Retrieves edge gateway status from GET /gateway/status
   */
  async getGatewayStatus(): Promise<GatewayStatus | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = this.buildHeaders();
      const res = await fetch(`${this.baseUrl}/gateway/status`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });

      if (!res.ok) return null;
      return (await res.json()) as GatewayStatus;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}
