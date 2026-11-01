import type {
  User,
  Site,
  SensorHealth,
  HeartbeatRecord,
  TelemetryReading,
  AnomalyAssessment,
  CodSeriesPoint,
  MlHealth,
  WitnessCheckpoint,
  SecurityEvent,
  AuditEvent,
  ChainVerificationResult,
  RecordVerificationResult,
  TamperAlert,
  GatewayStatus,
  Alert,
  AlertSummary,
  AttackLabStatus,
  AttackScenario,
  AttackRun,
} from '../types/index.js';

const metaEnv = (typeof import.meta !== 'undefined' && (import.meta as any).env) || {};
const processEnv = (typeof process !== 'undefined' && process.env) || {};

const isLocalhost =
  typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

const API_BASE =
  metaEnv.VITE_API_BASE_URL ||
  processEnv.VITE_API_BASE_URL ||
  '/api/v1';

const WITNESS_BASE =
  metaEnv.VITE_WITNESS_BASE_URL ||
  processEnv.VITE_WITNESS_BASE_URL ||
  '/api/v1/witness';

class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

class ApiClient {
  private token: string | null = null;
  private onUnauthorizedCallback?: () => void;

  constructor() {
    if (typeof document !== 'undefined') {
      this.token = this.getCookie('envirotrust_jwt') || localStorage.getItem('envirotrust_jwt');
    }
  }

  private getCookie(name: string): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]!) : null;
  }

  private setCookie(name: string, value: string, maxAgeSeconds: number = 86400) {
    if (typeof document === 'undefined') return;
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax`;
  }

  private clearCookie(name: string) {
    if (typeof document === 'undefined') return;
    document.cookie = `${name}=; path=/; max-age=0; SameSite=Lax`;
  }

  setToken(token: string | null) {
    this.token = token;
    if (token) {
      this.setCookie('envirotrust_jwt', token, 86400);
      try {
        localStorage.setItem('envirotrust_jwt', token);
      } catch {}
    } else {
      this.clearCookie('envirotrust_jwt');
      try {
        localStorage.removeItem('envirotrust_jwt');
      } catch {}
    }
  }

  getToken(): string | null {
    if (!this.token && typeof document !== 'undefined') {
      this.token = this.getCookie('envirotrust_jwt') || localStorage.getItem('envirotrust_jwt');
    }
    return this.token;
  }

  onUnauthorized(cb: () => void) {
    this.onUnauthorizedCallback = cb;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    baseUrl: string = API_BASE,
    isRetry = false
  ): Promise<T> {
    const url = `${baseUrl}${endpoint}`;
    const headers = new Headers(options.headers || {});

    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const currentToken = this.getToken();
    if (currentToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${currentToken}`);
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include', // Includes HttpOnly cookies (refresh token)
      });

      // Handle session expiration and automatic refresh
      if (response.status === 401 && !isRetry && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/refresh')) {
        const refreshed = await this.refreshToken(baseUrl);
        if (refreshed) {
          return this.request<T>(endpoint, options, baseUrl, true);
        } else {
          if (this.onUnauthorizedCallback) {
            this.onUnauthorizedCallback();
          }
        }
      }

      if (!response.ok) {
        let errJson: any;
        try {
          errJson = await response.json();
        } catch {
          errJson = { message: response.statusText, code: 'HTTP_ERROR' };
        }
        throw new ApiError(
          response.status,
          errJson.code || 'REQUEST_FAILED',
          errJson.message || `Request failed with status ${response.status}`,
          errJson
        );
      }

      // Check if 204 No Content
      if (response.status === 204) {
        return {} as T;
      }

      return (await response.json()) as T;
    } catch (err: any) {
      if (err instanceof ApiError) throw err;
      throw new ApiError(0, 'NETWORK_ERROR', err.message || 'Network request failed');
    }
  }

  // Token refresh logic - refreshes against Primary API with CSRF protection
  private async refreshToken(baseUrl: string = API_BASE): Promise<boolean> {
    try {
      const targetBase = baseUrl.includes('/witness') ? API_BASE : baseUrl;
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const csrfToken = this.getCookie('envirotrust_csrf');
      if (csrfToken) {
        headers['x-csrf-token'] = csrfToken;
      }

      const res = await fetch(`${targetBase}/auth/refresh`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });
      if (!res.ok) {
        this.setToken(null);
        return false;
      }
      const data = (await res.json()) as { accessToken: string };
      this.setToken(data.accessToken);
      return true;
    } catch {
      this.setToken(null);
      return false;
    }
  }

  // ==========================================
  // Authentication Endpoints
  // ==========================================
  async login(email: string, password: string): Promise<{ user: User; accessToken: string }> {
    const data = await this.request<{ success: boolean; user: User; accessToken: string }>(
      '/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }
    );
    this.setToken(data.accessToken);
    return { user: data.user, accessToken: data.accessToken };
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.setToken(null);
    }
  }

  async getMe(): Promise<User> {
    const data = await this.request<{ success: boolean; user: User }>('/auth/me');
    return data.user;
  }

  async refreshSession(): Promise<User | null> {
    // 1. If JWT is already stored in cookie or memory, verify immediately via /auth/me
    const existingToken = this.getToken();
    if (existingToken) {
      try {
        return await this.getMe();
      } catch {
        // Token might have expired, fall through to refresh
      }
    }

    // 2. Perform refresh via HttpOnly cookie & CSRF double-submit
    const refreshed = await this.refreshToken();
    if (!refreshed) return null;
    try {
      return await this.getMe();
    } catch {
      return null;
    }
  }

  // ==========================================
  // Monitoring Read Endpoints
  // ==========================================
  async getSites(): Promise<Site[]> {
    const data = await this.request<{ success: boolean; sites: Site[] }>('/monitoring/sites');
    return data.sites;
  }

  async getOverview(siteId?: string): Promise<{
    siteFilter: string | null;
    metrics: {
      totalReadings: number;
      totalSensors: number;
      recentSecurityEventsCount: number;
      anomalySummary: Record<string, number>;
      latestReadings: Array<{
        id: string;
        parameter: string;
        value: number;
        wireValue: string;
        unit: string;
        sensorId: string;
        siteId: string;
        stationId: string;
        measuredAt: string | null;
        receivedAt: string | null;
        signatureStatus: string;
        protocolStatus: string;
      }>;
    };
  }> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request(`/monitoring/overview${query}`);
  }

  async getReadings(filter: {
    siteId?: string;
    sensorId?: string;
    parameter?: string;
    from?: string;
    to?: string;
    limit?: number;
  }): Promise<{ count: number; readings: TelemetryReading[] }> {
    const params = new URLSearchParams();
    if (filter.siteId) params.set('siteId', filter.siteId);
    if (filter.sensorId) params.set('sensorId', filter.sensorId);
    if (filter.parameter) params.set('parameter', filter.parameter);
    if (filter.from) params.set('from', filter.from);
    if (filter.to) params.set('to', filter.to);
    if (filter.limit) params.set('limit', String(filter.limit));
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request(`/monitoring/readings${query}`);
  }

  async getSecurityEvents(siteId?: string, limit = 50): Promise<SecurityEvent[]> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    params.set('limit', String(limit));
    const data = await this.request<{ success: boolean; events: SecurityEvent[] }>(
      `/monitoring/security-events?${params.toString()}`
    );
    return data.events;
  }

  async getAuditEvents(siteId?: string, limit = 50): Promise<AuditEvent[]> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    params.set('limit', String(limit));
    const data = await this.request<{ success: boolean; events: AuditEvent[] }>(
      `/monitoring/audit-events?${params.toString()}`
    );
    return data.events;
  }

  // ==========================================
  // Sensor Health & Availability
  // ==========================================
  async getAllSensorsHealth(siteId?: string): Promise<SensorHealth[]> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    const query = params.toString() ? `?${params.toString()}` : '';
    const data = await this.request<{ success: boolean; sensors: any[] }>(`/sensors/health${query}`);
    return (data.sensors || []).map((s) => ({
      sensorId: s.sensorId || s.sensor_id,
      sensorCode: s.sensorCode || s.sensor_code || s.sensorId,
      siteId: s.siteId || s.site_id,
      siteCode: s.siteCode || s.site_code,
      stationId: s.stationId || s.station_id,
      stationCode: s.stationCode || s.station_code,
      parameter: s.parameter,
      unit: s.unit || (s.parameter === 'COD' || s.parameter === 'TSS' ? 'mg/L' : s.parameter === 'pH' ? 'pH units' : ''),
      status: s.status || s.currentStatus || 'OFFLINE',
      lastHeartbeatReceivedAt: s.lastHeartbeatReceivedAt || s.last_received_at || null,
      lastHeartbeatSentAt: s.lastHeartbeatSentAt || s.last_sent_at || null,
      missedIntervalsCount: s.missedIntervalsCount ?? s.missedIntervals ?? 0,
      expectedIntervalSeconds: s.expectedIntervalSeconds || 30,
      primaryDeliveryStatus: s.primaryDeliveryStatus || 'ONLINE',
      witnessDeliveryStatus: s.witnessDeliveryStatus || 'CONFIRMED',
      lastKnownSequence: s.lastHeartbeatSequence ?? s.lastKnownSequence ?? null,
      evaluatedAt: s.evaluatedAt || new Date().toISOString(),
    }));
  }

  async getSensorHealth(sensorId: string, siteId?: string): Promise<SensorHealth> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    const query = params.toString() ? `?${params.toString()}` : '';
    const data = await this.request<{ success: boolean; sensor: any }>(`/sensors/${encodeURIComponent(sensorId)}/health${query}`);
    const s = data.sensor;
    return {
      sensorId: s.sensorId || s.sensor_id,
      sensorCode: s.sensorCode || s.sensor_code || s.sensorId,
      siteId: s.siteId || s.site_id,
      siteCode: s.siteCode || s.site_code,
      stationId: s.stationId || s.station_id,
      stationCode: s.stationCode || s.station_code,
      parameter: s.parameter,
      unit: s.unit || (s.parameter === 'COD' || s.parameter === 'TSS' ? 'mg/L' : s.parameter === 'pH' ? 'pH units' : ''),
      status: s.status || s.currentStatus || 'OFFLINE',
      lastHeartbeatReceivedAt: s.lastHeartbeatReceivedAt || s.last_received_at || null,
      lastHeartbeatSentAt: s.lastHeartbeatSentAt || s.last_sent_at || null,
      missedIntervalsCount: s.missedIntervalsCount ?? s.missedIntervals ?? 0,
      expectedIntervalSeconds: s.expectedIntervalSeconds || 30,
      primaryDeliveryStatus: s.primaryDeliveryStatus || 'ONLINE',
      witnessDeliveryStatus: s.witnessDeliveryStatus || 'CONFIRMED',
      lastKnownSequence: s.lastHeartbeatSequence ?? s.lastKnownSequence ?? null,
      evaluatedAt: s.evaluatedAt || new Date().toISOString(),
    };
  }

  async getHeartbeatsHistory(sensorId: string, siteId?: string, limit = 50): Promise<HeartbeatRecord[]> {
    const params = new URLSearchParams();
    params.set('sensorId', sensorId);
    if (siteId) params.set('siteId', siteId);
    params.set('limit', String(limit));
    const data = await this.request<{ success: boolean; count: number; heartbeats: HeartbeatRecord[] }>(
      `/heartbeats/history?${params.toString()}`
    );
    return data.heartbeats;
  }

  // ==========================================
  // ML Assessment Read Endpoints
  // ==========================================
  async getMlHealth(): Promise<MlHealth> {
    return this.request<MlHealth>('/ml/health');
  }

  async getLatestAssessments(siteId?: string, limit = 50): Promise<AnomalyAssessment[]> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    params.set('limit', String(limit));
    const data = await this.request<{ success: boolean; count: number; assessments: any[] }>(
      `/ml/assessments/latest?${params.toString()}`
    );
    return data.assessments.map((a) => ({
      id: a.id,
      readingId: a.reading_id || a.readingId,
      messageId: a.message_id || a.messageId || '',
      sensorId: a.sensor_code || a.sensorId || 'COD-OUT-001',
      siteId: a.site_code || a.siteId || '',
      stationId: a.station_code || a.stationId || '',
      status: a.status,
      anomalyType: a.anomaly_type || a.anomalyType || null,
      actualValue: a.actual_value !== null ? Number(a.actual_value) : null,
      predictedValue: a.predicted_value !== null ? Number(a.predicted_value) : null,
      residual: a.residual !== null ? Number(a.residual) : null,
      threshold: a.threshold !== null ? Number(a.threshold) : null,
      severity: a.severity || 'NONE',
      modelVersion: a.model_version || a.modelVersion || 'rf-cod-v1.0',
      processingStatus: a.processing_status || a.processingStatus || 'COMPLETED',
      reasons: a.reasons || [],
      evaluatedAt: a.evaluated_at || a.evaluatedAt,
      measuredAt: a.measured_at || a.measuredAt,
      contextId: a.context_id || a.contextId,
    }));
  }

  async getSensorAssessments(sensorId: string, siteId?: string, limit = 50): Promise<AnomalyAssessment[]> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    params.set('limit', String(limit));
    const data = await this.request<{ success: boolean; count: number; assessments: any[] }>(
      `/ml/assessments/sensor/${encodeURIComponent(sensorId)}?${params.toString()}`
    );
    return data.assessments.map((a) => ({
      id: a.id,
      readingId: a.reading_id || a.readingId,
      messageId: a.message_id || a.messageId || '',
      sensorId: a.sensor_code || a.sensorId || sensorId,
      siteId: a.site_code || a.siteId || '',
      stationId: a.station_code || a.stationId || '',
      status: a.status,
      anomalyType: a.anomaly_type || a.anomalyType || null,
      actualValue: a.actual_value !== null ? Number(a.actual_value) : null,
      predictedValue: a.predicted_value !== null ? Number(a.predicted_value) : null,
      residual: a.residual !== null ? Number(a.residual) : null,
      threshold: a.threshold !== null ? Number(a.threshold) : null,
      severity: a.severity || 'NONE',
      modelVersion: a.model_version || a.modelVersion || 'rf-cod-v1.0',
      processingStatus: a.processing_status || a.processingStatus || 'COMPLETED',
      reasons: a.reasons || [],
      evaluatedAt: a.evaluated_at || a.evaluatedAt,
      measuredAt: a.measured_at || a.measuredAt,
      contextId: a.context_id || a.contextId,
    }));
  }

  async getCodSeries(
    siteId: string,
    sensorId?: string,
    range: { from?: string; to?: string; limit?: number } = {}
  ): Promise<CodSeriesPoint[]> {
    const params = new URLSearchParams();
    params.set('siteId', siteId);
    if (sensorId) params.set('sensorId', sensorId);
    if (range.from) params.set('from', range.from);
    if (range.to) params.set('to', range.to);
    if (range.limit) params.set('limit', String(range.limit));
    const data = await this.request<{ success: boolean; series: any[] }>(
      `/ml/series/cod?${params.toString()}`
    );
    return data.series.map((s) => ({
      readingId: s.readingId,
      siteId: s.siteId,
      sensorId: s.sensorId,
      modelVersion: s.modelVersion ?? null,
      measuredAt: s.measuredAt,
      actualCod: Number(s.actualCod),
      predictedCod: s.predictedCod !== null ? Number(s.predictedCod) : null,
      residual: s.residual !== null ? Number(s.residual) : null,
      threshold: s.threshold !== null ? Number(s.threshold) : null,
      severity: s.severity,
      status: s.status,
    }));
  }

  async getResidualsSeries(siteId: string, sensorId?: string): Promise<CodSeriesPoint[]> {
    const params = new URLSearchParams();
    params.set('siteId', siteId);
    if (sensorId) params.set('sensorId', sensorId);
    const data = await this.request<{ success: boolean; series: any[] }>(
      `/ml/series/residuals?${params.toString()}`
    );
    return data.series.map((s) => ({
      readingId: s.readingId,
      measuredAt: s.measuredAt,
      actualCod: Number(s.actualCod),
      predictedCod: s.predictedCod !== null ? Number(s.predictedCod) : null,
      residual: s.residual !== null ? Number(s.residual) : null,
      threshold: s.threshold !== null ? Number(s.threshold) : null,
      severity: s.severity,
      status: s.status,
    }));
  }

  async getJobStatusSummary(siteId?: string): Promise<Record<string, number>> {
    const params = new URLSearchParams();
    if (siteId) params.set('siteId', siteId);
    const query = params.toString() ? `?${params.toString()}` : '';
    const data = await this.request<{ success: boolean; summary: Record<string, number> }>(
      `/ml/jobs/status${query}`
    );
    return data.summary;
  }

  async getTamperAlerts(filter?: { status?: string; severity?: string; deviceId?: string }): Promise<TamperAlert[]> {
    const params = new URLSearchParams();
    if (filter?.status) params.set('status', filter.status);
    if (filter?.severity) params.set('severity', filter.severity);
    if (filter?.deviceId) params.set('deviceId', filter.deviceId);
    const qs = params.toString() ? `?${params.toString()}` : '';
    const data = await this.request<{ success: boolean; alerts: TamperAlert[] }>(
      `/ml/tamper/alerts${qs}`
    );
    return data.alerts || [];
  }

  async getGatewayStatus(): Promise<GatewayStatus | null> {
    try {
      const data = await this.request<{ success: boolean; gateway: GatewayStatus }>(
        '/ml/gateway/status'
      );
      return data.gateway || null;
    } catch {
      return null;
    }
  }

  // ==========================================
  // Administrative User Management (Admin Only)
  // ==========================================
  async getUsers(): Promise<User[]> {
    const data = await this.request<{ success: boolean; count: number; users: User[] }>('/admin/users');
    return data.users;
  }

  async createUser(payload: {
    email: string;
    password?: string;
    role: string;
    name?: string;
    sites?: string[];
  }): Promise<{ user: User; temporaryPassword?: string }> {
    return this.request('/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateUserRole(userId: string, role: string): Promise<User> {
    const data = await this.request<{ success: boolean; user: User }>(
      `/admin/users/${encodeURIComponent(userId)}/role`,
      {
        method: 'PATCH',
        body: JSON.stringify({ role }),
      }
    );
    return data.user;
  }

  async updateUserStatus(userId: string, status: 'ACTIVE' | 'DISABLED'): Promise<User> {
    const data = await this.request<{ success: boolean; user: User }>(
      `/admin/users/${encodeURIComponent(userId)}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }
    );
    return data.user;
  }

  async assignSite(userId: string, siteCode: string): Promise<void> {
    await this.request(`/admin/users/${encodeURIComponent(userId)}/sites`, {
      method: 'POST',
      body: JSON.stringify({ siteCode }),
    });
  }

  async removeSite(userId: string, siteId: string): Promise<void> {
    await this.request(`/admin/users/${encodeURIComponent(userId)}/sites/${encodeURIComponent(siteId)}`, {
      method: 'DELETE',
    });
  }

  async getAdminAuditEvents(limit = 50): Promise<any[]> {
    const data = await this.request<{ success: boolean; count: number; events: any[] }>(
      `/admin/audit-events?limit=${limit}`
    );
    return data.events;
  }

  // ==========================================
  // Independent Witness Endpoints
  // ==========================================
  async getLatestWitnessCheckpoint(stationId: string): Promise<WitnessCheckpoint | null> {
    try {
      const data = await this.request<{ success: boolean; checkpoint: WitnessCheckpoint }>(
        `/checkpoints/${encodeURIComponent(stationId)}/latest`,
        {},
        WITNESS_BASE
      );
      return data.checkpoint;
    } catch (err: any) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  async verifyWitnessChain(stationId: string, fromSequence = 1, toSequence?: number): Promise<ChainVerificationResult> {
    return this.request<ChainVerificationResult>(
      '/verify/chain',
      {
        method: 'POST',
        body: JSON.stringify({ stationId, fromSequence, toSequence }),
      },
      WITNESS_BASE
    );
  }

  async verifyWitnessRecord(messageId: string, payloadHash: string, signature: string): Promise<RecordVerificationResult> {
    return this.request<RecordVerificationResult>(
      '/verify/primary-record',
      {
        method: 'POST',
        body: JSON.stringify({ messageId, payloadHash, signature }),
      },
      WITNESS_BASE
    );
  }

  // ==========================================
  // Alert and Incident Management Endpoints
  // ==========================================
  async getAlerts(params: {
    siteId?: string;
    sensorId?: string;
    severity?: string;
    status?: string;
    alertType?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ alerts: Alert[]; total: number }> {
    const q = new URLSearchParams();
    if (params.siteId) q.set('siteId', params.siteId);
    if (params.sensorId) q.set('sensorId', params.sensorId);
    if (params.severity) q.set('severity', params.severity);
    if (params.status) q.set('status', params.status);
    if (params.alertType) q.set('alertType', params.alertType);
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));

    const queryStr = q.toString() ? `?${q.toString()}` : '';
    return this.request<{ success: boolean; alerts: Alert[]; total: number }>(`/alerts${queryStr}`);
  }

  async getAlertSummary(siteId?: string): Promise<AlertSummary> {
    const query = siteId ? `?siteId=${encodeURIComponent(siteId)}` : '';
    const data = await this.request<{ success: boolean; summary: AlertSummary }>(`/alerts/summary${query}`);
    return data.summary;
  }

  async getAlertById(alertId: string): Promise<Alert> {
    const data = await this.request<{ success: boolean; alert: Alert }>(`/alerts/${encodeURIComponent(alertId)}`);
    return data.alert;
  }

  async acknowledgeAlert(alertId: string): Promise<Alert> {
    const data = await this.request<{ success: boolean; message: string; alert: Alert }>(
      `/alerts/${encodeURIComponent(alertId)}/acknowledge`,
      { method: 'PATCH' }
    );
    return data.alert;
  }

  async resolveAlert(alertId: string, resolutionNote: string): Promise<Alert> {
    const data = await this.request<{ success: boolean; message: string; alert: Alert }>(
      `/alerts/${encodeURIComponent(alertId)}/resolve`,
      {
        method: 'PATCH',
        body: JSON.stringify({ resolutionNote }),
      }
    );
    return data.alert;
  }

  // Attack Simulation Lab (demo-only routes; 404 when the lab is disabled on the server)
  async getAttackLabStatus(): Promise<AttackLabStatus> {
    return this.request<AttackLabStatus>('/demo/attack-lab/status');
  }

  async getAttackLabScenarios(): Promise<{ scenarios: AttackScenario[]; canExecute: boolean }> {
    return this.request<{ scenarios: AttackScenario[]; canExecute: boolean }>('/demo/attack-lab/scenarios');
  }

  async runAttackScenario(scenarioId: string, confirm: boolean): Promise<{ runId: string }> {
    return this.request<{ runId: string }>(`/demo/attack-lab/scenarios/${encodeURIComponent(scenarioId)}/runs`, {
      method: 'POST',
      body: JSON.stringify({ confirm }),
    });
  }

  async getAttackLabRuns(limit = 25): Promise<AttackRun[]> {
    const data = await this.request<{ runs: AttackRun[] }>(`/demo/attack-lab/runs?limit=${limit}`);
    return data.runs;
  }

  async getAttackLabRun(runId: string): Promise<AttackRun> {
    const data = await this.request<{ run: AttackRun }>(`/demo/attack-lab/runs/${encodeURIComponent(runId)}`);
    return data.run;
  }

  async submitTamperEvent(envelope: unknown): Promise<any> {
    return this.request('/tamper/events', {
      method: 'POST',
      body: JSON.stringify(envelope),
    });
  }

  async submitWitnessTamperEvent(envelope: unknown, witnessToken?: string): Promise<any> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (witnessToken) {
      headers['X-Witness-Token'] = witnessToken;
    }
    return this.request(
      '/tamper/events',
      {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
      },
      WITNESS_BASE
    );
  }
}

export const api = new ApiClient();
