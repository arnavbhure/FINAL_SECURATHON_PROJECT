import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useAuth } from '../context/AuthContext.js';
import { api } from '../api/client.js';
import type { AnomalyAssessment, CodSeriesPoint, MlHealth, TamperAlert, GatewayStatus } from '../types/index.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import { TimeSeriesChart, type ChartDataPoint } from '../components/common/TimeSeriesChart.js';
import { LiveStreamStatus } from '../components/common/LiveStreamStatus.js';
import { useLiveSeries } from '../hooks/useLiveSeries.js';
import {
  BrainCircuit,
  RefreshCw,
  AlertTriangle,
  Info,
  Server,
  Building2,
  ShieldAlert,
  Network,
  CheckCircle2,
  Play,
  Pause,
  Clock,
  Radio,
} from 'lucide-react';

export const AnomaliesPage: React.FC = () => {
  const { selectedSite } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [assessments, setAssessments] = useState<AnomalyAssessment[]>([]);
  const [jobSummary, setJobSummary] = useState<Record<string, number>>({});
  const [mlHealth, setMlHealth] = useState<MlHealth | null>(null);
  const [tamperAlerts, setTamperAlerts] = useState<TamperAlert[]>([]);
  const [gatewayStatus, setGatewayStatus] = useState<GatewayStatus | null>(null);

  // Tabs & Controls
  const [activeTab, setActiveTab] = useState<'cod' | 'residuals'>('cod');
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [windowMinutes, setWindowMinutes] = useState<number>(15);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isPolling, setIsPolling] = useState<boolean>(false);

  // Concurrency guard ref
  const isFetchingRef = useRef<boolean>(false);
  const unmountedRef = useRef<boolean>(false);

  useEffect(() => {
    unmountedRef.current = false;
    return () => {
      unmountedRef.current = true;
    };
  }, []);

  // Fetch function with in-flight avoidance and deduplication
  const fetchData = useCallback(async (isInitial = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    setIsPolling(true);

    if (isInitial) {
      setLoading(true);
    }
    setError(null);

    try {
      // 1. Health (sanitized)
      try {
        const h = await api.getMlHealth();
        if (!unmountedRef.current) setMlHealth(h);
      } catch {
        if (!unmountedRef.current) setMlHealth({ enabled: false, reachable: false, baseUrl: 'unreachable' });
      }

      // 2. Assessments (latest 100)
      try {
        const a = await api.getLatestAssessments(selectedSite, 100);
        if (!unmountedRef.current) setAssessments(a);
      } catch {
        if (!unmountedRef.current) setAssessments([]);
      }

      // 3. Job status summary (COD and residual series stream separately via useLiveSeries)
      try {
        const js = await api.getJobStatusSummary(selectedSite);
        if (!unmountedRef.current) setJobSummary(js);
      } catch {
        if (!unmountedRef.current) setJobSummary({});
      }

      // 4. Physical Tamper Alerts (from backend ML & edge tamper route)
      try {
        const alerts = await api.getTamperAlerts();
        if (!unmountedRef.current) setTamperAlerts(alerts);
      } catch {
        if (!unmountedRef.current) setTamperAlerts([]);
      }

      // 5. Store-and-Forward Edge Gateway Status
      try {
        const gw = await api.getGatewayStatus();
        if (!unmountedRef.current) setGatewayStatus(gw);
      } catch {
        if (!unmountedRef.current) setGatewayStatus(null);
      }

      if (!unmountedRef.current) {
        setLastUpdated(new Date());
      }
    } catch (err: any) {
      if (!unmountedRef.current) {
        setError(err.message || 'Failed to fetch ML assessment data');
      }
    } finally {
      isFetchingRef.current = false;
      if (!unmountedRef.current) {
        setIsPolling(false);
        setLoading(false);
      }
    }
  }, [selectedSite]);

  // Initial load when selectedSite changes
  useEffect(() => {
    fetchData(true);
  }, [fetchData]);

  // Auto-refresh interval (every 3.5 seconds) with pause support
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      fetchData(false);
    }, 3500);

    return () => clearInterval(interval);
  }, [fetchData, isPaused]);

  // Live COD series (actual vs ML expected, plus residuals) kept as a bounded sliding time window.
  // The residuals endpoint serves the same rows, so one stream feeds both chart tabs.
  const windowMs = windowMinutes * 60 * 1000;
  const liveCod = useLiveSeries<CodSeriesPoint>({
    key: selectedSite,
    windowMs,
    enabled: !isPaused,
    fetchSince: (from) => api.getCodSeries(selectedSite, undefined, { from, limit: 1000 }),
    getId: (p) => p.readingId,
    getTime: (p) => Date.parse(p.measuredAt),
  });
  const filteredCodSeries = liveCod.points;
  const filteredResidualsSeries = liveCod.points;

  // Dynamic threshold derived from latest completed assessment in the series (not hardcoded)
  const activeResidualThreshold = useMemo(() => {
    for (let i = filteredResidualsSeries.length - 1; i >= 0; i--) {
      const item = filteredResidualsSeries[i];
      if (item && item.threshold !== null && item.threshold !== undefined && !isNaN(item.threshold)) {
        return item.threshold;
      }
    }
    return undefined;
  }, [filteredResidualsSeries]);

  // Transform COD Series to chart data (Actual vs Model Predicted)
  const codChartData: ChartDataPoint[] = useMemo(() => {
    return filteredCodSeries.map((p) => ({
      id: p.readingId,
      time: p.measuredAt
        ? new Date(p.measuredAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : '—',
      measuredAt: p.measuredAt,
      sensorId: p.sensorId,
      actual: p.actualCod,
      predicted: p.status === 'PENDING' || p.status === 'NOT_EVALUATED' || p.status === 'ERROR' ? null : p.predictedCod,
      residual: p.residual,
      threshold: p.threshold,
      status: p.status,
      modelVersion: p.modelVersion,
    }));
  }, [filteredCodSeries]);

  // Transform Residuals Series to chart data (Residual vs Dynamic Model Threshold)
  const residualChartData: ChartDataPoint[] = useMemo(() => {
    return filteredResidualsSeries.map((p) => ({
      id: p.readingId,
      time: p.measuredAt
        ? new Date(p.measuredAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : '—',
      measuredAt: p.measuredAt,
      sensorId: p.sensorId,
      actual: p.residual !== null && p.residual !== undefined ? p.residual : 0,
      threshold: p.threshold,
      status: p.status,
      modelVersion: p.modelVersion,
    }));
  }, [filteredResidualsSeries]);

  // Freshness calculation
  const getFreshness = () => {
    if (!lastUpdated) return { label: 'CONNECTING', color: 'var(--text-muted)' };
    const ageSec = (Date.now() - lastUpdated.getTime()) / 1000;
    if (ageSec < 8) return { label: 'LIVE (FRESH)', color: '#10b981' };
    if (ageSec < 30) return { label: 'ACTIVE', color: 'var(--air-force-blue)' };
    return { label: 'STALE DATA', color: 'var(--brick-red)' };
  };

  const freshness = getFreshness();

  return (
    <div>
      {/* Header with Live Data Badge and Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 14 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              Machine Learning Process Anomaly Detection
            </h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: 'var(--bg-surface-accent)',
                color: 'var(--carbon-black)',
                padding: '4px 12px',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 700,
                border: '1px solid var(--border-subtle)',
              }}
            >
              <Building2 size={13} color="var(--text-muted)" />
              <span>{selectedSite}</span>
            </span>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: isPaused ? 'rgba(100, 116, 139, 0.12)' : 'rgba(16, 185, 129, 0.12)',
                color: isPaused ? '#64748b' : '#059669',
                padding: '4px 10px',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 800,
                letterSpacing: '0.04em',
              }}
            >
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  backgroundColor: isPaused ? '#94a3b8' : '#10b981',
                  boxShadow: isPaused ? 'none' : '0 0 8px #10b981',
                  display: 'inline-block',
                }}
              />
              <span>{isPaused ? 'STREAM PAUSED' : 'LIVE STREAM'}</span>
            </span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4, marginBottom: 0 }}>
            Continuous zero-trust telemetry correlated against verified operational context. Model inference via Express API.
          </p>
        </div>

        {/* Live Controls: Pause/Resume, Window Filter, Manual Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {/* Sliding Window Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8125rem' }}>
            <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Window:</span>
            <select
              className="form-control"
              style={{ padding: '6px 12px', fontSize: '0.8125rem', height: 34, width: 'auto' }}
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value))}
            >
              <option value={5}>Latest 5 min</option>
              <option value={15}>Latest 15 min</option>
              <option value={30}>Latest 30 min</option>
              <option value={60}>Latest 1 hour</option>
            </select>
          </div>

          {/* Pause / Resume Button */}
          <button
            className={`btn ${isPaused ? 'btn-primary' : 'btn-secondary'} btn-sm`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Resume live graph stream' : 'Pause live graph stream to inspect points'}
            style={{ height: 34 }}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            <span>{isPaused ? 'Resume Stream' : 'Pause'}</span>
          </button>

          {/* Manual Refresh Button */}
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => {
              fetchData(false);
              liveCod.pollNow();
            }}
            disabled={isPolling}
            title="Poll Express API immediately"
            style={{ height: 34 }}
          >
            <RefreshCw size={14} className={isPolling ? 'spin' : ''} />
            <span>Poll Now</span>
          </button>
        </div>
      </div>

      {/* Stream Provenance & Freshness Bar */}
      <div
        style={{
          background: 'var(--bg-surface-accent)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-md)',
          padding: '8px 16px',
          marginBottom: 20,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.75rem',
          flexWrap: 'wrap',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>
            DATA PROVENANCE:{' '}
            <strong style={{ color: 'var(--carbon-black)' }}>SIMULATED SENSOR DATA (PH-OUT-001, COD-OUT-001, TSS-OUT-001)</strong>
          </span>
          <span style={{ color: 'var(--border-subtle)' }}>•</span>
          <span style={{ color: 'var(--text-muted)' }}>
            POINTS DISPLAYED: <strong style={{ color: 'var(--carbon-black)' }}>{codChartData.length}</strong>
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ color: 'var(--text-muted)' }}>
            LAST UPDATED:{' '}
            <strong style={{ color: 'var(--carbon-black)', fontFamily: 'ui-monospace, monospace' }}>
              {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Awaiting initial response...'}
            </strong>
          </span>
          <span style={{ color: 'var(--border-subtle)' }}>•</span>
          <span style={{ fontWeight: 800, color: freshness.color }}>
            {freshness.label}
          </span>
        </div>
      </div>

      {error && (
        <div className="alert-box danger" style={{ marginBottom: 20 }}>
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* LAN & Model Health Banner */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: '16px 20px',
          marginBottom: 24,
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 16,
          boxShadow: 'var(--shadow-sm)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-surface-accent)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--carbon-black)',
            }}
          >
            <Server size={20} />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '0.9375rem', color: 'var(--text-main)' }}>
              Remote ML Inference Engine:{' '}
              <span>
                {mlHealth?.enabled
                  ? mlHealth.reachable
                    ? 'Connected (FastAPI Ready)'
                    : 'Configured / Offline (Awaiting Teammate LAN Service)'
                  : 'Disabled'}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
              {mlHealth?.enabled
                ? mlHealth.reachable
                  ? `Active • Model Version: ${mlHealth.modelVersion || 'rf-cod-v1.0'} • Dual-Checking: Isolation Forest & Rule Engine`
                  : 'FastAPI service configured on LAN IP. When offline, incoming telemetry displays as PENDING ASSESSMENT without fabricated results.'
                : 'ML evaluation disabled via ML_ENABLED=false (telemetry ingestion remains fully active).'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <StatusBadge
            status={mlHealth?.enabled ? (mlHealth?.reachable ? 'ONLINE' : 'OFFLINE') : 'DISABLED'}
            label={mlHealth?.enabled ? (mlHealth?.reachable ? 'Connected' : 'ML Offline') : 'Disabled'}
          />
        </div>
      </div>

      {/* Statistical Advisory Notice */}
      <div className="alert-box info" style={{ marginBottom: 24 }}>
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Statistical Distinction:</strong> Machine learning assesses chemical and process correlation between physical effluent measurements (mg/L) and signed operating context. A <code>SUSPICIOUS</code> result indicates a statistical deviation requiring engineering review; it is strictly decoupled from regulatory exceedance limits.
        </div>
      </div>

      {/* Job Processing State Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', padding: '14px 18px', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Completed Assessments
          </div>
          <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#10b981', marginTop: 4 }}>
            {jobSummary['COMPLETED'] ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>Full context matched & inferred</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', padding: '14px 18px', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Pending Inference Jobs
          </div>
          <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--air-force-blue)', marginTop: 4 }}>
            {jobSummary['PENDING'] ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>Awaiting context arrival / inference</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', padding: '14px 18px', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Insufficient Context
          </div>
          <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f59e0b', marginTop: 4 }}>
            {jobSummary['INSUFFICIENT_CONTEXT'] ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>Context wait window elapsed (60s)</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', padding: '14px 18px', borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-sm)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Failed / Timeout
          </div>
          <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--brick-red)', marginTop: 4 }}>
            {jobSummary['FAILED'] ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>FastAPI offline or unreachable</div>
        </div>
      </div>

      {/* Dual Stream Time Series Graph Card */}
      <div className="card" style={{ marginBottom: 28 }}>
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <div className="card-title">
              <Radio size={18} color="var(--air-force-blue)" />
              <span>Real-Time Chemical Sensor & Inference Stream</span>
            </div>
            <div className="card-subtitle">
              Live dual-stream comparison: Continuous physical COD sensor telemetry vs. completed ML Random Forest predictions
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className={`btn btn-sm ${activeTab === 'cod' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('cod')}
            >
              Actual COD vs Expected ML
            </button>
            <button
              className={`btn btn-sm ${activeTab === 'residuals' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('residuals')}
            >
              Statistical Residuals (Δ)
            </button>
          </div>
        </div>

        <div className="card-body">
          <LiveStreamStatus
            paused={isPaused}
            loading={liveCod.loading}
            error={liveCod.error}
            consecutiveFailures={liveCod.consecutiveFailures}
            lastUpdated={liveCod.lastUpdated}
            pointCount={liveCod.points.length}
          />
          {activeTab === 'cod' ? (
            <TimeSeriesChart
              data={codChartData}
              title="COD Stream (mg/L) — Telemetry vs ML Predicted Baseline"
              yUnit="mg/L"
              windowMs={windowMs}
              paused={isPaused}
              emptyMessage={
                liveCod.loading
                  ? 'Connecting to live telemetry…'
                  : 'No COD readings in this window — start the simulator stream (npm run stream:all) to see live data.'
              }
            />
          ) : (
            <TimeSeriesChart
              data={residualChartData}
              title="Residual Deviation Stream (mg/L) — Absolute |Actual - Predicted|"
              yUnit="mg/L"
              threshold={activeResidualThreshold}
              thresholdLabel={
                activeResidualThreshold !== undefined
                  ? `Model Residual Boundary (${activeResidualThreshold.toFixed(2)} mg/L)`
                  : 'Model Boundary'
              }
              windowMs={windowMs}
              paused={isPaused}
              emptyMessage={
                liveCod.loading
                  ? 'Connecting to live telemetry…'
                  : 'No residual metrics in this window — completed assessments will display deviation spikes here.'
              }
            />
          )}
        </div>
      </div>

      {/* Anomaly Assessment Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <BrainCircuit size={18} color="var(--air-force-blue)" />
              <span>Assessment Ledger & Diagnostic Commentary</span>
            </div>
            <div className="card-subtitle">
              Immutable assessment records derived from verified telemetry and operations context
            </div>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {assessments.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Evaluated At</th>
                    <th>Sensor</th>
                    <th>Actual COD</th>
                    <th>Predicted COD</th>
                    <th>Residual</th>
                    <th>Threshold</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Anomaly Type</th>
                    <th>Context Reference</th>
                    <th>Model</th>
                    <th>Diagnostic Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {assessments.map((a) => (
                    <tr key={a.id}>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(a.evaluatedAt).toLocaleString()}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-main)', fontWeight: 600 }}>{a.sensorId}</td>
                      <td className="mono" style={{ fontWeight: 800, color: 'var(--text-main)' }}>
                        {a.actualValue !== null && a.actualValue !== undefined ? `${a.actualValue.toFixed(2)} mg/L` : '—'}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        {a.predictedValue !== null && a.predictedValue !== undefined ? `${a.predictedValue.toFixed(2)} mg/L` : '—'}
                      </td>
                      <td className="mono" style={{ fontWeight: a.status === 'SUSPICIOUS' ? 800 : 500, color: a.status === 'SUSPICIOUS' ? 'var(--color-danger)' : 'var(--text-main)' }}>
                        {a.residual !== null && a.residual !== undefined ? a.residual.toFixed(2) : '—'}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        {a.threshold !== null && a.threshold !== undefined ? a.threshold.toFixed(2) : '—'}
                      </td>
                      <td>
                        <StatusBadge status={a.status} />
                      </td>
                      <td>
                        <StatusBadge status={a.severity} />
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {a.anomalyType || '—'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-light)' }}>
                        {a.contextId ? `${a.contextId.slice(0, 8)}...` : 'NONE'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {a.modelVersion}
                      </td>
                      <td style={{ fontSize: '0.8125rem', maxWidth: 280, color: 'var(--text-muted)' }}>
                        {a.reasons && a.reasons.length > 0 ? (
                          <ul style={{ paddingLeft: 16, margin: 0 }}>
                            {a.reasons.map((r, i) => (
                              <li key={i}>{r}</li>
                            ))}
                          </ul>
                        ) : (
                          'No anomalies identified'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No anomaly records found</div>
              <p>Assessments will populate once COD telemetry is evaluated against operating context.</p>
            </div>
          )}
        </div>
      </div>

      {/* Physical Sensor Tamper & Edge Gateway Status Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 24, marginTop: 28 }}>
        {/* Physical Tamper Security Feed */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <ShieldAlert size={18} color="var(--brick-red)" />
                <span>Physical Sensor Tamper Feed</span>
              </div>
              <div className="card-subtitle">
                Hardware interlocks: enclosure open, seal break, and disconnect alerts
              </div>
            </div>
            <span className="facility-status-tag active">
              <span className="status-live-indicator" />
              <span>INTERLOCKS ACTIVE</span>
            </span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {tamperAlerts.length > 0 ? (
              <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Device ID</th>
                      <th>Event Type</th>
                      <th>Severity</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tamperAlerts.map((t, idx) => (
                      <tr key={t.alert_id || idx}>
                        <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {new Date(t.timestamp_utc).toLocaleTimeString()}
                        </td>
                        <td className="mono" style={{ fontWeight: 700, color: 'var(--text-main)' }}>
                          {t.device_id}
                        </td>
                        <td>
                          <span style={{ fontWeight: 700, color: 'var(--brick-red)', fontSize: '0.8125rem' }}>
                            {t.event_type}
                          </span>
                        </td>
                        <td>
                          <StatusBadge status={t.severity} />
                        </td>
                        <td>
                          <StatusBadge status={t.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state" style={{ padding: '32px 20px' }}>
                <CheckCircle2 size={32} color="#10b981" style={{ marginBottom: 8 }} />
                <div className="empty-state-title" style={{ fontSize: '0.9375rem' }}>All Hardware Interlocks Secure</div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: 0 }}>
                  No physical enclosure tampering, broken seals, or sensor disconnects detected.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Store-and-Forward Edge Gateway */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <Network size={18} color="var(--air-force-blue)" />
                <span>Edge Ingestion Gateway</span>
              </div>
              <div className="card-subtitle">
                Store-and-forward edge proxy with idempotent deduplication
              </div>
            </div>
            <StatusBadge
              status={gatewayStatus?.is_online ? 'ONLINE' : 'PENDING'}
              label={gatewayStatus?.is_online ? 'ONLINE' : 'CONNECTING'}
            />
          </div>
          <div className="card-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-surface-accent)', borderRadius: 'var(--radius-md)' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-muted)' }}>Service Role</span>
                <span className="mono" style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {gatewayStatus?.service || 'EnviroTrust Edge Gateway'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-surface-accent)', borderRadius: 'var(--radius-md)' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-muted)' }}>Buffered Messages</span>
                <span className="mono" style={{ fontSize: '0.875rem', fontWeight: 800, color: 'var(--air-force-blue)' }}>
                  {gatewayStatus?.total_recorded_messages ?? 0} recorded
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-surface-accent)', borderRadius: 'var(--radius-md)' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-muted)' }}>Deduplication Cache</span>
                <span className="mono" style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#10b981' }}>
                  ACTIVE (SHA-256 Receipt Tokens)
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
