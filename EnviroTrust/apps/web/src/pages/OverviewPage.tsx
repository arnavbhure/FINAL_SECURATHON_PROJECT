import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.js';
import { api } from '../api/client.js';
import type { SensorHealth, AnomalyAssessment, WitnessCheckpoint, TelemetryReading, CodSeriesPoint } from '../types/index.js';
import { MetricCard } from '../components/common/MetricCard.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import { TimeSeriesChart, ChartDataPoint } from '../components/common/TimeSeriesChart.js';
import { LiveStreamStatus } from '../components/common/LiveStreamStatus.js';
import { useLiveSeries } from '../hooks/useLiveSeries.js';
import {
  Activity,
  Radio,
  BrainCircuit,
  FileCheck2,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Server,
  Building2,
  CheckCircle2,
  ArrowRight,
  ExternalLink,
  Lock,
} from 'lucide-react';

// Sliding window shown by the live telemetry chart
const LIVE_WINDOW_MS = 5 * 60 * 1000;

const formatClockTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';

const codPointToChart = (p: CodSeriesPoint): ChartDataPoint => ({
  id: p.readingId,
  time: formatClockTime(p.measuredAt),
  measuredAt: p.measuredAt,
  sensorId: p.sensorId,
  actual: p.actualCod,
  predicted: p.predictedCod,
  residual: p.residual,
  status: p.status,
  modelVersion: p.modelVersion ?? null,
  label: `COD: ${p.actualCod} mg/L (ML Baseline: ${p.predictedCod ?? '—'})`,
});

const readingToChart = (r: TelemetryReading): ChartDataPoint => ({
  id: r.id,
  time: formatClockTime(r.measuredAt),
  ...(r.measuredAt ? { measuredAt: r.measuredAt } : {}),
  sensorId: r.sensorId,
  actual: Number(r.valueWire),
  label: `${r.parameter}: ${r.valueWire} ${r.unit}`,
});

export const OverviewPage: React.FC = () => {
  const { selectedSite } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isAutoRefresh, setIsAutoRefresh] = useState(true);
  const isFetchingRef = React.useRef(false);

  const [overviewMetrics, setOverviewMetrics] = useState<{
    totalReadings: number;
    totalSensors: number;
    recentSecurityEventsCount: number;
    anomalySummary: Record<string, number>;
    latestReadings: any[];
  } | null>(null);

  const [sensorsHealth, setSensorsHealth] = useState<SensorHealth[]>([]);
  const [recentAnomalies, setRecentAnomalies] = useState<AnomalyAssessment[]>([]);
  const [jobSummary, setJobSummary] = useState<Record<string, number>>({});
  const [mlHealth, setMlHealth] = useState<{ enabled: boolean; reachable: boolean; baseUrl: string; modelVersion?: string } | null>(null);
  const [checkpoint, setCheckpoint] = useState<WitnessCheckpoint | null>(null);
  const [activeParamTab, setActiveParamTab] = useState<'COD' | 'pH' | 'TSS'>('COD');

  // Interactive Witness Chain Verification state
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [chainVerifyStatus, setChainVerifyStatus] = useState<string | null>(null);

  const loadData = useCallback(async (silent = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    if (!silent) setLoading(true);
    setError(null);
    try {
      // 1. Overview metrics
      const ov = await api.getOverview(selectedSite);
      setOverviewMetrics(ov.metrics);

      // 2. Sensor health
      const sh = await api.getAllSensorsHealth(selectedSite);
      setSensorsHealth(sh);

      // 3. ML assessments (the telemetry chart streams separately via useLiveSeries)
      try {
        const an = await api.getLatestAssessments(selectedSite, 6);
        setRecentAnomalies(an);
      } catch {
        // fallback
      }

      // 4. ML jobs & health
      try {
        const js = await api.getJobStatusSummary(selectedSite);
        setJobSummary(js);
      } catch {
        // fallback
      }

      try {
        const mh = await api.getMlHealth();
        setMlHealth(mh);
      } catch {
        setMlHealth({ enabled: false, reachable: false, baseUrl: 'unreachable' });
      }

      // 5. Witness Checkpoint for selected station
      const stationId = selectedSite === 'PLANT-002' ? 'STATION-002' : 'STATION-001';
      try {
        const cp = await api.getLatestWitnessCheckpoint(stationId);
        setCheckpoint(cp);
      } catch {
        setCheckpoint(null);
      }
    } catch (err: any) {
      if (!silent) setError(err.message || 'Failed to fetch overview telemetry.');
    } finally {
      isFetchingRef.current = false;
      if (!silent) setLoading(false);
    }
  }, [selectedSite]);

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  // Periodic live telemetry polling loop (3.5s cadence)
  useEffect(() => {
    if (!isAutoRefresh) return;
    const interval = setInterval(() => {
      if (!isFetchingRef.current && document.visibilityState === 'visible') {
        loadData(true);
      }
    }, 3500);
    return () => clearInterval(interval);
  }, [loadData, isAutoRefresh]);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    setChainVerifyStatus(null);
    const stationId = selectedSite === 'PLANT-002' ? 'STATION-002' : 'STATION-001';
    try {
      const res = await api.verifyWitnessChain(stationId);
      if (res.valid) {
        setChainVerifyStatus(`Verified (${res.eventCount} events uninterrupted)`);
      } else {
        const errDetail = res.discrepancies?.[0]?.reason || 'Chain discrepancy detected';
        setChainVerifyStatus(`Failed: ${errDetail}`);
      }
    } catch (err: any) {
      setChainVerifyStatus('Verification error');
    } finally {
      setVerifyingChain(false);
    }
  };

  const onlineSensorsCount = sensorsHealth.filter((s) => s.status === 'ONLINE').length;
  const offlineSensorsCount = sensorsHealth.filter((s) => s.status === 'OFFLINE').length;
  const suspiciousCount = overviewMetrics ? overviewMetrics.anomalySummary['SUSPICIOUS'] || 0 : 0;

  // Continuous Graph Data: COD streams the dual series (Actual Sensor Telemetry + ML Expected
  // baseline); pH/TSS stream the raw signed readings. New points are appended as they arrive.
  const liveSeries = useLiveSeries<ChartDataPoint>({
    key: `${selectedSite}:${activeParamTab}`,
    windowMs: LIVE_WINDOW_MS,
    enabled: isAutoRefresh,
    fetchSince: async (from) => {
      if (activeParamTab === 'COD') {
        const series = await api.getCodSeries(selectedSite, undefined, { from, limit: 1000 });
        return series.map(codPointToChart);
      }
      const res = await api.getReadings({ siteId: selectedSite, parameter: activeParamTab, from, limit: 500 });
      return res.readings.map(readingToChart);
    },
    getId: (p) => p.id ?? p.time,
    getTime: (p) => (p.measuredAt ? Date.parse(p.measuredAt) : NaN),
  });

  const getBenchmarkLimit = () => {
    switch (activeParamTab) {
      case 'COD':
        return 100; // CPCB inland surface water standard
      case 'pH':
        return 8.5; // upper limit
      case 'TSS':
        return 100;
      default:
        return 100;
    }
  };

  return (
    <div>
      {/* Spacious Page Title & Action Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', letterSpacing: '-0.025em' }}>
              Operations & Compliance Dashboard
            </h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: '#ffffff',
                color: '#475569',
                padding: '4px 12px',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 700,
                border: '1px solid #e2e8f0',
              }}
            >
              <Building2 size={13} color="#64748b" />
              <span>{selectedSite}</span>
            </span>
          </div>
          <p style={{ color: '#64748b', fontSize: '0.875rem', marginTop: 4 }}>
            Continuous zero-trust telemetry verification, SHA-256 witness continuity, and FastAPI ML process assessment.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setIsAutoRefresh(!isAutoRefresh)}
            title={isAutoRefresh ? 'Pause continuous 3.5s polling' : 'Resume continuous polling'}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <span
              style={{
                display: 'inline-block',
                width: 7,
                height: 7,
                borderRadius: '50%',
                backgroundColor: isAutoRefresh ? '#10b981' : '#94a3b8',
                boxShadow: isAutoRefresh ? '0 0 6px rgba(16, 185, 129, 0.6)' : 'none',
              }}
            />
            <span>{isAutoRefresh ? 'Live Stream Active (3.5s)' : 'Stream Paused'}</span>
          </button>

          <button
            className="btn btn-secondary btn-sm"
            onClick={() => {
              loadData(false);
              liveSeries.pollNow();
            }}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="alert-box danger">
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Spacious Metric Cards — Clean Industrial Style (Zero Pastel Gradients) */}
      <div className="metrics-grid">
        <MetricCard
          label="Total Telemetry Readings"
          value={overviewMetrics ? overviewMetrics.totalReadings.toLocaleString() : '—'}
          subtext="Ed25519 canonical hardware signatures"
          icon={<Activity size={18} />}
          trend="+100% Signed"
          trendType="up"
        />

        <MetricCard
          label="Sensor Fleet Health"
          value={sensorsHealth.length > 0 ? `${onlineSensorsCount} / ${sensorsHealth.length} ONLINE` : '—'}
          subtext={offlineSensorsCount > 0 ? `${offlineSensorsCount} sensor(s) communication loss` : 'All physical sensors verified'}
          icon={<Radio size={18} />}
          trend={offlineSensorsCount === 0 ? 'All Active' : `${offlineSensorsCount} Offline`}
          trendType={offlineSensorsCount === 0 ? 'up' : 'down'}
        />

        <MetricCard
          label="ML Process Anomalies"
          value={suspiciousCount}
          subtext={
            overviewMetrics
              ? `${overviewMetrics.anomalySummary['CONSISTENT'] || 0} consistent, ${overviewMetrics.anomalySummary['NOT_EVALUATED'] || 0} awaiting context`
              : '—'
          }
          icon={<BrainCircuit size={18} />}
          trend={suspiciousCount === 0 ? '0 Anomaly' : `${suspiciousCount} Flagged`}
          trendType={suspiciousCount === 0 ? 'neutral' : 'down'}
        />

        <MetricCard
          label="Witness Chain Checkpoint"
          value={checkpoint ? `#${checkpoint.checkpointSequence}` : 'Active'}
          subtext="SHA-256 chain continuity anchored"
          icon={<ShieldCheck size={18} />}
          trend="ES256 Anchored"
          trendType="neutral"
        />
      </div>

      {/* Asymmetric 2-Column Dashboard Grid */}
      <div className="dashboard-split-layout">
        {/* Left Column (Primary Telemetry & Readings) */}
        <div className="dashboard-main-column">
          {/* Continuous Dual-Stream Telemetry & ML Chart Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <Activity size={18} color="#2563eb" />
                  <span>Effluent Telemetry Stream & Continuous ML Model</span>
                </div>
                <div className="card-subtitle">
                  Continuous chronological discharge plotted with ML baseline and CPCB regulatory standard
                </div>
              </div>

              {/* Parameter Filter Tabs */}
              <div style={{ display: 'flex', gap: 6 }}>
                {(['COD', 'pH', 'TSS'] as const).map((param) => (
                  <button
                    key={param}
                    type="button"
                    onClick={() => setActiveParamTab(param)}
                    style={{
                      padding: '5px 14px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      borderRadius: 'var(--radius-full)',
                      border: '1px solid',
                      borderColor: activeParamTab === param ? 'var(--air-force-blue)' : 'var(--border-subtle)',
                      backgroundColor: activeParamTab === param ? 'var(--air-force-blue-light)' : '#ffffff',
                      color: activeParamTab === param ? 'var(--air-force-blue)' : 'var(--text-muted)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      boxShadow: activeParamTab === param ? '0 1px 3px rgba(75, 136, 162, 0.15)' : 'none',
                    }}
                  >
                    {param === 'COD' ? 'COD (ML Correlated)' : param}
                  </button>
                ))}
              </div>
            </div>

            <div className="card-body">
              <LiveStreamStatus
                paused={!isAutoRefresh}
                loading={liveSeries.loading}
                error={liveSeries.error}
                consecutiveFailures={liveSeries.consecutiveFailures}
                lastUpdated={liveSeries.lastUpdated}
                pointCount={liveSeries.points.length}
              />
              <TimeSeriesChart
                data={liveSeries.points}
                title={`${activeParamTab} Continuous Stream (${activeParamTab === 'pH' ? 'pH units' : 'mg/L'}) · last 5 min`}
                yUnit={activeParamTab === 'pH' ? 'pH' : 'mg/L'}
                threshold={getBenchmarkLimit()}
                thresholdLabel="CPCB Sched. VI Limit"
                windowMs={LIVE_WINDOW_MS}
                paused={!isAutoRefresh}
                emptyMessage={
                  liveSeries.loading
                    ? 'Connecting to live telemetry…'
                    : `No ${activeParamTab} readings in the last 5 minutes — new sensor readings will stream in here.`
                }
              />
            </div>
          </div>

          {/* Recent Cryptographic Telemetry Table Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <FileCheck2 size={18} color="#059669" />
                  <span>Latest Authenticated Sensor Readings</span>
                </div>
                <div className="card-subtitle">
                  Individually validated with Ed25519 signatures and monotonic packet sequence nonces
                </div>
              </div>
              <Link to="/monitoring" className="btn btn-secondary btn-sm" style={{ gap: 4 }}>
                <span>View Full Telemetry</span>
                <ArrowRight size={14} />
              </Link>
            </div>

            <div className="card-body" style={{ padding: 0 }}>
              {overviewMetrics && overviewMetrics.latestReadings.length > 0 ? (
                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Parameter</th>
                        <th>Sensor ID</th>
                        <th>Measured Value</th>
                        <th>Timestamp (Sensor)</th>
                        <th>Signature</th>
                        <th>Freshness</th>
                      </tr>
                    </thead>
                    <tbody>
                      {overviewMetrics.latestReadings.map((r, i) => (
                        <tr key={i}>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span
                                style={{
                                  display: 'inline-block',
                                  width: 8,
                                  height: 8,
                                  borderRadius: '50%',
                                  backgroundColor:
                                    r.parameter === 'COD' ? '#2563eb' : r.parameter === 'pH' ? '#059669' : '#d97706',
                                }}
                              />
                              <strong style={{ color: '#0f172a' }}>{r.parameter}</strong>
                            </div>
                          </td>
                          <td className="mono" style={{ fontWeight: 600, color: '#334155' }}>
                            {r.sensorId}
                          </td>
                          <td className="mono" style={{ fontSize: '0.9375rem', fontWeight: 800, color: '#0f172a' }}>
                            {r.wireValue}{' '}
                            <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 500 }}>{r.unit}</span>
                          </td>
                          <td className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                            {r.measuredAt ? new Date(r.measuredAt).toLocaleTimeString() : '—'}
                          </td>
                          <td>
                            <StatusBadge status={r.signatureStatus} label="VALID" />
                          </td>
                          <td>
                            <StatusBadge status={r.protocolStatus} label="FRESH" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-title">No telemetry recorded yet</div>
                  <p>Run simulator emission to generate signed readings for {selectedSite}.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column (Witness State & ML Intelligence Widgets) */}
        <div className="dashboard-side-column">
          {/* Independent Witness Verification Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <ShieldCheck size={18} color="#4338ca" />
                  <span>Independent Witness Service</span>
                </div>
                <div className="card-subtitle">SHA-256 hash-chain with ES256 signed checkpoints</div>
              </div>
              <span
                style={{
                  fontSize: '0.625rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  backgroundColor: '#eef2ff',
                  color: '#4338ca',
                  border: '1px solid #c7d2fe',
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-full)',
                  whiteSpace: 'nowrap',
                  flexShrink: 0,
                }}
              >
                DUAL DELIVERY
              </span>
            </div>

            <div className="card-body">
              {checkpoint ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>Latest Checkpoint:</span>
                    <span className="mono" style={{ fontWeight: 800, color: '#0f172a', fontSize: '1.125rem' }}>
                      #{checkpoint.checkpointSequence}
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>Anchored Events:</span>
                    <span className="mono" style={{ fontWeight: 700, color: '#334155' }}>
                      {checkpoint.lastWitnessSequence} events
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>Chain Head Hash:</span>
                    <span className="mono" style={{ fontSize: '0.75rem', color: '#0f172a' }} title={checkpoint.chainHeadHash}>
                      {checkpoint.chainHeadHash.slice(0, 16)}...
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>Key Fingerprint:</span>
                    <span className="mono" style={{ fontSize: '0.75rem', color: '#64748b' }}>
                      {checkpoint.witnessPublicKeyFingerprint.slice(0, 14)}...
                    </span>
                  </div>

                  <div style={{ marginTop: 6, paddingTop: 12, borderTop: '1px solid #f1f5f9' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={handleVerifyChain}
                      disabled={verifyingChain}
                      style={{ width: '100%' }}
                    >
                      <Lock size={13} />
                      <span>{verifyingChain ? 'Verifying Chain...' : 'Verify Witness Hash Chain'}</span>
                    </button>
                    {chainVerifyStatus && (
                      <div
                        style={{
                          marginTop: 8,
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          textAlign: 'center',
                          color: chainVerifyStatus.includes('Verified') ? '#059669' : '#e11d48',
                        }}
                      >
                        {chainVerifyStatus}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ color: '#64748b', fontSize: '0.8125rem' }}>
                  No witness checkpoint anchored yet. Checkpoints are signed automatically every 10 events.
                </div>
              )}
            </div>
          </div>

          {/* Remote ML Service Status Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <BrainCircuit size={18} color="#2563eb" />
                  <span>Remote ML Anomaly Engine</span>
                </div>
                <div className="card-subtitle">RandomForest chemical correlation on teammate LAN laptop</div>
              </div>
              {mlHealth && (
                <div style={{ flexShrink: 0 }}>
                  <StatusBadge
                    status={mlHealth.enabled ? (mlHealth.reachable ? 'ONLINE' : 'OFFLINE') : 'DISABLED'}
                    label={mlHealth.enabled ? (mlHealth.reachable ? 'Connected' : 'LAN Pending') : 'Disabled'}
                  />
                </div>
              )}
            </div>

            <div className="card-body">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, textAlign: 'center', marginBottom: 16 }}>
                <div style={{ padding: '12px 8px', background: '#f8fafc', borderRadius: 'var(--radius-md)', border: '1px solid #e2e8f0' }}>
                  <div style={{ fontSize: '0.625rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>
                    Pending
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#0f172a', marginTop: 2 }}>
                    {jobSummary['PENDING'] || 0}
                  </div>
                </div>

                <div style={{ padding: '12px 8px', background: '#ecfdf5', borderRadius: 'var(--radius-md)', border: '1px solid #a7f3d0' }}>
                  <div style={{ fontSize: '0.625rem', fontWeight: 700, color: '#059669', textTransform: 'uppercase' }}>
                    Evaluated
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#059669', marginTop: 2 }}>
                    {jobSummary['COMPLETED'] || 0}
                  </div>
                </div>

                <div style={{ padding: '12px 8px', background: '#fff1f2', borderRadius: 'var(--radius-md)', border: '1px solid #fecdd3' }}>
                  <div style={{ fontSize: '0.625rem', fontWeight: 700, color: '#e11d48', textTransform: 'uppercase' }}>
                    Timeout
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#e11d48', marginTop: 2 }}>
                    {(jobSummary['FAILED'] || 0) + (jobSummary['INSUFFICIENT_CONTEXT'] || 0)}
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '0.75rem', color: '#64748b', lineHeight: 1.4 }}>
                <strong>Model Version:</strong> {mlHealth?.modelVersion || 'rf-cod-v1.0'}<br />
                <strong>Transport:</strong> Local LAN HTTP with canonical RFC 8785 JSON contracts
              </div>

              <div style={{ marginTop: 14 }}>
                <Link to="/anomalies" className="btn btn-secondary btn-sm" style={{ width: '100%', gap: 6 }}>
                  <span>Open Anomaly Center</span>
                  <ExternalLink size={13} />
                </Link>
              </div>
            </div>
          </div>

          {/* Quick Sensor Device Availability Card */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Radio size={18} color="#0284c7" />
                <span>Sensor Devices</span>
              </div>
              <Link to="/sensors" style={{ fontSize: '0.75rem', fontWeight: 700, color: '#2563eb', textDecoration: 'none' }}>
                All Sensors &rarr;
              </Link>
            </div>

            <div className="card-body" style={{ padding: '12px 20px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {sensorsHealth.map((s) => (
                  <div
                    key={s.sensorId}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 0',
                      borderBottom: '1px solid #f1f5f9',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: '50%',
                          backgroundColor: s.status === 'ONLINE' ? '#10b981' : '#f59e0b',
                        }}
                      />
                      <div>
                        <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a' }}>
                          {s.sensorCode || s.sensorId}
                        </div>
                        <div style={{ fontSize: '0.6875rem', color: '#94a3b8' }}>
                          {s.parameter} • {s.expectedIntervalSeconds}s pulse
                        </div>
                      </div>
                    </div>
                    <StatusBadge status={s.status} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
