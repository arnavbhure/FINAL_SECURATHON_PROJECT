import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/AuthContext.js';
import { api } from '../api/client.js';
import type { TelemetryReading } from '../types/index.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import { TimeSeriesChart, type ChartDataPoint } from '../components/common/TimeSeriesChart.js';
import { Activity, Filter, RefreshCw, AlertCircle, Clock, Building2 } from 'lucide-react';

export const MonitoringPage: React.FC = () => {
  const { selectedSite } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [readings, setReadings] = useState<TelemetryReading[]>([]);

  // Filters
  const [selectedParam, setSelectedParam] = useState<string>('ALL');
  const [selectedSensor, setSelectedSensor] = useState<string>('ALL');
  const [limit, setLimit] = useState<number>(100);

  // Regulatory benchmark toggle (hidden by default to avoid unverified compliance claims)
  const [showBenchmark, setShowBenchmark] = useState<boolean>(false);
  const [isAutoRefresh, setIsAutoRefresh] = useState(true);
  const isFetchingRef = React.useRef(false);

  const fetchReadings = useCallback(async (silent = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    if (!silent) setLoading(true);
    setError(null);
    try {
      const res = await api.getReadings({
        siteId: selectedSite,
        parameter: selectedParam === 'ALL' ? undefined : selectedParam,
        sensorId: selectedSensor === 'ALL' ? undefined : selectedSensor,
        limit,
      });
      setReadings(res.readings);
    } catch (err: any) {
      if (!silent) setError(err.message || 'Failed to fetch environmental readings');
    } finally {
      isFetchingRef.current = false;
      if (!silent) setLoading(false);
    }
  }, [selectedSite, selectedParam, selectedSensor, limit]);

  useEffect(() => {
    fetchReadings(false);
  }, [fetchReadings]);

  // Periodic live telemetry polling loop (4s cadence)
  useEffect(() => {
    if (!isAutoRefresh) return;
    const interval = setInterval(() => {
      if (!isFetchingRef.current && document.visibilityState === 'visible') {
        fetchReadings(true);
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [fetchReadings, isAutoRefresh]);

  // Transform readings to chart data
  const chartData: ChartDataPoint[] = useMemo(() => {
    // Reverse so oldest is left, newest is right
    const sorted = [...readings].reverse();
    return sorted.map((r) => ({
      time: r.measuredAt || new Date().toISOString(),
      actual: r.valueNumeric,
      status: r.anomaly?.status || 'NORMAL',
      label: `${r.parameter}: ${r.valueWire} ${r.unit}`,
    }));
  }, [readings]);

  // Indicative demonstration benchmarks (sourced from Schedule VI General Standards for Discharge)
  const getParamBenchmark = () => {
    if (!showBenchmark) return undefined;
    if (selectedParam === 'COD') return 100.0;
    if (selectedParam === 'TSS') return 50.0;
    if (selectedParam === 'pH') return 9.0;
    return undefined;
  };

  const getParamBenchmarkLabel = () => {
    if (selectedParam === 'COD') return 'Indicative Benchmark (COD 100 mg/L)';
    if (selectedParam === 'TSS') return 'Indicative Benchmark (TSS 50 mg/L)';
    if (selectedParam === 'pH') return 'Indicative Max pH (9.0)';
    return 'Demo Reference';
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              Environmental Telemetry & Compliance
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
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            Direct ingestion of signed sensor streams with explicit physical timestamp validation.
          </p>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={() => fetchReadings(false)} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh Data</span>
        </button>
      </div>

      {error && (
        <div className="alert-box danger">
          <AlertCircle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Filter Bar (Curved Surface Inspired by Image 2) */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: '16px 24px',
          marginBottom: 24,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 16,
          alignItems: 'center',
          boxShadow: 'var(--shadow-sm)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: 700 }}>
          <Filter size={16} />
          <span>Filters:</span>
        </div>

        <div>
          <select
            className="form-select"
            value={selectedParam}
            onChange={(e) => setSelectedParam(e.target.value)}
            style={{ width: 'auto', minWidth: 140 }}
          >
            <option value="ALL">All Parameters</option>
            <option value="COD">COD (mg/L)</option>
            <option value="pH">pH (pH units)</option>
            <option value="TSS">TSS (mg/L)</option>
          </select>
        </div>

        <div>
          <select
            className="form-select"
            value={selectedSensor}
            onChange={(e) => setSelectedSensor(e.target.value)}
            style={{ width: 'auto', minWidth: 170 }}
          >
            <option value="ALL">All Sensor Devices</option>
            <option value="COD-OUT-001">COD-OUT-001 (COD)</option>
            <option value="PH-OUT-001">PH-OUT-001 (pH)</option>
            <option value="TSS-OUT-001">TSS-OUT-001 (TSS)</option>
          </select>
        </div>

        <div>
          <select
            className="form-select"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            style={{ width: 'auto', minWidth: 120 }}
          >
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
            <option value={200}>Last 200</option>
          </select>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem', color: 'var(--text-main)', cursor: 'pointer', userSelect: 'none', fontWeight: 600 }}>
          <input
            type="checkbox"
            checked={showBenchmark}
            onChange={(e) => setShowBenchmark(e.target.checked)}
            style={{ accentColor: 'var(--air-force-blue)' }}
          />
          <span>Show Indicative Benchmark</span>
        </label>

        <div style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
          Showing <strong>{readings.length}</strong> verified telemetry record(s)
        </div>
      </div>

      {/* Time-Series Trend Chart Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Activity size={18} color="var(--air-force-blue)" />
            <span>Telemetry History Trend</span>
          </div>
          <div className="card-subtitle">
            Measured parameter values plotted across chronological physical emission timestamps
          </div>
        </div>
        <div className="card-body">
          {chartData.length > 0 ? (
            <>
              <TimeSeriesChart
                data={chartData}
                title={selectedParam !== 'ALL' ? `${selectedParam} Sensor Stream` : 'Multi-Parameter Stream'}
                yUnit={selectedParam === 'pH' ? 'pH' : 'mg/L'}
                threshold={getParamBenchmark()}
                thresholdLabel={getParamBenchmarkLabel()}
              />
              {showBenchmark && (
                <div style={{ marginTop: 20, padding: '16px 20px', background: 'var(--bg-surface-accent)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  <div style={{ fontWeight: 800, color: 'var(--text-main)', marginBottom: 6, fontSize: '0.8125rem' }}>
                    Demonstration Regulatory Benchmark Reference Metadata
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 10 }}>
                    <div><strong>Standard Source:</strong> Environment (Protection) Rules 1986, Sched. VI General Standards (Inland Surface Water)</div>
                    <div><strong>Parameter & Limit:</strong> {selectedParam !== 'ALL' ? selectedParam : 'COD'}: {getParamBenchmark()} {selectedParam === 'pH' ? '' : 'mg/L'}</div>
                    <div><strong>Effective Period:</strong> EPA 1986 as notified (indicative demonstration benchmark)</div>
                    <div><strong>Applicability Limitation:</strong> Actual discharge standards vary by industry sector, individual Consent to Operate (CTO) issued by State Pollution Control Boards (SPCB / MPCB), and local water body classification.</div>
                  </div>
                  <div style={{ marginTop: 10, color: 'var(--text-muted)', fontStyle: 'italic', lineHeight: 1.4 }}>
                    Note: This reference threshold is provided for demonstration only and does not establish legal compliance. Machine learning anomaly assessments operate on statistical process correlations and are strictly separated from regulatory exceedance evaluations.
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No telemetry data matching filter</div>
              <p>Adjust the filter parameters or ingest new readings via the sensor simulator.</p>
            </div>
          )}
        </div>
      </div>

      {/* Telemetry Readings Data Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Clock size={18} color="var(--air-force-blue)" />
              <span>Cryptographic Telemetry Ledger</span>
            </div>
            <div className="card-subtitle">
              Strictly distinguishing sensor physical measurement time (`measuredAt`) from primary receipt time (`receivedAt`)
            </div>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {readings.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Sequence</th>
                    <th>Sensor ID</th>
                    <th>Parameter</th>
                    <th>Value</th>
                    <th>Measurement Time</th>
                    <th>Receipt Time</th>
                    <th>Signature</th>
                    <th>Protocol</th>
                    <th>Witness State</th>
                    <th>Payload Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {readings.map((r) => (
                    <tr key={r.id}>
                      <td className="mono" style={{ fontWeight: 800, color: 'var(--carbon-black)' }}>
                        #{r.sequenceNo}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-main)', fontWeight: 600 }}>{r.sensorId}</td>
                      <td style={{ fontWeight: 800 }}>{r.parameter}</td>
                      <td className="mono" style={{ fontSize: '0.9375rem', fontWeight: 800 }}>
                        {r.valueWire} <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 500 }}>{r.unit}</span>
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} title="Physical sensor time">
                        {r.measuredAt ? new Date(r.measuredAt).toLocaleString() : '—'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-light)' }} title="Backend server arrival time">
                        {r.receivedAt ? new Date(r.receivedAt).toLocaleTimeString() : '—'}
                      </td>
                      <td>
                        <StatusBadge status={r.signatureStatus} />
                      </td>
                      <td>
                        <StatusBadge status={r.protocolStatus} />
                      </td>
                      <td>
                        <StatusBadge status={r.witnessStatus} />
                      </td>
                      <td className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }} title={r.payloadHash}>
                        {r.payloadHash.slice(0, 10)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No telemetry readings found</div>
              <p>There are no telemetry records matching the current selection.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
