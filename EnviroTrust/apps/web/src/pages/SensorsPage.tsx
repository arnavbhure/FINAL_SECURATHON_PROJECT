import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext.js';
import { api } from '../api/client.js';
import type { SensorHealth, HeartbeatRecord } from '../types/index.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import { Radio, RefreshCw, AlertCircle, History, Info, X, Building2 } from 'lucide-react';

export const SensorsPage: React.FC = () => {
  const { selectedSite } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sensors, setSensors] = useState<SensorHealth[]>([]);

  // Heartbeat history drawer state
  const [selectedSensorId, setSelectedSensorId] = useState<string | null>(null);
  const [heartbeatHistory, setHeartbeatHistory] = useState<HeartbeatRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const isFetchingRef = React.useRef(false);

  const fetchSensors = useCallback(async (silent = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    if (!silent) setLoading(true);
    setError(null);
    try {
      const data = await api.getAllSensorsHealth(selectedSite);
      setSensors(data);
    } catch (err: any) {
      if (!silent) setError(err.message || 'Failed to fetch sensor availability');
    } finally {
      isFetchingRef.current = false;
      if (!silent) setLoading(false);
    }
  }, [selectedSite]);

  useEffect(() => {
    fetchSensors(false);
    const interval = setInterval(() => {
      if (!isFetchingRef.current && document.visibilityState === 'visible') {
        fetchSensors(true);
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [fetchSensors]);

  // Open heartbeat history
  const handleViewHistory = async (sensorId: string) => {
    setSelectedSensorId(sensorId);
    setLoadingHistory(true);
    try {
      const history = await api.getHeartbeatsHistory(sensorId, selectedSite);
      setHeartbeatHistory(history);
    } catch (err: any) {
      console.error('Failed to load heartbeat history:', err);
      setHeartbeatHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  // Helper to format sensor display name and unit
  const formatSensorId = (s: SensorHealth) => {
    if (s.sensorCode && s.sensorCode.trim()) return s.sensorCode;
    if (s.sensorId.length > 18) {
      return `${s.sensorId.slice(0, 8)}...${s.sensorId.slice(-4)}`;
    }
    return s.sensorId;
  };

  const formatParamUnit = (param: string, unit?: string) => {
    if (unit && unit.trim()) return unit.trim();
    if (param === 'COD' || param === 'TSS') return 'mg/L';
    if (param === 'pH') return 'pH';
    if (param === 'TEMP') return '°C';
    if (param === 'TURBIDITY') return 'NTU';
    return '';
  };

  return (
    <div>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              Sensor Health & Heartbeat Availability
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
            Continuous cryptographic liveness evaluation based on signed heartbeats and monotonic sequences.
          </p>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={() => fetchSensors(false)} disabled={loading}>
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

      {/* Educational Advisory Callout */}
      <div className="alert-box info" style={{ marginBottom: 28 }}>
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Operational Distinction:</strong> An <code>OFFLINE</code> state indicates communication loss over the network (e.g. gateway timeout, power disruption, or scheduled maintenance), <em>not</em> proven physical tampering or fraud.
        </div>
      </div>

      {/* Sensor Health Table Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Radio size={18} color="var(--air-force-blue)" />
            <span>Registered Sensor Devices</span>
          </div>
          <div className="card-subtitle">
            Server-side evaluated availability state machine (ONLINE &rarr; STALE &rarr; OFFLINE)
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {sensors.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Sensor ID</th>
                    <th>Station</th>
                    <th>Parameter</th>
                    <th>Availability Status</th>
                    <th>Missed Intervals</th>
                    <th>Expected Interval</th>
                    <th>Last Heartbeat Received</th>
                    <th>Primary Delivery</th>
                    <th>Witness Delivery</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sensors.map((s) => (
                    <tr key={s.sensorId}>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontWeight: 700,
                              fontSize: '0.8125rem',
                              color: 'var(--carbon-black)',
                              backgroundColor: 'var(--bg-surface-accent)',
                              padding: '3px 8px',
                              borderRadius: 'var(--radius-sm)',
                              border: '1px solid var(--border-subtle)',
                              display: 'inline-block',
                            }}
                            title={s.sensorId}
                          >
                            {formatSensorId(s)}
                          </span>
                        </div>
                      </td>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ color: 'var(--text-muted)', fontWeight: 600, fontSize: '0.8125rem' }}>
                          {s.stationCode || 'ETP-OUT-001'}
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <strong style={{ color: 'var(--carbon-black)' }}>{s.parameter}</strong>{' '}
                        {(() => {
                          const unit = formatParamUnit(s.parameter, s.unit);
                          return unit ? (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 500 }}>
                              ({unit})
                            </span>
                          ) : null;
                        })()}
                      </td>
                      <td>
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="mono" style={{ color: (s.missedIntervalsCount || 0) > 0 ? 'var(--color-danger)' : 'var(--text-main)', fontWeight: 700 }}>
                        {s.missedIntervalsCount ?? 0}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>{s.expectedIntervalSeconds}s</td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {s.lastHeartbeatReceivedAt ? new Date(s.lastHeartbeatReceivedAt).toLocaleString() : 'Never'}
                      </td>
                      <td>
                        <StatusBadge status={s.primaryDeliveryStatus || 'CONFIRMED'} />
                      </td>
                      <td>
                        <StatusBadge status={s.witnessDeliveryStatus || 'PENDING'} />
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleViewHistory(s.sensorCode || s.sensorId)}
                          title="Inspect signed heartbeat log"
                        >
                          <History size={14} />
                          <span>History</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No sensors registered for this site</div>
              <p>Key provisioning registers sensors to sites upon platform initialization.</p>
            </div>
          )}
        </div>
      </div>

      {/* Heartbeat History Modal */}
      {selectedSensorId && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(39, 42, 32, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 50,
            padding: 16,
          }}
        >
          <div
            style={{
              background: 'var(--bg-surface)',
              borderRadius: 'var(--radius-xl)',
              maxWidth: 740,
              width: '100%',
              maxHeight: '85vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: 'var(--shadow-lg)',
              overflow: 'hidden',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div
              style={{
                padding: '20px 24px',
                borderBottom: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                backgroundColor: 'var(--bg-surface-subtle)',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1.1875rem', fontWeight: 800, color: 'var(--text-main)' }}>
                  Heartbeat History: <span className="mono" style={{ color: 'var(--carbon-black)' }}>{selectedSensorId}</span>
                </h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                  Cryptographically signed heartbeat pulse log proving physical sensor liveness
                </p>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedSensorId(null)}
                style={{ padding: 6, borderRadius: 'var(--radius-full)' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: 24, overflowY: 'auto', flex: 1 }}>
              {loadingHistory ? (
                <div className="loading-spinner">
                  <span>Loading heartbeat history...</span>
                </div>
              ) : heartbeatHistory.length > 0 ? (
                <div className="table-responsive" style={{ border: 'none', borderRadius: 0 }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Sequence</th>
                        <th>Sent At (Sensor)</th>
                        <th>Received At (Server)</th>
                        <th>Signature</th>
                        <th>Message ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {heartbeatHistory.map((hb) => (
                        <tr key={hb.id}>
                          <td className="mono" style={{ fontWeight: 800, color: 'var(--carbon-black)' }}>#{hb.sequenceNo}</td>
                          <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {new Date(hb.sentAt).toLocaleTimeString()}
                          </td>
                          <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-light)' }}>
                            {new Date(hb.receivedAt).toLocaleTimeString()}
                          </td>
                          <td>
                            <StatusBadge status={hb.signatureStatus} />
                          </td>
                          <td className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                            {hb.messageId.slice(0, 8)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-title">No heartbeats received</div>
                  <p>Sensor simulator has not yet emitted heartbeats for {selectedSensorId}.</p>
                </div>
              )}
            </div>

            <div
              style={{
                padding: '16px 24px',
                borderTop: '1px solid var(--border-subtle)',
                display: 'flex',
                justifyContent: 'flex-end',
                backgroundColor: 'var(--bg-surface-subtle)',
              }}
            >
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedSensorId(null)}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
