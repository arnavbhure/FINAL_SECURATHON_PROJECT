import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext.js';
import { api } from '../api/client.js';
import type {
  WitnessCheckpoint,
  AuditEvent,
  SecurityEvent,
  ChainVerificationResult,
  RecordVerificationResult,
} from '../types/index.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import {
  FileCheck2,
  Shield,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  Key,
  Building2,
} from 'lucide-react';

export const AuditPage: React.FC = () => {
  const { selectedSite } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [checkpoint, setCheckpoint] = useState<WitnessCheckpoint | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);

  // Interactive Verification states
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [chainResult, setChainResult] = useState<ChainVerificationResult | null>(null);

  const [reconcileMessageId, setReconcileMessageId] = useState('');
  const [reconcilePayloadHash, setReconcilePayloadHash] = useState('');
  const [reconcileSignature, setReconcileSignature] = useState('');
  const [reconciling, setReconciling] = useState(false);
  const [reconcileResult, setReconcileResult] = useState<RecordVerificationResult | null>(null);

  const stationId = selectedSite === 'PLANT-002' ? 'STATION-002' : 'STATION-001';

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. Witness Checkpoint
      try {
        const cp = await api.getLatestWitnessCheckpoint(stationId);
        setCheckpoint(cp);
      } catch {
        setCheckpoint(null);
      }

      // 2. Primary Audit Events
      try {
        const ae = await api.getAuditEvents(selectedSite, 50);
        setAuditEvents(ae);
      } catch {
        setAuditEvents([]);
      }

      // 3. Security Events
      try {
        const se = await api.getSecurityEvents(selectedSite, 50);
        setSecurityEvents(se);
      } catch {
        setSecurityEvents([]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch audit data');
    } finally {
      setLoading(false);
    }
  }, [selectedSite, stationId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle Chain Recomputation Verification
  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const result = await api.verifyWitnessChain(stationId, 1);
      setChainResult(result);
    } catch (err: any) {
      alert(`Chain verification failed: ${err.message}`);
    } finally {
      setVerifyingChain(false);
    }
  };

  // Handle Cross-Check Record
  const handleReconcileRecord = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reconcileMessageId || !reconcilePayloadHash || !reconcileSignature) {
      alert('Please fill in Message ID, Payload Hash, and Signature to verify.');
      return;
    }
    setReconciling(true);
    try {
      const res = await api.verifyWitnessRecord(
        reconcileMessageId.trim(),
        reconcilePayloadHash.trim(),
        reconcileSignature.trim()
      );
      setReconcileResult(res);
    } catch (err: any) {
      alert(`Record reconciliation failed: ${err.message}`);
    } finally {
      setReconciling(false);
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              Audit Chain & Independent Witness Verification
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
              <span>{selectedSite} • {stationId}</span>
            </span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            Zero-trust cryptographic hash chain verification, dual-delivery cross-checking, and external signed checkpoints.
          </p>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={loadData} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh Data</span>
        </button>
      </div>

      {error && (
        <div className="alert-box danger">
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Architecture Advisory Notice */}
      <div className="alert-box info" style={{ marginBottom: 28 }}>
        <Shield size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Architectural Guarantee:</strong> The Simulated Independent Witness operates as an autonomous service process with separate credentials and isolated PostgreSQL persistence. It independently verifies Ed25519 signatures upon dual-delivery, maintains a separate cryptographic hash chain, and issues signed periodic checkpoints.
        </div>
      </div>

      {/* Grid: Checkpoint Card & Chain Verification Tool */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 24, marginBottom: 28 }}>
        {/* Latest Witness Checkpoint Card */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <div className="card-title">
                <FileCheck2 size={18} color="var(--air-force-blue)" />
                <span>Latest Signed Witness Checkpoint</span>
              </div>
              <div className="card-subtitle">Anchored checkpoint signed by witness private key</div>
            </div>
            {checkpoint && (
              <span
                style={{
                  fontSize: '0.6875rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  backgroundColor: 'var(--color-success-bg)',
                  color: 'var(--color-success)',
                  padding: '3px 10px',
                  borderRadius: 'var(--radius-full)',
                  border: '1px solid var(--color-success-border)',
                }}
              >
                CONFIRMED
              </span>
            )}
          </div>
          <div className="card-body">
            {checkpoint ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Checkpoint Sequence:</span>
                  <span className="mono" style={{ fontWeight: 800, fontSize: '1.25rem', color: 'var(--carbon-black)' }}>
                    #{checkpoint.checkpointSequence}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Events Anchored:</span>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--text-main)' }}>{checkpoint.lastWitnessSequence}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Chain Head Hash:</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }} title={checkpoint.chainHeadHash}>
                    {checkpoint.chainHeadHash.slice(0, 24)}...
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Witness Key ID:</span>
                  <span className="mono" style={{ color: 'var(--text-main)' }}>{checkpoint.witnessKeyId}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Witness Fingerprint:</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }} title={checkpoint.witnessPublicKeyFingerprint}>
                    {checkpoint.witnessPublicKeyFingerprint.slice(0, 20)}...
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Signed At:</span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {new Date(checkpoint.createdAt).toLocaleString()}
                  </span>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-state-title">No checkpoints anchored yet</div>
                <p>Checkpoints are signed periodically every 10 events on the witness service.</p>
              </div>
            )}
          </div>
        </div>

        {/* Chain Verification Tool Card */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <div className="card-title">
                <Shield size={18} color="var(--air-force-blue)" />
                <span>Witness Hash Chain Verifier</span>
              </div>
              <div className="card-subtitle">Independent verification of uninterrupted SHA-256 chain continuity</div>
            </div>
          </div>
          <div className="card-body">
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 18, lineHeight: 1.5 }}>
              Initiate complete cryptographic recomputation of all events recorded on the witness service for station <strong>{stationId}</strong>, checking Genesis hash, sequence continuity, and previous-hash pointers.
            </p>

            <button
              className="btn btn-primary"
              onClick={handleVerifyChain}
              disabled={verifyingChain}
              style={{ width: '100%', marginBottom: 18 }}
            >
              <RefreshCw size={16} className={verifyingChain ? 'spin' : ''} />
              <span>{verifyingChain ? 'Recomputing Hash Chain...' : 'Verify Witness Chain Integrity'}</span>
            </button>

            {chainResult && (
              <div
                style={{
                  background: chainResult.valid ? 'var(--color-success-bg)' : 'var(--color-danger-bg)',
                  border: `1px solid ${chainResult.valid ? 'var(--color-success-border)' : 'var(--color-danger-border)'}`,
                  borderRadius: 'var(--radius-md)',
                  padding: '14px 16px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 800, color: chainResult.valid ? 'var(--color-success)' : 'var(--color-danger)' }}>
                  {chainResult.valid ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
                  <span>{chainResult.valid ? 'Chain Verified: Zero Discrepancies' : 'Integrity Failure Detected'}</span>
                </div>
                <div style={{ fontSize: '0.75rem', marginTop: 6, color: 'var(--text-main)' }}>
                  Verified <strong>{chainResult.eventCount}</strong> events up to sequence <strong>#{chainResult.headSequence}</strong>.
                  Head Hash: <code style={{ fontSize: '0.6875rem' }}>{chainResult.headHash.slice(0, 16)}...</code>
                </div>
                {chainResult.discrepancies.length > 0 && (
                  <ul style={{ color: 'var(--color-danger)', fontSize: '0.75rem', marginTop: 8, paddingLeft: 16 }}>
                    {chainResult.discrepancies.map((d, i) => (
                      <li key={i}>{d.reason}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Cross-Check Record Against Witness Tool Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Search size={18} color="var(--air-force-blue)" />
            <span>Cross-Check Primary Telemetry Record with Independent Witness</span>
          </div>
          <div className="card-subtitle">Prove that primary database record strictly matches independent witness dual-delivery receipt</div>
        </div>
        <div className="card-body">
          <form onSubmit={handleReconcileRecord} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, alignItems: 'flex-end' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Telemetry Message ID (UUID)</label>
              <input
                className="form-input"
                placeholder="00000000-0000-0000-0000-000000000000"
                value={reconcileMessageId}
                onChange={(e) => setReconcileMessageId(e.target.value)}
                required
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Primary Payload SHA-256 Hash</label>
              <input
                className="form-input"
                placeholder="64-character lowercase hex hash"
                value={reconcilePayloadHash}
                onChange={(e) => setReconcilePayloadHash(e.target.value)}
                required
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Ed25519 Base64 Signature</label>
              <input
                className="form-input"
                placeholder="88-character Base64 signature"
                value={reconcileSignature}
                onChange={(e) => setReconcileSignature(e.target.value)}
                required
              />
            </div>
            <div>
              <button type="submit" className="btn btn-secondary" style={{ width: '100%' }} disabled={reconciling}>
                <span>{reconciling ? 'Checking Witness...' : 'Cross-Check Record'}</span>
              </button>
            </div>
          </form>

          {reconcileResult && (
            <div style={{ marginTop: 18 }}>
              <div
                style={{
                  padding: '14px 16px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid',
                  backgroundColor: reconcileResult.status === 'MATCHED' ? 'var(--color-success-bg)' : 'var(--color-danger-bg)',
                  borderColor: reconcileResult.status === 'MATCHED' ? 'var(--color-success-border)' : 'var(--color-danger-border)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                }}
              >
                {reconcileResult.status === 'MATCHED' ? (
                  <CheckCircle2 size={20} color="var(--color-success)" />
                ) : (
                  <XCircle size={20} color="var(--color-danger)" />
                )}
                <div>
                  <div style={{ fontWeight: 800, color: reconcileResult.status === 'MATCHED' ? 'var(--color-success)' : 'var(--color-danger)' }}>
                    Reconciliation Status: {reconcileResult.status}
                  </div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-main)', marginTop: 2 }}>
                    {reconcileResult.status === 'MATCHED'
                      ? `Confirmed! Independent witness received identical payload hash and signature at sequence #${reconcileResult.witnessSequence}.`
                      : reconcileResult.reason || 'Verification failed.'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Primary Audit Chain Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Key size={18} color="var(--air-force-blue)" />
              <span>Primary Application Audit Chain</span>
            </div>
            <div className="card-subtitle">
              Append-only SHA-256 hash-chained event ledger for station {stationId}
            </div>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {auditEvents.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Sequence</th>
                    <th>Event Type</th>
                    <th>Entity / Message</th>
                    <th>Previous Hash</th>
                    <th>Current Event Hash</th>
                    <th>Recorded At</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((ae) => (
                    <tr key={ae.id}>
                      <td className="mono" style={{ fontWeight: 800, color: 'var(--carbon-black)' }}>
                        #{ae.eventSequence}
                      </td>
                      <td>
                        <StatusBadge status={ae.eventType} />
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }}>
                        {ae.entityId || (ae.messageId ? ae.messageId.slice(0, 8) + '...' : '—')}
                      </td>
                      <td className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }} title={ae.previousHash || ''}>
                        {ae.previousHash ? ae.previousHash.slice(0, 16) + '...' : 'GENESIS'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-main)' }} title={ae.eventHash}>
                        {ae.eventHash.slice(0, 16)}...
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {ae.createdAt ? new Date(ae.createdAt).toLocaleTimeString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No audit events recorded</div>
              <p>Primary hash chain events will appear here upon ingestion of telemetry and heartbeats.</p>
            </div>
          )}
        </div>
      </div>

      {/* Security Events Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <AlertTriangle size={18} color="var(--color-danger)" />
              <span>Security Events & Tampering Log</span>
            </div>
            <div className="card-subtitle">
              Protocol violations: invalid signatures, replayed sequences, timestamp anomalies
            </div>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {securityEvents.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Occurred At</th>
                    <th>Event Type</th>
                    <th>Reason Code</th>
                    <th>Sensor</th>
                    <th>Metadata Details</th>
                  </tr>
                </thead>
                <tbody>
                  {securityEvents.map((se) => (
                    <tr key={se.id}>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {se.occurredAt ? new Date(se.occurredAt).toLocaleString() : '—'}
                      </td>
                      <td>
                        <StatusBadge status={se.eventType} />
                      </td>
                      <td className="mono" style={{ fontWeight: 800, color: 'var(--color-danger)' }}>
                        {se.reasonCode}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-main)' }}>{se.sensorId || '—'}</td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {JSON.stringify(se.metadata)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">Zero security anomalies logged</div>
              <p>No replayed sequences or forged cryptographic signatures detected for {selectedSite}.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
