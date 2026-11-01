import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client.js';
import { useAuth } from '../context/AuthContext.js';
import type { Alert, AlertSummary, AlertSeverity, AlertStatus, AlertType } from '../types/index.js';
import {
  AlertTriangle,
  ShieldAlert,
  AlertOctagon,
  CheckCircle2,
  Clock,
  Filter,
  RefreshCw,
  Search,
  ExternalLink,
  X,
  Radio,
  FileCheck,
  Building,
  Info,
  Zap,
  Check,
} from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const { user } = useAuth();
  const isAuditor = user?.role === 'REGULATOR_AUDITOR';

  // State
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary>({
    totalOpen: 0,
    critical: 0,
    high: 0,
    warning: 0,
    resolved: 0,
    activeIncidents: 0,
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSite, setSelectedSite] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected Alert for Details Drawer/Modal
  const [activeAlert, setActiveAlert] = useState<Alert | null>(null);
  const [resolutionNote, setResolutionNote] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [actionFeedback, setActionFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Fetch summary and alerts
  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [alertsRes, summaryRes] = await Promise.all([
        api.getAlerts({
          siteId: selectedSite || undefined,
          severity: selectedSeverity || undefined,
          status: selectedStatus || undefined,
          alertType: selectedType || undefined,
          limit: 100,
        }),
        api.getAlertSummary(selectedSite || undefined),
      ]);

      setAlerts(alertsRes.alerts || []);
      setSummary(summaryRes);
    } catch (err: any) {
      setError(err.message || 'Failed to load alerts data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedSite, selectedSeverity, selectedStatus, selectedType]);

  useEffect(() => {
    fetchData();
    // 8-second authenticated poll for real-time alerts
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  // Acknowledge alert
  const handleAcknowledge = async (alertId: string) => {
    if (isAuditor) return;
    setActionLoading(true);
    setActionFeedback(null);
    try {
      const updated = await api.acknowledgeAlert(alertId);
      setActiveAlert(updated);
      setActionFeedback({ type: 'success', message: 'Alert acknowledged successfully.' });
      fetchData();
    } catch (err: any) {
      setActionFeedback({ type: 'error', message: err.message || 'Failed to acknowledge alert.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Resolve alert
  const handleResolve = async (alertId: string) => {
    if (isAuditor) return;
    if (!resolutionNote.trim() || resolutionNote.trim().length < 3) {
      setActionFeedback({ type: 'error', message: 'Please provide a resolution note of at least 3 characters.' });
      return;
    }
    setActionLoading(true);
    setActionFeedback(null);
    try {
      const updated = await api.resolveAlert(alertId, resolutionNote.trim());
      setActiveAlert(updated);
      setResolutionNote('');
      setActionFeedback({ type: 'success', message: 'Incident resolved successfully.' });
      fetchData();
    } catch (err: any) {
      setActionFeedback({ type: 'error', message: err.message || 'Failed to resolve incident.' });
    } finally {
      setActionLoading(false);
    }
  };

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchTitle = a.title?.toLowerCase().includes(q);
        const matchDesc = a.description?.toLowerCase().includes(q);
        const matchSensor = a.sensor_code?.toLowerCase().includes(q);
        const matchSite = a.site_code?.toLowerCase().includes(q);
        if (!matchTitle && !matchDesc && !matchSensor && !matchSite) return false;
      }
      return true;
    });
  }, [alerts, searchQuery]);

  const getSeverityBadge = (severity: AlertSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="badge badge-critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#fee2e2', color: '#b91c1c', border: '1px solid #f87171', padding: '3px 8px', borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700 }}>
            <ShieldAlert size={12} /> CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="badge badge-high" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#ffedd5', color: '#c2410c', border: '1px solid #fb923c', padding: '3px 8px', borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700 }}>
            <AlertTriangle size={12} /> HIGH
          </span>
        );
      case 'WARNING':
        return (
          <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#fef3c7', color: '#b45309', border: '1px solid #fcd34d', padding: '3px 8px', borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700 }}>
            <AlertOctagon size={12} /> WARNING
          </span>
        );
      default:
        return (
          <span className="badge badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#e0f2fe', color: '#0369a1', border: '1px solid #7dd3fc', padding: '3px 8px', borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700 }}>
            <Info size={12} /> INFO
          </span>
        );
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'OPEN':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#fee2e2', color: '#dc2626', padding: '2px 8px', borderRadius: '999px', fontSize: '0.7rem', fontWeight: 700 }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#dc2626', display: 'inline-block' }} />
            OPEN
          </span>
        );
      case 'ACKNOWLEDGED':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#fef3c7', color: '#d97706', padding: '2px 8px', borderRadius: '999px', fontSize: '0.7rem', fontWeight: 700 }}>
            <Clock size={11} /> ACKNOWLEDGED
          </span>
        );
      case 'RESOLVED':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: '#dcfce7', color: '#15803d', padding: '2px 8px', borderRadius: '999px', fontSize: '0.7rem', fontWeight: 700 }}>
            <CheckCircle2 size={11} /> RESOLVED
          </span>
        );
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 700, color: '#0f172a', margin: 0 }}>
              Alert & Incident Management Center
            </h1>
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '3px 9px',
                borderRadius: '999px',
                background: summary.critical > 0 ? '#fee2e2' : '#f1f5f9',
                color: summary.critical > 0 ? '#b91c1c' : '#475569',
                border: `1px solid ${summary.critical > 0 ? '#f87171' : '#cbd5e1'}`,
              }}
            >
              {summary.totalOpen} Active Incident{summary.totalOpen !== 1 ? 's' : ''}
            </span>
          </div>
          <p style={{ margin: '6px 0 0 0', color: '#64748b', fontSize: '0.88rem' }}>
            Centralized zero-trust security notifications for physical sensor tampering, availability dropouts, and regulatory incidents.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            background: '#ffffff',
            border: '1px solid #cbd5e1',
            borderRadius: '8px',
            color: '#334155',
            fontWeight: 600,
            fontSize: '0.84rem',
            cursor: refreshing ? 'not-allowed' : 'pointer',
            boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
          }}
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? 'Refreshing...' : 'Refresh Alerts'}
        </button>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
        <div style={{ background: '#ffffff', borderRadius: '12px', padding: '18px 20px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Total Open Alerts
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#0f172a', marginTop: '8px' }}>
            {summary.totalOpen}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '4px' }}>
            {summary.activeIncidents} unacknowledged
          </div>
        </div>

        <div style={{ background: '#ffffff', borderRadius: '12px', padding: '18px 20px', border: '1px solid #fee2e2', borderLeft: '4px solid #ef4444', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#b91c1c', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              CRITICAL
            </span>
            <ShieldAlert size={16} color="#ef4444" />
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#b91c1c', marginTop: '8px' }}>
            {summary.critical}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#ef4444', marginTop: '4px' }}>
            Requires immediate inspection
          </div>
        </div>

        <div style={{ background: '#ffffff', borderRadius: '12px', padding: '18px 20px', border: '1px solid #ffedd5', borderLeft: '4px solid #f97316', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#c2410c', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              HIGH PRIORITY
            </span>
            <AlertTriangle size={16} color="#f97316" />
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#c2410c', marginTop: '8px' }}>
            {summary.high}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#c2410c', marginTop: '4px' }}>
            Sensor communication offline
          </div>
        </div>

        <div style={{ background: '#ffffff', borderRadius: '12px', padding: '18px 20px', border: '1px solid #fef3c7', borderLeft: '4px solid #f59e0b', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#b45309', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              WARNINGS
            </span>
            <AlertOctagon size={16} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#b45309', marginTop: '8px' }}>
            {summary.warning}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#b45309', marginTop: '4px' }}>
            Stale / missed heartbeats
          </div>
        </div>

        <div style={{ background: '#ffffff', borderRadius: '12px', padding: '18px 20px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#15803d', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              RESOLVED
            </span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: 800, color: '#15803d', marginTop: '8px' }}>
            {summary.resolved}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>
            Archived incident history
          </div>
        </div>
      </div>

      {/* Attack Simulation Lab link (scenarios run server-side against the real ingestion pipeline) */}
      <div
        style={{
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: '12px',
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={16} color="#3b82f6" />
            <span style={{ fontWeight: 700, fontSize: '0.88rem', color: '#1e293b' }}>ATTACK SIMULATION LAB</span>
            <span style={{ fontSize: '0.65rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: '#fee2e2', color: '#991b1b' }}>
              DEMO ENVIRONMENT
            </span>
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: '0.78rem', color: '#64748b' }}>
            Security alerts raised by rejected attack attempts appear in this list. Run scenarios and inspect their evidence in the lab.
          </p>
        </div>
        <Link to="/attack-lab" className="btn btn-secondary btn-sm">
          <ExternalLink size={14} />
          <span>Open Attack Simulation Lab</span>
        </Link>
      </div>

      {/* Filter Bar */}
      <div
        style={{
          background: '#ffffff',
          borderRadius: '12px',
          padding: '14px 18px',
          border: '1px solid #e2e8f0',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: '6px', padding: '6px 12px' }}>
            <Search size={14} color="#94a3b8" />
            <input
              type="text"
              placeholder="Search alerts or sensors..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '0.82rem', width: '180px' }}
            />
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f8fafc', fontSize: '0.82rem', color: '#334155' }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High Priority</option>
            <option value="WARNING">Warning</option>
            <option value="INFO">Info</option>
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f8fafc', fontSize: '0.82rem', color: '#334155' }}
          >
            <option value="">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f8fafc', fontSize: '0.82rem', color: '#334155' }}
          >
            <option value="">All Types</option>
            <option value="PHYSICAL_TAMPER">Physical Tamper</option>
            <option value="SENSOR_OFFLINE">Sensor Offline</option>
            <option value="SENSOR_STALE">Sensor Stale</option>
            <option value="SENSOR_RECOVERED">Sensor Recovered</option>
            <option value="SECURITY_EVENT">Security Event</option>
          </select>
        </div>

        <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
          Showing <strong>{filteredAlerts.length}</strong> of {alerts.length} record{alerts.length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Alerts Table Card */}
      <div style={{ background: '#ffffff', borderRadius: '12px', border: '1px solid #e2e8f0', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.02)' }}>
        {loading ? (
          <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
            <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 12px auto' }} />
            <div>Loading verified alert records...</div>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
            <CheckCircle2 size={32} color="#10b981" style={{ margin: '0 auto 12px auto' }} />
            <div style={{ fontWeight: 600, color: '#0f172a' }}>No active alerts matching filter</div>
            <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '4px' }}>
              All monitored industrial effluent sensors and stations operating within compliant security baselines.
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
              <thead>
                <tr style={{ background: '#f8fafc', borderBottom: '1px solid #e2e8f0', color: '#475569', fontWeight: 600 }}>
                  <th style={{ padding: '12px 18px' }}>Severity</th>
                  <th style={{ padding: '12px 18px' }}>Alert Title</th>
                  <th style={{ padding: '12px 18px' }}>Sensor / Station</th>
                  <th style={{ padding: '12px 18px' }}>Site</th>
                  <th style={{ padding: '12px 18px' }}>Detection Time</th>
                  <th style={{ padding: '12px 18px' }}>Status</th>
                  <th style={{ padding: '12px 18px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => {
                  const isSimulated = alert.metadata && (alert.metadata as any).simulated;
                  return (
                    <tr
                      key={alert.id}
                      style={{
                        borderBottom: '1px solid #f1f5f9',
                        transition: 'background 0.15s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = '#f8fafc')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <td style={{ padding: '14px 18px' }}>
                        {getSeverityBadge(alert.severity)}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <div style={{ fontWeight: 600, color: '#0f172a', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {alert.title}
                          {isSimulated && (
                            <span style={{ fontSize: '0.62rem', fontWeight: 700, padding: '1px 5px', borderRadius: '4px', background: '#fef3c7', color: '#b45309' }}>
                              SIMULATED
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#64748b', marginTop: '2px', maxWidth: '380px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {alert.description}
                        </div>
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <div style={{ fontWeight: 600, color: '#1e293b' }}>
                          {alert.sensor_code || 'N/A'}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                          {alert.station_code || 'ETP-OUTLET-001'}
                        </div>
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: '#475569', fontWeight: 500 }}>
                          <Building size={13} color="#94a3b8" />
                          {alert.site_code || 'PLANT-001'}
                        </span>
                      </td>
                      <td style={{ padding: '14px 18px', color: '#64748b', fontSize: '0.78rem' }}>
                        {new Date(alert.created_at).toLocaleString()}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        {getStatusBadge(alert.status)}
                      </td>
                      <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                        <button
                          onClick={() => {
                            setActiveAlert(alert);
                            setActionFeedback(null);
                            setResolutionNote('');
                          }}
                          style={{
                            padding: '5px 12px',
                            background: '#f1f5f9',
                            color: '#0f172a',
                            border: '1px solid #cbd5e1',
                            borderRadius: '6px',
                            fontWeight: 600,
                            fontSize: '0.78rem',
                            cursor: 'pointer',
                          }}
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Incident Detail Modal / Drawer */}
      {activeAlert && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '20px',
          }}
        >
          <div
            style={{
              background: '#ffffff',
              borderRadius: '16px',
              maxWidth: '680px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              padding: '28px',
              display: 'flex',
              flexDirection: 'column',
              gap: '20px',
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid #e2e8f0', paddingBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  {getSeverityBadge(activeAlert.severity)}
                  {getStatusBadge(activeAlert.status)}
                  {activeAlert.metadata && (activeAlert.metadata as any).simulated && (
                    <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', background: '#fee2e2', color: '#b91c1c' }}>
                      SIMULATED DEMO EVENT
                    </span>
                  )}
                </div>
                <h2 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#0f172a', margin: 0 }}>
                  {activeAlert.title}
                </h2>
              </div>
              <button
                onClick={() => setActiveAlert(null)}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#64748b' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Description & Overview */}
            <div style={{ background: '#f8fafc', padding: '14px 18px', borderRadius: '10px', border: '1px solid #e2e8f0', fontSize: '0.86rem', color: '#334155', lineHeight: '1.5' }}>
              {activeAlert.description}
            </div>

            {/* Key Metadata Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '0.8rem' }}>
              <div>
                <span style={{ color: '#64748b' }}>Sensor Code:</span>{' '}
                <strong style={{ color: '#0f172a' }}>{activeAlert.sensor_code || 'N/A'}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Site Code:</span>{' '}
                <strong style={{ color: '#0f172a' }}>{activeAlert.site_code || 'PLANT-001'}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Station Code:</span>{' '}
                <strong style={{ color: '#0f172a' }}>{activeAlert.station_code || 'ETP-OUTLET-001'}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Detection Source:</span>{' '}
                <strong style={{ color: '#0f172a' }}>{activeAlert.detection_source}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Created At:</span>{' '}
                <strong style={{ color: '#0f172a' }}>{new Date(activeAlert.created_at).toLocaleString()}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Source Event ID:</span>{' '}
                <code style={{ fontSize: '0.72rem', background: '#e2e8f0', padding: '2px 4px', borderRadius: '4px' }}>
                  {activeAlert.source_event_id ? activeAlert.source_event_id.slice(0, 16) + '...' : 'System'}
                </code>
              </div>
            </div>

            {/* Recommended Inspection Checklist */}
            <div style={{ border: '1px solid #e2e8f0', borderRadius: '10px', padding: '16px' }}>
              <div style={{ fontWeight: 700, fontSize: '0.84rem', color: '#0f172a', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <CheckCircle2 size={15} color="#3b82f6" />
                RECOMMENDED OPERATIONAL ACTIONS & INSPECTION CHECKLIST
              </div>
              <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.82rem', color: '#334155', lineHeight: '1.6' }}>
                {activeAlert.recommended_action.split('\n').map((line, idx) => (
                  <li key={idx}>{line.replace(/^-\s*/, '')}</li>
                ))}
              </ul>
            </div>

            {/* Authority Boundary Disclaimer */}
            <div style={{ background: '#f8fafc', borderLeft: '3px solid #64748b', padding: '10px 14px', borderRadius: '6px', fontSize: '0.75rem', color: '#475569' }}>
              <strong>Operational & Regulatory Boundary:</strong> This record is an internal dashboard alert. Automated regulatory notifications have not been dispatched to external environmental authorities. Formal compliance escalation must proceed via official channels according to applicable consent conditions.
            </div>

            {/* Resolution History / Note if already resolved */}
            {activeAlert.status === 'RESOLVED' && (
              <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', padding: '12px 16px', fontSize: '0.82rem', color: '#166534' }}>
                <div style={{ fontWeight: 700, marginBottom: '4px' }}>Resolved Incident</div>
                <div><strong>Note:</strong> {activeAlert.resolution_note || 'Resolved via verified recovery.'}</div>
                <div style={{ fontSize: '0.75rem', color: '#15803d', marginTop: '4px' }}>
                  Resolved at: {activeAlert.resolved_at ? new Date(activeAlert.resolved_at).toLocaleString() : 'N/A'}
                  {activeAlert.resolved_by_name && ` by ${activeAlert.resolved_by_name}`}
                </div>
              </div>
            )}

            {/* Action Feedback */}
            {actionFeedback && (
              <div
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '0.8rem',
                  fontWeight: 500,
                  background: actionFeedback.type === 'success' ? '#f0fdf4' : '#fef2f2',
                  color: actionFeedback.type === 'success' ? '#166534' : '#991b1b',
                  border: `1px solid ${actionFeedback.type === 'success' ? '#bbf7d0' : '#fecaca'}`,
                }}
              >
                {actionFeedback.message}
              </div>
            )}

            {/* Incident Actions (RBAC Scoped) */}
            <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {isAuditor ? (
                <div style={{ padding: '8px 12px', background: '#f1f5f9', borderRadius: '6px', fontSize: '0.8rem', color: '#64748b', textAlign: 'center' }}>
                  Regulator Auditor Role: Read-only access to alerts and incident history.
                </div>
              ) : activeAlert.status !== 'RESOLVED' ? (
                <>
                  {activeAlert.status === 'OPEN' && (
                    <button
                      onClick={() => handleAcknowledge(activeAlert.id)}
                      disabled={actionLoading}
                      style={{
                        padding: '10px 16px',
                        background: '#f59e0b',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '8px',
                        fontWeight: 600,
                        fontSize: '0.84rem',
                        cursor: actionLoading ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                      }}
                    >
                      <Clock size={16} />
                      {actionLoading ? 'Updating...' : 'Acknowledge Alert'}
                    </button>
                  )}

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                    <label style={{ fontSize: '0.8rem', fontWeight: 600, color: '#334155' }}>
                      Resolution Note (Required to resolve incident):
                    </label>
                    <textarea
                      placeholder="e.g., Physical inspection confirmed sensor seal intact. Power supply reset and telemetry validated."
                      value={resolutionNote}
                      onChange={(e) => setResolutionNote(e.target.value)}
                      rows={3}
                      style={{
                        width: '100%',
                        padding: '10px',
                        borderRadius: '8px',
                        border: '1px solid #cbd5e1',
                        fontSize: '0.82rem',
                        outline: 'none',
                        resize: 'vertical',
                      }}
                    />
                    <button
                      onClick={() => handleResolve(activeAlert.id)}
                      disabled={actionLoading || !resolutionNote.trim()}
                      style={{
                        padding: '10px 16px',
                        background: !resolutionNote.trim() ? '#94a3b8' : '#10b981',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '8px',
                        fontWeight: 600,
                        fontSize: '0.84rem',
                        cursor: !resolutionNote.trim() || actionLoading ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px',
                      }}
                    >
                      <CheckCircle2 size={16} />
                      {actionLoading ? 'Resolving...' : 'Mark Incident Resolved'}
                    </button>
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
