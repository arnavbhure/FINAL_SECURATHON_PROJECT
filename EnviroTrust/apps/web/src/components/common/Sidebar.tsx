import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.js';
import { api } from '../../api/client.js';
import {
  LayoutDashboard,
  Activity,
  Radio,
  BrainCircuit,
  FileCheck2,
  Users,
  Shield,
  LogOut,
  User as UserIcon,
  CheckCircle2,
  AlertTriangle,
  FlaskConical,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const [openAlertsCount, setOpenAlertsCount] = useState<number>(0);
  const [hasCritical, setHasCritical] = useState<boolean>(false);

  useEffect(() => {
    let isMounted = true;
    const fetchSummary = async () => {
      try {
        const summary = await api.getAlertSummary();
        if (isMounted) {
          setOpenAlertsCount(summary.totalOpen || 0);
          setHasCritical(summary.critical > 0);
        }
      } catch {
        // silent fail on poll
      }
    };

    fetchSummary();
    const interval = setInterval(fetchSummary, 8000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getRoleLabel = (role?: string) => {
    switch (role) {
      case 'PLATFORM_ADMIN':
        return 'Administrator';
      case 'FACTORY_OPERATOR':
        return 'Plant Operator';
      case 'REGULATOR_AUDITOR':
        return 'Auditor';
      default:
        return 'User';
    }
  };

  const getInitials = (email?: string) => {
    if (!email) return 'ET';
    const parts = email.split('@')[0] || '';
    return parts.slice(0, 2).toUpperCase();
  };

  return (
    <aside className="sidebar">
      <div>
        {/* Brand Header */}
        <div className="sidebar-brand">
          <div className="brand-logo-container">
            <div className="brand-icon-box">
              <Shield size={20} className="brand-icon-shield" />
            </div>
            <div className="brand-text-block">
              <div className="brand-name">EnviroTrust</div>
              <div className="brand-subtext">Regulated Effluent Auditing</div>
            </div>
          </div>
        </div>

        {/* Navigation Sections */}
        <nav className="sidebar-nav">
          <div className="sidebar-section-title">Telemetry & Process</div>

          <NavLink
            to="/"
            end
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <LayoutDashboard size={19} className="nav-icon" />
            <span className="nav-label">Dashboard</span>
          </NavLink>

          <NavLink
            to="/monitoring"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Activity size={19} className="nav-icon" />
            <span className="nav-label">Sensor Telemetry</span>
          </NavLink>

          <NavLink
            to="/sensors"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Radio size={19} className="nav-icon" />
            <span className="nav-label">Fleet Availability</span>
          </NavLink>

          <NavLink
            to="/anomalies"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <BrainCircuit size={19} className="nav-icon" />
            <span className="nav-label">ML Anomaly Engine</span>
          </NavLink>

          <div className="sidebar-section-title" style={{ marginTop: '22px' }}>
            Compliance & Security
          </div>

          <NavLink
            to="/alerts"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <AlertTriangle size={19} className="nav-icon" />
            <span className="nav-label">Alerts & Incidents</span>
            {openAlertsCount > 0 && (
              <span
                style={{
                  marginLeft: 'auto',
                  fontSize: '0.68rem',
                  fontWeight: 700,
                  padding: '2px 7px',
                  borderRadius: '999px',
                  background: hasCritical ? '#ef4444' : '#f59e0b',
                  color: '#ffffff',
                }}
              >
                {openAlertsCount}
              </span>
            )}
          </NavLink>

          <NavLink
            to="/audit"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <FileCheck2 size={19} className="nav-icon" />
            <span className="nav-label">Witness Hash Chain</span>
            <span className="nav-badge-verified">
              <CheckCircle2 size={11} />
            </span>
          </NavLink>

          <NavLink
            to="/attack-lab"
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <FlaskConical size={19} className="nav-icon" />
            <span className="nav-label">Attack Simulation Lab</span>
          </NavLink>

          {user?.role === 'PLATFORM_ADMIN' && (
            <NavLink
              to="/users"
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Users size={19} className="nav-icon" />
              <span className="nav-label">User Management</span>
            </NavLink>
          )}
        </nav>
      </div>

      {/* User Card & Logout (TABELA Inspired) */}
      <div className="sidebar-footer">
        <div className="sidebar-user-card">
          <div className="user-avatar-circle">
            <span className="user-avatar-text">{getInitials(user?.email)}</span>
          </div>
          <div className="user-info-text">
            <div className="user-display-email" title={user?.email}>
              {user?.email?.split('@')[0] || 'User'}
            </div>
            <div className="user-display-role">{getRoleLabel(user?.role)}</div>
          </div>
        </div>

        <button
          type="button"
          className="sidebar-logout-btn"
          onClick={() => logout()}
          title="Sign out of active session"
        >
          <LogOut size={16} />
          <span>Log Out</span>
        </button>
      </div>
    </aside>
  );
};
