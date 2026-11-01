import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.js';
import { api } from '../../api/client.js';
import type { UserRole } from '../../types/index.js';
import { ShieldAlert } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();

  // If loading finished and no token exists in memory or cookie, fail closed to /login
  if (!loading && !api.getToken()) {
    return <Navigate to="/login" replace />;
  }

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#111318',
          color: '#94a3b8',
        }}
      >
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: '50%',
            border: '3px solid rgba(75, 136, 162, 0.2)',
            borderTopColor: 'var(--air-force-blue)',
            animation: 'spin 0.8s linear infinite',
            marginBottom: 16,
          }}
        />
        <div style={{ fontWeight: 600, fontSize: '0.875rem', letterSpacing: '0.02em', color: '#cbd5e1' }}>
          Verifying session credentials...
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return (
      <div className="card" style={{ maxWidth: 600, margin: '60px auto' }}>
        <div className="card-header">
          <div className="card-title" style={{ color: 'var(--color-danger)' }}>
            <ShieldAlert size={20} />
            <span>403 — Unauthorized Role Access</span>
          </div>
        </div>
        <div className="card-body">
          <p style={{ marginBottom: 16 }}>
            Your account role <strong>{user.role}</strong> does not have permission to access this administrative module.
          </p>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            All platform data access is strictly enforced server-side. Contact your system administrator if you believe your assigned permissions are incorrect.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

