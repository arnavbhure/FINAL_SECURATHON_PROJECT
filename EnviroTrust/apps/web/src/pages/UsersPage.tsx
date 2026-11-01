import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api/client.js';
import type { User, UserRole } from '../types/index.js';
import { StatusBadge } from '../components/common/StatusBadge.js';
import {
  Users,
  UserPlus,
  RefreshCw,
  AlertCircle,
  Shield,
  CheckCircle2,
  X,
  History,
  Trash2,
  Plus,
} from 'lucide-react';

export const UsersPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [users, setUsers] = useState<User[]>([]);
  const [adminAuditEvents, setAdminAuditEvents] = useState<any[]>([]);

  // Create User Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('FACTORY_OPERATOR');
  const [newSite, setNewSite] = useState('PLANT-001');
  const [creating, setCreating] = useState(false);

  // Site Assign Modal state
  const [selectedUserForSite, setSelectedUserForSite] = useState<User | null>(null);
  const [siteToAssign, setSiteToAssign] = useState('PLANT-002');
  const [assigningSite, setAssigningSite] = useState(false);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const u = await api.getUsers();
      setUsers(u);

      try {
        const events = await api.getAdminAuditEvents(50);
        setAdminAuditEvents(events);
      } catch {
        setAdminAuditEvents([]);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch user list');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEmail || !newPassword) {
      setError('Email and password are required.');
      return;
    }
    setCreating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await api.createUser({
        email: newEmail.trim(),
        password: newPassword,
        name: newName.trim() || undefined,
        role: newRole,
        sites: newRole !== 'PLATFORM_ADMIN' ? [newSite] : [],
      });
      setSuccessMsg(`User ${newEmail} created successfully.`);
      setShowCreateModal(false);
      setNewEmail('');
      setNewPassword('');
      setNewName('');
      await fetchUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    if (!confirm(`Are you sure you want to change this user's role to ${newRole}? This will invalidate active sessions immediately.`)) {
      return;
    }
    try {
      await api.updateUserRole(userId, newRole);
      setSuccessMsg(`User role updated to ${newRole}.`);
      await fetchUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to update user role');
    }
  };

  const handleStatusToggle = async (user: User) => {
    const targetStatus = user.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    if (!confirm(`Are you sure you want to set status to ${targetStatus} for ${user.email}?`)) {
      return;
    }
    try {
      await api.updateUserStatus(user.id, targetStatus);
      setSuccessMsg(`User ${user.email} status updated to ${targetStatus}.`);
      await fetchUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to update user status');
    }
  };

  const handleAssignSite = async () => {
    if (!selectedUserForSite) return;
    setAssigningSite(true);
    try {
      await api.assignSite(selectedUserForSite.id, siteToAssign);
      setSuccessMsg(`Site ${siteToAssign} assigned to ${selectedUserForSite.email}.`);
      setSelectedUserForSite(null);
      await fetchUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to assign site');
    } finally {
      setAssigningSite(false);
    }
  };

  const handleRemoveSite = async (userId: string, siteId: string) => {
    if (!confirm(`Remove site membership '${siteId}' for this user?`)) return;
    try {
      await api.removeSite(userId, siteId);
      setSuccessMsg(`Site membership removed.`);
      await fetchUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to remove site membership');
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              User Management & Administrative Governance
            </h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                backgroundColor: 'var(--bg-surface-accent)',
                color: 'var(--text-muted)',
                padding: '4px 12px',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 700,
                border: '1px solid var(--border-subtle)',
              }}
            >
              <Shield size={13} />
              <span>PLATFORM ADMIN ONLY</span>
            </span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            Manage human operator accounts, role-based access control, and site-scoped cryptographic boundary assignments.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={fetchUsers} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowCreateModal(true)}>
            <UserPlus size={14} />
            <span>Create New User</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="alert-box danger">
          <AlertCircle size={18} />
          <div>{error}</div>
        </div>
      )}

      {successMsg && (
        <div className="alert-box info" style={{ backgroundColor: 'var(--color-success-bg)', borderColor: 'var(--color-success-border)', color: 'var(--color-success)' }}>
          <CheckCircle2 size={18} />
          <div>{successMsg}</div>
        </div>
      )}

      {/* Users Table Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Users size={18} color="var(--air-force-blue)" />
              <span>Registered Human Accounts</span>
            </div>
            <div className="card-subtitle">
              All human access tokens are verified server-side with session-level revocation checks
            </div>
          </div>
          <span className="brand-badge" style={{ backgroundColor: 'var(--carbon-black)', color: 'var(--snow)' }}>
            Admin Restricted
          </span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {users.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Email Address</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Assigned Sites</th>
                    <th>Created At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td style={{ fontWeight: 700, color: 'var(--text-main)' }}>
                        {u.email}
                        {u.name && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', fontWeight: 500 }}>{u.name}</span>}
                      </td>
                      <td>
                        <select
                          className="form-select"
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.id, e.target.value)}
                          style={{ padding: '4px 10px', fontSize: '0.75rem', width: 'auto', borderRadius: 'var(--radius-sm)' }}
                        >
                          <option value="PLATFORM_ADMIN">PLATFORM_ADMIN</option>
                          <option value="FACTORY_OPERATOR">FACTORY_OPERATOR</option>
                          <option value="REGULATOR_AUDITOR">REGULATOR_AUDITOR</option>
                        </select>
                      </td>
                      <td>
                        <StatusBadge status={u.status} />
                      </td>
                      <td>
                        {u.role === 'PLATFORM_ADMIN' ? (
                          <span style={{ fontSize: '0.75rem', color: 'var(--color-success)', fontWeight: 700 }}>All Sites (Global)</span>
                        ) : u.sites && u.sites.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                            {u.sites.map((s) => (
                              <span
                                key={s}
                                className="mono"
                                style={{
                                  background: 'var(--bg-surface-accent)',
                                  border: '1px solid var(--border-subtle)',
                                  padding: '3px 8px',
                                  borderRadius: 'var(--radius-full)',
                                  fontSize: '0.6875rem',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 6,
                                  color: 'var(--text-main)',
                                }}
                              >
                                {s}
                                <button
                                  type="button"
                                  onClick={() => handleRemoveSite(u.id, s)}
                                  title={`Remove ${s}`}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    padding: 0,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    color: 'var(--text-muted)',
                                  }}
                                >
                                  <X size={12} />
                                </button>
                              </span>
                            ))}
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: '2px 6px', fontSize: '0.625rem', borderRadius: 'var(--radius-full)' }}
                              onClick={() => setSelectedUserForSite(u)}
                              title="Add site membership"
                            >
                              <Plus size={10} />
                            </button>
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.75rem', color: 'var(--color-danger)', fontWeight: 600 }}>No sites assigned</span>
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—'}
                      </td>
                      <td>
                        <button
                          className={`btn btn-sm ${u.status === 'ACTIVE' ? 'btn-danger' : 'btn-secondary'}`}
                          onClick={() => handleStatusToggle(u)}
                        >
                          {u.status === 'ACTIVE' ? 'Disable' : 'Enable'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No human users registered</div>
              <p>Run seed script or use the button above to register an account.</p>
            </div>
          )}
        </div>
      </div>

      {/* Administrative Audit Events Card */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <History size={18} color="var(--air-force-blue)" />
              <span>Administrative & Authentication Audit Trail</span>
            </div>
            <div className="card-subtitle">
              Durably recorded administrative mutations and authentication events (never exposing secrets)
            </div>
          </div>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {adminAuditEvents.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Target User</th>
                    <th>IP / Client</th>
                    <th>Metadata Details</th>
                  </tr>
                </thead>
                <tbody>
                  {adminAuditEvents.map((e, idx) => (
                    <tr key={idx}>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(e.created_at || e.createdAt).toLocaleString()}
                      </td>
                      <td>
                        <StatusBadge status={e.event_type || e.eventType || 'ADMIN_ACTION'} />
                      </td>
                      <td style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{e.actor_email || e.actorEmail || 'System'}</td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>{e.target_email || e.targetEmail || '—'}</td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-light)' }}>
                        {e.ip_address || e.ipAddress || '127.0.0.1'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: 280 }}>
                        {JSON.stringify(e.metadata || e.sanitized_metadata || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-title">No audit records logged yet</div>
              <p>Administrative mutations will append tamper-evident audit logs here.</p>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Create User */}
      {showCreateModal && (
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
              maxWidth: 500,
              width: '100%',
              boxShadow: 'var(--shadow-lg)',
              padding: 32,
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-main)' }}>Register New User</h3>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setShowCreateModal(false)}
                style={{ padding: 6, borderRadius: 'var(--radius-full)' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateUser}>
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  placeholder="analyst@plant.local"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Full Name (Optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Jane Doe"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Password</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Minimum 8 characters"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Role</label>
                <select
                  className="form-select"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                >
                  <option value="FACTORY_OPERATOR">FACTORY_OPERATOR (Site-scoped)</option>
                  <option value="REGULATOR_AUDITOR">REGULATOR_AUDITOR (Read-only)</option>
                  <option value="PLATFORM_ADMIN">PLATFORM_ADMIN (Global)</option>
                </select>
              </div>

              {newRole !== 'PLATFORM_ADMIN' && (
                <div className="form-group">
                  <label className="form-label">Initial Site Scope</label>
                  <select
                    className="form-select"
                    value={newSite}
                    onChange={(e) => setNewSite(e.target.value)}
                  >
                    <option value="PLANT-001">PLANT-001 — Mumbai Chemical Effluent Treatment</option>
                    <option value="PLANT-002">PLANT-002 — Pune Industrial Wastewater Complex</option>
                  </select>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 28 }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={creating}>
                  <span>{creating ? 'Creating User...' : 'Create User'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Assign Site Membership */}
      {selectedUserForSite && (
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
              maxWidth: 420,
              width: '100%',
              boxShadow: 'var(--shadow-lg)',
              padding: 28,
              border: '1px solid var(--border-subtle)',
            }}
          >
            <h3 style={{ fontSize: '1.1875rem', fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
              Assign Site Membership
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 18 }}>
              Grant <strong>{selectedUserForSite.email}</strong> access to an additional industrial site.
            </p>

            <div className="form-group">
              <label className="form-label">Site Code</label>
              <select
                className="form-select"
                value={siteToAssign}
                onChange={(e) => setSiteToAssign(e.target.value)}
              >
                <option value="PLANT-001">PLANT-001 (Mumbai Chemical)</option>
                <option value="PLANT-002">PLANT-002 (Pune Industrial)</option>
              </select>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 24 }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedUserForSite(null)}
                disabled={assigningSite}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleAssignSite}
                disabled={assigningSite}
              >
                <span>{assigningSite ? 'Assigning...' : 'Assign Site'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
