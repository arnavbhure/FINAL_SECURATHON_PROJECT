import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.js';
import {
  Shield,
  Eye,
  EyeOff,
  AlertCircle,
  ArrowRight,
  Sparkles,
  ChevronLeft,
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const { login, user } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [selectedRole, setSelectedRole] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Demo mode is explicitly checked for local evaluation
  const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true';

  // If already logged in, redirect to dashboard overview
  React.useEffect(() => {
    if (user) {
      navigate('/', { replace: true });
    }
  }, [user, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      await login(email.trim(), password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err.message || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = (roleKey: string, quickEmail: string) => {
    setSelectedRole(roleKey);
    setEmail(quickEmail);
    setPassword('DemoPassword123!');
  };

  return (
    <div className="betterstack-login-page">
      {/* Top Left Navigation Pill (Better Stack Template) */}
      <div className="betterstack-top-bar">
        <button
          type="button"
          onClick={() => navigate('/')}
          className="betterstack-back-btn"
          title="Return to Dashboard"
        >
          <ChevronLeft size={15} />
          <span>Back to EnviroTrust</span>
        </button>
      </div>

      {/* Centered Floating Authentication Container */}
      <div className="betterstack-login-container">
        {/* Brand Icon Mark */}
        <div className="betterstack-brand-squircle">
          <Shield size={24} className="betterstack-brand-icon" />
        </div>

        {/* Headline & Subtitle */}
        <h1 className="betterstack-title">Welcome back</h1>
        <p className="betterstack-subtitle">
          Sign in to access verified sensor telemetry & audit records.
        </p>

        {/* Error Alert Box */}
        {error && (
          <div className="betterstack-alert-error">
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="betterstack-form">
          <div className="betterstack-field-group">
            <label className="betterstack-label" htmlFor="betterstack-email">
              E-mail
            </label>
            <input
              id="betterstack-email"
              type="email"
              className="betterstack-input"
              placeholder="operator@envirotrust.local"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setSelectedRole(null);
              }}
              disabled={loading}
              autoComplete="username"
              required
            />
          </div>

          <div className="betterstack-field-group">
            <div className="betterstack-label-row">
              <label className="betterstack-label" htmlFor="betterstack-password">
                Password
              </label>
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="betterstack-toggle-password-btn"
              >
                {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                <span>{showPassword ? 'Hide' : 'Show'}</span>
              </button>
            </div>
            <div className="betterstack-password-wrap">
              <input
                id="betterstack-password"
                type={showPassword ? 'text' : 'password'}
                className="betterstack-input"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                autoComplete="current-password"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            className="betterstack-submit-btn"
            disabled={loading}
          >
            <span>{loading ? 'Authenticating terminal...' : 'Sign in to Dashboard'}</span>
            {!loading && <ArrowRight size={16} />}
          </button>
        </form>

        {/* Demo Profiles Quick Login (Preserved for Local Evaluation under isDemoMode) */}
        {isDemoMode && (
          <div className="betterstack-demo-section">
            <div className="betterstack-divider">
              <span>or quick demo profile</span>
            </div>

            <div className="betterstack-demo-roles">
              <button
                type="button"
                className={`betterstack-role-pill ${selectedRole === 'admin' ? 'active' : ''}`}
                onClick={() => handleQuickLogin('admin', 'admin@envirotrust.local')}
                title="Sign in as Platform Administrator"
              >
                <span className="betterstack-role-dot red" />
                <span>Admin</span>
              </button>

              <button
                type="button"
                className={`betterstack-role-pill ${selectedRole === 'operator' ? 'active' : ''}`}
                onClick={() => handleQuickLogin('operator', 'operator@envirotrust.local')}
                title="Sign in as Plant Operator"
              >
                <span className="betterstack-role-dot blue" />
                <span>Operator</span>
              </button>

              <button
                type="button"
                className={`betterstack-role-pill ${selectedRole === 'auditor' ? 'active' : ''}`}
                onClick={() => handleQuickLogin('auditor', 'auditor@envirotrust.local')}
                title="Sign in as Regulatory Auditor"
              >
                <span className="betterstack-role-dot slate" />
                <span>Auditor</span>
              </button>
            </div>
          </div>
        )}

        {/* Footer Legal & Protocol Note */}
        <div className="betterstack-footer">
          <p>
            You are accessing a regulated industrial terminal protected by{' '}
            <strong>RFC 8785 canonical verification</strong> and{' '}
            <strong>ES256 session tokens</strong>.
          </p>
          <div className="betterstack-watermark">
            SIMULATED DATA — HACKATHON PROTOTYPE
          </div>
        </div>
      </div>
    </div>
  );
};
