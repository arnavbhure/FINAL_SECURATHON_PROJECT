import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client.js';
import type { AttackLabStatus, AttackRun, AttackScenario } from '../types/index.js';
import {
  canRunScenario,
  mlResultLines,
  outcomeLabel,
  outcomeTone,
  runDurationSeconds,
  TONE_STYLES,
} from './attackLabView.js';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Circle,
  Loader2,
  Play,
  RefreshCw,
  ShieldAlert,
  FlaskConical,
  Server,
  Database,
  BrainCircuit,
  ExternalLink,
  KeyRound,
  Info,
} from 'lucide-react';

const SEVERITY_TONE: Record<AttackScenario['severity'], keyof typeof TONE_STYLES> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'info',
  LOW: 'neutral',
};

const Pill: React.FC<{ tone: keyof typeof TONE_STYLES; children: React.ReactNode; title?: string }> = ({ tone, children, title }) => {
  const s = TONE_STYLES[tone];
  return (
    <span
      title={title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        fontSize: '0.6875rem',
        fontWeight: 700,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        padding: '3px 9px',
        borderRadius: 'var(--radius-full)',
        color: s.color,
        background: s.background,
        border: `1px solid ${s.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
};

const KeyValue: React.FC<{ label: string; value: React.ReactNode; mono?: boolean }> = ({ label, value, mono }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: '0.8125rem', padding: '3px 0' }}>
    <span style={{ color: 'var(--text-muted)' }}>{label}</span>
    <span className={mono ? 'mono' : undefined} style={{ color: 'var(--text-main)', textAlign: 'right', wordBreak: 'break-all' }}>
      {value ?? '—'}
    </span>
  </div>
);

const StepIcon: React.FC<{ status: string }> = ({ status }) => {
  if (status === 'PASSED') return <CheckCircle2 size={17} color="var(--color-success)" />;
  if (status === 'FAILED') return <XCircle size={17} color="var(--color-danger)" />;
  if (status === 'RUNNING') return <Loader2 size={17} className="spin" color="var(--air-force-blue)" />;
  return <Circle size={17} color="var(--text-muted)" />;
};

function exchangeRows(outcome: Record<string, unknown> | null): Array<[string, string]> {
  if (!outcome) return [];
  const rows: Array<[string, string]> = [];
  const visit = (prefix: string, value: unknown) => {
    if (value === null || value === undefined) return;
    if (typeof value === 'object' && !Array.isArray(value)) {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) visit(prefix ? `${prefix}.${k}` : k, v);
      return;
    }
    rows.push([prefix, Array.isArray(value) ? value.join(', ') : String(value)]);
  };
  visit('', outcome);
  return rows.slice(0, 18);
}

export const AttackLabPage: React.FC = () => {
  const [status, setStatus] = useState<AttackLabStatus | null>(null);
  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [runs, setRuns] = useState<AttackRun[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeRun, setActiveRun] = useState<AttackRun | null>(null);
  const [labDisabled, setLabDisabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [starting, setStarting] = useState(false);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const selected = useMemo(() => scenarios.find((s) => s.id === selectedId) || null, [scenarios, selectedId]);

  const loadAll = useCallback(async () => {
    try {
      const [st, sc, rs] = await Promise.all([api.getAttackLabStatus(), api.getAttackLabScenarios(), api.getAttackLabRuns(25)]);
      setStatus(st);
      setScenarios(sc.scenarios);
      setRuns(rs);
      setLabDisabled(false);
      setError(null);
      setSelectedId((cur) => cur || sc.scenarios[0]?.id || null);
    } catch (err: any) {
      if (err?.status === 404) {
        setLabDisabled(true);
      } else {
        setError(err?.message || 'Failed to load Attack Lab status');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
    const id = setInterval(loadAll, 15000);
    return () => clearInterval(id);
  }, [loadAll]);

  // Poll the active run until it finishes; results come only from the persisted run record.
  const followRun = useCallback(
    (runId: string) => {
      if (pollTimer.current) clearTimeout(pollTimer.current);
      const tick = async () => {
        try {
          const run = await api.getAttackLabRun(runId);
          setActiveRun(run);
          if (run.status === 'RUNNING') {
            pollTimer.current = setTimeout(tick, 1500);
          } else {
            loadAll();
          }
        } catch (err: any) {
          setError(err?.message || 'Lost track of the running scenario');
        }
      };
      tick();
    },
    [loadAll]
  );

  useEffect(() => () => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
  }, []);

  // Re-attach to a run already in progress (e.g. started from the CLI or another browser).
  useEffect(() => {
    if (status?.activeRun && activeRun?.id !== status.activeRun.id) followRun(status.activeRun.id);
  }, [status?.activeRun, activeRun?.id, followRun]);

  const startRun = async () => {
    if (!selected) return;
    setStarting(true);
    setError(null);
    try {
      const { runId } = await api.runAttackScenario(selected.id, true);
      setConfirming(false);
      followRun(runId);
    } catch (err: any) {
      const details = Array.isArray(err?.details?.details)
        ? ` (${err.details.details.map((d: any) => d.label || d).join('; ')})`
        : '';
      setError(`${err?.message || 'Failed to start scenario'}${details}`);
    } finally {
      setStarting(false);
    }
  };

  const runPermission = selected ? canRunScenario(status, selected) : { allowed: false, reason: null };
  const displayedRun = activeRun && (!selected || activeRun.scenarioId === selected.id || activeRun.status === 'RUNNING') ? activeRun : null;
  const displayedScenario = displayedRun ? scenarios.find((s) => s.id === displayedRun.scenarioId) : selected;

  if (loading) {
    return (
      <div className="empty-state">
        <Loader2 size={22} className="spin" />
        <div className="empty-state-title">Loading Attack Simulation Lab…</div>
      </div>
    );
  }

  if (labDisabled) {
    return (
      <div>
        <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)' }}>Attack Simulation Lab</h1>
        <div className="alert-box info" style={{ marginTop: 18 }}>
          <Info size={18} style={{ flexShrink: 0 }} />
          <div>
            The Attack Lab is disabled on this server. It is only available in a local demo environment started with{' '}
            <code>DEMO_MODE=true</code> and <code>ATTACK_LAB_ENABLED=true</code> (never in production). See{' '}
            <code>docs/JUDGE_DEMO_RUNBOOK.md</code>.
          </div>
        </div>
      </div>
    );
  }

  const failedChecks = status?.safety.checks.filter((c) => !c.ok) || [];

  return (
    <div>
      {/* A. Lab header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 22, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h1 style={{ fontSize: '1.625rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>Attack Simulation Lab</h1>
            <Pill tone="danger">
              <FlaskConical size={12} /> {status?.environmentLabel || 'DEMO ENVIRONMENT'}
            </Pill>
            <Pill tone="neutral">
              {status?.siteCode} • {status?.stationCode}
            </Pill>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4, maxWidth: 820 }}>
            Runs predefined attacks against the live local Primary API, Simulated Independent Witness and ML service. Every result below
            is read back from real HTTP responses, database records and verifier output — nothing is pre-scripted.
          </p>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={loadAll}>
          <RefreshCw size={14} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="alert-box danger" style={{ marginBottom: 18 }}>
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {status && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 14, marginBottom: 22 }}>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-body" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8125rem', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <Server size={15} /> Primary API
                </span>
                <Pill tone={status.services.primary.reachable ? 'success' : 'danger'}>{status.services.primary.reachable ? 'UP' : 'DOWN'}</Pill>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>{status.services.primary.detail}</div>
            </div>
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-body" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8125rem', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <Database size={15} /> Witness
                </span>
                <Pill tone={status.services.witness.reachable ? 'success' : 'danger'}>{status.services.witness.reachable ? 'UP' : 'DOWN'}</Pill>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>
                {status.services.witness.displayName || 'Simulated Independent Witness'} {status.services.witness.witnessId ? `(${status.services.witness.witnessId})` : ''}
              </div>
            </div>
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-body" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8125rem', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <BrainCircuit size={15} /> ML service
                </span>
                <Pill tone={status.services.ml.reachable ? (status.services.ml.enabledOnPrimary ? 'success' : 'warning') : 'neutral'}>
                  {!status.services.ml.reachable ? 'UNAVAILABLE' : status.services.ml.enabledOnPrimary ? 'ENABLED' : 'ML_ENABLED=false'}
                </Pill>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>
                {status.services.ml.reachable
                  ? `Model ${status.services.ml.modelVersion || 'unknown'} • ready: ${status.services.ml.ready === null ? 'unknown' : String(status.services.ml.ready)}`
                  : status.services.ml.detail}
              </div>
            </div>
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-body" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8125rem', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <ShieldAlert size={15} /> Safety gates
                </span>
                <Pill tone={status.safety.ok ? 'success' : 'danger'}>
                  {status.safety.ok ? 'ALL PASS' : `${failedChecks.length} FAILED`}
                </Pill>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }} title={status.safety.checks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}: ${c.detail}`).join('\n')}>
                {status.safety.ok ? 'Demo mode, lab flag, non-production, DB identities, local targets' : failedChecks.map((c) => c.label).join('; ')}
              </div>
            </div>
          </div>
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-body" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 700, fontSize: '0.8125rem', display: 'flex', gap: 6, alignItems: 'center' }}>
                  <KeyRound size={15} /> Demo identities
                </span>
                <Pill tone={Object.values(status.demoIdentities).every((d) => d.ready) ? 'success' : 'warning'}>
                  {Object.values(status.demoIdentities).filter((d) => d.ready).length}/{Object.keys(status.demoIdentities).length}
                </Pill>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>
                {Object.entries(status.demoIdentities)
                  .map(([code, d]) => `${code}${d.ready ? '' : ' (missing)'}`)
                  .join(' • ')}
              </div>
            </div>
          </div>
        </div>
      )}

      {status && !status.canExecute && (
        <div className="alert-box info" style={{ marginBottom: 18 }}>
          <Info size={18} style={{ flexShrink: 0 }} />
          <div>Read-only view: you can review recorded runs and evidence. Only explicitly authorized demo administrators can run scenarios.</div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 380px) 1fr', gap: 20, alignItems: 'start' }} className="attack-lab-layout">
        {/* B. Scenario cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {scenarios.map((s) => {
            const isSelected = s.id === selectedId;
            const last = runs.find((r) => r.scenarioId === s.id && r.status !== 'RUNNING');
            return (
              <button
                key={s.id}
                type="button"
                onClick={() => {
                  setSelectedId(s.id);
                  setConfirming(false);
                  if (activeRun?.status !== 'RUNNING') {
                    if (last) followRun(last.id);
                    else setActiveRun(null);
                  }
                }}
                className="card"
                style={{
                  marginBottom: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  padding: '12px 14px',
                  border: `1px solid ${isSelected ? 'var(--air-force-blue)' : 'var(--border-subtle)'}`,
                  boxShadow: isSelected ? '0 0 0 2px var(--air-force-blue-light)' : undefined,
                  background: 'var(--bg-surface)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontWeight: 800, fontSize: '0.875rem', color: 'var(--text-main)' }}>
                    <span className="mono" style={{ color: 'var(--air-force-blue)', marginRight: 6 }}>{s.letter}</span>
                    {s.name}
                  </span>
                  <Pill tone={SEVERITY_TONE[s.severity]}>{s.severity}</Pill>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>{s.threatCategory}</div>
                {last && (
                  <div style={{ marginTop: 6, display: 'flex', gap: 6, alignItems: 'center', fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                    Last run: <Pill tone={outcomeTone(last.outcome)}>{outcomeLabel(last.outcome)}</Pill>
                    <span>{new Date(last.startedAt).toLocaleTimeString()}</span>
                  </div>
                )}
              </button>
            );
          })}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, minWidth: 0 }}>
          {/* Scenario explanation + run controls */}
          {selected && (
            <div className="card" style={{ marginBottom: 0 }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    <span className="mono" style={{ color: 'var(--air-force-blue)' }}>{selected.letter}</span>
                    <span>{selected.name}</span>
                  </div>
                  <div className="card-subtitle">{selected.threatCategory}</div>
                </div>
                <Pill tone={SEVERITY_TONE[selected.severity]}>{selected.severity} risk</Pill>
              </div>
              <div className="card-body">
                <p style={{ fontSize: '0.875rem', color: 'var(--text-main)', lineHeight: 1.55, marginBottom: 12 }}>{selected.description}</p>
                <KeyValue label="Security mechanism tested" value={selected.mechanismTested} />
                <KeyValue label="Expected system response" value={selected.expectedResponse} />
                <KeyValue label="Typical duration" value={`≈ ${selected.estimatedDurationSeconds}s`} />

                <div style={{ marginTop: 16, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  {!confirming ? (
                    <button
                      className="btn btn-primary"
                      disabled={!runPermission.allowed || starting}
                      onClick={() => setConfirming(true)}
                      title={runPermission.reason || undefined}
                    >
                      <Play size={15} />
                      <span>Run Simulation</span>
                    </button>
                  ) : (
                    <div
                      style={{
                        display: 'flex',
                        gap: 10,
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        padding: '10px 12px',
                        borderRadius: 'var(--radius-md)',
                        background: selected.requiresConfirmation ? 'var(--amber-gold-light)' : 'var(--bg-surface-accent)',
                        border: `1px solid ${selected.requiresConfirmation ? 'var(--amber-gold-border)' : 'var(--border-subtle)'}`,
                      }}
                    >
                      <span style={{ fontSize: '0.8125rem' }}>
                        {selected.requiresConfirmation
                          ? 'This scenario puts the demo sensor in service and creates real incidents (or isolates its witness path). Run it against the live demo services?'
                          : 'Send this attack to the live local Primary API and Witness?'}
                      </span>
                      <button className="btn btn-danger btn-sm" onClick={startRun} disabled={starting}>
                        {starting ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
                        <span>Confirm run</span>
                      </button>
                      <button className="btn btn-secondary btn-sm" onClick={() => setConfirming(false)} disabled={starting}>
                        Cancel
                      </button>
                    </div>
                  )}
                  {!runPermission.allowed && runPermission.reason && (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{runPermission.reason}</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* C. Execution results */}
          {displayedRun ? (
            <div className="card" style={{ marginBottom: 0 }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    {displayedRun.status === 'RUNNING' ? <Loader2 size={17} className="spin" /> : <FlaskConical size={17} />}
                    <span>
                      {displayedScenario?.letter} · {displayedScenario?.name || displayedRun.scenarioId}
                    </span>
                  </div>
                  <div className="card-subtitle mono">
                    Run {displayedRun.id.slice(0, 8)} • started {new Date(displayedRun.startedAt).toLocaleTimeString()} •{' '}
                    {runDurationSeconds(displayedRun)}s • {displayedRun.actorLabel} ({displayedRun.actorSource})
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                  <Pill tone={outcomeTone(displayedRun.outcome)}>{displayedRun.status === 'RUNNING' ? 'RUNNING' : outcomeLabel(displayedRun.outcome)}</Pill>
                  {displayedRun.status !== 'RUNNING' && (
                    <Pill tone={displayedRun.expectationMet ? 'success' : 'warning'}>
                      {displayedRun.expectationMet ? 'Expected response confirmed' : 'Expected response NOT confirmed'}
                    </Pill>
                  )}
                </div>
              </div>
              <div className="card-body">
                {displayedRun.summary && (
                  <div
                    style={{
                      padding: '10px 12px',
                      borderRadius: 'var(--radius-md)',
                      marginBottom: 14,
                      fontSize: '0.875rem',
                      fontWeight: 600,
                      ...(() => {
                        const t = TONE_STYLES[outcomeTone(displayedRun.outcome)];
                        return { color: t.color, background: t.background, border: `1px solid ${t.border}` };
                      })(),
                    }}
                  >
                    {displayedRun.summary}
                    {displayedRun.classification && (
                      <div className="mono" style={{ fontSize: '0.75rem', marginTop: 4, fontWeight: 500 }}>
                        Classification: {displayedRun.classification}
                      </div>
                    )}
                  </div>
                )}
                {displayedRun.actorSource === 'TEST' && (
                  <div className="alert-box info" style={{ marginBottom: 12 }}>
                    <Info size={16} style={{ flexShrink: 0 }} />
                    <div>Recorded by an automated test run, which may use mock services. Not a live demonstration.</div>
                  </div>
                )}
                {displayedRun.error && (
                  <div className="alert-box danger" style={{ marginBottom: 12 }}>
                    <XCircle size={16} />
                    <div>{displayedRun.error}</div>
                  </div>
                )}

                {/* Progress timeline */}
                <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {displayedRun.steps.map((step) => (
                    <li key={step.index} style={{ display: 'flex', gap: 10 }}>
                      <div style={{ paddingTop: 1 }}>
                        <StepIcon status={step.status} />
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 700, fontSize: '0.8125rem', color: 'var(--text-main)' }}>
                          {step.index}. {step.title}
                        </div>
                        {step.detail && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: 2 }}>
                            {step.detail}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                  {displayedRun.steps.length === 0 && <li style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Waiting for the first step…</li>}
                </ol>

                {displayedRun.status !== 'RUNNING' && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14, marginTop: 18 }}>
                    <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: 12 }}>
                      <div style={{ fontWeight: 800, fontSize: '0.8125rem', marginBottom: 6 }}>Primary API response</div>
                      {exchangeRows(displayedRun.primaryOutcome).map(([k, v]) => (
                        <KeyValue key={k} label={k} value={v} mono />
                      ))}
                      {!displayedRun.primaryOutcome && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Not applicable</div>}
                    </div>
                    <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: 12 }}>
                      <div style={{ fontWeight: 800, fontSize: '0.8125rem', marginBottom: 6 }}>Simulated Independent Witness response</div>
                      {exchangeRows(displayedRun.witnessOutcome).map(([k, v]) => (
                        <KeyValue key={k} label={k} value={v} mono />
                      ))}
                      {!displayedRun.witnessOutcome && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Not applicable</div>}
                    </div>
                    {displayedRun.mlResult && (
                      <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: 12 }}>
                        <div style={{ fontWeight: 800, fontSize: '0.8125rem', marginBottom: 6 }}>ML assessment (as returned by the model)</div>
                        {mlResultLines(displayedRun.mlResult).map((l) => (
                          <KeyValue key={l.label} label={l.label} value={l.value} mono />
                        ))}
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6 }}>{displayedRun.mlResult.detail}</div>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 6 }}>
                          The anomaly score is not a COD prediction. A SUSPICIOUS flag is not proof of fraud.
                        </div>
                      </div>
                    )}
                    <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: 12 }}>
                      <div style={{ fontWeight: 800, fontSize: '0.8125rem', marginBottom: 6 }}>Security & database evidence</div>
                      <KeyValue label="Primary security events" value={displayedRun.securityEventIds.primary.map((id) => id.slice(0, 8)).join(', ') || 'none'} mono />
                      <KeyValue label="Witness security events" value={displayedRun.securityEventIds.witness.map((id) => id.slice(0, 8)).join(', ') || 'none'} mono />
                      <KeyValue label="Alerts" value={displayedRun.alertIds.map((id) => id.slice(0, 8)).join(', ') || 'none'} mono />
                      {typeof displayedRun.verificationEvidence['failureReason'] === 'object' && displayedRun.verificationEvidence['failureReason'] && (
                        <KeyValue
                          label="Verifier failure reason"
                          value={String((displayedRun.verificationEvidence['failureReason'] as Record<string, unknown>)['reason'])}
                        />
                      )}
                      {(() => {
                        const c = displayedRun.verificationEvidence['mlControlSample'] as { evaluated: number; flagged: number } | null | undefined;
                        return c ? (
                          <KeyValue label="Genuine readings flagged by the same model" value={`${c.flagged} of ${c.evaluated}`} />
                        ) : null;
                      })()}
                      {typeof displayedRun.verificationEvidence['notCheckpointAnchored'] === 'number' && (
                        <KeyValue label="Newer events not checkpoint-anchored" value={String(displayedRun.verificationEvidence['notCheckpointAnchored'])} />
                      )}
                    </div>
                  </div>
                )}

                {/* D. Evidence links */}
                {displayedRun.status !== 'RUNNING' && displayedScenario && (
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 16 }}>
                    {displayedScenario.evidenceLinks.map((l) => (
                      <Link key={l.path} to={l.path} className="btn btn-secondary btn-sm">
                        <ExternalLink size={13} />
                        <span>{l.label}</span>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card" style={{ marginBottom: 0 }}>
              <div className="card-body">
                <div className="empty-state">
                  <div className="empty-state-title">No run selected</div>
                  <p>Run a scenario, or open one from the run history below. Results appear only after the services respond.</p>
                </div>
              </div>
            </div>
          )}

          {/* Run history */}
          <div className="card" style={{ marginBottom: 0 }}>
            <div className="card-header">
              <div>
                <div className="card-title">Run history</div>
                <div className="card-subtitle">Persisted demo-run evidence (separate from trusted telemetry)</div>
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {[
                  { to: '/alerts', label: 'Alerts' },
                  { to: '/anomalies', label: 'Anomalies' },
                  { to: '/audit', label: 'Audit' },
                  { to: '/monitoring', label: 'Telemetry' },
                  { to: '/sensors', label: 'Sensors' },
                ].map((l) => (
                  <Link key={l.to} to={l.to} className="btn btn-secondary btn-sm">
                    {l.label}
                  </Link>
                ))}
              </div>
            </div>
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Scenario</th>
                    <th>Outcome</th>
                    <th>Classification</th>
                    <th>Expected</th>
                    <th>Actor</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r) => {
                    const sc = scenarios.find((s) => s.id === r.scenarioId);
                    return (
                      <tr
                        key={r.id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => {
                          setSelectedId(r.scenarioId);
                          setConfirming(false);
                          followRun(r.id);
                        }}
                      >
                        <td className="mono">{new Date(r.startedAt).toLocaleString()}</td>
                        <td>
                          <span className="mono" style={{ color: 'var(--air-force-blue)' }}>{sc?.letter}</span> {sc?.name || r.scenarioId}
                        </td>
                        <td>
                          <Pill tone={outcomeTone(r.outcome)}>{r.status === 'RUNNING' ? 'RUNNING' : outcomeLabel(r.outcome)}</Pill>
                        </td>
                        <td className="mono" style={{ fontSize: '0.75rem' }}>{r.classification || '—'}</td>
                        <td>{r.status === 'RUNNING' ? '…' : r.expectationMet ? 'Yes' : 'No'}</td>
                        <td style={{ fontSize: '0.75rem' }}>{r.actorLabel}</td>
                      </tr>
                    );
                  })}
                  {runs.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                        No runs recorded yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
