import React from 'react';

interface LiveStreamStatusProps {
  paused?: boolean;
  loading: boolean;
  error: string | null;
  consecutiveFailures: number;
  lastUpdated: Date | null;
  pointCount: number;
}

/** Compact connection indicator for a live polling chart (live / connecting / reconnecting / paused). */
export const LiveStreamStatus: React.FC<LiveStreamStatusProps> = ({
  paused = false,
  loading,
  error,
  consecutiveFailures,
  lastUpdated,
  pointCount,
}) => {
  let label: string;
  let color: string;
  if (paused) {
    label = 'PAUSED';
    color = '#94a3b8';
  } else if (error) {
    label = `RECONNECTING (attempt ${consecutiveFailures})`;
    color = 'var(--brick-red)';
  } else if (loading) {
    label = 'CONNECTING';
    color = 'var(--air-force-blue)';
  } else {
    label = 'LIVE';
    color = '#10b981';
  }

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        flexWrap: 'wrap',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
        marginBottom: 10,
      }}
      title={error ?? undefined}
    >
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 800, color, letterSpacing: '0.04em' }}>
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            backgroundColor: color,
            boxShadow: label === 'LIVE' ? '0 0 6px rgba(16, 185, 129, 0.6)' : 'none',
            display: 'inline-block',
          }}
        />
        {label}
      </span>
      <span>
        {pointCount} point(s) in window · last update{' '}
        <strong style={{ color: 'var(--carbon-black)', fontFamily: 'ui-monospace, monospace' }}>
          {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'}
        </strong>
      </span>
      {error && !paused && <span>· showing last received data</span>}
    </div>
  );
};
