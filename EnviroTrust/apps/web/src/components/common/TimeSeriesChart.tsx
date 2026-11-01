import React, { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';

export interface ChartDataPoint {
  id?: string;
  time: string;
  actual: number;
  predicted?: number | null;
  residual?: number | null;
  threshold?: number | null;
  status?: string;
  modelVersion?: string | null;
  measuredAt?: string;
  sensorId?: string;
  label?: string;
}

interface TimeSeriesChartProps {
  data: ChartDataPoint[];
  title?: string;
  yUnit?: string;
  threshold?: number;
  thresholdLabel?: string;
  /**
   * Enables live time-axis mode: points are placed by `measuredAt` inside a sliding window of this
   * width ending at "now", and the plot scrolls continuously between data updates.
   */
  windowMs?: number;
  /** Live mode only: freezes scrolling (e.g. while the stream is paused for inspection). */
  paused?: boolean;
  /** Live mode only: message shown over the empty plot while no points are in the window. */
  emptyMessage?: string;
}

const svgWidth = 800;
const svgHeight = 250;
const padding = { top: 20, right: 24, bottom: 36, left: 56 };
const plotWidth = svgWidth - padding.left - padding.right;
const plotHeight = svgHeight - padding.top - padding.bottom;

// Live mode re-lays out points this often; requestAnimationFrame scrolls smoothly in between.
const REANCHOR_MS = 1000;
const TICK_STEPS_MS = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600].map((s) => s * 1000);

const pointTime = (d: ChartDataPoint) => (d.measuredAt ? Date.parse(d.measuredAt) : NaN);

export const TimeSeriesChart: React.FC<TimeSeriesChartProps> = ({
  data,
  title,
  yUnit = 'mg/L',
  threshold,
  thresholdLabel = 'Threshold',
  windowMs,
  paused = false,
  emptyMessage = 'Waiting for live telemetry…',
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<ChartDataPoint | null>(null);
  const isLive = windowMs !== undefined && windowMs > 0;
  const idSuffix = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const gradientId = `streamAreaGradient-${idSuffix}`;
  const clipId = `streamPlotClip-${idSuffix}`;

  // Live mode: layout is computed relative to `anchor`; the scroll group is translated by the
  // time elapsed since then, so the x-axis keeps moving without re-rendering every frame.
  const [anchor, setAnchor] = useState(() => Date.now());
  const anchorRef = useRef(anchor);
  const pausedRef = useRef(paused);
  const scrollGroupRef = useRef<SVGGElement>(null);
  const pxPerMs = isLive ? plotWidth / windowMs : 0;

  const applyScroll = useCallback(() => {
    const group = scrollGroupRef.current;
    if (!group || pxPerMs === 0) return;
    const offset = pausedRef.current ? 0 : (Date.now() - anchorRef.current) * pxPerMs;
    group.setAttribute('transform', `translate(${(-offset).toFixed(2)} 0)`);
  }, [pxPerMs]);

  useLayoutEffect(() => {
    anchorRef.current = anchor;
    pausedRef.current = paused;
    applyScroll();
  });

  useEffect(() => {
    if (!isLive) return;
    setAnchor(Date.now());
    if (paused) return;
    const interval = setInterval(() => setAnchor(Date.now()), REANCHOR_MS);
    return () => clearInterval(interval);
  }, [isLive, paused]);

  useEffect(() => {
    if (!isLive || paused) return;
    let frame = requestAnimationFrame(function step() {
      applyScroll();
      frame = requestAnimationFrame(step);
    });
    return () => cancelAnimationFrame(frame);
  }, [isLive, paused, applyScroll]);

  if (!isLive && (!data || data.length === 0)) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">No time series data available</div>
        <p>Telemetry readings matching the selected filter will appear here.</p>
      </div>
    );
  }

  // In live mode only points with a valid timestamp are plotted, in chronological order.
  const points = isLive
    ? data.filter((d) => Number.isFinite(pointTime(d))).sort((a, b) => pointTime(a) - pointTime(b))
    : data;
  const windowStart = isLive ? anchor - windowMs : 0;

  // Calculate min & max Y (live mode: from points currently inside the window)
  const allValues: number[] = [];
  (isLive ? points.filter((d) => pointTime(d) >= windowStart) : points).forEach((d) => {
    if (!isNaN(d.actual)) allValues.push(d.actual);
    if (d.predicted !== undefined && d.predicted !== null && !isNaN(d.predicted)) {
      allValues.push(d.predicted);
    }
  });
  if (threshold !== undefined) allValues.push(threshold);
  if (allValues.length === 0) allValues.push(0);

  const minY = Math.max(0, Math.min(...allValues) * 0.9);
  const maxY = Math.max(10, Math.max(...allValues) * 1.15);
  const yRange = maxY - minY || 1;

  // Scale functions
  const getX = (index: number) => {
    if (isLive) return padding.left + plotWidth - (anchor - pointTime(points[index]!)) * pxPerMs;
    if (points.length <= 1) return padding.left + plotWidth / 2;
    return padding.left + (index / (points.length - 1)) * plotWidth;
  };

  const getY = (val: number) => {
    return padding.top + plotHeight - ((val - minY) / yRange) * plotHeight;
  };

  // Helper for smooth spline curves
  const createSmoothPath = (points: Array<{ x: number; y: number }>) => {
    if (points.length === 0) return '';
    if (points.length === 1) return `M ${points[0]!.x} ${points[0]!.y}`;

    let path = `M ${points[0]!.x} ${points[0]!.y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i === 0 ? 0 : i - 1]!;
      const p1 = points[i]!;
      const p2 = points[i + 1]!;
      const p3 = points[i + 2 < points.length ? i + 2 : i + 1]!;

      const cp1x = p1.x + (p2.x - p0.x) / 6;
      const cp1y = p1.y + (p2.y - p0.y) / 6;
      const cp2x = p2.x - (p3.x - p1.x) / 6;
      const cp2y = p2.y - (p3.y - p1.y) / 6;

      path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
    }
    return path;
  };

  const actualPoints = points.map((d, idx) => ({ x: getX(idx), y: getY(d.actual) }));
  const actualPath = createSmoothPath(actualPoints);

  // Soft area fill path underneath the actual spline (TABELA / Pinterest inspired)
  const lastX = actualPoints.length > 0 ? actualPoints[actualPoints.length - 1]!.x : svgWidth - padding.right;
  const firstX = actualPoints.length > 0 ? actualPoints[0]!.x : padding.left;
  const bottomY = padding.top + plotHeight;
  const areaPath = actualPoints.length > 0
    ? `${actualPath} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`
    : '';

  // Predicted points and path
  const hasPredicted = points.some((d) => d.predicted !== undefined && d.predicted !== null);
  const predictedPoints = points
    .map((d, idx) => (d.predicted !== null && d.predicted !== undefined ? { x: getX(idx), y: getY(d.predicted) } : null))
    .filter((p): p is { x: number; y: number } => p !== null);
  const predictedPath = createSmoothPath(predictedPoints);

  // Ticks
  const yTicks = [
    minY,
    minY + yRange * 0.25,
    minY + yRange * 0.5,
    minY + yRange * 0.75,
    maxY,
  ];

  // Live mode time ticks: pick a round step giving at most ~8 labels, and cover slightly past
  // "now" so labels scrolling in from the right are already rendered between re-layouts.
  const timeTicks: number[] = [];
  let tickStepMs = 0;
  if (isLive) {
    tickStepMs = TICK_STEPS_MS.find((step) => windowMs / step <= 8) ?? TICK_STEPS_MS[TICK_STEPS_MS.length - 1]!;
    for (let t = Math.ceil(windowStart / tickStepMs) * tickStepMs - tickStepMs; t <= anchor + REANCHOR_MS * 3; t += tickStepMs) {
      timeTicks.push(t);
    }
  }
  const formatTick = (t: number) =>
    new Date(t).toLocaleTimeString([], tickStepMs < 60_000
      ? { hour: '2-digit', minute: '2-digit', second: '2-digit' }
      : { hour: '2-digit', minute: '2-digit' });

  return (
    <div style={{ width: '100%' }}>
      {title && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18, flexWrap: 'wrap', gap: 10 }}>
          <span style={{ fontWeight: 800, fontSize: '0.9375rem', color: '#18191a' }}>{title}</span>
          <div style={{ display: 'flex', gap: 14, fontSize: '0.75rem', fontWeight: 600 }}>
            {/* Legend: Actual */}
            <span style={{ color: '#4b88a2', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 14, height: 2.5, backgroundColor: '#4b88a2', borderRadius: 1, display: 'inline-block' }} />
              <span>Actual Sensor Stream</span>
            </span>

            {/* Legend: ML Predicted */}
            {hasPredicted && (
              <span style={{ color: '#059669', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 14, height: 2.5, borderTop: '2px dashed #059669', display: 'inline-block' }} />
                <span>ML Expected Baseline</span>
              </span>
            )}

            {/* Legend: Threshold */}
            {threshold !== undefined && (
              <span style={{ color: '#bb0a21', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 14, height: 2, borderTop: '2px dashed #bb0a21', display: 'inline-block' }} />
                <span>{thresholdLabel} ({threshold})</span>
              </span>
            )}
          </div>
        </div>
      )}

      <div style={{ position: 'relative', width: '100%', height: svgHeight }}>
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          preserveAspectRatio="none"
          style={{ width: '100%', height: '100%', overflow: 'visible' }}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#4b88a2" stopOpacity="0.22" />
              <stop offset="65%" stopColor="#4b88a2" stopOpacity="0.05" />
              <stop offset="100%" stopColor="#4b88a2" stopOpacity="0.0" />
            </linearGradient>
            {isLive && (
              <clipPath id={clipId}>
                <rect x={padding.left} y={0} width={plotWidth + 6} height={svgHeight} />
              </clipPath>
            )}
          </defs>

          {/* Y Axis Grid lines */}
          {yTicks.map((tick, i) => {
            const y = getY(tick);
            return (
              <g key={i}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={svgWidth - padding.right}
                  y2={y}
                  stroke="#e8ecf1"
                  strokeWidth="1"
                />
                <text
                  x={padding.left - 10}
                  y={y + 4}
                  fill="#94a3b8"
                  fontSize="10"
                  fontFamily="ui-monospace, monospace"
                  textAnchor="end"
                  fontWeight="600"
                >
                  {tick.toFixed(1)} {i === yTicks.length - 1 ? yUnit : ''}
                </text>
              </g>
            );
          })}

          {/* Reference Threshold Line */}
          {threshold !== undefined && (
            <line
              x1={padding.left}
              y1={getY(threshold)}
              x2={svgWidth - padding.right}
              y2={getY(threshold)}
              stroke="#bb0a21"
              strokeWidth="1.5"
              strokeDasharray="4,4"
              opacity="0.85"
            />
          )}

          <g clipPath={isLive ? `url(#${clipId})` : undefined}>
            <g ref={scrollGroupRef}>
              {/* Live mode moving time grid & labels */}
              {timeTicks.map((t) => {
                const x = padding.left + plotWidth - (anchor - t) * pxPerMs;
                return (
                  <g key={t}>
                    <line x1={x} y1={padding.top} x2={x} y2={padding.top + plotHeight} stroke="#f1f4f8" strokeWidth="1" />
                    <text
                      x={x}
                      y={padding.top + plotHeight + 20}
                      fill="#94a3b8"
                      fontSize="10"
                      fontFamily="ui-monospace, monospace"
                      textAnchor="middle"
                      fontWeight="600"
                    >
                      {formatTick(t)}
                    </text>
                  </g>
                );
              })}

              {/* Soft Wave Area Fill */}
              {areaPath && (
                <path
                  d={areaPath}
                  fill={`url(#${gradientId})`}
                />
              )}

              {/* ML Predicted Baseline Path (Continuous Green Dashed Curve) */}
              {hasPredicted && (
                <path
                  d={predictedPath}
                  fill="none"
                  stroke="#059669"
                  strokeWidth="2"
                  strokeDasharray="5,4"
                />
              )}

              {/* Actual Telemetry Spline Path (Continuous Air Force Blue Solid Curve) */}
              <path
                d={actualPath}
                fill="none"
                stroke="#4b88a2"
                strokeWidth="2.5"
              />

              {/* Interactive Data Points */}
              {points.map((d, idx) => {
                const x = getX(idx);
                const y = getY(d.actual);
                const isSuspicious = d.status === 'SUSPICIOUS';

                return (
                  <g key={d.id ?? idx}>
                    <circle
                      cx={x}
                      cy={y}
                      r={isSuspicious ? 5 : 3.5}
                      fill={isSuspicious ? '#bb0a21' : '#4b88a2'}
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      style={{ cursor: 'pointer', transition: 'r 0.15s ease' }}
                      onMouseEnter={() => setHoveredPoint(d)}
                      onMouseLeave={() => setHoveredPoint(null)}
                    />
                  </g>
                );
              })}
            </g>
          </g>
        </svg>

        {isLive && points.length === 0 && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#94a3b8',
              fontSize: '0.8125rem',
              fontWeight: 600,
              pointerEvents: 'none',
            }}
          >
            {emptyMessage}
          </div>
        )}

        {/* Hover Tooltip Card */}
        {hoveredPoint && (
          <div
            style={{
              position: 'absolute',
              top: 10,
              right: 14,
              backgroundColor: '#252627',
              color: '#ffffff',
              padding: '12px 16px',
              borderRadius: '10px',
              fontSize: '0.75rem',
              boxShadow: '0 10px 25px rgba(0, 0, 0, 0.25)',
              pointerEvents: 'none',
              zIndex: 20,
              border: '1px solid #37393d',
              minWidth: 180,
            }}
          >
            <div style={{ fontWeight: 800, marginBottom: 6, color: '#93c5fd' }}>
              {hoveredPoint.measuredAt ? new Date(hoveredPoint.measuredAt).toLocaleString() : hoveredPoint.time}
            </div>
            {hoveredPoint.sensorId && (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>Sensor ID:</span>
                <strong style={{ color: '#ffffff' }}>{hoveredPoint.sensorId}</strong>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
              <span style={{ color: '#94a3b8' }}>Actual Sensor:</span>
              <strong style={{ color: '#ffffff' }}>{hoveredPoint.actual.toFixed(2)} {yUnit}</strong>
            </div>
            {hoveredPoint.predicted !== undefined && hoveredPoint.predicted !== null ? (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>ML Expected:</span>
                <strong style={{ color: '#34d399' }}>{hoveredPoint.predicted.toFixed(2)} {yUnit}</strong>
              </div>
            ) : hoveredPoint.status === 'PENDING' ? (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>ML Expected:</span>
                <span style={{ color: '#f59e0b', fontStyle: 'italic' }}>Pending Assessment</span>
              </div>
            ) : null}
            {hoveredPoint.residual !== undefined && hoveredPoint.residual !== null && (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>Residual Δ:</span>
                <strong style={{ color: '#d3d4d9' }}>{hoveredPoint.residual.toFixed(2)}</strong>
              </div>
            )}
            {hoveredPoint.threshold !== undefined && hoveredPoint.threshold !== null && (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>Applied Threshold:</span>
                <strong style={{ color: '#fca5a5' }}>{hoveredPoint.threshold.toFixed(2)}</strong>
              </div>
            )}
            {hoveredPoint.modelVersion && (
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ color: '#94a3b8' }}>Model Version:</span>
                <span style={{ color: '#93c5fd' }}>{hoveredPoint.modelVersion}</span>
              </div>
            )}
            {hoveredPoint.status && (
              <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid #37393d', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#94a3b8' }}>Assessment:</span>
                <span
                  style={{
                    fontWeight: 700,
                    color:
                      hoveredPoint.status === 'SUSPICIOUS'
                        ? '#f87171'
                        : hoveredPoint.status === 'PENDING'
                        ? '#f59e0b'
                        : hoveredPoint.status === 'ERROR'
                        ? '#ef4444'
                        : hoveredPoint.status === 'NOT_EVALUATED'
                        ? '#94a3b8'
                        : '#34d399',
                  }}
                >
                  {hoveredPoint.status === 'PENDING' ? 'PENDING ASSESSMENT' : hoveredPoint.status}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
