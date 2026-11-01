import React from 'react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  iconTone?: 'blue' | 'emerald' | 'amber' | 'rose' | 'indigo';
  trend?: string;
  trendType?: 'up' | 'down' | 'neutral';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon,
  iconTone,
  trend,
  trendType = 'neutral',
}) => {
  const resolvedTone =
    iconTone || (trendType === 'up' ? 'emerald' : trendType === 'down' ? 'rose' : 'blue');

  return (
    <div className="metric-card">
      <div className="metric-header-row">
        <span className="metric-title-label">{label}</span>
        {icon && <div className={`metric-header-icon ${resolvedTone}`}>{icon}</div>}
      </div>

      <div className="metric-main-value">{value}</div>

      <div className="metric-footer-row">
        {trend && (
          <span className={`metric-trend-chip ${trendType}`}>
            {trendType === 'up' && <ArrowUpRight size={13} />}
            {trendType === 'down' && <ArrowDownRight size={13} />}
            {trendType === 'neutral' && <Minus size={13} />}
            <span>{trend}</span>
          </span>
        )}
        {subtext && <span className="metric-subtext-note">{subtext}</span>}
      </div>
    </div>
  );
};
