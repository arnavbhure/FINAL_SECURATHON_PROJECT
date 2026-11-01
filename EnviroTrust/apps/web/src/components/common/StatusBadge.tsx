import React from 'react';

interface StatusBadgeProps {
  status: string | null | undefined;
  type?: 'availability' | 'signature' | 'protocol' | 'ml' | 'witness' | 'general';
  label?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, label }) => {
  if (!status) {
    return (
      <span className="status-badge neutral">
        <span className="status-badge-dot neutral" />
        <span>UNKNOWN</span>
      </span>
    );
  }

  const normalized = status.toLowerCase();
  const displayLabel = label || status.replace(/_/g, ' ');

  const isGreen = [
    'online',
    'valid',
    'consistent',
    'fresh',
    'active',
    'matched',
    'confirmed',
    'received',
  ].includes(normalized);
  const isRed = [
    'offline',
    'suspicious',
    'invalid',
    'error',
    'critical',
    'disabled',
    'payload_mismatch',
    'signature_mismatch',
  ].includes(normalized);
  const isAmber = [
    'stale',
    'not_evaluated',
    'delayed',
    'gap_detected',
    'warning',
  ].includes(normalized);

  const dotClass = isGreen ? 'green' : isRed ? 'red' : isAmber ? 'amber' : 'neutral';

  return (
    <span className={`status-badge ${normalized}`}>
      <span className={`status-badge-dot ${dotClass}`} />
      <span>{displayLabel}</span>
    </span>
  );
};

