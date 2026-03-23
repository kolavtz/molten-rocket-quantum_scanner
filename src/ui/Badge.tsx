// QuantumShield Badge Component
// Based on design system: colors for status (success, warning, error, info)

import React from 'react';

interface BadgeProps {
  variant?: 'success' | 'warning' | 'error' | 'info';
  children: React.ReactNode;
  icon?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'info',
  children,
  icon,
}) => {
  return (
    <span className={`badge badge-${variant}`}>
      {icon && <span>{icon}</span>}
      {children}
    </span>
  );
};

// Example badges for QuantumShield
export const PQCReadyBadge: React.FC = () => (
  <Badge variant="success">✓ PQC Ready</Badge>
);

export const LegacyBadge: React.FC = () => (
  <Badge variant="warning">⚠ Legacy Crypto</Badge>
);

export const ComplianceBadge: React.FC<{ fips: string }> = ({ fips }) => (
  <Badge variant="info">NIST {fips}</Badge>
);
