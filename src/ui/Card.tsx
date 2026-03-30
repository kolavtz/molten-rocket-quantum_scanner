// QuantumShield Card Component
// Based on design system: shadows, spacing, hover effects

import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

interface CardHeaderProps {
  children: React.ReactNode;
}

interface CardBodyProps {
  children: React.ReactNode;
}

interface CardFooterProps {
  children: React.ReactNode;
}

const Card: React.FC<CardProps> = ({ children, className = '', onClick }) => (
  <div className={`card ${className}`} onClick={onClick}>
    {children}
  </div>
);

const CardHeader: React.FC<CardHeaderProps> = ({ children }) => (
  <div className="card-header">{children}</div>
);

const CardBody: React.FC<CardBodyProps> = ({ children }) => (
  <div className="card-body">{children}</div>
);

const CardFooter: React.FC<CardFooterProps> = ({ children }) => (
  <div className="card-footer">{children}</div>
);

export { Card, CardHeader, CardBody, CardFooter };
