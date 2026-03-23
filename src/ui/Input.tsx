// QuantumShield Input Component
// Based on design system: labels, validation, help text

import React from 'react';

interface InputProps {
  label?: string;
  type?: 'text' | 'email' | 'password' | 'number' | 'url' | 'tel';
  placeholder?: string;
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  disabled?: boolean;
  error?: string;
  helpText?: string;
  required?: boolean;
  className?: string;
}

export const Input: React.FC<InputProps> = ({
  label,
  type = 'text',
  placeholder,
  value,
  onChange,
  disabled = false,
  error,
  helpText,
  required = false,
  className = '',
}) => {
  return (
    <div className="input-group">
      {label && (
        <label>
          {label}
          {required && <span style={{ color: '#EF4444' }}>*</span>}
        </label>
      )}
      <input
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        disabled={disabled}
        className={className}
      />
      {error && <p className="help-text error-text">{error}</p>}
      {helpText && !error && <p className="help-text">{helpText}</p>}
    </div>
  );
};
