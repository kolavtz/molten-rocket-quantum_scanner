// QuantumShield Modal Component
// Based on design system: overlay, animations, focus trap

import React, { useEffect, useRef } from 'react';

interface ModalProps {
  open: boolean;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  actions?: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  title,
  children,
  onClose,
  actions,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      // Focus on modal
      modalRef.current?.focus();
      // Prevent body scroll
      document.body.style.overflow = 'hidden';
      // Handle Escape key
      const handleEscape = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          onClose();
        }
      };
      document.addEventListener('keydown', handleEscape);
      return () => {
        document.removeEventListener('keydown', handleEscape);
        document.body.style.overflow = 'auto';
      };
    }
  }, [open, onClose]);

  if (!open) return null;

  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onClick={handleBackdropClick}>
      <div className="modal" ref={modalRef} role="dialog" aria-modal="true">
        <div className="card-header">
          <h2>{title}</h2>
          <button
            className="btn btn-outline btn-sm"
            onClick={onClose}
            style={{ position: 'absolute', top: '16px', right: '16px' }}
            aria-label="Close modal"
          >
            ×
          </button>
        </div>
        <div className="card-body">{children}</div>
        {actions && <div className="card-footer">{actions}</div>}
      </div>
    </div>
  );
};
