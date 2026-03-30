// Example: Scanner Page Implementation
// Shows how to use all QuantumShield UI components together

import React, { useState } from 'react';
import { Button, Card, CardHeader, CardBody, CardFooter, Input, Badge, Modal } from './ui';
import styles from './scanner-page.module.css';

interface ScannerPageProps {
  onScanSubmit?: (domain: string) => Promise<void>;
}

export const ScannerPage: React.FC<ScannerPageProps> = ({ onScanSubmit }) => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [showModal, setShowModal] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDomain(e.target.value);
    setError('');
  };

  const validateDomain = (value: string): boolean => {
    // Simple validation: check if it looks like a domain or IP
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$/;
    return domainRegex.test(value);
  };

  const handleScan = async () => {
    // Validate
    if (!domain.trim()) {
      setError('Enter a domain or IP address');
      return;
    }

    if (!validateDomain(domain)) {
      setError('Invalid domain or IP format');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Call API
      if (onScanSubmit) {
        await onScanSubmit(domain);
      } else {
        // Simulate API call
        const response = await fetch(`/api/scan?target=${encodeURIComponent(domain)}`);
        if (!response.ok) throw new Error('Scan failed');
      }

      setSuccess(true);
      setDomain('');
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickScan = (target: string) => {
    setDomain(target);
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleScan();
    }
  };

  return (
    <div className={styles.scannerContainer}>
      {/* Hero Section */}
      <div className={styles.hero}>
        <h1>Scan for Quantum-Safe Cryptography</h1>
        <p>Discover cryptographic assets on your systems and validate NIST PQC compliance</p>
      </div>

      {/* Main Card */}
      <Card className={styles.scanCard}>
        <CardHeader>
          <h2>Enter Target to Scan</h2>
          <Badge variant="info">Real-time TLS Analysis</Badge>
        </CardHeader>

        <CardBody>
          <Input
            label="Domain or IP Address"
            type="url"
            placeholder="example.com or 192.168.1.1"
            value={domain}
            onChange={handleChange}
            onKeyPress={handleKeyPress}
            disabled={loading}
            error={error}
            helpText="Enter a domain name, subdomain, or IPv4 address to scan for cryptographic assets"
            required
          />

          {success && (
            <div className={styles.successMessage}>
              ✓ Scan initiated successfully. Redirecting to results...
            </div>
          )}
        </CardBody>

        <CardFooter>
          <Button
            variant="primary"
            size="lg"
            loading={loading}
            disabled={!domain.trim() || loading}
            onClick={handleScan}
          >
            {loading ? 'Scanning...' : 'Scan Now'}
          </Button>

          <Button
            variant="outline"
            onClick={() => setShowModal(true)}
            disabled={loading}
          >
            Learn More
          </Button>
        </CardFooter>
      </Card>

      {/* Quick Examples */}
      <div className={styles.examplesSection}>
        <h3>Try These Examples</h3>
        <p>Click below to scan a well-known target</p>

        <div className={styles.exampleButtons}>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleQuickScan('google.com')}
            disabled={loading}
          >
            google.com
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleQuickScan('github.com')}
            disabled={loading}
          >
            github.com
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleQuickScan('cloudflare.com')}
            disabled={loading}
          >
            cloudflare.com
          </Button>
        </div>
      </div>

      {/* Info Cards */}
      <div className={styles.infoGrid}>
        <Card>
          <CardHeader>
            <h3>What We Scan</h3>
          </CardHeader>
          <CardBody>
            <p>We analyze TLS certificates, cipher suites, key exchange algorithms, and quantum-safe readiness</p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h3>What You Get</h3>
          </CardHeader>
          <CardBody>
            <p>Cryptographic asset inventory (CBOM), NIST PQC compliance status, and migration recommendations</p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h3>Why It Matters</h3>
          </CardHeader>
          <CardBody>
            <p>Quantum computers threaten current encryption. Learn your quantum-safe readiness today</p>
          </CardBody>
        </Card>
      </div>

      {/* Info Modal */}
      <Modal
        open={showModal}
        title="About QuantumShield"
        onClose={() => setShowModal(false)}
        actions={
          <Button variant="primary" onClick={() => setShowModal(false)}>
            Got It
          </Button>
        }
      >
        <p>
          <strong>QuantumShield</strong> is a quantum-safe cryptography readiness scanner that helps organizations
          understand their cryptographic posture and prepare for the quantum computing era.
        </p>

        <h4 style={{ marginTop: '16px' }}>Key Features:</h4>
        <ul style={{ marginLeft: '20px', marginTop: '8px' }}>
          <li>Automated cryptographic asset discovery</li>
          <li>NIST PQC (FIPS 203/204/205) compliance validation</li>
          <li>Harvest Now, Decrypt Later (HNDL) risk assessment</li>
          <li>Server-specific migration guidance</li>
        </ul>

        <h4 style={{ marginTop: '16px' }}>Standards:</h4>
        <div style={{ marginTop: '8px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <Badge variant="success">NIST FIPS 203 (ML-KEM)</Badge>
          <Badge variant="success">NIST FIPS 204 (ML-DSA)</Badge>
          <Badge variant="success">NIST FIPS 205 (SLH-DSA)</Badge>
        </div>
      </Modal>
    </div>
  );
};

export default ScannerPage;
