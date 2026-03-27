# Multi-pass Math Specification and SQL Skeleton Mapping

This document encodes the foundational mathematical principles and MySQL implementations for the 6 target dashboards, serving as the single source of truth for all calculations.

## 1. Asset Inventory Dashboard

### Math Definitions
- **Set $A$**: Set of all active (non-deleted) assets.
- **Total Assets**: $|A|$
- **Asset Type Distribution**: $CountType(T) = |\{a \in A : type(a) = T\}|$
- **Asset Risk Distribution**: $CountRisk(R) = |\{a \in A : risk(a) = R\}|$
- **Expiring Certs**: $|C_{0-30}|$ where $C$ is the set of all active certificates, and expiry $d(c) \le 30$.
- **High Risk Assets**: $|\{a \in A : risk(a) \in \{Critical, High\}\}|$

### MySQL Skeletons
These metrics are stored in a daily/periodic snapshot table, or queryable directly via live aggregate views.

```sql
-- Total Assets
SELECT COUNT(*) FROM assets WHERE is_deleted = 0;

-- Asset Type/Risk Distributions
SELECT type, COUNT(*) FROM assets WHERE is_deleted = 0 GROUP BY type;
SELECT risk_level, COUNT(*) FROM assets WHERE is_deleted = 0 GROUP BY risk_level;

-- Expiring Certificates (0-30 days)
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
  AND DATEDIFF(valid_until, NOW()) BETWEEN 0 AND 30;

-- Persisting via Daily Summary (Table: org_inventory_metrics)
INSERT INTO org_inventory_metrics (date, total_assets, high_risk_assets, expiring_certs) 
VALUES (CURRENT_DATE, @total, @high_risk, @expiring);
```

---

## 2. PQC Compliance & Posture

### Math Definitions
- **Endpoint PQC Score**: $PQCScore(e) = \left( \sum qsafe(q) \right) / |Q_e| \times 100$
- **Asset PQC Score**: Average of endpoint scores for the asset $a$.
- **Asset Posture Classification**: 
  - **Elite**: Score $\ge 90$, 0 Critical findings.
  - **Standard**: $70 \le Score < 90$.
  - **Legacy**: $40 \le Score < 70$ OR has Legacy config.
  - **Critical**: Score $< 40$ OR has Critical finding.

### MySQL Skeletons
Scores are persisted per-asset in `compliance_scores`.

```sql
-- Compute Asset PQC Score (aggregate of endpoint/cert scores)
SELECT c.asset_id, AVG(p.pqc_score) as avg_score
FROM pqc_classification p
JOIN certificates c ON p.certificate_id = c.id
WHERE p.is_deleted = 0
GROUP BY c.asset_id;

-- Distribute into Classes (Using compliance_scores)
SELECT tier, COUNT(*) as asset_count 
FROM compliance_scores 
WHERE type = 'pqc_class' AND is_deleted = 0
GROUP BY tier;
```

---

## 3. CBOM Metrics and Crypto Inventory

### Math Definitions
- **Set $B$**: CBOM entries linked to $A$.
- **Total Applications**: Count of distinct `asset_id` in $B$.
- **Sites Surveyed**: Distinct hostnames.
- **Weak Crypto Count**: $\sum isWeak(b)$ where $isWeak = 1$ if legacy protocol, < 2048 key, etc.
- **Cert Issues Count**: $\sum isCertIssue(c)$.

### MySQL Skeletons
Persisted in `cbom_summary`.

```sql
-- Total Applications generating CBOM
SELECT COUNT(DISTINCT asset_id) FROM cbom_entries WHERE is_deleted = 0;

-- Weak Cryptography
SELECT COUNT(*) FROM cbom_entries WHERE (key_length < 2048 OR protocol_version_name IN ('TLSv1.0', 'TLSv1.1')) AND is_deleted = 0;

-- Persisting (Table: cbom_summary)
INSERT INTO cbom_summary (scan_id, total_components, weak_crypto_count, cert_issues_count)
VALUES (@scan_id, @total, @weak, @cert_issues);
```

---

## 4. Cyber Rating (Enterprise Score)

### Math Definitions
- **Risk Penalty**: $RiskPenalty(a) = w_c \cdot r_{crit}(a) + w_h \cdot r_{high}(a) + w_m \cdot r_{med}(a)$
- **Asset Rating**: $\max(0, PQCScore(a) - (\alpha \cdot RiskPenalty(a)))$
- **Enterprise Score**: $\lfloor \overline{S} \times 10 \rfloor$ (range 0-1000).

### MySQL Skeletons
Enterprise metrics are saved directly in `cyber_rating`.

```sql
-- Compute avg Asset Score
SELECT AVG((score_value - (critical_count*10 + high_count*5))) 
FROM compliance_scores WHERE type='pqc' AND is_deleted = 0;

-- Fetch Latest Enterprise Score
SELECT enterprise_score, rating_tier 
FROM cyber_rating 
ORDER BY generated_at DESC LIMIT 1;
```

---

## 5. Discovery Metrics and Maps/Graphs

### Math Definitions
- **Total Domains**: Count of discovery domains linked to $A$.
- **IP to Location**: Group by Region/Country.
- **Graph Edges**: Joins based on `AS number`, `subnet`, or `cert fingerprint`.

### MySQL Skeletons
```sql
-- Total Discovered Endpoints
SELECT status, COUNT(*) FROM discovery_items WHERE is_deleted = 0 GROUP BY status;

-- Graph Edges (Self-join on fingerprints for component linking)
SELECT a1.id as source, a2.id as target 
FROM certificates c1 
JOIN certificates c2 ON c1.fingerprint_sha256 = c2.fingerprint_sha256 AND c1.id != c2.id
JOIN assets a1 ON c1.asset_id = a1.id
JOIN assets a2 ON c2.asset_id = a2.id;
```

---

## 6. Home Dashboard (Enterprise Console)

### Math Definitions
Aggregates key top-level metrics.
- **Quantum Safe %**: $(|A_{qsafe}| / |A|) \times 100$
- **Vulnerable Assets**: Count of assets in Legacy or Critical tiers.

### MySQL Skeletons
Pulling pre-computed aggregates from our persistence tables.

```sql
-- Quantum Safe %
SELECT 
    (SELECT COUNT(*) FROM compliance_scores WHERE tier IN ('Elite', 'Standard') AND type = 'pqc_class') / 
    (SELECT COUNT(*) FROM assets WHERE is_deleted = 0) * 100 as quantum_safe_pct;

-- Vulnerable Assets
SELECT COUNT(*) FROM compliance_scores WHERE tier IN ('Legacy', 'Critical') AND type = 'pqc_class';
```
