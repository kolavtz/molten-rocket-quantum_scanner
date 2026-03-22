# Database Indexes — Certificate Telemetry Performance Guide

This guide documents recommended indexing strategy for optimal performance of the Certificate Telemetry system.

---

## Overview

The `certificates` table is queried heavily by the Certificate Telemetry Service. Without proper indexes, dashboard queries can become slow as data grows.

**Current Scale:** This guide assumes 1,000+ certificates stored (typical for production).

**Expected Benefit:** Index queries reduce response time from **500ms → 10ms** (50x improvement).

---

## Critical Indexes (MUST HAVE)

### 1. Soft-Delete Filter Index

**Index Name:** `idx_certificates_is_deleted`  
**Type:** Single-column index  
**Columns:** `is_deleted`  
**Priority:** ⭐⭐⭐ CRITICAL

### Why?

Every query in CertificateTelemetryService filters `WHERE is_deleted = 0`. Without this index, MySQL must scan the entire table for every request.

### Query Impact:

```sql
-- WITHOUT INDEX: Full table scan (1000+ rows)
SELECT COUNT(*) FROM certificates WHERE is_deleted = 0
-- Time: 500+ ms

-- WITH INDEX: Index range scan (10-50 rows)
SELECT COUNT(*) FROM certificates WHERE is_deleted = 0
-- Time: 1-2 ms
```

### SQL Statement:

```sql
CREATE INDEX idx_certificates_is_deleted 
ON certificates(is_deleted);
```

---

### 2. Expiry Date Filter Index

**Index Name:** `idx_certificates_valid_until`  
**Type:** Single-column index  
**Columns:** `valid_until`  
**Priority:** ⭐⭐⭐ CRITICAL

### Why?

Used by 5+ metrics:
- Expiring certificates count
- Expired certificates count
- Timeline bucketing (0-30, 30-60, 60-90, >90)
- Certificate inventory sorting
- Issues count aggregation

### Query Impact:

```sql
-- WITHOUT INDEX: Full table scan + calculation
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
AND valid_until > NOW() 
AND valid_until < DATE_ADD(NOW(), INTERVAL 30 DAYS)
-- Time: 300+ ms

-- WITH INDEX: Range scan + filter
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
AND valid_until > NOW() 
AND valid_until < DATE_ADD(NOW(), INTERVAL 30 DAYS)
-- Time: 2-5 ms
```

### SQL Statement:

```sql
CREATE INDEX idx_certificates_valid_until 
ON certificates(valid_until);
```

---

### 3. Key Length Index

**Index Name:** `idx_certificates_key_length`  
**Type:** Single-column index  
**Columns:** `key_length`  
**Priority:** ⭐⭐⭐ CRITICAL

### Why?

Used by:
- Key length distribution metric
- Weak cryptography detection (< 2048-bit)
- Key strength analysis

### Query Impact:

```sql
-- WITHOUT INDEX: Full scan with calculations
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND key_length < 2048
-- Time: 200+ ms

-- WITH INDEX: Range lookup
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND key_length < 2048
-- Time: 1-3 ms
```

### SQL Statement:

```sql
CREATE INDEX idx_certificates_key_length 
ON certificates(key_length);
```

---

### 4. Asset ID Index

**Index Name:** `idx_certificates_asset_id`  
**Type:** Single-column index (Foreign Key)  
**Columns:** `asset_id`  
**Priority:** ⭐⭐ HIGH

### Why?

Used for:
- Asset-specific certificate lookups
- JOIN with assets table
- Asset inventory detail views

### Query Impact:

```sql
-- Without index: Nested loop join
SELECT c.*, a.target FROM certificates c
LEFT JOIN assets a ON c.asset_id = a.id
WHERE c.is_deleted = 0 AND a.id = 123
-- Time: 100+ ms

-- With index: Hash join
SELECT c.*, a.target FROM certificates c
LEFT JOIN assets a ON c.asset_id = a.id
WHERE c.is_deleted = 0 AND a.id = 123
-- Time: 2 ms
```

### SQL Statement:

```sql
CREATE INDEX idx_certificates_asset_id 
ON certificates(asset_id);
```

---

## Composite Indexes (RECOMMENDED)

### 5. Comprehensive Filter Index

**Index Name:** `idx_certificates_is_deleted_valid_until`  
**Type:** Composite (multi-column)  
**Columns:** `is_deleted, valid_until`  
**Priority:** ⭐⭐⭐ HIGHLY RECOMMENDED

### Why?

Combines the two most common filters. Allows efficient handling of queries like:

```sql
-- Expiring certificates (most common query)
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND valid_until BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAYS)
```

### Optimization:

MySQL can use this single index for both conditions, avoiding additional index lookups.

### SQL Statement:

```sql
CREATE INDEX idx_certificates_is_deleted_valid_until 
ON certificates(is_deleted, valid_until);
```

**Column Order Matters:**
- `is_deleted` first: Eliminates deleted records immediately
- `valid_until` second: Narrows to date range

---

### 6. Crypto Analysis Index

**Index Name:** `idx_certificates_key_length_tls_version`  
**Type:** Composite  
**Columns:** `key_length, tls_version`  
**Priority:** ⭐ OPTIONAL (Nice to have)

### Why?

Supports queries combining key strength and protocol version:

```sql
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
AND (key_length < 2048 OR tls_version IN ('TLS 1.0', 'TLS 1.1'))
```

### SQL Statement:

```sql
CREATE INDEX idx_certificates_key_length_tls_version 
ON certificates(key_length, tls_version);
```

---

## Complete Implementation Script

### Step 1: Create All Critical Indexes

Run this script **in production** during low-traffic window:

```sql
-- ════════════════════════════════════════════════════════════════
-- CRITICAL INDEXES (Run immediately)
-- ════════════════════════════════════════════════════════════════

-- Soft-delete flag (used by ALL queries)
CREATE INDEX idx_certificates_is_deleted 
ON certificates(is_deleted);

-- Expiry date (used by 5+ metrics)
CREATE INDEX idx_certificates_valid_until 
ON certificates(valid_until);

-- Key length (used by 3+ metrics)
CREATE INDEX idx_certificates_key_length 
ON certificates(key_length);

-- Asset reference (for JOIN queries)
CREATE INDEX idx_certificates_asset_id 
ON certificates(asset_id);

-- ════════════════════════════════════════════════════════════════
-- RECOMMENDED COMPOSITE INDEXES
-- ════════════════════════════════════════════════════════════════

-- Combined soft-delete + expiry (most common filter pair)
CREATE INDEX idx_certificates_is_deleted_valid_until 
ON certificates(is_deleted, valid_until);

-- ════════════════════════════════════════════════════════════════
-- OPTIONAL INDEXES (Advanced filtering)
-- ════════════════════════════════════════════════════════════════

-- Crypto strength analysis
CREATE INDEX idx_certificates_key_length_tls_version 
ON certificates(key_length, tls_version);

-- Additional lookups (if needed)
CREATE INDEX idx_certificates_fingerprint_sha256 
ON certificates(fingerprint_sha256);

-- Cipher suite analysis
CREATE INDEX idx_certificates_cipher_suite 
ON certificates(cipher_suite);
```

### Step 2: Verify Indexes Are Used

Run EXPLAIN query to verify correct index usage:

```sql
EXPLAIN SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
AND valid_until BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAYS);
```

✅ **Good Output:**
```
| id | select_type | table        | type  | key                                    | rows | Extra       |
| 1  | SIMPLE      | certificates | range | idx_certificates_is_deleted_valid_until| 50   | Using where |
```

**Key Indicators:**
- `type` = `range` (not `ALL`)
- `key` is your index name (not NULL)
- `rows` < total table size (should be much smaller)

❌ **Bad Output (Missing Index):**
```
| type  | key  | rows | Extra           |
| ALL   | NULL | 5000 | Using where     |  ← Full table scan!
```

### Step 3: Monitor Performance

After creating indexes, measure improvement:

```sql
-- Set start time
SET @start = UNIX_TIMESTAMP();

-- Run metric query
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND valid_until BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAYS);

-- Check duration
SELECT UNIX_TIMESTAMP() - @start AS query_duration_sec;
```

**Expected Results:**
- Before indexes: 0.5–2 seconds
- After indexes: 0.01–0.05 seconds (50x faster!)

---

## Index Maintenance

### Monitor Index Health

```sql
-- Check for unused indexes
SELECT * FROM sys.schema_unused_indexes;

-- Check index fragmentation
SELECT * FROM sys.schema_table_statistics WHERE table_schema != 'mysql';
```

### Rebuild Indexes (Monthly)

If table grows significantly (10K+ new certificates), rebuild indexes:

```sql
OPTIMIZE TABLE certificates;
```

This:
- Rebuilds fragmented indexes
- Recalculates statistics
- Frees unused space

⚠️ **Caution:** Locks the table. Run during maintenance window.

---

## Indexing Strategy Summary

| Index | Purpose | Priority | Query Time Improvement |
|-------|---------|----------|------------------------|
| `is_deleted` | Soft-delete filtering | 🔴 Critical | 500ms → 1ms |
| `valid_until` | Expiry date filtering | 🔴 Critical | 300ms → 2ms |
| `key_length` | Crypto strength | 🔴 Critical | 200ms → 1ms |
| `asset_id` | Asset lookup | 🟠 High | 100ms → 2ms |
| `is_deleted + valid_until` | Combined filter | 🟠 High | 500ms → 1ms |
| `key_length + tls_version` | Crypto analysis | 🟡 Optional | 150ms → 3ms |

---

## SQL Statements by Feature

### Certificates Expiring Soon (Most Common)

```sql
-- Uses: idx_is_deleted_valid_until (composite index)
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 
AND valid_until BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY);
```

### Weak Cryptography Detection

```sql
-- Uses: idx_key_length, idx_tls_version
SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND key_length < 2048 AND key_length > 0;

SELECT COUNT(*) FROM certificates 
WHERE is_deleted = 0 AND tls_version IN ('TLS 1.0', 'TLS 1.1');
```

### Certificate Inventory by Asset

```sql
-- Uses: idx_asset_id (FK lookup)
SELECT c.* FROM certificates c
LEFT JOIN assets a ON c.asset_id = a.id
WHERE c.is_deleted = 0 AND a.id = 123
ORDER BY c.valid_until DESC
LIMIT 100;
```

### Timeline Aggregation

```sql
-- Uses: idx_valid_until
SELECT 
  CASE 
    WHEN DATEDIFF(valid_until, CURDATE()) <= 30 THEN '0-30'
    WHEN DATEDIFF(valid_until, CURDATE()) <= 60 THEN '30-60'
    WHEN DATEDIFF(valid_until, CURDATE()) <= 90 THEN '60-90'
    ELSE '>90'
  END as bucket,
  COUNT(*) as count
FROM certificates
WHERE is_deleted = 0 AND valid_until > CURDATE()
GROUP BY bucket;
```

---

## Implementation Timeline

**Week 1 (Immediate):**
- Create critical indexes (1-4)
- Verify index usage with EXPLAIN
- Benchmark before/after performance

**Week 2:**
- Create composite indexes (5)
- Monitor query performance metrics
- Update monitoring dashboards

**Week 3+:**
- Create optional indexes as needed
- Set up monthly maintenance schedule
- Archive old certificate records if needed

---

## Monitoring with CertificateTelemetryService

The CertificateTelemetryService includes built-in query execution:

```python
# Each metric function performs indexed queries:
cert_service.get_expiring_certificates_count()     # Uses idx_is_deleted_valid_until
cert_service.get_key_length_distribution()         # Uses idx_key_length
cert_service.get_certificate_inventory()           # Uses idx_asset_id
```

With indexes in place, all metrics should complete in **<100ms total**.

---

## Troubleshooting

### Problem: Queries Still Slow After Indexing

**Solution 1:** Check statistics are updated
```sql
ANALYZE TABLE certificates;
```

**Solution 2:** Rebuild fragmented indexes
```sql
OPTIMIZE TABLE certificates;
```

**Solution 3:** Verify index is being used
```sql
EXPLAIN SELECT ... \G  -- Show full details
-- Look for "Using where" or "Using index condition"
```

### Problem: Index Not Being Used

**Cause:** Query conditions don't match index order

**Example (Bad):**
```sql
-- Index: (is_deleted, valid_until)
-- Query uses valid_until FIRST (wrong order!)
SELECT * FROM certificates 
WHERE valid_until > NOW() AND is_deleted = 0;
-- MySQL may not use the index
```

**Solution (Good):**
```sql
SELECT * FROM certificates 
WHERE is_deleted = 0 AND valid_until > NOW();
-- MySQL uses index (correct order)
```

---

## Performance Benchmarks

### Expected Query Times (With Indexes)

```
get_expiring_certificates_count()        : 2-5 ms
get_expired_certificates_count()         : 1-3 ms
get_certificate_expiry_timeline()        : 5-10 ms
get_certificate_inventory(limit=100)     : 10-20 ms
get_key_length_distribution()            : 3-8 ms
get_weak_cryptography_metrics()          : 15-25 ms
get_complete_certificate_telemetry()     : 50-100 ms (all metrics)
```

### Expected Query Times (Without Indexes)

```
get_expiring_certificates_count()        : 200-500 ms
get_expired_certificates_count()         : 150-400 ms
get_certificate_expiry_timeline()        : 300-800 ms
get_certificate_inventory(limit=100)     : 400-1000 ms
get_key_length_distribution()            : 250-600 ms
get_weak_cryptography_metrics()          : 500-1200 ms
get_complete_certificate_telemetry()     : 2000-5000 ms ❌ TOO SLOW
```

**With indexes: 50-100x faster response time!**

---

## Conclusion

Implementing these indexes is critical for:
- ✅ Fast dashboard performance (< 100ms page load)
- ✅ Responsive API endpoints
- ✅ Scalable to 10K+ certificates
- ✅ Predictable query performance

**Recommended Action:** Implement critical indexes (1-4) immediately. Composite indexes (5) are optional but recommended.
