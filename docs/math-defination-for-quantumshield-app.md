

# write me the mathmathical defination for all the data metric and kpi or anykind of math that is / will be required in the given app project and what will that be looking like, and make all the math based connections in all the dashboard like our new dashboard and all data and expectations i want to calculate these definately but want to keep the result in mysql so it becomes easy for retrieval and saving etc: now write me full math definations logics and conventions and all the details needed for the app to function and logics , write me full ultra detailed version of the math basis for our app and make it consistent over all the location in the app dashboards (app has 6 dasboard in total)

Below is a math spec you can treat as the “single source of truth” for all KPIs and metrics across your six dashboards. You can then encode these formulas into MySQL columns and API logic.

***

## 1. Common Sets, Counters, Time Windows

Let:

- $A$ = set of all assets in inventory (not soft-deleted).
- $S$ = set of all scans.
- $E$ = set of all TLS endpoints discovered for assets in $A$.
- $C$ = set of all certificates attached to endpoints in $E$.
- $Q$ = set of all PQC classification rows (algorithm-level) for endpoints in $E$.
- $R$ = set of all “findings” (issues: weak cipher, expiring cert, etc.) for endpoints in $E$.

All dashboards must operate on *filtered* sets:

- Inventory scope: only rows linked to an asset $a \in A$.
- Optional time filter $[t_{\text{start}}, t_{\text{end}}]$ applied via “last_scan_at” or “detection_date” when you implement date filters.

For any set $X$,

- $|X|$ = count of elements.
- $X_{\text{filter}}$ = subset of $X$ satisfying filter predicate.

These are what you actually compute in SQL and, if you want, persist in summary tables for fast retrieval.

***

## 2. Asset Inventory Dashboard Math

### 2.1 Counts and distributions

1. Total Assets

$$
\text{TotalAssets} = |A|
$$
2. Asset type distribution
Let $\text{type}(a)$ ∈ {WebApp, API, Server, Gateway, LoadBalancer, Other}. Then:

$$
\text{CountType}(T) = |\{a \in A : \text{type}(a) = T\}|
$$

Percent for type $T$:

$$
\text{PctType}(T) = 
\begin{cases}
\frac{\text{CountType}(T)}{\text{TotalAssets}} \times 100 & \text{if } \text{TotalAssets} > 0 \\
0 & \text{otherwise}
\end{cases}
$$
3. Asset risk distribution
Let $\text{risk}(a)$ ∈ {Critical, High, Medium, Low}. Then:

$$
\text{CountRisk}(R) = |\{a \in A : \text{risk}(a) = R\}|
$$

$$
\text{PctRisk}(R) =
\begin{cases}
\frac{\text{CountRisk}(R)}{\text{TotalAssets}} \times 100 & \text{if } \text{TotalAssets} > 0\\
0 & \text{otherwise}
\end{cases}
$$
4. IP version breakdown
Let $\text{hasIPv4}(a)$ and $\text{hasIPv6}(a)$ be boolean flags. Define:
    - $A_{\text{IPv4}} = \{a \in A : \text{hasIPv4}(a) = 1\}$
    - $A_{\text{IPv6}} = \{a \in A : \text{hasIPv6}(a) = 1\}$

$$
\text{PctIPv4} = 
\begin{cases}
\frac{|A_{\text{IPv4}}|}{|A_{\text{IPv4}}| + |A_{\text{IPv6}}|} \times 100 & \text{if denominator} > 0 \\
0 & \text{otherwise}
\end{cases}
$$

$$
\text{PctIPv6} = 
\begin{cases}
\frac{|A_{\text{IPv6}}|}{|A_{\text{IPv4}}| + |A_{\text{IPv6}}|} \times 100 & \text{if denominator} > 0 \\
0 & \text{otherwise}
\end{cases}
$$
5. Certificate expiry buckets (0–30, 31–60, 61–90, >90 days)

For each cert $c \in C$ with expiry date $\text{exp}(c)$ and reference date $t_{\text{now}}$:

$$
d(c) = \text{days\_between}(\text{exp}(c), t_{\text{now}})
$$

Define subsets (only for inventory assets: certificates whose endpoint belongs to $E$ and asset ∈ $A$):
    - $C_{0-30} = \{c \in C : 0 \le d(c) \le 30\}$
    - $C_{31-60} = \{c \in C : 31 \le d(c) \le 60\}$
    - $C_{61-90} = \{c \in C : 61 \le d(c) \le 90\}$
    - $C_{>90} = \{c \in C : d(c) > 90\}$
    - $C_{\text{expired}} = \{c \in C : d(c) < 0\}$ (if you want explicit expired bucket)

Counts are $|C_{0-30}|$ etc.
6. “Expiring certificates” KPI

$$
\text{ExpiringCerts} = |C_{0-30}|
$$
7. “High-risk assets” KPI

$$
\text{HighRiskAssets} = |\{a \in A : \text{risk}(a) = \text{Critical or High}\}|
$$

All these can be persisted in a daily snapshot table like `inventory_metrics(date, total_assets, high_risk_assets, ...)` if you want trend charts.

[^1]

***

## 3. PQC Compliance \& Posture Math

### 3.1 Endpoint-level PQC score (0–100)

For each endpoint $e \in E$, it uses some set of algorithms $Q_e \subseteq Q$. Label each algorithm row $q$ with:

- $\text{qsafe}(q) = 1$ if Quantum Safe, 0 otherwise.
- Optionally weight by algorithm category (KEM vs Signature vs Cipher).

Simplest unweighted endpoint PQC score:

$$
\text{PQCScore}(e) =
\begin{cases}
\frac{\sum_{q \in Q_e} \text{qsafe}(q)}{|Q_e|} \times 100 & \text{if } |Q_e| > 0\\
0 & \text{otherwise}
\end{cases}
$$

Store this as a column `pqc_score` per endpoint or per (asset, scan) in `compliance_scores`.

### 3.2 Asset-level PQC score

Let $E_a =$ endpoints belonging to asset $a$. Then:

$$
\text{PQCScore}(a) =
\begin{cases}
\frac{\sum_{e \in E_a} \text{PQCScore}(e)}{|E_a|} & \text{if } |E_a| > 0\\
0 & \text{otherwise}
\end{cases}
$$

Persist as:

- `compliance_scores(asset_id, type='pqc', score_value)`.


### 3.3 Asset posture classification (Elite / Standard / Legacy / Critical)

Define thresholds (configurable, but consistent everywhere):

- Elite: $\text{PQCScore}(a) \ge 90$ and no Critical findings.
- Standard: $70 \le \text{PQCScore}(a) < 90$.
- Legacy: $40 \le \text{PQCScore}(a) < 70$ or at least one “Legacy” config (e.g., TLS 1.0 / 1.1).
- Critical: $\text{PQCScore}(a) < 40$ or at least one Critical finding (weak keys, SSLv3 etc.).

You can formalize:

Let:

- $\text{HasCritical}(a) = 1$ if any finding in $R$ for asset $a$ has severity = Critical.
- $\text{HasLegacy}(a) = 1$ if any finding indicates legacy protocol/cipher.

Then classification $Class(a)$:

- If $\text{HasCritical}(a) = 1$ or $\text{PQCScore}(a) < 40$ ⇒ Critical.
- Else if $\text{HasLegacy}(a) = 1$ or $40 \le \text{PQCScore}(a) < 70$ ⇒ Legacy.
- Else if $70 \le \text{PQCScore}(a) < 90$ ⇒ Standard.
- Else if $\text{PQCScore}(a) \ge 90$ and $\text{HasCritical}(a)=0$ ⇒ Elite.

Store in `compliance_scores(asset_id, type='pqc_class', tier='Elite/Standard/...')`.

### 3.4 PQC dashboard metrics

1. Asset counts per class:

$$
N_{\text{Elite}} = |\{a \in A : Class(a) = \text{Elite}\}|
$$

(similar for Standard, Legacy, Critical).

2. Percentages:

$$
\text{PctClass}(K) =
\begin{cases}
\frac{N_{K}}{\text{TotalAssets}} \times 100 & \text{if } \text{TotalAssets} > 0\\
0 & \text{otherwise}
\end{cases}
$$

3. Single-line bar chart for “assets by classification grade” uses $N_{\text{Elite}}, N_{\text{Standard}}, N_{\text{Legacy}}, N_{\text{Critical}}$.
4. “Application status for PQC readiness” is just the same percentages rendered as segments.

[^1]

***

## 4. CBOM Metrics and Crypto Inventory Math

All CBOM and crypto metrics must be functions of the CBOM data linked to inventory assets.

### 4.1 Definitions

Let $B$ = set of CBOM entries for endpoints of assets in $A$. Each entry $b \in B$ has:

- asset id, algorithm name, category (KEM, Signature, Cipher, Hash), key length $k(b)$, protocol version $p(b)$, CA name, is_weak flag, issue_type, etc.[^1]

1. Total applications

$$
\text{TotalApplications} = |\{\text{distinct asset\_id in } B\}|
$$
2. Sites surveyed
Depending on how you model a “site” (e.g., distinct hostname among endpoints of assets), define:

$$
\text{SitesSurveyed} = |\{\text{distinct hostname in } E \text{ for } a \in A\}|
$$
3. Active certificates
As in inventory math, but restrict to CBOM scope:

$$
\text{ActiveCerts} = |\{c \in C : d(c) \ge 0\}|
$$
4. Weak cryptography count
Let $\text{isWeak}(b) = 1$ if key length below policy, deprecated cipher, or protocol < TLS 1.2. Then:

$$
\text{WeakCryptoCount} = \sum_{b \in B} \text{isWeak}(b)
$$
5. Certificate issues count
Define $\text{isCertIssue}(c) = 1$ if expired or expiring within policy threshold or mismatched hostname, etc. Then:

$$
\text{CertIssuesCount} = \sum_{c \in C} \text{isCertIssue}(c)
$$

### 4.2 Distributions

1. Key length distribution
Group $B$ by key length $k$:

$$
\text{CountKeyLen}(L) = |\{b \in B : k(b) = L\}|
$$
2. Cipher usage
Group by cipher name:

$$
\text{CountCipher}(X) = |\{b \in B : \text{cipher}(b) = X\}|
$$
3. Top Certificate Authorities

$$
\text{CountCA}(Y) = |\{b \in B : \text{CAName}(b) = Y\}|
$$

Percent:

$$
\text{PctCA}(Y) =
\begin{cases}
\frac{\text{CountCA}(Y)}{\sum_Z \text{CountCA}(Z)} \times 100 & \text{if denominator} > 0\\
0 & \text{otherwise}
\end{cases}
$$
4. Protocol version distribution

$$
\text{CountProto}(V) = |\{b \in B : p(b) = V\}|
$$

All these are basic GROUP BY counts persisted in `cbom_summary` if you want snapshots.

[^1]

***

## 5. Cyber Rating Math (0–1000 Enterprise Score)

Cyber rating is an organization-wide score aggregating asset-level PQC posture, crypto hygiene, and risks.

### 5.1 Normalization inputs

For each asset $a$:

- PQC score $\text{PQCScore}(a)$ from section 3.2.
- Risk severity counts:
    - $r_{\text{crit}}(a)$ = number of critical findings in $R$ for asset $a$.
    - $r_{\text{high}}(a)$, $r_{\text{med}}(a)$, etc.

Normalize risk penalties per asset:

$$
\text{RiskPenalty}(a) = w_c \cdot r_{\text{crit}}(a) + w_h \cdot r_{\text{high}}(a) + w_m \cdot r_{\text{med}}(a)
$$

with weights $w_c > w_h > w_m \ge 0$. These are configuration constants.

### 5.2 Asset-level normalized score (0–100)

Define an asset cyber score:

$$
\text{AssetCyberScore}(a) = \max\left(0, \text{PQCScore}(a) - \alpha \cdot \text{RiskPenalty}(a)\right)
$$

where $\alpha$ is a scaling factor (e.g., penalty per finding).

### 5.3 Enterprise 0–1000 score

Let $A_{\text{scored}} = \{a \in A : \text{AssetCyberScore}(a) \text{ defined}\}$.

Compute average asset score:

$$
\overline{S} =
\begin{cases}
\frac{1}{|A_{\text{scored}}|} \sum_{a \in A_{\text{scored}}} \text{AssetCyberScore}(a) & \text{if } |A_{\text{scored}}| > 0\\
0 & \text{otherwise}
\end{cases}
$$

Normalize to 0–1000 range:

$$
\text{EnterpriseScore} = \left\lfloor \overline{S} \times 10 \right\rfloor
$$

Persist this periodically in `cyber_rating(enterprise_score, generated_at, ...)`.

### 5.4 Tier mapping

- Tier-1 Elite: $\text{EnterpriseScore} \ge 700$.
- Tier-2 Standard: $400 \le \text{EnterpriseScore} < 700$.
- Tier-3 Legacy: $0 \le \text{EnterpriseScore} < 400$.
- Critical flag if any asset is classified Critical.

Store `rating_tier` alongside `enterprise_score`.

[^1]

***

## 6. Discovery Metrics and Maps/Graphs

### 6.1 Discovery counts

For each discovery dimension:

- Domains: $D =$ discovery_domains table rows linked to assets in $A$ (or also raw, depending on view).

$$
\text{TotalDomains} = |D|
$$
- SSL: $SSL =$ discovery_ssl rows.
- IPs: $I =$ discovery_ips rows.
- Software: $SW =$ discovery_software rows.

Same pattern, counts and percentages by status (New, Confirmed, Ignored):

$$
\text{CountStatus}_D(S) = |\{d \in D : \text{status}(d) = S\}|
$$

### 6.2 IP → location distribution

For each IP record $i \in I$ with country or region code, you can define:

$$
\text{CountCountry}(Z) = |\{i \in I : \text{country}(i) = Z\}|
$$

These feed the map (markers) and optional bar charts.

### 6.3 Network graph

Define a graph $G = (V, E_G)$:

- $V = A$ or endpoints for assets in $A$.
- Edges connect nodes sharing some property, e.g.:
    - Same AS number.
    - Same certificate fingerprint.
    - Same subnet.

This is more structural than numeric; the “math” is simply graph definition:

$$
E_G = \{(v_1, v_2) \in V \times V : \text{relates}(v_1, v_2) = 1\}
$$

You don’t need to persist edges if you can compute them on the fly via joins/grouping.

***

## 7. Home Dashboard Math (Enterprise Console)

Home is a summary over the previous sections.

### 7.1 Core KPIs

- Total Assets = $|A|$
- Total Scans = $|S|$ (only scans that touched inventory assets, or all scans depending on design).
- Quantum Safe % (asset-level view):
Define:

$$
A_{\text{qsafe}} = \{a \in A : \text{PQCScore}(a) \ge T_{\text{qsafe}}\}
$$

(e.g., threshold $T_{\text{qsafe}} = 90$ or configuration.)

$$
\text{QuantumSafePct} =
\begin{cases}
\frac{|A_{\text{qsafe}}|}{|A|} \times 100 & \text{if } |A| > 0\\
0 & \text{otherwise}
\end{cases}
$$
- Vulnerable assets count:

$$
A_{\text{vuln}} = \{a \in A : Class(a) \in \{\text{Legacy}, \text{Critical}\}\}
$$

$$
\text{VulnerableAssetsCount} = |A_{\text{vuln}}|
$$
- Average PQC compliance score:

$$
\overline{\text{PQCScore}} =
\begin{cases}
\frac{1}{|A|} \sum_{a \in A} \text{PQCScore}(a) & \text{if } |A| > 0\\
0 & \text{otherwise}
\end{cases}
$$

These are the same numbers used in PQC and Cyber Rating pages, so you must reuse the same formulas, not recompute differently.

[^1]

***

## 8. Reporting Metrics

Reporting itself is configuration and status, but you may want:

- Count of scheduled reports:

$$
\text{ScheduledReports} = |\{\text{report\_schedule rows where enabled=1}\}|
$$
- Count of failed/completed on-demand reports in a window:

$$
\text{CompletedReports} = |\{r \in \text{report\_requests} : \text{status}(r) = \text{completed}, \text{requested\_at}\in [t_{\text{start}}, t_{\text{end}}]\}|
$$

These are simple counts.

***

## 9. Implementation Conventions for MySQL

To make this consistent and easy to retrieve:

1. **Store raw inputs** in normalized tables:
    - assets, endpoints, certificates, algorithms, findings, cbom_entries, pqc scores.
2. **Store derived metrics** in summary tables:
    - `asset_metrics(asset_id, pqc_score, risk_penalty, pqc_class_tier, last_updated)`
    - `org_pqc_metrics(date, avg_pqc_score, pct_elite, pct_legacy, ... )`
    - `cbom_summary(date, total_apps, weak_crypto_count, cert_issues_count, ...)`
    - `cyber_rating(enterprise_score, rating_tier, generated_at)`

Fill these via background jobs or after scans.
3. **API endpoints** should:
    - Either compute on the fly using these formulas, or
    - Read from the summary tables (but summary tables must be consistent with these formulas).
4. **Rounding and display**:
    - Store scores as integers or decimals (e.g. `DECIMAL(5,2)` for percentages).
    - Normalize and round only at the last possible stage (e.g. UI), but keep “true” values in DB.

***

Do you want a second pass that turns these formulas into a table of “metric → SQL skeleton” for each of your six dashboards (Home, Inventory, Discovery, CBOM, PQC, Cyber)?
<span style="display:none">[^2][^3]</span>

<div align="center">⁂</div>

[^1]: Software-Requirement-Specification1_for-paracipher-project-signed-signed.pdf

[^2]: prototype-expectations.pdf

[^3]: Software-Requirement-Specification1_for-paracipher-project-signed-signed.pdf

