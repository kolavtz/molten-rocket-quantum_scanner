/**
 * AssetDetailModal.js
 * Comprehensive Asset Intelligence Popup for QuantumShield
 */
(function() {
    'use strict';

    class AssetDetailModal {
        constructor() {
            this.modal = document.getElementById('qsAssetDetailModal');
            this.map = null;
            this.graph = null;
            this.pqcChart = null;
            this.currentAssetId = null;
            this.data = null;
            this._boundEsc = null;

            if (!this.modal) {
                return;
            }

            this._ensureClosedState();
            this._initTabListeners();
            this._initCloseListeners();
        }

        /**
         * Orchestrates modal opening: handles data fetching, loading states, and view initialization.
         */
        async open(assetId) {
            if (!this.modal) {
                console.error("AssetDetailModal element not found in DOM.");
                return;
            }

            if (!assetId) {
                this._showStatus('Unable to open details: missing asset id.', true);
                return;
            }

            this.currentAssetId = assetId;
            this.modal.classList.add('open');
            this.modal.setAttribute('aria-hidden', 'false');
            this._bindEscape();
            this._resetTabs('overview');
            this._showStatus("Loading comprehensive telemetry...");

            try {
                const response = await fetch(`/api/assets/${assetId}/comprehensive`);
                const contentType = String(response.headers.get('content-type') || '').toLowerCase();
                if (!contentType.includes('application/json')) {
                    if (response.status === 401 || response.status === 403 || response.redirected) {
                        throw new Error('Your session has expired or access is denied. Please sign in again.');
                    }
                    const raw = await response.text();
                    const sample = String(raw || '').trim().slice(0, 120);
                    throw new Error(`Unexpected non-JSON response (HTTP ${response.status}). ${sample ? `Server says: ${sample}` : ''}`.trim());
                }

                const result = await response.json();
                if (!response.ok || !result.success) {
                    const reason = result?.message || result?.error?.message || `HTTP ${response.status}`;
                    throw new Error(reason || 'Failed to fetch asset details');
                }

                this.data = result.data;
                this._renderAll();
                this._showStatus(`Telemetry synced for ${this.data.target}`);
            } catch (err) {
                console.error("AssetDetailModal Error:", err);
                this._showStatus(`Error: ${err.message}`, true);
            }
        }

        /**
         * Closes the modal and cleans up active interactive components.
         */
        close() {
            if (!this.modal) return;
            this.modal.classList.remove('open');
            this.modal.setAttribute('aria-hidden', 'true');
            this._unbindEscape();
            this._cleanup();
        }

        _ensureClosedState() {
            this.modal.classList.remove('open');
            this.modal.setAttribute('aria-hidden', 'true');
        }

        _bindEscape() {
            this._unbindEscape();
            this._boundEsc = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    this.close();
                }
            };
            document.addEventListener('keydown', this._boundEsc);
        }

        _unbindEscape() {
            if (this._boundEsc) {
                document.removeEventListener('keydown', this._boundEsc);
                this._boundEsc = null;
            }
        }

        _initCloseListeners() {
            if (!this.modal) return;
            this.modal.addEventListener('click', (event) => {
                if (event.target === this.modal) {
                    this.close();
                }
            });
        }

        _resetTabs(defaultTab) {
            if (!this.modal) return;
            const targetTab = defaultTab || 'overview';
            this.modal.querySelectorAll('.qs-tab-btn').forEach((btn) => {
                btn.classList.toggle('active', btn.dataset.tab === targetTab);
            });
            this.modal.querySelectorAll('.qs-tab-pane').forEach((pane) => {
                pane.style.display = pane.id === `tab-${targetTab}` ? 'block' : 'none';
            });
        }

        /**
         * Master render function that populates all tab panes from the fetched DTO.
         */
        _renderAll() {
            const d = this.data;
            
            // Header & Side Info
            document.getElementById('qsModalTitle').textContent = `Intelligence: ${d.target}`;
            document.getElementById('qsModalSubtitle').textContent = `Asset ID: ${d.id} | Scanned: ${d.network.discovery.length > 0 ? d.network.discovery[0].date : 'Never'}`;
            document.getElementById('qsValIPv4').textContent = d.ipv4 || "None";
            document.getElementById('qsValIPv6').textContent = d.ipv6 || "None";
            document.getElementById('qsValType').textContent = d.type.toUpperCase();
            document.getElementById('qsValRisk').textContent = d.risk_level;
            document.getElementById('qsValOwner').textContent = d.owner || "Unassigned";
            document.getElementById('qsFullDetailLink').href = `/assets/${d.id}`;
            
            // DNS Records
            const dnsTbody = document.getElementById('qsTableDNS');
            dnsTbody.innerHTML = d.network.dns.length > 0 
                ? d.network.dns.map(r => `<tr><td><span class="qs-badge warn">${r.type || 'TXT'}</span></td><td>${r.name}</td><td><small class="qs-mono-val">${r.value}</small></td></tr>`).join('')
                : '<tr><td colspan="3" class="text-center text-muted">No records detected in latest scan.</td></tr>';

            // Details snapshot (mirrors the key metrics shown in full details view)
            const details = (d.details && typeof d.details === 'object') ? d.details : {};
            const snapshot = document.getElementById('qsViewSecuritySnapshot');
            if (snapshot) {
                const latestCert = (details.latest_certificate && typeof details.latest_certificate === 'object')
                    ? details.latest_certificate
                    : {};
                const tlsCipher = `${latestCert.tls_version || d.security?.certificate?.tls_version || 'N/A'} / ${latestCert.cipher_suite || 'N/A'}`;
                snapshot.innerHTML = `
                    <div class="list-row"><span class="left">PQC Score</span><strong>${Number(details.pqc_score || d.security?.pqc?.score || 0).toFixed(1)}</strong></div>
                    <div class="list-row"><span class="left">PQC Status</span><strong>${this._escapeHtml(details.pqc_status || d.security?.pqc?.status || 'Unknown')}</strong></div>
                    <div class="list-row"><span class="left">Readiness</span><strong>${this._escapeHtml(details.readiness || 'Standard Protocol')}</strong></div>
                    <div class="list-row"><span class="left">Certificates</span><strong>${Number(details.certificates_count || 0)}</strong></div>
                    <div class="list-row"><span class="left">Discovery Items</span><strong>${Number(details.discovery_count || 0)}</strong></div>
                    <div class="list-row"><span class="left">Total Scans</span><strong>${Number(details.scan_count || d.network?.discovery?.length || 0)}</strong></div>
                    <div class="list-row"><span class="left">TLS / Cipher</span><strong>${this._escapeHtml(tlsCipher)}</strong></div>
                `;
            }

            const servicesBox = document.getElementById('qsViewDiscoveredServices');
            if (servicesBox) {
                const services = Array.isArray(details.discovered_services) ? details.discovered_services : [];
                servicesBox.innerHTML = services.length > 0
                    ? services.slice(0, 12).map((svc) => {
                        const host = this._escapeHtml(svc.host || svc.target || '?');
                        const port = this._escapeHtml(String(svc.port ?? '?'));
                        const service = this._escapeHtml(svc.service || svc.protocol || 'Unknown');
                        return `<div class="list-row"><span class="left">${host}:${port}</span><strong>${service}</strong></div>`;
                    }).join('')
                    : '<div class="text-muted">No discovered services yet.</div>';
            }

            const recBox = document.getElementById('qsViewRecommendations');
            if (recBox) {
                const recommendations = Array.isArray(details.recommendations) ? details.recommendations : [];
                recBox.innerHTML = recommendations.length > 0
                    ? recommendations.slice(0, 8).map((rec) => {
                        const title = this._escapeHtml(rec.title || rec.name || 'Recommendation');
                        const description = this._escapeHtml(rec.description || rec.detail || rec.message || '');
                        return `
                            <div class="qs-detail-card" style="padding:0.6rem; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06);">
                                <div style="font-weight:700; margin-bottom:0.25rem;">${title}</div>
                                <div style="color:var(--text-secondary); font-size:0.74rem;">${description || 'No additional details provided.'}</div>
                            </div>
                        `;
                    }).join('')
                    : '<div class="text-muted">No recommendations available.</div>';
            }

            // Security: Certificate
            const certBox = document.getElementById('qsCertDetails');
            if (d.security.certificate) {
                const c = d.security.certificate;
                const details = (c.certificate_details && typeof c.certificate_details === 'object') ? c.certificate_details : {};
                const validity = (details.validity && typeof details.validity === 'object') ? details.validity : {};
                const spki = (details.subject_public_key_info && typeof details.subject_public_key_info === 'object')
                    ? details.subject_public_key_info
                    : {};
                certBox.innerHTML = `
                    <div class="qs-cert-item">
                        <div class="qs-cert-label">Subject</div>
                        <div class="qs-cert-value">${this._escapeHtml(c.subject || 'N/A')}</div>
                    </div>
                    <div class="qs-cert-item">
                        <div class="qs-cert-label">Issuer</div>
                        <div class="qs-cert-value">${this._escapeHtml(c.issuer || 'N/A')}</div>
                    </div>
                    <div class="qs-cert-item">
                        <div class="qs-cert-label">Validity</div>
                        <div class="qs-cert-value">${this._escapeHtml(c.valid_from || 'N/A')} to ${this._escapeHtml(c.valid_until || 'N/A')} (${Number(c.expiry_days || 0)} days remaining)</div>
                    </div>
                    <div class="qs-cert-item">
                        <div class="qs-cert-label">Algorithm</div>
                        <div class="qs-cert-value">${this._escapeHtml(c.key_algorithm || 'Unknown')} ${Number(c.key_length || 0)} bits | ${this._escapeHtml(c.signature_algorithm || 'Unknown')}</div>
                    </div>
                    <div class="p-2 mt-2" style="background: rgba(0,0,0,0.4); border-radius: 4px;">
                        <span class="qs-badge ${c.is_expired ? 'danger' : 'safe'}">${c.is_expired ? 'EXPIRED' : 'ACTIVE'}</span>
                        <span class="qs-badge warn">${this._escapeHtml(c.tls_version || 'Unknown')}</span>
                    </div>
                    <details class="qs-cert-item" style="margin-top:0.65rem; border:1px solid rgba(255,255,255,0.07); border-radius:8px; padding:0.5rem;">
                        <summary style="cursor:pointer; font-size:0.72rem; color:var(--text-secondary);">Show full X.509 certificate details</summary>
                        <div style="display:grid; gap:0.35rem; margin-top:0.55rem; font-size:0.76rem;">
                            <div><strong>Certificate Version:</strong> ${this._escapeHtml(details.certificate_version || 'N/A')}</div>
                            <div><strong>Serial Number:</strong> ${this._escapeHtml(details.serial_number || 'N/A')}</div>
                            <div><strong>Certificate Signature Algorithm:</strong> ${this._escapeHtml(details.certificate_signature_algorithm || 'N/A')}</div>
                            <div><strong>Issuer:</strong> ${this._escapeHtml(details.issuer || c.issuer || 'N/A')}</div>
                            <div><strong>Validity Not Before:</strong> ${this._escapeHtml(validity.not_before || c.valid_from || 'N/A')}</div>
                            <div><strong>Validity Not After:</strong> ${this._escapeHtml(validity.not_after || c.valid_until || 'N/A')}</div>
                            <div><strong>Subject:</strong> ${this._escapeHtml(details.subject || c.subject || 'N/A')}</div>
                            <div><strong>Subject Public Key Algorithm:</strong> ${this._escapeHtml(spki.subject_public_key_algorithm || c.key_algorithm || 'N/A')}</div>
                            <div><strong>Subject Public Key Bits:</strong> ${this._escapeHtml(String(spki.subject_public_key_bits || c.key_length || 'N/A'))}</div>
                            <div><strong>Extensions:</strong> ${this._renderCollection(details.extensions)}</div>
                            <div><strong>Certificate Key Usage:</strong> ${this._renderCollection(details.certificate_key_usage)}</div>
                            <div><strong>Extended Key Usage:</strong> ${this._renderCollection(details.extended_key_usage)}</div>
                            <div><strong>Certificate Basic Constraints:</strong> ${this._renderCollection(details.certificate_basic_constraints)}</div>
                            <div><strong>Certificate Subject Key ID:</strong> ${this._escapeHtml(details.certificate_subject_key_id || 'N/A')}</div>
                            <div><strong>Certificate Authority Key ID:</strong> ${this._escapeHtml(details.certificate_authority_key_id || 'N/A')}</div>
                            <div><strong>Authority Information Access:</strong> ${this._renderCollection(details.authority_information_access)}</div>
                            <div><strong>Certificate Subject Alternative Name:</strong> ${this._renderCollection(details.certificate_subject_alternative_name)}</div>
                            <div><strong>Certificate Policies:</strong> ${this._renderCollection(details.certificate_policies)}</div>
                            <div><strong>CRL Distribution Points:</strong> ${this._renderCollection(details.crl_distribution_points)}</div>
                            <div><strong>Signed Certificate Timestamp List:</strong> ${this._renderCollection(details.signed_certificate_timestamp_list)}</div>
                        </div>
                    </details>
                `;
            } else {
                certBox.innerHTML = '<div class="text-center py-4 text-muted">No certificates found on scanned endpoints.</div>';
            }

            // CBOM
            const cbomTbody = document.getElementById('qsTableCBOM');
            cbomTbody.innerHTML = d.security.cbom.length > 0
                ? d.security.cbom.map(e => `
                    <tr>
                        <td><strong>${e.algorithm}</strong></td>
                        <td>${e.category}</td>
                        <td>${e.key_length || '-'}</td>
                        <td>${e.nist_status || '-'}</td>
                        <td><span class="qs-badge ${e.quantum_safe ? 'safe' : 'danger'}">${e.quantum_safe ? 'YES' : 'NO'}</span></td>
                    </tr>`).join('')
                : '<tr><td colspan="5" class="text-center text-muted">Zero cryptographic elements identified.</td></tr>';

            // PQC Readiness
            document.getElementById('qsPqcScore').textContent = Math.round(d.security.pqc.score);
            const pqcBadge = document.getElementById('qsPqcLabel');
            const status = d.security.pqc.status.toLowerCase();
            pqcBadge.textContent = status.toUpperCase();
            pqcBadge.className = 'qs-badge ' + (status === 'safe' ? 'safe' : (status === 'unsafe' ? 'danger' : 'warn'));

            const pqcList = document.getElementById('qsPqcList');
            pqcList.innerHTML = d.security.pqc.classifications.length > 0
                ? d.security.pqc.classifications.map(f => `
                    <div class="qs-detail-card mb-2" style="padding: 0.75rem;">
                        <div class="d-flex justify-content-between align-items-center">
                            <strong>${f.algorithm}</strong>
                            <span class="qs-badge ${f.status === 'safe' ? 'safe' : 'danger'}">${f.status}</span>
                        </div>
                        <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 4px;">NIST Cat: ${f.nist_category || 'N/A'} | Score: ${f.score}</div>
                    </div>`).join('')
                : '<div class="text-center py-4">No PQC specific telemetry.</div>';

            // Timeline
            const timeline = document.getElementById('qsTimeline');
            timeline.innerHTML = d.network.discovery.length > 0
                ? d.network.discovery.map(item => `
                    <div class="timeline-step">
                        <strong>${item.type.toUpperCase()}</strong>: Detected as ${item.status}<br>
                        <small>${item.date}</small>
                    </div>`).join('')
                : 'Initial asset enrollment. No further telemetry discovery recorded.';

            // Geo
            document.getElementById('qsGeoTarget').textContent = d.target;
            document.getElementById('qsGeoLoc').textContent = `${d.network.geo.city}, ${d.network.geo.country}`;

            // Lazy init interactive parts for current tab
            this._initMap();
            this._initPqcChart();
        }

        /**
         * Initializes Leaflet Map specifically for the asset's geolocation.
         */
        _initMap() {
            if (this.map) {
                this.map.remove();
                this.map = null;
            }

            const geo = this.data.network.geo;
            const mapContainer = document.getElementById('qsDetailMap');
            
            if (!geo || geo.lat === null || geo.lon === null || (geo.lat === 0 && geo.lon === 0)) {
                mapContainer.innerHTML = `
                    <div class="d-flex flex-column align-items-center justify-content-center h-100 text-muted" style="background: rgba(255,255,255,0.02);">
                        <i class="fas fa-map-marker-alt fa-2x mb-3" style="opacity: 0.2;"></i>
                        <div>Geolocation unavailable for this target.</div>
                        <small style="font-size: 0.7rem; margin-top: 4px;">Internal or private IP range detected.</small>
                    </div>`;
                return;
            }

            // Clear container before init
            mapContainer.innerHTML = '';
            
            this.map = L.map('qsDetailMap', {
                zoomControl: false,
                attributionControl: false
            }).setView([geo.lat, geo.lon], 11);

            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                maxZoom: 19
            }).addTo(this.map);

            const customIcon = L.divIcon({
                className: 'qs-map-marker',
                html: '<div class="marker-pulse"></div><div class="marker-core"></div>',
                iconSize: [20, 20],
                iconAnchor: [10, 10]
            });

            const marker = L.marker([geo.lat, geo.lon], { icon: customIcon }).addTo(this.map);
            
            const popupContent = `
                <div class="qs-map-popup">
                    <div class="popup-title">${this.data.target}</div>
                    <div class="popup-loc">${geo.city}, ${geo.country}</div>
                    <div class="popup-isp">${geo.isp || 'N/A'}</div>
                </div>
            `;
            
            marker.bindPopup(popupContent).openPopup();

            // Add a subtle circle area
            L.circle([geo.lat, geo.lon], {
                color: 'var(--accent)',
                fillColor: 'var(--accent)',
                fillOpacity: 0.05,
                radius: 5000,
                weight: 1
            }).addTo(this.map);
        }

        /**
         * Initializes the PQC Radar chart or Bar chart.
         */
        _initPqcChart() {
            if (this.pqcChart) this.pqcChart.destroy();
            const ctx = document.getElementById('qsPqcChart').getContext('2d');
            const score = this.data.security.pqc.score;
            
            this.pqcChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Remaining'],
                    datasets: [{
                        data: [score, 100 - score],
                        backgroundColor: ['#00ffcc', 'rgba(255,255,255,0.05)'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '80%',
                    plugins: { legend: { display: false } }
                }
            });
        }

        /**
         * Initializes the Network Context Graph using vis-network.
         */
        _initNetworkGraph() {
            if (this.graph) {
                this.graph.destroy();
                this.graph = null;
            }

            const container = document.getElementById('qsNetworkGraph');
            const graphData = this.data.network.graph;

            if (!graphData.nodes.length) {
                container.innerHTML = '<div class="d-flex align-items-center justify-content-center h-100 text-muted">Insufficient data for graph construction.</div>';
                return;
            }

            const colorMap = {
                asset: '#00ffcc',
                ip: '#00ccff',
                service: '#bd93f9'
            };

            const visData = {
                nodes: new vis.DataSet(graphData.nodes.map(n => ({
                    ...n,
                    color: { background: colorMap[n.group] || '#ccc', border: 'transparent' },
                    font: { color: '#ffffff' }
                }))),
                edges: new vis.DataSet(graphData.edges.map(e => ({
                    ...e,
                    color: { color: 'rgba(255,255,255,0.2)' }
                })))
            };

            const options = {
                nodes: { shape: 'dot', size: 16 },
                physics: {
                    enabled: true,
                    barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 95 }
                },
                interaction: { hover: true }
            };

            this.graph = new vis.Network(container, visData, options);
        }

        _initTabListeners() {
            if (!this.modal) return;
            this.modal.querySelectorAll('.qs-tab-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const tabName = btn.dataset.tab;
                    
                    // Toggle Buttons
                    this.modal.querySelectorAll('.qs-tab-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    
                    // Toggle Panes
                    this.modal.querySelectorAll('.qs-tab-pane').forEach(p => p.style.display = 'none');
                    const activePane = document.getElementById(`tab-${tabName}`);
                    activePane.style.display = 'block';

                    // Re-initialize dynamic parts if needed
                    if (tabName === 'network') {
                        setTimeout(() => this._initNetworkGraph(), 50);
                    } else if (tabName === 'overview' && this.map) {
                        setTimeout(() => this.map.invalidateSize(), 50);
                    }
                });
            });
        }

        _showStatus(msg, isError = false) {
            const sub = document.getElementById('qsModalSubtitle');
            if (!sub) return;
            sub.textContent = msg;
            sub.style.color = isError ? 'var(--danger)' : 'var(--text-secondary)';
        }

        _escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        _renderCollection(value) {
            if (Array.isArray(value)) {
                if (!value.length) return '[]';
                return this._escapeHtml(value.join(', '));
            }
            if (value && typeof value === 'object') {
                const entries = Object.entries(value);
                if (!entries.length) return '{}';
                return this._escapeHtml(entries.map(([k, v]) => `${k}: ${v}`).join(', '));
            }
            if (value === null || value === undefined || value === '') return 'N/A';
            return this._escapeHtml(String(value));
        }

        _cleanup() {
            if (this.map) this.map.remove();
            if (this.graph) this.graph.destroy();
            if (this.pqcChart) this.pqcChart.destroy();
            this.map = null;
            this.graph = null;
            this.pqcChart = null;
            this.currentAssetId = null;
            this.data = null;
            this._resetTabs('overview');
        }
    }

    // Global Registry
    window.AssetDetailModal = new AssetDetailModal();

})();
