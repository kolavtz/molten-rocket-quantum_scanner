(function () {
  'use strict';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  }

  function parsePorts(raw) {
    var text = String(raw || '').trim();
    if (!text) return undefined;
    return text.replace(/\s+/g, ',').split(',').map(function (x) { return Number(String(x).trim()); }).filter(function (n) {
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    });
  }

  function readFileAsText(file) {
    return new Promise(function (resolve, reject) {
      if (!file) {
        resolve('');
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        resolve(String(reader.result || ''));
      };
      reader.onerror = function () {
        reject(new Error('Unable to read CSV file.'));
      };
      reader.readAsText(file);
    });
  }

  function parseCsvTargetEntries(csvText) {
    var text = String(csvText || '');
    if (!text.trim()) return [];

    return text.split(/\r?\n/).map(function (line) {
      return String(line || '').trim();
    }).filter(function (line) {
      return !!line;
    }).map(function (line, idx) {
      var isHeader = idx === 0 && /^(ip|target|host)\b/i.test(line);
      if (isHeader) return null;

      var firstComma = line.indexOf(',');
      var target = '';
      var portSegment = '';
      if (firstComma >= 0) {
        target = line.slice(0, firstComma).trim();
        portSegment = line.slice(firstComma + 1).trim();
      } else {
        target = line.trim();
      }

      if (!target) return null;
      var ports = parsePorts(portSegment);
      if (ports && ports.length) {
        return { target: target, ports: ports };
      }
      return { target: target };
    }).filter(function (row) { return !!row; });
  }

  function setActionMessage(msg, isError) {
    var node = document.getElementById('scanActionMsg');
    if (!node) return;
    node.textContent = msg || '';
    node.style.color = isError ? 'var(--danger)' : 'var(--text-secondary)';
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatValue(value, fallback) {
    var text = String(value == null || value === '' ? (fallback || '') : value);
    return text || (fallback || '—');
  }

  function formatDate(value) {
    if (!value) return '—';
    var parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
  }

  function setDetailVisibility(hasContent) {
    var panel = document.getElementById('scanDetailPanel');
    var empty = document.getElementById('scanDetailEmpty');
    var content = document.getElementById('scanDetailContent');
    if (panel) panel.style.display = 'block';
    if (empty) empty.style.display = hasContent ? 'none' : 'block';
    if (content) content.style.display = hasContent ? 'block' : 'none';
  }

  function setDetailText(id, value) {
    var node = document.getElementById(id);
    if (node) node.textContent = formatValue(value);
  }

  function renderDetailSummary(lines) {
    var holder = document.getElementById('scanDetailSummary');
    if (!holder) return;
    holder.innerHTML = (lines || []).map(function (line) {
      return '<div style="display:flex; gap:0.6rem; align-items:flex-start;"><span style="color:var(--accent); font-weight:700;">•</span><span>' + escapeHtml(line) + '</span></div>';
    }).join('') || '<div style="color:var(--text-secondary);">No additional result summary is available yet.</div>';
  }

  function renderRawResult(payload) {
    var node = document.getElementById('scanDetailRaw');
    if (!node) return;
    try {
      node.textContent = JSON.stringify(payload || {}, null, 2);
    } catch (_err) {
      node.textContent = String(payload || '');
    }
  }

  function renderScanMetricCards(kpis) {
    var holder = document.getElementById('scanLiveKpis');
    if (!holder) return;
    var metrics = kpis || {};
    var keys = [
      ['total_scans', 'Total Scans'],
      ['running', 'Running'],
      ['completed', 'Completed'],
      ['failed', 'Failed'],
      ['success_rate', 'Success Rate %'],
      ['avg_pqc_score', 'Avg PQC Score'],
      ['scans_last_24h', 'Scans (24h)'],
      ['total_assets_found', 'Assets Found']
    ];
    holder.innerHTML = keys.map(function (entry) {
      var key = entry[0];
      var label = entry[1];
      var raw = metrics[key];
      var value = (raw == null || raw === '') ? '0' : String(raw);
      return (
        '<div class="glass-card" style="padding:0.7rem;">' +
        '<div style="font-size:0.72rem; color:var(--text-secondary); text-transform:uppercase;">' + escapeHtml(label) + '</div>' +
        '<div style="font-size:1.05rem; font-weight:700; margin-top:0.25rem;">' + escapeHtml(value) + '</div>' +
        '</div>'
      );
    }).join('');
  }

  function renderCertificateRows(payload) {
    var body = document.getElementById('scanCertTableBody');
    var summary = document.getElementById('scanCertSummary');
    var pageInfo = document.getElementById('scanCertPageInfo');
    var prevBtn = document.getElementById('scanCertPrev');
    var nextBtn = document.getElementById('scanCertNext');

    if (!body || !summary || !pageInfo || !prevBtn || !nextBtn) return;

    var data = (payload && payload.data) ? payload.data : {};
    var items = Array.isArray(data.items) ? data.items : [];
    var kpis = data.kpis || {};
    var total = Number(data.total || 0);
    var page = Number(data.page || 1);
    var totalPages = Number(data.total_pages || 1);

    summary.textContent =
      'Total: ' + formatValue(kpis.total_certificates, '0') +
      ' · Expired: ' + formatValue(kpis.expired, '0') +
      ' · Expiring ≤30d: ' + formatValue(kpis.expiring_30_days, '0') +
      ' · Weak TLS: ' + formatValue(kpis.weak_tls, '0') +
      ' · Weak Keys: ' + formatValue(kpis.weak_keys, '0');

    if (!items.length) {
      body.innerHTML = '<tr><td colspan="8" style="color:var(--text-secondary);">No certificate details found for this scan.</td></tr>';
    } else {
      body.innerHTML = items.map(function (row) {
        var fingerprint = String(row.fingerprint_sha256 || '');
        var fingerprintShort = fingerprint ? (fingerprint.slice(0, 18) + (fingerprint.length > 18 ? '...' : '')) : '—';
        return (
          '<tr>' +
            '<td>' + escapeHtml(formatValue(row.endpoint, '—')) + '</td>' +
            '<td>' + escapeHtml(formatValue(row.subject_cn, '—')) + '</td>' +
            '<td>' + escapeHtml(formatValue(row.issuer, '—')) + '</td>' +
            '<td>' + escapeHtml(formatValue(row.status, 'Unknown')) + '</td>' +
            '<td>' + escapeHtml(formatValue(row.tls_version, '—')) + '</td>' +
            '<td>' + escapeHtml(formatValue(row.key_length, '0')) + '</td>' +
            '<td>' + escapeHtml(formatDate(row.valid_until)) + '</td>' +
            '<td title="' + escapeHtml(fingerprint) + '">' + escapeHtml(fingerprintShort) + '</td>' +
          '</tr>'
        );
      }).join('');
    }

    pageInfo.textContent = 'Page ' + page + '/' + totalPages + ' · Total ' + total;
    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= totalPages;
  }

  function getApiClient() {
    return (typeof window !== 'undefined' && window.QuantumShieldApiClient && typeof window.QuantumShieldApiClient.fetch === 'function')
      ? window.QuantumShieldApiClient
      : null;
  }

  async function fetchApiJson(endpoint) {
    var client = getApiClient();
    if (client) {
      return client.fetch(endpoint, { method: 'GET', useCache: false });
    }

    var resp = await fetch('/api' + endpoint, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json', 'X-CSRFToken': getCsrfToken() }
    });
    var data = {};
    try { data = await resp.json(); } catch (_err) { data = {}; }
    if (!resp.ok) throw new Error(data.message || ('Request failed (' + resp.status + ')'));
    return data;
  }

  function renderProgressRows(map) {
    var holder = document.getElementById('scanProgress');
    if (!holder) return;
    var ids = Object.keys(map || {});
    if (!ids.length) {
      holder.innerHTML = '<div style="color:var(--text-secondary);">No active scans.</div>';
      return;
    }

    holder.innerHTML = ids.map(function (scanId) {
      var row = map[scanId] || {};
      var target = escapeHtml(String(row.target || ''));
      var displayId = escapeHtml(scanId);
      var status = String(row.status || 'unknown');
      var statusColor = 'var(--text-secondary)';
      if (status === 'completed') statusColor = 'var(--safe)';
      if (status === 'running') statusColor = 'var(--warn)';
      if (status === 'failed' || status === 'error') statusColor = 'var(--danger)';
      var meta = row.result_scan_id ? ('<a href="/results/' + encodeURIComponent(String(row.result_scan_id)) + '" target="_blank" rel="noreferrer" style="color:var(--accent);">Open result</a>') : '';
      if (row.error) {
        meta = escapeHtml(String(row.error));
      }
      return (
        '<div class="glass-card" style="padding:0.5rem 0.7rem; border-left:2px solid ' + statusColor + ';">' +
        '<strong>' + displayId + '</strong> · ' + target + ' · <span style="text-transform:uppercase; color:' + statusColor + ';">' + escapeHtml(status) + '</span>' +
        (meta ? ('<div style="color:var(--text-secondary); margin-top:0.2rem;">' + meta + '</div>') : '') +
        '</div>'
      );
    }).join('');
  }

  async function postJson(url, payload) {
    var resp = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRFToken': getCsrfToken()
      },
      body: JSON.stringify(payload || {})
    });
    var data = {};
    try { data = await resp.json(); } catch (_err) { data = {}; }
    if (!resp.ok) {
      throw new Error(data.message || ('Request failed (' + resp.status + ')'));
    }
    return data;
  }

  async function fetchStatus(scanId) {
    var resp = await fetch('/api/scans/' + encodeURIComponent(scanId) + '/status', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json', 'X-CSRFToken': getCsrfToken() }
    });
    var data = {};
    try { data = await resp.json(); } catch (_err) { data = {}; }
    if (!resp.ok) {
      throw new Error(data.message || ('Status failed (' + resp.status + ')'));
    }
    return data;
  }

  function currentRadioValue(name, fallbackValue) {
    var node = document.querySelector('input[name="' + name + '"]:checked');
    return node ? String(node.value || fallbackValue || '') : String(fallbackValue || '');
  }

  function togglePanel(toggleId, panelId) {
    var toggle = document.getElementById(toggleId);
    var panel = document.getElementById(panelId);
    if (!toggle || !panel) return;
    panel.style.display = toggle.checked ? 'block' : 'none';
  }

  function switchMode(mode, canBulk) {
    var tabSingle = document.getElementById('tabSingle');
    var tabBulk = document.getElementById('tabBulk');
    var modeSingle = document.getElementById('modeSingle');
    var modeBulk = document.getElementById('modeBulk');

    var useBulk = canBulk && mode === 'bulk';
    if (modeSingle) modeSingle.style.display = useBulk ? 'none' : 'block';
    if (modeBulk) modeBulk.style.display = useBulk ? 'block' : 'none';

    if (tabSingle) {
      tabSingle.classList.toggle('scan-tab-active', !useBulk);
      tabSingle.setAttribute('aria-selected', (!useBulk).toString());
    }
    if (tabBulk) {
      tabBulk.classList.toggle('scan-tab-active', useBulk);
      tabBulk.setAttribute('aria-selected', useBulk.toString());
    }
  }

  function init(options) {
    options = options || {};
    var canBulkScan = !!options.canBulkScan;

    var singleBtn = document.getElementById('singleScanBtn');
    var bulkBtn = document.getElementById('bulkScanBtn');
    var singleTarget = document.getElementById('singleTarget');
    var bulkTargets = document.getElementById('bulkTargets');
    var bulkCsvFile = document.getElementById('bulkCsvFile');
    var bulkCsvHint = document.getElementById('bulkCsvHint');
    var portsInput = document.getElementById('portsInput');
    var autodiscoverySingle = document.getElementById('autodiscoverySingle');
    var autodiscoveryBulk = document.getElementById('autodiscoveryBulk');
    var addToInventorySingle = document.getElementById('addToInventorySingle');
    var addToInventoryBulk = document.getElementById('addToInventoryBulk');
    var singleOwner = document.getElementById('singleOwner');
    var bulkOwner = document.getElementById('bulkOwner');
    var singleRisk = document.getElementById('singleRisk');
    var bulkRisk = document.getElementById('bulkRisk');
    var singleNotes = document.getElementById('singleNotes');
    var bulkNotes = document.getElementById('bulkNotes');
    var singleAssetClassValue = document.getElementById('singleAssetClassValue');
    var bulkAssetClassValue = document.getElementById('bulkAssetClassValue');

    var scheduleTarget = document.getElementById('scheduleTarget');
    var scheduleFrequency = document.getElementById('scheduleFrequency');
    var scheduleTime = document.getElementById('scheduleTime');
    var scheduleTimezone = document.getElementById('scheduleTimezone');
    var scheduleAutoAdd = document.getElementById('scheduleAutoAdd');
    var scheduleCreateBtn = document.getElementById('scheduleCreateBtn');
    var schedulesList = document.getElementById('schedulesList');

    var tabSingle = document.getElementById('tabSingle');
    var tabBulk = document.getElementById('tabBulk');

    if (tabSingle) tabSingle.addEventListener('click', function () { switchMode('single', canBulkScan); });
    if (tabBulk) tabBulk.addEventListener('click', function () { switchMode('bulk', canBulkScan); });
    switchMode('single', canBulkScan);

    if (addToInventorySingle) {
      addToInventorySingle.addEventListener('change', function () {
        togglePanel('addToInventorySingle', 'inventorySingleFields');
      });
      togglePanel('addToInventorySingle', 'inventorySingleFields');
    }
    if (addToInventoryBulk) {
      addToInventoryBulk.addEventListener('change', function () {
        togglePanel('addToInventoryBulk', 'inventoryBulkFields');
      });
      togglePanel('addToInventoryBulk', 'inventoryBulkFields');
    }

    document.querySelectorAll('[data-target-quick]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (!singleTarget) return;
        singleTarget.value = String(btn.getAttribute('data-target-quick') || '');
        singleTarget.focus();
      });
    });

    var scanMap = {};
    var pollTimer = null;
    var detailState = {
      scanId: '',
      live: null,
      result: null,
      certPage: 1,
      certPageSize: 10,
      certTotalPages: 1,
      certTargetScanId: ''
    };

    async function loadScanMetrics() {
      try {
        var metricsPayload = await fetchApiJson('/scans/metrics');
        var kpis = (metricsPayload && metricsPayload.data && metricsPayload.data.kpis) ? metricsPayload.data.kpis : {};
        renderScanMetricCards(kpis);
      } catch (_err) {
        renderScanMetricCards({});
      }
    }

    async function loadCertificatesForScan(scanId, page) {
      if (!scanId) return;
      var activePage = Number(page || detailState.certPage || 1);
      var endpoint = '/scans/' + encodeURIComponent(scanId) + '/certificates?page=' + encodeURIComponent(activePage) + '&page_size=' + encodeURIComponent(detailState.certPageSize || 10) + '&sort=valid_until&order=asc';
      try {
        var certPayload = await fetchApiJson(endpoint);
        detailState.certPage = Number((certPayload && certPayload.data && certPayload.data.page) || activePage);
        detailState.certTotalPages = Number((certPayload && certPayload.data && certPayload.data.total_pages) || 1);
        detailState.certTargetScanId = scanId;
        renderCertificateRows(certPayload);
      } catch (_err) {
        renderCertificateRows({ data: { items: [], total: 0, page: 1, total_pages: 1, kpis: {} } });
      }
    }

    function syncDetailView() {
      var live = detailState.live || {};
      var result = detailState.result || {};
      var report = Object.keys(result).length ? result : live;

      if (!detailState.scanId) {
        setDetailVisibility(false);
        return;
      }

      setDetailVisibility(true);
      setDetailText('scanDetailId', report.scan_id || detailState.scanId);
      setDetailText('scanDetailTarget', report.target || live.target || '—');
      setDetailText('scanDetailStatus', report.status || live.status || 'unknown');
      setDetailText('scanDetailAssets', report.total_assets != null ? report.total_assets : (live.assets_found != null ? live.assets_found : '—'));
      setDetailText('scanDetailScore', report.overall_pqc_score != null ? report.overall_pqc_score : (live.pqc_score != null ? live.pqc_score : '—'));
      setDetailText('scanDetailResultId', report.scan_id || live.result_scan_id || '—');
      setDetailText('scanDetailStarted', formatDate(report.started_at || live.started_at || live.updated_at));
      setDetailText('scanDetailCompleted', formatDate(report.completed_at || live.completed_at || live.updated_at));
      setDetailText('scanDetailSource', report.scan_kind || report.source || live.scan_kind || 'scan center');
      setDetailText('scanDetailJob', live.job_id || report.job_id || '—');

      var lines = [];
      if (report.overview && typeof report.overview === 'object') {
        if (report.overview.summary) lines.push(String(report.overview.summary));
        if (report.overview.asset_count != null) lines.push('Assets in overview: ' + report.overview.asset_count);
        if (report.overview.average_compliance_score != null) lines.push('Average compliance score: ' + report.overview.average_compliance_score);
      }
      if (report.discovered_services && report.discovered_services.length) {
        lines.push('Discovered services: ' + report.discovered_services.length);
      }
      if (live.error) {
        lines.push('Live status error: ' + live.error);
      }
      renderDetailSummary(lines);

      var openLink = document.getElementById('scanDetailResultLink');
      if (openLink) {
        var hasFullReport = !!(Object.keys(result).length && (result.overview || result.total_assets != null || (result.discovered_services && result.discovered_services.length)));
        var resultId = result.scan_id || live.result_scan_id || detailState.scanId;
        if (hasFullReport && resultId) {
          openLink.href = '/results/' + encodeURIComponent(String(resultId));
          openLink.textContent = 'Open Full Result';
          openLink.removeAttribute('aria-disabled');
          openLink.style.pointerEvents = '';
          openLink.style.opacity = '';
        } else {
          openLink.href = '#';
          openLink.textContent = 'Result Unavailable';
          openLink.setAttribute('aria-disabled', 'true');
          openLink.style.pointerEvents = 'none';
          openLink.style.opacity = '0.55';
        }
      }

      renderRawResult({ live: live, result: result });
    }

    async function loadDetail(scanId) {
      if (!scanId) return;
      detailState.scanId = scanId;
      detailState.live = null;
      detailState.result = null;
      detailState.certPage = 1;
      detailState.certTotalPages = 1;
      detailState.certTargetScanId = '';
      setDetailVisibility(false);
      setActionMessage('Loading scan details for ' + scanId + '...');

      try {
        var statusPayload = await fetchApiJson('/scans/' + encodeURIComponent(scanId) + '/status');
        detailState.live = statusPayload.data || statusPayload || {};

        var resultScanId = String((detailState.live || {}).result_scan_id || scanId);
        try {
          var resultPayload = await fetchApiJson('/scans/' + encodeURIComponent(resultScanId) + '/result');
          detailState.result = resultPayload.data || resultPayload || {};
        } catch (_resultErr) {
          detailState.result = {};
        }

        await loadCertificatesForScan(resultScanId, 1);

        syncDetailView();
        setActionMessage('Showing details for ' + scanId + '.');
      } catch (err) {
        setActionMessage(err.message || 'Failed to load scan details.', true);
        detailState.live = { scan_id: scanId, status: 'unknown' };
        detailState.result = {};
        renderCertificateRows({ data: { items: [], total: 0, page: 1, total_pages: 1, kpis: {} } });
        syncDetailView();
      }
    }

    function showRecordDetails(record) {
      if (!record || !record.scan_id) return;
      loadDetail(String(record.scan_id));
    }

    function startPolling(scanIds) {
      (scanIds || []).forEach(function (id) {
        if (!scanMap[id]) {
          scanMap[id] = { scan_id: id, status: 'queued' };
        }
      });
      renderProgressRows(scanMap);

      if (pollTimer) return;
      pollTimer = setInterval(async function () {
        var ids = Object.keys(scanMap);
        if (!ids.length) {
          clearInterval(pollTimer);
          pollTimer = null;
          return;
        }

        var allDone = true;
        for (var i = 0; i < ids.length; i += 1) {
          var id = ids[i];
          try {
            var payload = await fetchStatus(id);
            scanMap[id] = payload.data || { scan_id: id, status: 'unknown' };
            if (detailState.scanId === id) {
              detailState.live = scanMap[id];
              syncDetailView();
            }
            var st = String((scanMap[id] || {}).status || '').toLowerCase();
            if (st !== 'completed' && st !== 'failed') {
              allDone = false;
            }
          } catch (_err) {
            allDone = false;
          }
        }

        renderProgressRows(scanMap);
        loadScanMetrics();
        if (allDone) {
          clearInterval(pollTimer);
          pollTimer = null;
          setActionMessage('All scans completed. Refreshing table...');
          if (window.QuantumShieldApiTable && window.QuantumShieldApiTable.fetchDashboardPage) {
            // trigger table refresh by simulating search button click
            var searchBtn = document.querySelector('[data-api-search-btn]');
            if (searchBtn) searchBtn.click();
          }
          loadScanMetrics();
        }
      }, 2500);
    }

    if (singleBtn) {
      singleBtn.addEventListener('click', async function () {
        var target = (singleTarget && singleTarget.value ? singleTarget.value : '').trim();
        if (!target) {
          setActionMessage('Please provide a target.', true);
          return;
        }
        try {
          setActionMessage('Submitting single scan...');
          var payload = await postJson('/api/scans', {
            target: target,
            ports: parsePorts(portsInput && portsInput.value),
            autodiscovery: !!(autodiscoverySingle && autodiscoverySingle.checked),
            add_to_inventory: !!(addToInventorySingle && addToInventorySingle.checked),
            owner: singleOwner ? String(singleOwner.value || '').trim() : '',
            risk_level: singleRisk ? String(singleRisk.value || 'Medium') : 'Medium',
            notes: singleNotes ? String(singleNotes.value || '').trim() : '',
            asset_type: 'Web App',
            asset_class_mode: currentRadioValue('singleAssetClassMode', 'auto'),
            asset_class_value: singleAssetClassValue ? String(singleAssetClassValue.value || '').trim() : ''
          });
          setActionMessage('Scan queued: ' + payload.scan_id);
          startPolling([payload.scan_id]);
          if (singleTarget) singleTarget.value = '';
        } catch (err) {
          setActionMessage(err.message || 'Failed to submit single scan.', true);
        }
      });
    }

    if (bulkBtn) {
      bulkBtn.addEventListener('click', async function () {
        if (!canBulkScan) {
          setActionMessage('Bulk scanning is restricted to Admin/Manager roles.', true);
          return;
        }

        var lines = String((bulkTargets && bulkTargets.value) || '').split(/\r?\n/);
        var targetEntries = lines.map(function (x) { return x.trim(); }).filter(Boolean).map(function (target) {
          return { target: target };
        });

        if (bulkCsvFile && bulkCsvFile.files && bulkCsvFile.files.length > 0) {
          try {
            var csvRows = await readFileAsText(bulkCsvFile.files[0]);
            var csvEntries = parseCsvTargetEntries(csvRows);
            if (csvEntries.length) {
              targetEntries = targetEntries.concat(csvEntries);
              if (bulkCsvHint) {
                bulkCsvHint.textContent = 'Loaded ' + csvEntries.length + ' target(s) from CSV.';
              }
            } else if (bulkCsvHint) {
              bulkCsvHint.textContent = 'CSV loaded but no valid targets were found.';
            }
          } catch (csvError) {
            setActionMessage(csvError.message || 'Unable to parse CSV file.', true);
            return;
          }
        }

        if (!targetEntries.length) {
          setActionMessage('Please provide at least one target for bulk scan.', true);
          return;
        }

        try {
          setActionMessage('Submitting bulk scan (' + targetEntries.length + ' targets)...');
          var payload = await postJson('/api/scans/bulk', {
            targets: targetEntries.map(function (entry) { return entry.target; }),
            target_entries: targetEntries,
            ports: parsePorts(portsInput && portsInput.value),
            autodiscovery: !!(autodiscoveryBulk && autodiscoveryBulk.checked),
            add_to_inventory: !!(addToInventoryBulk && addToInventoryBulk.checked),
            owner: bulkOwner ? String(bulkOwner.value || '').trim() : '',
            risk_level: bulkRisk ? String(bulkRisk.value || 'Medium') : 'Medium',
            notes: bulkNotes ? String(bulkNotes.value || '').trim() : '',
            asset_type: 'Web App',
            asset_class_mode: currentRadioValue('bulkAssetClassMode', 'auto'),
            asset_class_value: bulkAssetClassValue ? String(bulkAssetClassValue.value || '').trim() : ''
          });
          setActionMessage('Bulk scan queued: ' + payload.queued_count + ' targets');
          startPolling(payload.scan_ids || []);
          if (bulkTargets) bulkTargets.value = '';
          if (bulkCsvFile) bulkCsvFile.value = '';
          if (bulkCsvHint) bulkCsvHint.textContent = 'CSV format: ip,[ports separated by comma or space]';
        } catch (err) {
          setActionMessage(err.message || 'Failed to submit bulk scan.', true);
        }
      });
    }

    async function loadSchedules() {
      if (!schedulesList) return;
      try {
        var resp = await fetch('/api/scan-schedules', {
          method: 'GET',
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' }
        });

        if (!resp.ok) {
          if (resp.status === 403) {
            schedulesList.innerHTML = '<div style="color:var(--text-secondary);">Schedule access is restricted to Admin/Manager.</div>';
            return;
          }
          throw new Error('Failed to load schedules');
        }

        var result = await resp.json();
        var schedules = result.data || result.schedules || [];

        if (!schedules.length) {
          schedulesList.innerHTML = '<div style="color:var(--text-secondary);">No scheduled scans found. Please set up scheduled scans.</div>';
          return;
        }

        schedulesList.innerHTML = schedules.map(function (schedule) {
          var detail = String(schedule.frequency || 'daily') + ' at ' + String(schedule.scheduled_time || '--:--') + ' (' + String(schedule.timezone || 'UTC') + ')';
          var auto = schedule.auto_add_to_inventory ? '<div style="font-size:0.75rem; color:var(--safe);">Auto-add enabled</div>' : '';
          var scheduleId = String(schedule.id || '');
          return (
            '<div class="glass-card" style="padding:0.7rem; display:flex; justify-content:space-between; gap:0.8rem; align-items:center;">' +
              '<div>' +
                '<div style="font-weight:700;">' + escapeHtml(String(schedule.target || '')) + '</div>' +
                '<div style="font-size:0.8rem; color:var(--text-secondary);">' + escapeHtml(detail) + '</div>' +
                auto +
              '</div>' +
              '<div class="row-actions">' +
                '<button class="quick-btn" data-schedule-detail="' + scheduleId + '" type="button">Details</button>' +
                '<button class="quick-btn" data-schedule-edit="' + scheduleId + '" type="button">Edit</button>' +
                '<button class="quick-btn" data-schedule-delete="' + scheduleId + '" type="button">Delete</button>' +
              '</div>' +
            '</div>'
          );
        }).join('');

        schedulesList.querySelectorAll('[data-schedule-detail]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            showScheduleDetails(String(btn.getAttribute('data-schedule-detail') || ''));
          });
        });

        schedulesList.querySelectorAll('[data-schedule-edit]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            editSchedule(String(btn.getAttribute('data-schedule-edit') || ''));
          });
        });

        schedulesList.querySelectorAll('[data-schedule-delete]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            deleteSchedule(String(btn.getAttribute('data-schedule-delete') || ''));
          });
        });
      } catch (_err) {
        schedulesList.innerHTML = '<div style="color:var(--danger);">Failed to load schedules.</div>';
      }
    }

    async function createSchedule() {
      if (!scheduleTarget || !scheduleFrequency || !scheduleTime || !scheduleTimezone) return;
      var target = String(scheduleTarget.value || '').trim();
      var frequency = String(scheduleFrequency.value || 'daily').trim();
      var when = String(scheduleTime.value || '').trim();
      var timezone = String(scheduleTimezone.value || 'UTC').trim();
      var auto = !!(scheduleAutoAdd && scheduleAutoAdd.checked);

      if (!target || !when) {
        setActionMessage('Schedule target and time are required.', true);
        return;
      }

      try {
        await postJson('/api/scan-schedules', {
          target: target,
          frequency: frequency,
          scheduled_time: when,
          timezone: timezone,
          auto_add_to_inventory: auto
        });
        setActionMessage('Schedule created successfully.');
        scheduleTarget.value = '';
        scheduleTime.value = '';
        if (scheduleAutoAdd) scheduleAutoAdd.checked = false;
        await loadSchedules();
      } catch (err) {
        setActionMessage(err.message || 'Failed to create schedule.', true);
      }
    }

    async function deleteSchedule(scheduleId) {
      if (!scheduleId) return;
      if (!window.confirm('Delete this schedule?')) return;
      try {
        var resp = await fetch('/api/scan-schedules/' + encodeURIComponent(scheduleId), {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: {
            'Accept': 'application/json',
            'X-CSRFToken': getCsrfToken()
          }
        });
        var payload = {};
        try { payload = await resp.json(); } catch (_e) { payload = {}; }
        if (!resp.ok) throw new Error(payload.message || 'Failed to delete schedule.');
        setActionMessage('Schedule deleted.');
        await loadSchedules();
      } catch (err) {
        setActionMessage(err.message || 'Failed to delete schedule.', true);
      }
    }

    async function getSchedule(scheduleId) {
      if (!scheduleId) {
        throw new Error('Missing schedule id.');
      }

      var resp = await fetch('/api/scan-schedules/' + encodeURIComponent(scheduleId), {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'X-CSRFToken': getCsrfToken() }
      });
      var payload = {};
      try { payload = await resp.json(); } catch (_e) { payload = {}; }
      if (!resp.ok) throw new Error(payload.message || 'Failed to fetch schedule details.');
      return payload.data || payload;
    }

    async function updateSchedule(scheduleId, payload) {
      var resp = await fetch('/api/scan-schedules/' + encodeURIComponent(scheduleId), {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify(payload || {})
      });

      var body = {};
      try { body = await resp.json(); } catch (_e) { body = {}; }
      if (!resp.ok) throw new Error(body.message || 'Failed to update schedule.');
      return body;
    }

    async function showScheduleDetails(scheduleId) {
      try {
        var schedule = await getSchedule(scheduleId);
        var lines = [
          'ID: ' + String(schedule.id || ''),
          'Target: ' + String(schedule.target || ''),
          'Frequency: ' + String(schedule.frequency || ''),
          'Time: ' + String(schedule.scheduled_time || '') + ' (' + String(schedule.timezone || 'UTC') + ')',
          'Auto Add: ' + (schedule.auto_add_to_inventory ? 'Yes' : 'No'),
          'Status: ' + String(schedule.status || 'active'),
          'Created: ' + formatDate(schedule.created_at),
          'Updated: ' + formatDate(schedule.updated_at)
        ];
        window.alert(lines.join('\n'));
      } catch (err) {
        setActionMessage(err.message || 'Failed to load schedule details.', true);
      }
    }

    async function editSchedule(scheduleId) {
      try {
        var current = await getSchedule(scheduleId);

        var target = window.prompt('Schedule target', String(current.target || ''));
        if (target === null) return;
        target = String(target || '').trim();

        var frequency = window.prompt('Frequency (daily|weekly|monthly)', String(current.frequency || 'daily'));
        if (frequency === null) return;
        frequency = String(frequency || '').trim().toLowerCase();

        var scheduledTime = window.prompt('Scheduled time (HH:MM)', String(current.scheduled_time || '12:00'));
        if (scheduledTime === null) return;
        scheduledTime = String(scheduledTime || '').trim();

        var timezone = window.prompt('Timezone', String(current.timezone || 'UTC'));
        if (timezone === null) return;
        timezone = String(timezone || '').trim();

        var autoAddRaw = window.prompt('Auto add to inventory? (yes/no)', current.auto_add_to_inventory ? 'yes' : 'no');
        if (autoAddRaw === null) return;
        var autoAdd = /^y(es)?$/i.test(String(autoAddRaw || '').trim());

        await updateSchedule(scheduleId, {
          target: target,
          frequency: frequency,
          scheduled_time: scheduledTime,
          timezone: timezone,
          auto_add_to_inventory: autoAdd
        });

        setActionMessage('Schedule updated successfully.');
        await loadSchedules();
      } catch (err) {
        setActionMessage(err.message || 'Failed to update schedule.', true);
      }
    }

    if (scheduleCreateBtn) {
      scheduleCreateBtn.addEventListener('click', createSchedule);
    }

    var detailRefreshBtn = document.getElementById('scanDetailRefreshBtn');
    if (detailRefreshBtn) {
      detailRefreshBtn.addEventListener('click', function () {
        if (detailState.scanId) {
          loadDetail(detailState.scanId);
        }
      });
    }

    var certPrevBtn = document.getElementById('scanCertPrev');
    var certNextBtn = document.getElementById('scanCertNext');
    if (certPrevBtn) {
      certPrevBtn.addEventListener('click', function () {
        if (!detailState.certTargetScanId) return;
        if (detailState.certPage <= 1) return;
        loadCertificatesForScan(detailState.certTargetScanId, detailState.certPage - 1);
      });
    }
    if (certNextBtn) {
      certNextBtn.addEventListener('click', function () {
        if (!detailState.certTargetScanId) return;
        if (detailState.certPage >= detailState.certTotalPages) return;
        loadCertificatesForScan(detailState.certTargetScanId, detailState.certPage + 1);
      });
    }

    if (canBulkScan && schedulesList) {
      loadSchedules();
    }

    renderProgressRows(scanMap);
    renderCertificateRows({ data: { items: [], total: 0, page: 1, total_pages: 1, kpis: {} } });
    loadScanMetrics();

    detailLoader = showRecordDetails;
  }

  async function promote(scanId, destination) {
    if (!scanId) {
      window.alert('Missing scan id for promotion.');
      return;
    }

    var target = String(destination || 'inventory').toLowerCase();
    if (target !== 'inventory' && target !== 'cbom') {
      target = 'inventory';
    }

    try {
      var resp = await fetch('/api/scans/' + encodeURIComponent(scanId) + '/promote', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ destination: target })
      });

      var payload = {};
      try { payload = await resp.json(); } catch (_err) { payload = {}; }
      if (!resp.ok) {
        throw new Error(payload.message || 'Promotion failed.');
      }

      window.alert(payload.message || ('Scan promoted to ' + target + '.'));

      var searchBtn = document.querySelector('[data-api-search-btn]');
      if (searchBtn) {
        searchBtn.click();
      }
    } catch (err) {
      window.alert(err.message || 'Promotion failed.');
    }
  }

  var detailLoader = function () {};

  window.QuantumShieldScans = {
    init: init,
    promote: promote,
    showRecordDetails: function (record) {
      detailLoader(record);
    }
  };
})();
