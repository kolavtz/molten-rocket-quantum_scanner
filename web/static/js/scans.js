(function () {
  'use strict';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  }

  function parsePorts(raw) {
    var text = String(raw || '').trim();
    if (!text) return undefined;
    return text.split(',').map(function (x) { return Number(String(x).trim()); }).filter(function (n) {
      return Number.isInteger(n) && n >= 1 && n <= 65535;
    });
  }

  function setActionMessage(msg, isError) {
    var node = document.getElementById('scanActionMsg');
    if (!node) return;
    node.textContent = msg || '';
    node.style.color = isError ? '#f87171' : 'var(--text-secondary)';
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
      var target = String(row.target || '');
      var status = String(row.status || 'unknown');
      var meta = row.result_scan_id ? ('result=' + row.result_scan_id) : '';
      if (row.error) {
        meta = String(row.error);
      }
      return (
        '<div class="glass-card" style="padding:0.5rem 0.7rem;">' +
        '<strong>' + scanId + '</strong> · ' + target + ' · <span style="text-transform:uppercase;">' + status + '</span>' +
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

  function init() {
    var singleBtn = document.getElementById('singleScanBtn');
    var bulkBtn = document.getElementById('bulkScanBtn');
    var singleTarget = document.getElementById('singleTarget');
    var bulkTargets = document.getElementById('bulkTargets');
    var portsInput = document.getElementById('portsInput');

    var scanMap = {};
    var pollTimer = null;

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
            var st = String((scanMap[id] || {}).status || '').toLowerCase();
            if (st !== 'completed' && st !== 'failed') {
              allDone = false;
            }
          } catch (_err) {
            allDone = false;
          }
        }

        renderProgressRows(scanMap);
        if (allDone) {
          clearInterval(pollTimer);
          pollTimer = null;
          setActionMessage('All scans completed. Refreshing table...');
          if (window.QuantumShieldApiTable && window.QuantumShieldApiTable.fetchDashboardPage) {
            // trigger table refresh by simulating search button click
            var searchBtn = document.querySelector('[data-api-search-btn]');
            if (searchBtn) searchBtn.click();
          }
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
            ports: parsePorts(portsInput && portsInput.value)
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
        var lines = String((bulkTargets && bulkTargets.value) || '').split(/\r?\n/);
        var targets = lines.map(function (x) { return x.trim(); }).filter(Boolean);
        if (!targets.length) {
          setActionMessage('Please provide at least one target for bulk scan.', true);
          return;
        }

        try {
          setActionMessage('Submitting bulk scan (' + targets.length + ' targets)...');
          var payload = await postJson('/api/scans/bulk', {
            targets: targets,
            ports: parsePorts(portsInput && portsInput.value)
          });
          setActionMessage('Bulk scan queued: ' + payload.queued_count + ' targets');
          startPolling(payload.scan_ids || []);
          if (bulkTargets) bulkTargets.value = '';
        } catch (err) {
          setActionMessage(err.message || 'Failed to submit bulk scan.', true);
        }
      });
    }

    renderProgressRows(scanMap);
  }

  window.QuantumShieldScans = {
    init: init
  };
})();
