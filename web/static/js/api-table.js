(function () {
  'use strict';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  }

  function qs(selector, root) {
    return (root || document).querySelector(selector);
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function buildQuery(params) {
    var qp = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      if (params[key] !== undefined && params[key] !== null && String(params[key]).length > 0) {
        qp.set(key, String(params[key]));
      }
    });
    return qp.toString();
  }

  function normalizeEnvelope(payload) {
    var raw = payload || {};
    var data = (raw && raw.data && typeof raw.data === 'object') ? raw.data : raw;
    return {
      success: typeof raw.success === 'boolean' ? raw.success : true,
      items: Array.isArray(data.items) ? data.items : [],
      total: Number(data.total || 0),
      page: Number(data.page || 1),
      page_size: Number(data.page_size || data.pageSize || 25),
      total_pages: Number(data.total_pages || data.totalPages || 1),
      kpis: (data.kpis && typeof data.kpis === 'object') ? data.kpis : {},
      filters: (raw.filters && typeof raw.filters === 'object') ? raw.filters : {},
      error: raw.error || null,
    };
  }

  async function fetchDashboardPage(apiUrl, params) {
    if (window.QuantumShieldApiClient && typeof window.QuantumShieldApiClient.get === 'function') {
      var clientPayload = await window.QuantumShieldApiClient.get(apiUrl, params || {});
      return normalizeEnvelope(clientPayload);
    }

    var url = apiUrl + '?' + buildQuery(params || {});
    var response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      credentials: 'same-origin',
    });

    var data = {};
    try {
      data = await response.json();
    } catch (err) {
      data = {};
    }

    if (!response.ok) {
      var message = (data.error && data.error.message) || data.message || ('Request failed (' + response.status + ')');
      throw new Error(message);
    }

    return normalizeEnvelope(data);
  }

  function renderCell(col, item, rowIndex, options) {
    var raw = item[col.field];
    var value = raw == null ? '' : raw;

    if (typeof col.render === 'function') {
      return col.render(raw, item, rowIndex, options);
    }

    if (col.field === 'actions' && value) {
      var href = String(value);
      var label = col.actionLabel || 'View details';
      if (href.indexOf('/status') !== -1) {
        label = 'View status';
      } else if (href.indexOf('/results/') !== -1) {
        label = col.actionLabel || 'Open result';
      }
      return '<a class="scan-button scan-button-secondary" href="' + escapeHtml(href) + '">' + escapeHtml(label) + '</a>';
    }

    return escapeHtml(value);
  }

  function renderTable(tableBody, columns, items, options) {
    if (window.QuantumShieldUniversalTable && typeof window.QuantumShieldUniversalTable.renderBody === 'function') {
      window.QuantumShieldUniversalTable.renderBody(tableBody, columns, items);
      return;
    }

    if (!tableBody) return;
    if (!Array.isArray(items) || items.length === 0) {
      var emptyMessage = (options && options.emptyMessage) ? String(options.emptyMessage) : 'No records found.';
      tableBody.innerHTML = '<tr><td colspan="' + columns.length + '">' + escapeHtml(emptyMessage) + '</td></tr>';
      return;
    }

    var rows = items.map(function (item, rowIndex) {
      var tds = columns.map(function (col) {
        return '<td>' + renderCell(col, item, rowIndex, options) + '</td>';
      }).join('');
      return '<tr class="api-table-row" data-api-row-index="' + rowIndex + '">' + tds + '</tr>';
    }).join('');

    tableBody.innerHTML = rows;
  }

  function renderHeaders(headerRow, columns) {
    if (window.QuantumShieldUniversalTable && typeof window.QuantumShieldUniversalTable.renderHead === 'function') {
      window.QuantumShieldUniversalTable.renderHead(headerRow, columns);
      return;
    }

    if (!headerRow) return;
    headerRow.innerHTML = columns.map(function (col) {
      return '<th>' + escapeHtml(col.label) + '</th>';
    }).join('');
  }

  function setText(selector, text, root) {
    var node = qs(selector, root);
    if (node) node.textContent = String(text == null ? '' : text);
  }

  function setError(message, root) {
    var node = qs('[data-api-error]', root);
    if (!node) return;
    if (!message) {
      node.style.display = 'none';
      node.textContent = '';
      return;
    }
    node.style.display = 'block';
    node.textContent = message;
  }

  function renderKpis(kpis, root) {
    var holder = qs('[data-api-kpis]', root);
    if (!holder) return;
    var keys = Object.keys(kpis || {});
    if (!keys.length) {
      holder.innerHTML = '';
      return;
    }
    holder.innerHTML = keys.map(function (key) {
      return '<div class="overview-card glass-card"><div class="overview-value">' + escapeHtml(kpis[key]) + '</div><div class="overview-label">' + escapeHtml(key.replace(/_/g, ' ')) + '</div></div>';
    }).join('');
  }

  function initApiTablePage(config) {
    var root = qs(config.rootSelector || '[data-api-table-page]');
    if (!root) return;

    var state = {
      page: Number(config.page || 1),
      page_size: Number(config.pageSize || 25),
      sort: config.sort || 'id',
      order: config.order || 'asc',
      q: '',
    };

    var headerRow = qs('[data-api-table-head]', root);
    var body = qs('[data-api-table-body]', root);
    var searchInput = qs('[data-api-search-input]', root);
    var searchBtn = qs('[data-api-search-btn]', root);
    var prevBtn = qs('[data-api-prev]', root);
    var nextBtn = qs('[data-api-next]', root);
    var lastItems = [];

    renderHeaders(headerRow, config.columns || []);

    function resolveExtraParams() {
      if (typeof config.getExtraParams === 'function') {
        var dynamicParams = config.getExtraParams();
        if (dynamicParams && typeof dynamicParams === 'object') {
          return dynamicParams;
        }
      }
      return config.extraParams || {};
    }

    async function refresh() {
      setError('', root);
      try {
        var payload = await fetchDashboardPage(config.apiUrl, Object.assign({}, state, resolveExtraParams()));
        lastItems = payload.items || [];
        renderTable(body, config.columns || [], lastItems, config);
        renderKpis(payload.kpis || {}, root);
        setText('[data-api-total]', payload.total || 0, root);
        setText('[data-api-page]', payload.page || 1, root);
        setText('[data-api-total-pages]', payload.total_pages || 1, root);

        var currentPage = Number(payload.page || 1);
        var totalPages = Number(payload.total_pages || 1);
        if (prevBtn) prevBtn.disabled = currentPage <= 1;
        if (nextBtn) nextBtn.disabled = currentPage >= totalPages;

        if (typeof config.onRowClick === 'function' && body) {
          body.querySelectorAll('tr[data-api-row-index]').forEach(function (row) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', function (evt) {
              if (evt.target && evt.target.closest('a,button,input,label')) return;
              var idx = Number(row.getAttribute('data-api-row-index'));
              if (!Number.isNaN(idx) && lastItems[idx]) {
                config.onRowClick(lastItems[idx], row);
              }
            });
          });
        }
      } catch (err) {
        setError(err.message || 'Failed to load dashboard data. Please try again.', root);
      }
    }

    if (searchBtn && searchInput) {
      searchBtn.addEventListener('click', function () {
        state.q = searchInput.value || '';
        state.page = 1;
        refresh();
      });
    }

    if (searchInput) {
      searchInput.addEventListener('keydown', function (evt) {
        if (evt.key === 'Enter') {
          evt.preventDefault();
          state.q = searchInput.value || '';
          state.page = 1;
          refresh();
        }
      });
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', function () {
        state.page = Math.max(1, state.page - 1);
        refresh();
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', function () {
        state.page = state.page + 1;
        refresh();
      });
    }

    refresh();

    return {
      refresh: refresh,
      getState: function () {
        return Object.assign({}, state);
      },
      setPage: function (page) {
        state.page = Math.max(1, Number(page || 1));
      },
      setQuery: function (q) {
        state.q = String(q || '');
      },
    };
  }

  window.QuantumShieldApiTable = {
    initApiTablePage: initApiTablePage,
    fetchDashboardPage: fetchDashboardPage,
    renderTable: renderTable,
  };
})();
