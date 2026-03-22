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

  async function fetchDashboardPage(apiUrl, params) {
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
      throw new Error(data.message || ('Request failed (' + response.status + ')'));
    }

    return data;
  }

  function renderTable(tableBody, columns, items) {
    if (!tableBody) return;
    if (!Array.isArray(items) || items.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="' + columns.length + '">No records found.</td></tr>';
      return;
    }

    var rows = items.map(function (item) {
      var tds = columns.map(function (col) {
        var raw = item[col.field];
        var value = raw == null ? '' : raw;
        return '<td>' + escapeHtml(value) + '</td>';
      }).join('');
      return '<tr>' + tds + '</tr>';
    }).join('');

    tableBody.innerHTML = rows;
  }

  function renderHeaders(headerRow, columns) {
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

    renderHeaders(headerRow, config.columns || []);

    async function refresh() {
      setError('', root);
      try {
        var payload = await fetchDashboardPage(config.apiUrl, Object.assign({}, state, config.extraParams || {}));
        renderTable(body, config.columns || [], payload.items || []);
        renderKpis(payload.kpis || {}, root);
        setText('[data-api-total]', payload.total || 0, root);
        setText('[data-api-page]', payload.page || 1, root);
        setText('[data-api-total-pages]', payload.total_pages || 1, root);

        var currentPage = Number(payload.page || 1);
        var totalPages = Number(payload.total_pages || 1);
        if (prevBtn) prevBtn.disabled = currentPage <= 1;
        if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
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
  }

  window.QuantumShieldApiTable = {
    initApiTablePage: initApiTablePage,
    fetchDashboardPage: fetchDashboardPage,
    renderTable: renderTable,
  };
})();
