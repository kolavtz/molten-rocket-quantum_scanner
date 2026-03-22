(function () {
  'use strict';

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderHead(headerRow, columns) {
    if (!headerRow) return;
    headerRow.innerHTML = (columns || []).map(function (col) {
      return '<th>' + escapeHtml(col.label || col.field || '') + '</th>';
    }).join('');
  }

  function renderBody(tableBody, columns, items) {
    if (!tableBody) return;

    var cols = columns || [];
    var rows = Array.isArray(items) ? items : [];

    if (!rows.length) {
      tableBody.innerHTML = '<tr><td colspan="' + cols.length + '">No records found.</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.map(function (item) {
      return '<tr>' + cols.map(function (col) {
        var raw = item[col.field];
        var val = (typeof col.render === 'function') ? col.render(raw, item) : raw;
        return '<td>' + escapeHtml(val == null ? '' : val) + '</td>';
      }).join('') + '</tr>';
    }).join('');
  }

  window.QuantumShieldUniversalTable = {
    renderHead: renderHead,
    renderBody: renderBody,
    escapeHtml: escapeHtml,
  };
})();
