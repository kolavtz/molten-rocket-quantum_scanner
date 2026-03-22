/**
 * Shared inventory table interactions.
 *
 * Handles:
 * - page-size submission
 * - go-to-page clamping
 * - select-all / selection count
 * - bulk action payload preparation
 */
(function () {
  'use strict';

  function qs(root, selector) {
    return root.querySelector(selector);
  }

  function qsa(root, selector) {
    return Array.from(root.querySelectorAll(selector));
  }

  function updateSelectionSummary(tableRoot) {
    const scopeRoot = tableRoot.closest('[data-table-shell]') || tableRoot;
    const selected = qsa(scopeRoot, '[data-row-checkbox]:checked');
    const summary = qs(scopeRoot, '[data-selected-count]');
    if (summary) {
      summary.textContent = selected.length + ' item' + (selected.length === 1 ? '' : 's') + ' selected';
    }

    const selectAll = qs(scopeRoot, '[data-select-all]');
    if (selectAll) {
      const all = qsa(scopeRoot, '[data-row-checkbox]');
      selectAll.checked = all.length > 0 && selected.length === all.length;
      selectAll.indeterminate = selected.length > 0 && selected.length < all.length;
    }
  }

  function prepareBulkPayload(tableRoot) {
    const scopeRoot = tableRoot.closest('[data-table-shell]') || tableRoot;
    const bulkInput = qs(scopeRoot, '[data-bulk-ids]');
    if (!bulkInput) return [];
    const ids = qsa(scopeRoot, '[data-row-checkbox]:checked').map((input) => input.value).filter(Boolean);
    bulkInput.value = ids.join(',');
    return ids;
  }

  function initTableComponent(tableRoot) {
    const scopeRoot = tableRoot.closest('[data-table-shell]') || tableRoot;
    const searchForm = qs(tableRoot, '[data-table-search]');
    const pageSizeSelect = qs(tableRoot, '[data-page-size]');
    const gotoForm = qs(tableRoot, '.goto-page-form');
    const gotoInput = qs(tableRoot, '.goto-page-input');
    const selectAll = qs(scopeRoot, '[data-select-all]');
    const bulkForm = qs(scopeRoot, '[data-bulk-form]');
    const bulkAction = qs(scopeRoot, '[data-bulk-action]');
    const table = qs(tableRoot, 'table');

    if (pageSizeSelect && searchForm) {
      pageSizeSelect.addEventListener('change', () => searchForm.submit());
    }

    if (gotoForm && gotoInput) {
      gotoForm.addEventListener('submit', (event) => {
        const min = Number(gotoInput.min || '1');
        const max = Number(gotoInput.max || '1');
        const value = Number(gotoInput.value || '1');
        if (!Number.isFinite(value)) {
          event.preventDefault();
          gotoInput.value = '1';
          return;
        }
        if (value < min) gotoInput.value = String(min);
        if (value > max) gotoInput.value = String(max);
      });
    }

    if (selectAll) {
      selectAll.addEventListener('change', () => {
        qsa(scopeRoot, '[data-row-checkbox]').forEach((checkbox) => {
          checkbox.checked = selectAll.checked;
        });
        updateSelectionSummary(tableRoot);
      });
    }

    qsa(scopeRoot, '[data-row-checkbox]').forEach((checkbox) => {
      checkbox.addEventListener('change', () => updateSelectionSummary(tableRoot));
    });

    if (bulkForm && bulkAction) {
      bulkForm.addEventListener('submit', (event) => {
        const ids = prepareBulkPayload(tableRoot);
        if (!ids.length) {
          event.preventDefault();
          return;
        }
        const action = bulkAction.value;
        if (action === 'bulk-edit') {
          bulkForm.action = bulkForm.dataset.bulkEditAction || bulkForm.action;
        } else {
          bulkForm.action = bulkForm.dataset.bulkDeleteAction || bulkForm.action;
        }
      });
    }

    if (table) {
      const currentSort = new URLSearchParams(window.location.search).get('sort');
      qsa(tableRoot, '[data-sort-field]').forEach((header) => {
        if (header.dataset.sortField === currentSort) {
          header.classList.add('sort-active');
        }
      });
    }

    updateSelectionSummary(tableRoot);
  }

  document.addEventListener('DOMContentLoaded', () => {
    qsa(document, '[data-table-component]').forEach(initTableComponent);
  });
})();
