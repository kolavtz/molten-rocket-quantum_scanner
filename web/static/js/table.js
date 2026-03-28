/**
 * Shared inventory table interactions.
 * 
 * Handles:
 * - page-size submission
 * - go-to-page clamping
 * - select-all / selection count (using event delegation for reliability)
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

  function updateSelectionSummary(tableComponent) {
    const scopeRoot = tableComponent.closest('[data-table-shell]') || tableComponent;
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

  function prepareBulkPayload(tableComponent) {
    const scopeRoot = tableComponent.closest('[data-table-shell]') || tableComponent;
    const bulkInput = qs(scopeRoot, '[data-bulk-ids]');
    if (!bulkInput) return [];
    const ids = qsa(scopeRoot, '[data-row-checkbox]:checked').map((input) => input.value).filter(Boolean);
    bulkInput.value = ids.join(',');
    return ids;
  }

  function initTableComponent(tableComponent) {
    const scopeRoot = tableComponent.closest('[data-table-shell]') || tableComponent;
    const searchForm = qs(tableComponent, '[data-table-search]');
    const pageSizeSelect = qs(tableComponent, '[data-page-size]');
    const gotoForm = qs(tableComponent, '.goto-page-form');
    const gotoInput = qs(tableComponent, '.goto-page-input');
    const bulkForm = qs(scopeRoot, '[data-bulk-form]');
    const bulkAction = qs(scopeRoot, '[data-bulk-action]');

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

    // Asset Intelligence Modal Trigger (Explicit Only)
    tableComponent.addEventListener('click', (event) => {
        const trigger = event.target.closest('[data-open-asset-details]');
        if (!trigger) return;

        const assetId = trigger.dataset.assetId;
        if (assetId && window.AssetDetailModal) {
            window.AssetDetailModal.open(assetId);
        }
    });

    // Use Event Delegation for checkboxes and "Select All"
    tableComponent.addEventListener('change', (event) => {
      const target = event.target;
      
      // Handle Select All
      if (target.matches('[data-select-all]')) {
        const isChecked = target.checked;
        qsa(scopeRoot, '[data-row-checkbox]').forEach((checkbox) => {
          checkbox.checked = isChecked;
        });
        updateSelectionSummary(tableComponent);
        return;
      }

      // Handle individual row checkbox
      if (target.matches('[data-row-checkbox]')) {
        updateSelectionSummary(tableComponent);
        return;
      }
    });

    if (bulkForm && bulkAction) {
      bulkForm.addEventListener('submit', (event) => {
        const ids = prepareBulkPayload(tableComponent);
        if (!ids.length) {
          event.preventDefault();
          alert('Please select at least one item.');
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

    // Initial sync
    updateSelectionSummary(tableComponent);

    // Listen for manual update triggers
    tableComponent.addEventListener('qs:table:update', () => {
      updateSelectionSummary(tableComponent);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    qsa(document, '[data-table-component]').forEach(initTableComponent);
  });
})();
