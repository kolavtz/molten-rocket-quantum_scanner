/**
 * QuantumShield — Unified Interactable Table Framework (v2)
 * Provides: search filter · sortable columns · pagination · side-detail drawer
 * Auto-activates on every .scans-table-wrapper on the page.
 */
(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        document.querySelectorAll('.scans-table-wrapper').forEach(setupTable);
    }

    function setupTable(wrapper) {
        const table = wrapper.querySelector('.scans-table');
        if (!table) return;

        const tbody      = table.querySelector('tbody');
        const allRows    = Array.from(tbody.querySelectorAll('tr'));
        const headersEl  = Array.from(table.querySelectorAll('thead th'));
        let sortColIdx   = -1;
        let sortDir      = 1; // 1 asc, -1 desc
        let currentPage  = 0;
        let pageSize     = 10;

        /* ── Build toolbar (search + per-page) ─────────────────── */
        const toolbar = document.createElement('div');
        toolbar.className = 'pnb-toolbar';
        toolbar.innerHTML = `
            <div class="pnb-toolbar-left">
                <span class="pnb-toolbar-label">View</span>
                <select class="pnb-page-size-select" aria-label="Rows per page">
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="0">All</option>
                </select>
                <span class="pnb-toolbar-label">per page</span>
            </div>
            <div class="pnb-toolbar-right">
                <input class="pnb-search" type="text" placeholder="Search…" aria-label="Search table">
            </div>`;
        wrapper.parentNode.insertBefore(toolbar, wrapper);

        /* ── Build split container ─────────────────────────────── */
        const container = document.createElement('div');
        container.className = 'pnb-split-container';
        wrapper.parentNode.insertBefore(container, wrapper);

        const tableContent = document.createElement('div');
        tableContent.className = 'pnb-table-content';
        container.appendChild(tableContent);
        tableContent.appendChild(wrapper);

        /* ── Side-detail drawer ────────────────────────────────── */
        const sidePanel = document.createElement('div');
        sidePanel.className = 'pnb-side-details';
        sidePanel.innerHTML = `
            <div class="pnb-details-header">
                <span>Item Details</span>
                <button class="pnb-close-btn" aria-label="Close">✕</button>
            </div>
            <div class="pnb-details-body"></div>`;
        container.appendChild(sidePanel);
        const detailsBody = sidePanel.querySelector('.pnb-details-body');

        sidePanel.querySelector('.pnb-close-btn').addEventListener('click', closePanel);

        /* ── Build pagination bar ──────────────────────────────── */
        const pagBar = document.createElement('div');
        pagBar.className = 'pnb-pagination';
        pagBar.innerHTML = `
            <span class="pnb-page-info"></span>
            <div class="pnb-page-btns">
                <button class="pnb-btn" data-action="first" title="First page">«</button>
                <button class="pnb-btn" data-action="prev"  title="Previous">‹</button>
                <span class="pnb-page-num"></span>
                <button class="pnb-btn" data-action="next"  title="Next">›</button>
                <button class="pnb-btn" data-action="last"  title="Last page">»</button>
            </div>`;
        wrapper.parentNode.insertBefore(pagBar, sidePanel.nextSibling);

        /* ── Wire up header sort ───────────────────────────────── */
        headersEl.forEach((th, idx) => {
            th.style.cursor = 'pointer';
            th.addEventListener('click', () => {
                if (sortColIdx === idx) {
                    sortDir *= -1;
                } else {
                    sortColIdx = idx;
                    sortDir = 1;
                }
                headersEl.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
                th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
                currentPage = 0;
                render();
            });
        });

        /* ── Wire up search ────────────────────────────────────── */
        const searchInput = toolbar.querySelector('.pnb-search');
        searchInput.addEventListener('input', () => { currentPage = 0; render(); });

        /* ── Wire up per-page selector ─────────────────────────── */
        const pageSel = toolbar.querySelector('.pnb-page-size-select');
        pageSel.addEventListener('change', () => {
            pageSize = parseInt(pageSel.value, 10);
            currentPage = 0;
            render();
        });

        /* ── Wire up pagination buttons ────────────────────────── */
        pagBar.querySelectorAll('.pnb-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                const total  = filteredRows().length;
                const pages  = pageSize === 0 ? 1 : Math.max(1, Math.ceil(total / pageSize));
                if (action === 'first') currentPage = 0;
                if (action === 'prev')  currentPage = Math.max(0, currentPage - 1);
                if (action === 'next')  currentPage = Math.min(pages - 1, currentPage + 1);
                if (action === 'last')  currentPage = pages - 1;
                render();
            });
        });

        /* ── Row click → side detail ───────────────────────────── */
        const headers = headersEl.map(th => th.textContent.replace(/[⇅⬆⬇]/g, '').trim());

        function attachRowClick(row) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', e => {
                if (e.target.closest('a,button,details,summary,input,select')) return;
                table.querySelectorAll('tr.pnb-selected').forEach(r => r.classList.remove('pnb-selected'));
                row.classList.add('pnb-selected');

                detailsBody.innerHTML = '';
                let hasData = false;
                row.querySelectorAll('td').forEach((cell, idx) => {
                    const label = headers[idx] || `Col ${idx + 1}`;
                    const raw   = cell.innerHTML.trim();
                    if (!raw || raw === '-' || raw === '—' || raw === '---') return;
                    hasData = true;
                    const item = document.createElement('div');
                    item.className = 'pnb-detail-item';
                    item.innerHTML = `<div class="pnb-detail-label">${escHtml(label)}</div><div class="pnb-detail-value">${raw}</div>`;
                    detailsBody.appendChild(item);
                });
                if (hasData) sidePanel.classList.add('active');
            });
        }

        allRows.forEach(attachRowClick);

        /* ── Core render ───────────────────────────────────────── */
        function filteredRows() {
            const q = searchInput.value.toLowerCase().trim();
            let rows = q ? allRows.filter(r => r.textContent.toLowerCase().includes(q)) : allRows.slice();

            if (sortColIdx >= 0) {
                rows.sort((a, b) => {
                    const va = (a.children[sortColIdx] || {}).textContent || '';
                    const vb = (b.children[sortColIdx] || {}).textContent || '';
                    return va.localeCompare(vb, undefined, {numeric: true}) * sortDir;
                });
            }
            return rows;
        }

        function render() {
            const rows  = filteredRows();
            const total = rows.length;
            const effective = pageSize === 0 ? total : pageSize;
            const pages = Math.max(1, Math.ceil(total / effective));
            currentPage = Math.min(currentPage, pages - 1);

            const start = pageSize === 0 ? 0 : currentPage * effective;
            const end   = pageSize === 0 ? total : start + effective;
            const slice = rows.slice(start, end);

            allRows.forEach(r => { r.style.display = 'none'; });
            slice.forEach(r  => { r.style.display = ''; });

            // Update page info label
            const infoEl = pagBar.querySelector('.pnb-page-info');
            const numEl  = pagBar.querySelector('.pnb-page-num');
            const s = total === 0 ? 0 : start + 1;
            const e = Math.min(end, total);
            infoEl.textContent = `${s} – ${e} of ${total}`;
            numEl.textContent  = `${currentPage + 1} / ${pages}`;

            // Disable buttons
            pagBar.querySelectorAll('.pnb-btn').forEach(btn => {
                const action = btn.dataset.action;
                btn.disabled = (action === 'first' || action === 'prev') ? currentPage === 0
                             : (action === 'next'  || action === 'last')  ? currentPage >= pages - 1
                             : false;
            });
        }

        function closePanel() {
            sidePanel.classList.remove('active');
            table.querySelectorAll('tr.pnb-selected').forEach(r => r.classList.remove('pnb-selected'));
        }

        function escHtml(str) {
            return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        }

        // Initial render
        render();
    }
})();
