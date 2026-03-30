/**
 * QuantumShield unified table helper.
 * Enhances client-managed tables with search, sorting, pagination and row details.
 * Server-managed tables are skipped via data-table-mode="server".
 */
(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        document.querySelectorAll('table.scans-table').forEach(setupTable);
    }

    function setupTable(table) {
        if (table.dataset.tableified) return;
        if ((table.dataset.tableMode || '').toLowerCase() === 'server') return;
        table.dataset.tableified = 'true';

        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        const allRows = Array.from(tbody.querySelectorAll('tr'));
        if (allRows.length === 0 || allRows[0].textContent.includes('No ')) return;

        const headersEl = Array.from(table.querySelectorAll('thead th'));
        let sortColIdx = -1;
        let sortDir = 1;
        let currentPage = 0;
        let pageSize = 10;

        const wrapper = document.createElement('div');
        wrapper.className = 'scans-table-wrapper';
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);

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
                <input class="pnb-search" type="text" placeholder="Search..." aria-label="Search table">
            </div>`;
        wrapper.parentNode.insertBefore(toolbar, wrapper);

        const container = document.createElement('div');
        container.className = 'pnb-split-container';
        wrapper.parentNode.insertBefore(container, wrapper);

        const tableContent = document.createElement('div');
        tableContent.className = 'pnb-table-content';
        container.appendChild(tableContent);
        tableContent.appendChild(wrapper);

        const sidePanel = document.createElement('div');
        sidePanel.className = 'pnb-side-details';
        sidePanel.innerHTML = `
            <div class="pnb-details-header">
                <span>Item Details</span>
                <button class="pnb-close-btn" aria-label="Close">x</button>
            </div>
            <div class="pnb-details-body"></div>`;
        container.appendChild(sidePanel);
        const detailsBody = sidePanel.querySelector('.pnb-details-body');

        sidePanel.querySelector('.pnb-close-btn').addEventListener('click', closePanel);

        const pagBar = document.createElement('div');
        pagBar.className = 'pnb-pagination';
        pagBar.innerHTML = `
            <span class="pnb-page-info"></span>
            <div class="pnb-goto-container">
                <span>Go to:</span>
                <input type="number" class="pnb-goto-page" min="1">
            </div>
            <div class="pnb-page-btns">
                <button class="pnb-btn" data-action="first" type="button" title="First">&lt;&lt;</button>
                <button class="pnb-btn" data-action="prev" type="button" title="Previous">&lt;</button>
                <span class="pnb-page-num"></span>
                <button class="pnb-btn" data-action="next" type="button" title="Next">&gt;</button>
                <button class="pnb-btn" data-action="last" type="button" title="Last">&gt;&gt;</button>
            </div>`;
        wrapper.parentNode.insertBefore(pagBar, sidePanel.nextSibling);

        headersEl.forEach((th, idx) => {
            th.addEventListener('click', () => {
                if (sortColIdx === idx) {
                    sortDir *= -1;
                } else {
                    sortColIdx = idx;
                    sortDir = 1;
                }
                headersEl.forEach((header) => {
                    header.classList.remove('sort-asc', 'sort-desc');
                    const indicator = header.querySelector('.table-sort-indicator');
                    if (indicator) indicator.textContent = '<>';
                });
                th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
                const indicator = th.querySelector('.table-sort-indicator');
                if (indicator) indicator.textContent = sortDir === 1 ? '^' : 'v';
                currentPage = 0;
                render();
            });
            th.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    th.click();
                }
            });
        });

        const searchInput = toolbar.querySelector('.pnb-search');
        searchInput.addEventListener('input', () => {
            currentPage = 0;
            render();
        });

        const pageSel = toolbar.querySelector('.pnb-page-size-select');
        pageSel.addEventListener('change', () => {
            pageSize = parseInt(pageSel.value, 10);
            currentPage = 0;
            render();
        });

        const gotoInput = pagBar.querySelector('.pnb-goto-page');
        gotoInput.addEventListener('change', () => {
            const pages = pageSize === 0 ? 1 : Math.ceil(filteredRows().length / pageSize);
            const pageNum = parseInt(gotoInput.value, 10);
            if (!isNaN(pageNum) && pageNum >= 1 && pageNum <= pages) {
                currentPage = pageNum - 1;
                render();
            } else {
                gotoInput.value = currentPage + 1;
            }
        });

        pagBar.querySelectorAll('.pnb-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                const total = filteredRows().length;
                const pages = pageSize === 0 ? 1 : Math.max(1, Math.ceil(total / pageSize));
                if (action === 'first') currentPage = 0;
                if (action === 'prev') currentPage = Math.max(0, currentPage - 1);
                if (action === 'next') currentPage = Math.min(pages - 1, currentPage + 1);
                if (action === 'last') currentPage = pages - 1;
                render();
            });
        });

        const headers = headersEl.map((th) => {
            const label = th.querySelector('.table-sort-label');
            return (label ? label.textContent : th.textContent).replace(/[<>^v]/g, '').trim();
        });

        function attachRowClick(row) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', (event) => {
                if (event.target.closest('a,button,details,summary,input,select')) return;
                table.querySelectorAll('tr.pnb-selected').forEach((r) => r.classList.remove('pnb-selected'));
                row.classList.add('pnb-selected');

                detailsBody.innerHTML = '';
                let hasData = false;
                row.querySelectorAll('td').forEach((cell, idx) => {
                    const label = headers[idx] || `Col ${idx + 1}`;
                    const raw = cell.innerHTML.trim();
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

        function filteredRows() {
            const q = searchInput.value.toLowerCase().trim();
            let rows = q ? allRows.filter((row) => row.textContent.toLowerCase().includes(q)) : allRows.slice();

            if (sortColIdx >= 0) {
                rows.sort((a, b) => {
                    const va = (a.children[sortColIdx] || {}).textContent || '';
                    const vb = (b.children[sortColIdx] || {}).textContent || '';
                    return va.localeCompare(vb, undefined, { numeric: true }) * sortDir;
                });
            }
            return rows;
        }

        function render() {
            const rows = filteredRows();
            const total = rows.length;
            const effective = pageSize === 0 ? total : pageSize;
            const pages = Math.max(1, Math.ceil(total / Math.max(1, effective)));
            if (currentPage >= pages) currentPage = pages - 1;
            if (currentPage < 0) currentPage = 0;

            const start = pageSize === 0 ? 0 : currentPage * effective;
            const end = pageSize === 0 ? total : start + effective;
            const slice = rows.slice(start, end);

            allRows.forEach((row) => { row.style.display = 'none'; });
            slice.forEach((row) => { row.style.display = ''; });

            const infoEl = pagBar.querySelector('.pnb-page-info');
            const numEl = pagBar.querySelector('.pnb-page-num');
            const s = total === 0 ? 0 : start + 1;
            const e = Math.min(end, total);
            infoEl.textContent = `${s} - ${e} of ${total}`;
            numEl.textContent = `${currentPage + 1} / ${pages}`;
            gotoInput.value = currentPage + 1;

            pagBar.querySelectorAll('.pnb-btn').forEach((btn) => {
                const action = btn.dataset.action;
                btn.disabled = (action === 'first' || action === 'prev')
                    ? currentPage === 0
                    : (action === 'next' || action === 'last')
                        ? currentPage >= pages - 1
                        : false;
            });
        }

        function closePanel() {
            sidePanel.classList.remove('active');
            table.querySelectorAll('tr.pnb-selected').forEach((row) => row.classList.remove('pnb-selected'));
        }

        function escHtml(str) {
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        render();
    }
})();
