/**
 * Unified scans-table split details and sorting framework
 */
document.addEventListener("DOMContentLoaded", () => {
    const tableWrappers = document.querySelectorAll(".scans-table-wrapper");

    tableWrappers.forEach(wrapper => {
        const table = wrapper.querySelector(".scans-table");
        if (!table) return;

        // 1. Create Split Container Wrapper
        const container = document.createElement("div");
        container.className = "pnb-split-container";
        wrapper.parentNode.insertBefore(container, wrapper);

        const tableContent = document.createElement("div");
        tableContent.className = "pnb-table-content";
        container.appendChild(tableContent);
        tableContent.appendChild(wrapper);

        // 2. Create Details Panel
        const sideDetails = document.createElement("div");
        sideDetails.className = "pnb-side-details";
        
        const header = document.createElement("div");
        header.className = "pnb-details-header";
        header.innerHTML = '<span>Item Details</span><button class="btn-close btn-close-white" style="font-size: 0.75rem; background:none; border:none; color:var(--text-secondary); cursor:pointer;" aria-label="Close">✕</button>';
        sideDetails.appendChild(header);

        const detailsBody = document.createElement("div");
        detailsBody.className = "pnb-details-body";
        sideDetails.appendChild(detailsBody);

        container.appendChild(sideDetails);

        // Sidebar close button triggers
        header.querySelector("button").addEventListener("click", () => {
            sideDetails.classList.remove("active");
            table.querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected", "table-active"));
        });

        // 3. Row Click Logic to populate details sidebar
        const headersNode = table.querySelectorAll("thead th");
        const headers = Array.from(headersNode).map(th => th.textContent.replace('⇅','').replace('⬆','').replace('⬇','').trim());
        const rows = table.querySelectorAll("tbody tr");

        rows.forEach(row => {
            row.style.cursor = "pointer";
            row.addEventListener("click", (e) => {
                if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON' || e.target.closest('a') || e.target.closest('button')) return;

                table.querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected", "table-active"));
                row.classList.add("selected", "table-active");

                detailsBody.innerHTML = "";
                const cells = row.querySelectorAll("td");
                
                let hasData = false;
                cells.forEach((cell, idx) => {
                    const label = headers[idx] || `Field ${idx + 1}`;
                    const value = cell.innerHTML.trim();

                    if (!value || value === '-' || value === '---' || label.toLowerCase().includes('id') || value.includes('No nameserver')) return;

                    hasData = true;
                    const item = document.createElement("div");
                    item.className = "pnb-detail-item";
                    item.innerHTML = `
                        <div class="pnb-detail-label">${label}</div>
                        <div class="pnb-detail-value">${value}</div>
                    `;
                    detailsBody.appendChild(item);
                });

                if (hasData) {
                    sideDetails.classList.add("active");
                }
            });
        });

        // 4. Global Sorting Logic attaching to all <th> cells
        headersNode.forEach((th, idx) => {
            th.addEventListener("click", () => {
                let sortDir = 1;
                if (th.classList.contains("sort-asc")) {
                    sortDir = -1;
                    th.classList.remove("sort-asc");
                    th.classList.add("sort-desc");
                } else if (th.classList.contains("sort-desc")) {
                    sortDir = 1;
                    th.classList.remove("sort-desc");
                    th.classList.add("sort-asc");
                } else {
                    headersNode.forEach(t => t.classList.remove("sort-asc", "sort-desc"));
                    th.classList.add("sort-asc");
                }

                const tbody = table.querySelector("tbody");
                const currentRows = Array.from(tbody.querySelectorAll("tr"));

                // Safeguards empty states row
                if (currentRows.length <= 1 && currentRows[0] && currentRows[0].textContent.includes('No data')) return;

                currentRows.sort((a, b) => {
                    if (!a.children[idx] || !b.children[idx]) return 0;
                    const valA = a.children[idx].textContent.trim();
                    const valB = b.children[idx].textContent.trim();
                    return valA.localeCompare(valB, undefined, {numeric: true}) * sortDir;
                });

                tbody.innerHTML = "";
                currentRows.forEach(r => tbody.appendChild(r));
            });
        });
    });
});
