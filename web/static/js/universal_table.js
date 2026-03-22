/**
 * Universal Data Table Component
 * Provides sortable, searchable, paginated table rendering
 */

class UniversalTable {
    constructor(options = {}) {
        this.containerId = options.containerId || 'table-container';
        this.columns = options.columns || [];
        this.data = [];
        this.total = 0;
        this.page = 1;
        this.pageSize = options.pageSize || 25;
        this.sortField = options.sortField || 'id';
        this.sortOrder = options.sortOrder || 'asc';
        this.searchQuery = '';
        this.isLoading = false;
        this.dataFetcher = options.dataFetcher; // Async function to fetch data
        this.onRowClick = options.onRowClick;
        this.formatters = options.formatters || {};
    }

    /**
     * Initialize and render the table
     */
    async init() {
        await this.fetchData();
        this.render();
    }

    /**
     * Fetch data using the provided fetcher function
     */
    async fetchData() {
        if (!this.dataFetcher) {
            console.error('No data fetcher provided');
            return;
        }

        this.isLoading = true;
        this.showLoading();

        try {
            const response = await this.dataFetcher({
                page: this.page,
                pageSize: this.pageSize,
                sort: this.sortField,
                order: this.sortOrder,
                search: this.searchQuery
            });

            this.data = response.data.items || [];
            this.total = response.data.total || 0;
        } catch (error) {
            console.error('Failed to fetch data:', error);
            this.showError(error.message);
        } finally {
            this.isLoading = false;
        }
    }

    /**
     * Render the complete table
     */
    render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        container.innerHTML = `
            <div class="table-wrapper">
                ${this.renderControls()}
                ${this.renderTableHeader()}
                ${this.renderTableBody()}
                ${this.renderPagination()}
            </div>
        `;

        this.attachEventListeners();
    }

    /**
     * Render search, sort controls
     */
    renderControls() {
        return `
            <div class="table-controls">
                <div class="search-box">
                    <input 
                        type="text" 
                        id="table-search" 
                        class="search-input" 
                        placeholder="Search..."
                        value="${this.searchQuery}"
                    >
                    <span class="search-icon">🔍</span>
                </div>
                <div class="results-info">
                    Showing ${(this.page - 1) * this.pageSize + 1} to ${Math.min(this.page * this.pageSize, this.total)} of ${this.total} records
                </div>
            </div>
        `;
    }

    /**
     * Render table header with sortable columns
     */
    renderTableHeader() {
        const headerHTML = this.columns.map(col => {
            const isSorted = this.sortField === col.field;
            const sortIndicator = isSorted ? (this.sortOrder === 'asc' ? ' ↑' : ' ↓') : '';
            
            return `
                <th 
                    class="column-header ${isSorted ? 'sorted' : ''} ${col.sortable !== false ? 'sortable' : ''}"
                    data-field="${col.field}"
                >
                    ${col.label}${sortIndicator}
                </th>
            `;
        }).join('');

        return `
            <table class="universal-table">
                <thead>
                    <tr>${headerHTML}</tr>
                </thead>
                <tbody id="table-body">
                </tbody>
            </table>
        `;
    }

    /**
     * Render table rows
     */
    renderTableBody() {
        if (this.data.length === 0) {
            return '<div class="table-empty">No data found</div>';
        }

        const rows = this.data.map((row, idx) => {
            const cells = this.columns.map(col => {
                let value = row[col.field];
                
                // Apply custom formatter if available
                if (this.formatters[col.field]) {
                    value = this.formatters[col.field](value, row);
                }

                return `<td>${value || '-'}</td>`;
            }).join('');

            return `
                <tr class="table-row" data-row-id="${row.id || idx}">
                    ${cells}
                </tr>
            `;
        }).join('');

        const tbody = document.getElementById('table-body');
        if (tbody) {
            tbody.innerHTML = rows;
        }

        return rows;
    }

    /**
     * Render pagination controls
     */
    renderPagination() {
        const totalPages = Math.ceil(this.total / this.pageSize);
        if (totalPages <= 1) return '';

        let pageButtons = '';
        const startPage = Math.max(1, this.page - 2);
        const endPage = Math.min(totalPages, this.page + 2);

        if (startPage > 1) {
            pageButtons += `<button class="page-btn" data-page="1">1</button>`;
            if (startPage > 2) {
                pageButtons += `<span class="page-ellipsis">...</span>`;
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === this.page ? 'active' : '';
            pageButtons += `<button class="page-btn ${activeClass}" data-page="${i}">${i}</button>`;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                pageButtons += `<span class="page-ellipsis">...</span>`;
            }
            pageButtons += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;
        }

        return `
            <div class="pagination">
                <button class="nav-btn" id="prev-page" ${this.page === 1 ? 'disabled' : ''}>← Previous</button>
                <div class="page-buttons">
                    ${pageButtons}
                </div>
                <button class="nav-btn" id="next-page" ${this.page >= totalPages ? 'disabled' : ''}>Next →</button>
            </div>
        `;
    }

    /**
     * Show loading state
     */
    showLoading() {
        const container = document.getElementById(this.containerId);
        if (container) {
            container.innerHTML = '<div class="table-loading">Loading...</div>';
        }
    }

    /**
     * Show error message
     */
    showError(message) {
        const container = document.getElementById(this.containerId);
        if (container) {
            container.innerHTML = `<div class="table-error">Error: ${message}</div>`;
        }
    }

    /**
     * Attach event listeners to table elements
     */
    attachEventListeners() {
        // Search
        const searchInput = document.getElementById('table-search');
        if (searchInput) {
            let timeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(timeout);
                this.searchQuery = e.target.value;
                this.page = 1;
                timeout = setTimeout(() => this.reload(), 500);
            });
        }

        // Column sorting
        document.querySelectorAll('.column-header.sortable').forEach(header => {
            header.addEventListener('click', async () => {
                const field = header.dataset.field;
                if (this.sortField === field) {
                    this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortField = field;
                    this.sortOrder = 'asc';
                }
                this.page = 1;
                await this.reload();
            });
        });

        // Pagination
        document.querySelectorAll('.page-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                this.page = parseInt(btn.dataset.page);
                await this.reload();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        });

        // Previous/Next buttons
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');

        if (prevBtn) {
            prevBtn.addEventListener('click', async () => {
                if (this.page > 1) {
                    this.page--;
                    await this.reload();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', async () => {
                const totalPages = Math.ceil(this.total / this.pageSize);
                if (this.page < totalPages) {
                    this.page++;
                    await this.reload();
                }
            });
        }

        // Row click
        if (this.onRowClick) {
            document.querySelectorAll('.table-row').forEach(row => {
                row.addEventListener('click', () => {
                    const rowId = row.dataset.rowId;
                    const rowData = this.data[rowId];
                    this.onRowClick(rowData);
                });
            });
        }
    }

    /**
     * Reload table data and re-render
     */
    async reload() {
        await this.fetchData();
        this.render();
    }

    /**
     * Set new data directly (for testing or custom updates)
     */
    setData(items, total) {
        this.data = items;
        this.total = total;
        this.render();
    }

    /**
     * Export data to CSV
     */
    exportCSV() {
        const csv = [
            this.columns.map(col => col.label).join(','),
            ...this.data.map(row =>
                this.columns.map(col => row[col.field] || '').join(',')
            )
        ].join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'export.csv';
        a.click();
    }
}
