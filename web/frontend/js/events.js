let authToken = null;
let currentPage = 1;
let currentPageSize = 25;
let currentFilters = {};
let totalEvents = 0;
let totalPages = 1;
let autoRefreshInterval = null;
let autoRefreshEnabled = true;

window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
    loadEvents();
    setupAutoRefresh(); 
});

function setupAutoRefresh() {
    const refreshToggle = document.createElement('div');
    refreshToggle.className = 'mb-3';
    refreshToggle.innerHTML = `
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" id="autoRefreshToggle" checked>
            <label class="form-check-label" for="autoRefreshToggle">
                Auto-refresh (every 10 seconds)
            </label>
        </div>
    `;

    const searchForm = document.getElementById('searchForm');
    searchForm.parentNode.insertBefore(refreshToggle, searchForm);

    document.getElementById('autoRefreshToggle').addEventListener('change', function() {
        autoRefreshEnabled = this.checked;
        if (autoRefreshEnabled) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });

    startAutoRefresh();
}

function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }

    autoRefreshInterval = setInterval(() => {
        if (autoRefreshEnabled) {
            console.log('Auto-refreshing events...');
            loadEvents(currentPage);
        }
    }, 10000);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

function checkAuth() {
    authToken = localStorage.getItem('siem_auth_token');
    const username = localStorage.getItem('siem_username');

    if (!authToken || !username) {
        window.location.href = '/login';
        return;
    }

    document.getElementById('usernameDisplay').textContent = username;
}

function logout() {
    localStorage.removeItem('siem_auth_token');
    localStorage.removeItem('siem_username');
    window.location.href = '/login';
}

function setupEventListeners() {
    document.getElementById('searchForm').addEventListener('submit', function(e) {
        e.preventDefault();
        loadEvents(1);
    });

    document.getElementById('pageSize').addEventListener('change', function() {
        currentPageSize = parseInt(this.value);
        loadEvents(1);
    });

    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1); 

    document.getElementById('startDate').value = today.toISOString().split('T')[0];
    document.getElementById('endDate').value = tomorrow.toISOString().split('T')[0];
}

async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {
        'Authorization': `Basic ${authToken}`,
        'Content-Type': 'application/json'
    };

    const options = {
        method,
        headers
    };

    if (body && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(endpoint, options);

        if (response.status === 401) {
            logout();
            return null;
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        showError('Failed to load data: ' + error.message);
        return null;
    }
}

async function loadEvents(page = 1) {
    currentPage = page;
    showLoading();
    const params = new URLSearchParams({
        page: currentPage,
        limit: currentPageSize
    });

    const searchText = document.getElementById('searchText').value;
    const useRegex = document.getElementById('useRegex').checked;
    const severity = document.getElementById('severityFilter').value;
    const eventType = document.getElementById('eventTypeFilter').value;
    const source = document.getElementById('sourceFilter').value;
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;

    if (searchText) {
        params.append('search', searchText);
        if (useRegex) {
            params.append('use_regex', 'true'); 
        }
    }
    if (severity) params.append('severity', severity);
    if (eventType) params.append('event_type', eventType);
    if (source) params.append('source', source);
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);

    const data = await apiCall(`/api/events?${params.toString()}`);

    if (data && data.status === 'success') {
        displayEvents(data.data);
        updatePagination(data.pagination);
        updateEventsCount(data.pagination);
    }
    hideLoading();
}

function displayEvents(events) {
    const tbody = document.getElementById('eventsTableBody');

    if (!events || events.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4">
                    <div class="text-muted">
                        <i class="bi bi-search display-6"></i>
                        <p class="mt-2">No events found matching your criteria</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    let html = '';

    events.forEach(event => {
        let timestamp = event.timestamp || '';
        if (timestamp) {
            try {
                const date = new Date(timestamp);
                timestamp = date.toLocaleString();
            } catch (e) {
            }
        }

        const severity = event.severity || 'low';
        const severityClass = `severity-${severity}`;

        const truncate = (text, length = 20) => {
            if (!text) return '';
            return text.length > length ? text.substring(0, length) + '...' : text;
        };

        html += `
            <tr class="event-row" onclick="showEventDetails('${event._id || ''}')">
                <td>${timestamp}</td>
                <td><span class="severity-badge ${severityClass}">${severity.toUpperCase()}</span></td>
                <td>${event.event_type || 'N/A'}</td>
                <td>${event.source || 'N/A'}</td>
                <td>${truncate(event.hostname)}</td>
                <td>${truncate(event.user)}</td>
                <td>${truncate(event.process)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="event.stopPropagation(); showEventDetails('${event._id || ''}')">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

function updatePagination(pagination) {//страницы
    const paginationEl = document.getElementById('pagination');

    if (!pagination || pagination.pages <= 1) {
        paginationEl.innerHTML = '';
        return;
    }

    totalPages = pagination.pages;

    let html = '';
    const maxVisiblePages = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

    if (endPage - startPage + 1 < maxVisiblePages) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    html += `
        <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="loadEvents(${currentPage - 1})">
                <i class="bi bi-chevron-left"></i>
            </a>
        </li>
    `;

    for (let i = startPage; i <= endPage; i++) {
        html += `
            <li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" onclick="loadEvents(${i})">${i}</a>
            </li>
        `;
    }

    html += `
        <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="loadEvents(${currentPage + 1})">
                <i class="bi bi-chevron-right"></i>
            </a>
        </li>
    `;

    paginationEl.innerHTML = html;
}

function updateEventsCount(pagination) {
    const countEl = document.getElementById('eventsCount');

    if (!pagination) {
        countEl.textContent = 'No events found';
        return;
    }

    const start = (pagination.page - 1) * pagination.limit + 1;
    const end = Math.min(pagination.page * pagination.limit, pagination.total);

    countEl.textContent = `Showing ${start}-${end} of ${pagination.total} events`;
}

async function showEventDetails(eventId) {
    if (!eventId) return;

    const data = await apiCall(`/api/events/${eventId}`);

    if (data && data.status === 'success') {
        const event = data.data;
        const modalContent = document.getElementById('eventDetailsContent');

        let timestamp = event.timestamp || '';
        if (timestamp) {
            try {
                const date = new Date(timestamp);
                timestamp = date.toLocaleString();
            } catch (e) {
            }
        }

        const severity = event.severity || 'low';
        const severityClass = `severity-${severity}`;

        let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">Timestamp:</span>
                        ${timestamp}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Severity:</span>
                        <span class="severity-badge ${severityClass}">${severity.toUpperCase()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Event Type:</span>
                        ${event.event_type || 'N/A'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Source:</span>
                        ${event.source || 'N/A'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Agent ID:</span>
                        ${event.agent_id || 'N/A'}
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">Hostname:</span>
                        ${event.hostname || 'N/A'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">User:</span>
                        ${event.user || 'N/A'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Process:</span>
                        ${event.process || 'N/A'}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Command:</span>
                        ${event.command || 'N/A'}
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <strong>Raw Log</strong>
                        </div>
                        <div class="card-body">
                            <pre class="mb-0" style="white-space: pre-wrap; max-height: 300px; overflow-y: auto;">${event.raw_log || 'No raw log available'}</pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        modalContent.innerHTML = html;

        const modal = new bootstrap.Modal(document.getElementById('eventDetailsModal'));
        modal.show();
    }
}

async function exportEvents(format) {
    const query = buildExportQuery();

    const endpoint = format === 'csv' ?
        '/api/events/export/csv' :
        '/api/events/export/json';

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                format: format,
                query: query
            })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `siem_events_${new Date().toISOString().slice(0, 10)}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            showError('Export failed');
        }
    } catch (error) {
        showError('Export failed: ' + error.message);
    }
}

function buildExportQuery() {
    const query = {};
    const conditions = [];

    const searchText = document.getElementById('searchText').value;
    const severity = document.getElementById('severityFilter').value;
    const eventType = document.getElementById('eventTypeFilter').value;
    const source = document.getElementById('sourceFilter').value;
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;

    if (searchText) {
        conditions.push({
            $or: [
                {"raw_log": {"$like": `%${searchText}%`}},
                {"user": {"$like": `%${searchText}%`}},
                {"process": {"$like": `%${searchText}%`}},
                {"command": {"$like": `%${searchText}%`}}
            ]
        });
    }

    if (severity) {
        conditions.push({"severity": severity});
    }

    if (eventType) {
        conditions.push({"event_type": eventType});
    }

    if (source) {
        conditions.push({"source": source});
    }

    if (startDate) {
        conditions.push({"timestamp": {"$gt": startDate}});
    }

    if (endDate) {
        conditions.push({"timestamp": {"$lt": endDate}});
    }

    if (conditions.length > 0) {
        if (conditions.length === 1) {
            return conditions[0];
        } else {
            return {"$and": conditions};
        }
    }

    return {};
}

function clearFilters() {
    document.getElementById('searchText').value = '';
    document.getElementById('severityFilter').value = '';
    document.getElementById('eventTypeFilter').value = '';
    document.getElementById('sourceFilter').value = '';

    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    document.getElementById('startDate').value = today.toISOString().split('T')[0];
    document.getElementById('endDate').value = tomorrow.toISOString().split('T')[0];

    loadEvents(1);
}

function showLoading() {
    let overlay = document.getElementById('loadingOverlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">Loading events...</p>
            </div>
        `;
        document.querySelector('.events-table-container').style.position = 'relative';
        document.querySelector('.events-table-container').appendChild(overlay);
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.remove();
    }
}

function showError(message) {
    console.error('Error:', message);
    alert('Error: ' + message);
}