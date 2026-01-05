let authToken = null;
let charts = {};
let autoRefreshInterval = null;
let currentAbortController = null;
let isLoading = false;

window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    loadDashboard();
    startAutoRefresh();
});

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

async function apiCall(endpoint, method = 'GET', body = null, signal = null) {
    const cacheBuster = `_t=${Date.now()}`;
    const separator = endpoint.includes('?') ? '&' : '?';
    const url = endpoint + separator + cacheBuster;
    
    const headers = {
        'Authorization': `Basic ${authToken}`,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache'
    };

    const options = {
        method,
        headers
    };

    if (signal) {
        options.signal = signal;
    }

    if (body && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(url, options);

        if (response.status === 401) {
            logout();
            return null;
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status} ${response.statusText}`);
        }

        const json = await response.json();

        if (typeof json !== 'object' || json === null) {
            console.warn('Unexpected non-JSON response from', endpoint, json);
            return null;
        }

        return json;
    } catch (error) {
        if (error.name === 'AbortError') {
            throw error;
        }
        console.error(`API call failed for ${endpoint}:`, error);
        return null;
    }
}

async function loadDashboard() {
    if (!authToken) {
        console.warn('No auth token, skipping dashboard load');
        return;
    }
    
    if (isLoading) {
        console.log('Dashboard load already in progress, skipping');
        return;
    }
    
    isLoading = true;
    setIsLoading(true);
    
    try {
        console.log('Loading dashboard data at', new Date().toLocaleTimeString());
        
        const endpoints = [
            '/api/dashboard/agents',
            '/api/dashboard/logins',
            '/api/dashboard/hosts',
            '/api/dashboard/events-by-type',
            '/api/dashboard/events-by-severity',
            '/api/dashboard/top-users',
            '/api/dashboard/top-processes',
            '/api/dashboard/events-timeline'
        ];
        
        const promises = endpoints.map(async (endpoint) => {
            try {
                return await apiCall(endpoint);
            } catch (error) {
                console.warn(`Failed to load ${endpoint}:`, error.message);
                return null;
            }
        });
        
        const results = await Promise.all(promises);
        
        const resultsMap = {};
        endpoints.forEach((endpoint, index) => {
            resultsMap[endpoint] = results[index];
        });
        
        updateDashboardUI(resultsMap);
        
        console.log('Dashboard updated successfully at', new Date().toLocaleTimeString());
        
    } catch (error) {
        console.error('Critical error in loadDashboard:', error);
        showToast('Failed to load dashboard data', 'error');
    } finally {
        isLoading = false;
        setIsLoading(false);
    }
}

function updateDashboardUI(resultsMap) {
    updateSummaryStats(
        resultsMap['/api/dashboard/agents'],
        resultsMap['/api/dashboard/logins'],
        resultsMap['/api/dashboard/events-by-severity']
    );
    
    updateCharts(
        resultsMap['/api/dashboard/events-by-type'],
        resultsMap['/api/dashboard/events-by-severity'],
        resultsMap['/api/dashboard/events-timeline']
    );
    
    updateRecentLogins(resultsMap['/api/dashboard/logins']);
    updateActiveHosts(resultsMap['/api/dashboard/hosts']);
    updateTopUsers(resultsMap['/api/dashboard/top-users']);
    updateTopProcesses(resultsMap['/api/dashboard/top-processes']);
    updateActiveAgents(resultsMap['/api/dashboard/agents']);
    
    document.getElementById('updateTime').textContent = new Date().toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function setIsLoading(loading) {
    const spinners = document.querySelectorAll('.loading .spinner-border');
    const refreshBtn = document.querySelector('button[onclick="refreshDashboard()"]');
    
    if (loading) {
        spinners.forEach(el => el.classList.remove('d-none'));
        if (refreshBtn) refreshBtn.disabled = true;
    } else {
        spinners.forEach(el => el.classList.add('d-none'));
        if (refreshBtn) refreshBtn.disabled = false;
    }
}

function updateSummaryStats(agentsData, loginsData, severityData) {
    if (agentsData && agentsData.data) {
        document.getElementById('totalAgents').textContent = agentsData.count || 0;
    }
    
    if (severityData && severityData.data) {
        const totalEvents = severityData.total_count_24h !== undefined 
            ? severityData.total_count_24h 
            : severityData.data.reduce((sum, count) => sum + count, 0);
        document.getElementById('totalEvents24h').textContent = totalEvents;
        
        const highIndex = severityData.labels ? severityData.labels.indexOf('high') : 2;
        if (highIndex !== -1) {
            document.getElementById('highSeverity').textContent = severityData.data[highIndex] || 0;
        }
    }
    
    if (loginsData && loginsData.data) {
        const failedLoginTypes = [
            'failed_login',
            'auth_failure', 
            'ssh_login_failed',
            'invalid_user',
            'pam_auth_failure',
            'brute_force'
        ];
        
        const failedKeywords = [
            'failed', 'failure', 'invalid', 'denied', 
            'refused', 'rejected', 'unauthorized'
        ];
        
        let failedCount = 0;
        
        for (const login of loginsData.data) {
            const eventType = (login.event_type || '').toLowerCase();
            const rawLog = (login.raw_log || '').toLowerCase();
            
            const isFailedByType = failedLoginTypes.some(type => 
                eventType.includes(type)
            );
            
            const isFailedByContent = failedKeywords.some(keyword =>
                rawLog.toLowerCase().includes(keyword)
            );
            
            const isFailedBySuccess = login.success === false;
            
            if (isFailedByType || isFailedByContent || isFailedBySuccess) {
                failedCount++;
            }
        }
        
        document.getElementById('failedLogins').textContent = failedCount;
    }
}

function updateCharts(eventsByTypeData, eventsBySeverityData, timelineData) {            
    if (eventsByTypeData?.labels?.length && eventsByTypeData?.data?.length) {//Events by type
        if (charts.eventTypesChart) {
            charts.eventTypesChart.data.labels = eventsByTypeData.labels.slice(0, 10);
            charts.eventTypesChart.data.datasets[0].data = eventsByTypeData.data.slice(0, 10);
            charts.eventTypesChart.update('none');
        } else {
            createEventTypesChart(eventsByTypeData);
        }
    }            
    if (eventsBySeverityData?.labels?.length && eventsBySeverityData?.data?.length) {//Events by severity
        if (charts.severityChart) {
            charts.severityChart.data.labels = eventsBySeverityData.labels;
            charts.severityChart.data.datasets[0].data = eventsBySeverityData.data;
            charts.severityChart.update('none');
        } else {
            createSeverityChart(eventsBySeverityData);
        }
    }            
    if (timelineData?.labels?.length && timelineData?.data?.length) {// Timeline
        if (charts.timelineChart) {
            const shortLabels = timelineData.labels.map(label => 
                (label.split(' ').pop() || label).substring(0, 5)
            );
            
            charts.timelineChart.data.labels = shortLabels;
            charts.timelineChart.data.datasets[0].data = timelineData.data;
            charts.timelineChart.update('none');
        } else {
            createTimelineChart(timelineData);
        }
    } else {
        if (charts.timelineChart) {
            charts.timelineChart.destroy();
            charts.timelineChart = null;
        }
    }
}

function createEventTypesChart(data) {
    const ctx = document.getElementById('eventTypesChart').getContext('2d');
    const backgroundColors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
        '#FF9F40', '#8AC926', '#1982C4', '#6A4C93', '#FF595E'
    ];
    charts.eventTypesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels.slice(0, 10),
            datasets: [{
                label: 'Number of Events',
                data: data.data.slice(0, 10),
                backgroundColor: backgroundColors,
                borderColor: backgroundColors.map(color => color.replace('0.8', '1')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

function createSeverityChart(data) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    const severityColors = {
        'critical': '#FF0000',
        'high': '#FF6384',
        'medium': '#FF9F40',
        'low': '#36A2EB',
        'unknown': '#C9CBCF'
    };
    const backgroundColors = data.labels.map(label => 
        severityColors[label.toLowerCase()] || '#C9CBCF'
    );
    charts.severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.data,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function createTimelineChart(data) {
    if (!data || !Array.isArray(data.labels) || !Array.isArray(data.data)) {
        console.warn('Invalid timeline data:', data);
        return;
    }

    const canvas = document.getElementById('timelineChart');
    const ctx = canvas.getContext('2d');
    
    canvas.style.height = '';
    canvas.style.width = '';

    if (charts.timelineChart) {
        charts.timelineChart.destroy();
        charts.timelineChart = null;
    }

    charts.timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Events per hour',
                data: data.data,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#4361ee',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 3,
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: ctx => `Events: ${ctx.raw}`
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: { display: true, text: 'Number of Events' },
                    ticks: { precision: 0 },
                    grid: { color: 'rgba(0,0,0,0.05)' }
                },
                x: {
                    title: { display: true, text: 'Time (hours)' },
                    grid: { color: 'rgba(0,0,0,0.05)' }
                }
            }
        }
    });
}

function updateRecentLogins(data) {
    const container = document.getElementById('recentLogins');            
    if (!data) {
        container.innerHTML = '<div class="text-muted">No data received</div>';
        return;
    }
    if (data.status === 'error') {
        container.innerHTML = `<div class="text-danger">Error: ${data.message || 'Unknown error'}</div>`;
        return;
    }
    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<div class="text-muted">No recent logins found</div>';
        return;
    }
    let html = '';
    data.data.slice(0, 8).forEach(login => {
        const time = login.timestamp ? 
            new Date(login.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : 
            'N/A';
        const successClass = login.success ? 'text-success' : 'text-danger';
        const successIcon = login.success ? 'bi-check-circle' : 'bi-x-circle';
        const eventType = login.event_type || 'login_attempt';
        html += `
            <div class="event-item">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <i class="bi ${successIcon} ${successClass} me-2"></i>
                        <strong>${login.user || 'unknown'}</strong>
                        <small class="text-muted ms-2">${eventType}</small>
                    </div>
                    <div>
                        <small class="text-muted">${time}</small>
                    </div>
                </div>
                <div class="small text-muted mt-1">
                    ${login.hostname || 'Unknown host'} - ${login.source || 'Unknown source'}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function updateActiveHosts(data) {
    const container = document.getElementById('activeHosts');
    if (!data || !data.data || data.data.length === 0) {
        container.innerHTML = '<div class="text-muted">No active hosts found</div>';
        return;
    }
    let html = '';
    data.data.slice(0, 8).forEach(host => {
        const severity = host.severity_counts || {};
        const highCount = severity.high || 0;
        const severityBadge = highCount > 0 ? 
            `<span class="badge bg-danger ms-2">${highCount} high</span>` : 
            `<span class="badge bg-success ms-2">Normal</span>`;
        html += `
            <div class="event-item">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <i class="bi bi-pc me-2"></i>
                        <strong>${host.hostname}</strong>
                        ${severityBadge}
                    </div>
                    <div>
                        <span class="badge bg-primary">${host.event_count} events</span>
                    </div>
                </div>
                <div class="small text-muted mt-1">
                    Sources: ${(host.sources || []).slice(0, 3).join(', ')}
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

function updateTopProcesses(data) {
    const container = document.getElementById('processesList');
    if (!data) {
        container.innerHTML = '<div class="text-muted">No data received</div>';
        return;
    }
    if (data.status === 'error') {
        container.innerHTML = `<div class="text-danger">Error: ${data.message || 'Unknown error'}</div>`;
        return;
    }
    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<div class="text-muted">No process data found</div>';
        return;
    }
    let html = '<table class="table table-sm">';
    html += '<thead><tr><th>Process</th><th class="text-end">Events</th><th>Sources</th></tr></thead>';
    html += '<tbody>';
    data.data.slice(0, 8).forEach(process => {
        html += `
            <tr>
                <td>
                    <i class="bi bi-gear me-2"></i>
                    ${process.process || 'Unknown'}
                </td>
                <td class="text-end">
                    <span class="badge bg-primary">${process.event_count || 0}</span>
                </td>
                <td>
                    <small class="text-muted">${(process.sources || []).slice(0, 2).join(', ')}</small>
                </td>
            </tr>
        `;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function updateTopUsers(data) {
    const container = document.getElementById('topUsersList');
    if (!data) {
        container.innerHTML = '<div class="text-muted">No data received</div>';
        return;
    }
    if (data.status === 'error') {
        container.innerHTML = `<div class="text-danger">Error: ${data.message || 'Unknown error'}</div>`;
        return;
    }
    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<div class="text-muted">No user data found</div>';
        return;
    }
    let html = '<table class="table table-sm">';
    html += '<thead><tr><th>User</th><th class="text-end">Events</th><th>Event Types</th></tr></thead>';
    html += '<tbody>';
    data.data.slice(0, 8).forEach(user => {
        html += `
            <tr>
                <td>
                    <i class="bi bi-person-circle me-2"></i>
                    ${user.user || 'Unknown'}
                </td>
                <td class="text-end">
                    <span class="badge bg-primary">${user.event_count || 0}</span>
                </td>
                <td>
                    <small class="text-muted">${(user.event_types || []).slice(0, 2).join(', ')}</small>
                </td>
            </tr>
        `;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function updateActiveAgents(data) {
    const container = document.getElementById('activeAgentsList');
    if (!data || !data.data || data.data.length === 0) {
        container.innerHTML = '<div class="text-muted">No active agents found</div>';
        return;
    }
    let html = '<table class="table table-sm">';
    html += '<thead><tr><th>Agent</th><th class="text-end">Events</th><th>Last Activity</th></tr></thead>';
    html += '<tbody>';
    data.data.slice(0, 8).forEach(agent => {
        const lastActivity = agent.last_activity ? 
            new Date(agent.last_activity).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : 
            'N/A';
        html += `
            <tr>
                <td>
                    <i class="bi bi-hdd me-2"></i>
                    ${agent.agent_id || 'Unknown'}
                </td>
                <td class="text-end">
                    <span class="badge bg-primary">${agent.event_count || 0}</span>
                </td>
                <td>
                    <small class="text-muted">${lastActivity}</small>
                </td>
            </tr>
        `;
    });
    html += '</tbody></table>';
    container.innerHTML = html;
}

function refreshDashboard() {
    console.log('Manual refresh triggered at', new Date().toLocaleTimeString());
    if (charts.timelineChart) {
        charts.timelineChart.destroy();
        charts.timelineChart = null;
    }
    if (charts.severityChart) {
        charts.severityChart.destroy();
        charts.severityChart = null;
    }
    if (charts.eventTypesChart) {
        charts.eventTypesChart.destroy();
        charts.eventTypesChart = null;
    }
    loadDashboard();
}

function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    autoRefreshInterval = setInterval(() => {
        console.log('Auto-refreshing dashboard at', new Date().toLocaleTimeString());
        refreshDashboard();
    }, 15000);
}

window.addEventListener('beforeunload', () => {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
});

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    document.body.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => {
        document.body.removeChild(toast);
    });
}