function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleString();
    } catch (e) {
        return dateString;
    }
}

function truncateText(text, length = 50) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

function getSeverityClass(severity) {
    const severityLower = (severity || 'low').toLowerCase();
    return `severity-${severityLower}`;
}

function getSeverityBadge(severity) {
    const severityLower = (severity || 'low').toLowerCase();
    const severityClass = getSeverityClass(severity);
    return `<span class="severity-badge ${severityClass}">${severityLower.toUpperCase()}</span>`;
}