document.addEventListener('DOMContentLoaded', function () {
    fetchAdminData();
    // Refresh data every 10 seconds
    setInterval(fetchAdminData, 10000);

    const showMonthBtn = document.getElementById('showMonthBtn');
    const monthSection = document.getElementById('monthChartSection');
    const overallSections = document.querySelectorAll('.overall-section');
    const fadeableSections = document.querySelectorAll('.fadeable');

    showMonthBtn.dataset.mode = 'overall'; // track current mode for toggling

    const viewAttackPathBtn = document.getElementById('viewAttackPathBtn');
    const attackPathSection = document.getElementById('attackPathSection');
    viewAttackPathBtn.dataset.open = 'false';

    // Auto-open attack path if navigated here from stage 5 Fix It button
    if (window.location.hash === '#attack-path') {
        fetch('/attack_report_data')
            .then(r => r.json())
            .then(report => {
                renderAttackPath(report);
                attackPathSection.style.display = 'block';
                viewAttackPathBtn.textContent = 'Hide Attack Path';
                viewAttackPathBtn.dataset.open = 'true';
                attackPathSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            })
            .catch(err => console.error('Error fetching attack report:', err));
    }

    viewAttackPathBtn.addEventListener('click', function () {
        if (viewAttackPathBtn.dataset.open === 'true') {
            attackPathSection.style.display = 'none';
            viewAttackPathBtn.textContent = 'View Attack Path';
            viewAttackPathBtn.dataset.open = 'false';
        } else {
            fetch('/attack_report_data')
                .then(r => r.json())
                .then(report => {
                    renderAttackPath(report);
                    attackPathSection.style.display = 'block';
                    viewAttackPathBtn.textContent = 'Hide Attack Path';
                    viewAttackPathBtn.dataset.open = 'true';
                })
                .catch(err => console.error('Error fetching attack report:', err));
        }
    });

    showMonthBtn.addEventListener('click', function () {
        const mode = showMonthBtn.dataset.mode || 'overall';
        if (mode === 'overall') {
            if (!latestAdminData) {
                return;
            }
            transitionToMonthly(overallSections, monthSection, fadeableSections, showMonthBtn, () => {
                updateMonthlyCharts(latestAdminData);
            });
        } else {
            transitionToOverall(overallSections, monthSection, fadeableSections, showMonthBtn);
        }
    });
});

function fetchAdminData() {
    fetch('/admin_data')
        .then(response => response.json())
        .then(data => {
            updateDashboard(data);
        })
        .catch(error => console.error('Error fetching admin data:', error));
}

let requestChart; // To hold the Chart.js instance for request distribution (pie)
let methodChart;  // To hold the Chart.js instance for methods (bar)
let statusChart;  // To hold the Chart.js instance for status codes (bar)
let timeChart;    // To hold the Chart.js instance for requests over time (line)
let monthChart;   // To hold the Chart.js instance for month-wise view
let requestChartMonthly;
let methodChartMonthly;
let statusChartMonthly;
let timeChartMonthly;
let honeypotChart; // To hold the Chart.js instance for honeypot logs
let threatRadarChart; // Radar chart instance
let latestAdminData; // Cache the latest admin payload so the button can reuse it

function updateDashboard(data) {
    latestAdminData = data;
    // Update stat cards
    document.getElementById('totalRequests').textContent = data.total_requests;
    document.getElementById('legitCount').textContent = data.legit_count;
    document.getElementById('maliciousCount').textContent = data.malicious_count;
    document.getElementById('honeypotHits').textContent = data.honeypot_hits;
    updateMonthlyStats(data);

    // Update charts
    updateRequestChart(data.risk_labels, data.risk_values);
    updateMethodChart(data.method_labels, data.method_values);
    updateStatusChart(data.status_labels, data.status_values);
    updateTimeChart(data.time_labels, data.time_values);
    updateTimeChart(data.time_labels, data.time_values);
    // updateHoneypotChart(data.honeypot_time_labels, data.honeypot_time_values); 
    if (data.attack_type_labels && data.attack_type_values) {
        // Radar needs >= 3 axes to render as a polygon; pad with zeroed placeholders if needed
        let radarLabels = [...data.attack_type_labels];
        let radarValues = [...data.attack_type_values];
        const ALL_ATTACK_TYPES = ["XSS", "SSTI", "SQL Injection", "XXE (XML External Entity)",
                                   "Insecure Deserialization", "SSRF", "Command Injection", "Path Traversal"];
        for (const t of ALL_ATTACK_TYPES) {
            if (!radarLabels.includes(t)) {
                radarLabels.push(t);
                radarValues.push(0);
            }
        }
        renderThreatRadar(radarLabels, radarValues);
    }
    const monthSection = document.getElementById('monthChartSection');
    if (monthSection.style.display === 'block') {
        updateMonthlyCharts(data);
    }


    // Update high risk events table
    updateHighRiskEventsTable(data.high_risk_events);

    // Update request/response redirect log table
    updateRedirectLogsTable(data.redirect_logs);
}

function updateRequestChart(labels, values) {
    const ctx = document.getElementById('requestChart').getContext('2d');

    if (requestChart) {
        requestChart.destroy(); // Destroy existing chart before creating a new one
    }

    requestChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: ['#FF6384', '#36A2EB'], // Colors for malicious and legitimate
                hoverOffset: 4
            }]
        },
        plugins: [ChartDataLabels],
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Request Distribution'
                },
                datalabels: {
                    color: '#fff',
                    font: {
                        weight: 'bold',
                        size: 14
                    },
                    formatter: function (value) {
                        return value;
                    }
                }
            }
        }
    });
}

function updateMethodChart(labels, values) {
    const ctx = document.getElementById('methodChart').getContext('2d');

    if (methodChart) {
        methodChart.destroy();
    }

    methodChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests by Method',
                data: values,
                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Requests by HTTP Method'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'HTTP Method'
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Requests'
                    }
                }
            }
        }
    });
}

function updateStatusChart(labels, values) {
    const ctx = document.getElementById('statusChart').getContext('2d');

    if (statusChart) {
        statusChart.destroy();
    }

    statusChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests by Status Code',
                data: values,
                backgroundColor: 'rgba(153, 102, 255, 0.6)',
                borderColor: 'rgba(153, 102, 255, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Requests by HTTP Status Code'
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'HTTP Status Code'
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Requests'
                    }
                }
            }
        }
    });
}

function updateTimeChart(labels, values) {
    const ctx = document.getElementById('timeChart').getContext('2d');

    if (timeChart) {
        timeChart.destroy();
    }

    timeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests Over Time',
                data: values,
                fill: false,
                borderColor: 'rgb(255, 99, 132)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Requests Over Time (Hourly)'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateMonthlyStats(data) {
    const total = document.getElementById('totalRequestsMonthly');
    const legit = document.getElementById('legitCountMonthly');
    const malicious = document.getElementById('maliciousCountMonthly');
    const honeypot = document.getElementById('honeypotHitsMonthly');
    if (total) total.textContent = data.total_requests;
    if (legit) legit.textContent = data.legit_count;
    if (malicious) malicious.textContent = data.malicious_count;
    if (honeypot) honeypot.textContent = data.honeypot_hits;
}

function updateMonthChart(labels, values) {
    const ctx = document.getElementById('monthChart').getContext('2d');

    if (monthChart) {
        monthChart.destroy();
    }

    monthChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests by Month',
                data: values,
                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Requests by Month'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateMonthlyCharts(data) {
    updateRequestChartMonthly(data.risk_labels, data.risk_values);
    updateMethodChartMonthly(data.method_labels, data.method_values);
    updateStatusChartMonthly(data.status_labels, data.status_values);
    updateTimeChartMonthly(data.time_labels, data.time_values);
    updateMonthChart(data.month_labels, data.month_values);
}

function updateRequestChartMonthly(labels, values) {
    const ctx = document.getElementById('requestChartMonthly').getContext('2d');
    if (requestChartMonthly) {
        requestChartMonthly.destroy();
    }
    requestChartMonthly = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: ['#FF6384', '#36A2EB'],
                hoverOffset: 4
            }]
        },
        plugins: [ChartDataLabels],
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Request Distribution' },
                datalabels: {
                    color: '#fff',
                    font: {
                        weight: 'bold',
                        size: 14
                    },
                    formatter: function (value) {
                        return value;
                    }
                }
            }
        }
    });
}

function updateMethodChartMonthly(labels, values) {
    const ctx = document.getElementById('methodChartMonthly').getContext('2d');
    if (methodChartMonthly) {
        methodChartMonthly.destroy();
    }
    methodChartMonthly = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests by Method',
                data: values,
                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Requests by HTTP Method' }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'HTTP Method'
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Requests'
                    }
                }
            }
        }
    });
}

function updateStatusChartMonthly(labels, values) {
    const ctx = document.getElementById('statusChartMonthly').getContext('2d');
    if (statusChartMonthly) {
        statusChartMonthly.destroy();
    }
    statusChartMonthly = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests by Status Code',
                data: values,
                backgroundColor: 'rgba(153, 102, 255, 0.6)',
                borderColor: 'rgba(153, 102, 255, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Requests by HTTP Status Code' }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'HTTP Status Code'
                    }
                },
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Requests'
                    }
                }
            }
        }
    });
}

function updateTimeChartMonthly(labels, values) {
    const ctx = document.getElementById('timeChartMonthly').getContext('2d');
    if (timeChartMonthly) {
        timeChartMonthly.destroy();
    }
    timeChartMonthly = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests Over Time',
                data: values,
                fill: false,
                borderColor: 'rgb(255, 99, 132)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Requests Over Time (Hourly)' }
            },
            scales: { y: { beginAtZero: true } }
        }
    });
}

function transitionToMonthly(overallSections, monthSection, fadeableSections, toggleBtn, afterFadeCallback) {
    fadeableSections.forEach(section => section.classList.add('fade-hide'));
    setTimeout(() => {
        overallSections.forEach(section => {
            section.style.display = 'none';
        });
        monthSection.style.display = 'block';
        monthSection.classList.remove('fade-hide');
        if (toggleBtn) {
            toggleBtn.textContent = 'Back to Overall';
            toggleBtn.dataset.mode = 'monthly';
        }
        if (afterFadeCallback) {
            afterFadeCallback();
        }
    }, 200);
}

function transitionToOverall(overallSections, monthSection, fadeableSections, toggleBtn) {
    monthSection.classList.add('fade-hide');
    setTimeout(() => {
        monthSection.style.display = 'none';
        overallSections.forEach(section => {
            section.style.display = '';
        });
        fadeableSections.forEach(section => section.classList.remove('fade-hide'));
        if (toggleBtn) {
            toggleBtn.textContent = 'Show Month-wise Analysis';
            toggleBtn.dataset.mode = 'overall';
        }
    }, 200);
}

function updateHighRiskEventsTable(events) {
    const tableBody = document.getElementById('highRiskEventsTable').querySelector('tbody');
    tableBody.innerHTML = ''; // Clear existing rows

    events.forEach(event => {
        const row = tableBody.insertRow();
        row.insertCell().textContent = event.timestamp;
        row.insertCell().textContent = event.ip;
        row.insertCell().textContent = event.path;
        row.insertCell().textContent = event.risk_level;
        row.insertCell().textContent = event.attack_type;
        row.insertCell().textContent = event.payload;
    });
}

function updateRedirectLogsTable(logs) {
    const tableBody = document.getElementById('redirectLogsTable').querySelector('tbody');
    tableBody.innerHTML = '';

    logs.forEach(log => {
        const row = tableBody.insertRow();
        row.insertCell().textContent = log.timestamp;
        row.insertCell().textContent = `${log.method || ''} ${log.path || ''}`.trim();
        row.insertCell().textContent = log.target;
        row.insertCell().textContent = log.verdict;
        row.insertCell().textContent = log.reason;
        row.insertCell().textContent = log.ip;
        row.insertCell().textContent = log.user_agent;
    });
}

function renderThreatRadar(labels, values) {
    const ctx = document.getElementById('threatRadarChart').getContext('2d');

    if (threatRadarChart) {
        threatRadarChart.destroy();
    }

    threatRadarChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Attack Profile',
                data: values,
                fill: true,
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderColor: 'rgb(255, 99, 132)',
                pointBackgroundColor: 'rgb(255, 99, 132)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgb(255, 99, 132)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            elements: {
                line: {
                    borderWidth: 3
                }
            },
            scales: {
                r: {
                    angleLines: {
                        display: false
                    },
                    suggestedMin: 0,
                    ticks: {
                        backdropColor: 'rgba(0,0,0,0)'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

function renderAttackPath(report) {
    const mapEl = document.getElementById('attackPathMap');
    mapEl.innerHTML = '';
    report.stages.forEach((row) => {
        const step = document.createElement('div');
        step.className = 'attack-step ' + (row.status === 'completed' ? 'done' : 'pending');
        step.innerHTML = `
            <div class="astep-head">
                <span class="astep-name">${row.stage}</span>
                <span class="astep-badge ${row.status === 'completed' ? 'ok' : 'wait'}">${row.status === 'completed' ? 'Compromised' : 'Pending'}</span>
            </div>
            <div class="astep-type">${row.attack_type}</div>
        `;
        mapEl.appendChild(step);
        const arrow = document.createElement('span');
        arrow.className = 'astep-arrow';
        arrow.textContent = '→';
        mapEl.appendChild(arrow);
    });

    // Fix It card at the end
    const fixStep = document.createElement('div');
    fixStep.className = 'attack-step fix-it-step';
    fixStep.innerHTML = `
        <div class="astep-head">
            <span class="astep-name">Fix It</span>
            <span class="astep-badge ok">&#128736;</span>
        </div>
        <div class="astep-type">Remediation</div>
        <button class="fix-it-btn" style="margin-top:8px;width:100%;" id="fixItSummaryBtn">View Fixes</button>
    `;
    mapEl.appendChild(fixStep);

    document.getElementById('fixItSummaryBtn').onclick = function () {
        document.getElementById('fixItModal').style.display = 'flex';
    };

    const tbody = document.getElementById('attackPathTable').querySelector('tbody');
    tbody.innerHTML = '';
    report.stages.forEach((row, idx) => {
        const tr = tbody.insertRow();
        tr.insertCell().textContent = row.stage;
        tr.insertCell().textContent = row.path;
        tr.insertCell().textContent = row.attack_type;
        const payloadCell = tr.insertCell();
        payloadCell.textContent = row.payload;
        payloadCell.style.fontFamily = 'Consolas, monospace';
        payloadCell.style.fontSize = '0.85em';
        payloadCell.style.wordBreak = 'break-all';
        tr.insertCell().textContent = row.fix;
        const statusCell = tr.insertCell();
        statusCell.innerHTML = row.status === 'completed'
            ? '<span style="color:#1a7a4a;font-weight:700;">Completed</span>'
            : '<span style="color:#b35c00;font-weight:700;">Pending</span>';

        // Action cell — Fix It button only when completed
        const actionCell = tr.insertCell();
        if (row.status === 'completed') {
            const fixId = 'fix-detail-' + idx;
            const btn = document.createElement('button');
            btn.textContent = 'Fix It';
            btn.className = 'fix-it-btn';
            btn.onclick = function () {
                const detail = document.getElementById(fixId);
                detail.style.display = detail.style.display === 'table-row' ? 'none' : 'table-row';
            };
            actionCell.appendChild(btn);

            // Expandable detail row
            const detailRow = tbody.insertRow();
            detailRow.id = fixId;
            detailRow.style.display = 'none';
            detailRow.style.background = '#fffbf0';
            const detailCell = detailRow.insertCell();
            detailCell.colSpan = 7;
            detailCell.style.padding = '12px 18px';
            detailCell.style.borderTop = '2px solid #e0a040';
            detailCell.innerHTML = `
                <strong style="color:#b35c00;">&#128736; Recommended Fix — ${row.attack_type}:</strong>
                <span style="margin-left:8px;color:#555;">${row.fix}</span>
                <div style="margin-top:10px;">
                    <button class="fix-it-btn" onclick="document.getElementById('${fixId}').style.display='none'">&#x25B2; Hide Fix</button>
                </div>`;
        } else {
            actionCell.textContent = '—';
            actionCell.style.color = '#aaa';
            actionCell.style.textAlign = 'center';
        }
    });
}
