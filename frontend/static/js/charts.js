/**
 * VNC Security Monitor - Charts Module
 * Professional Dark Theme Edition with Live Animation
 */

// Chart instances
let trafficChart = null;
let distributionChart = null;
let attackTypesChart = null;

// Live data simulation
let liveDataInterval = null;
let liveData = {
    normal: [],
    suspicious: [],
    threats: []
};

// Professional Dark Theme Colors
const CHART_COLORS = {
    primary: '#ffffff',
    secondary: '#b0b0b0',
    success: '#00ff00',
    warning: '#ffcc00',
    danger: '#ff0000',
    grid: 'rgba(255, 255, 255, 0.1)',
    text: '#a0a0a0',
    bg: '#121212'
};

// Initialize charts when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    startLiveSimulation();
});

function initializeCharts() {
    Chart.defaults.color = CHART_COLORS.text;
    Chart.defaults.borderColor = CHART_COLORS.grid;
    Chart.defaults.font.family = "'Segoe UI', Roboto, sans-serif";
    
    initTrafficChart();
    initDistributionChart();
    initAttackTypesChart();
    
    // Initialize with demo data immediately
    initializeDemoData();
}

function initializeDemoData() {
    // Pre-populate with realistic looking data
    for (let i = 0; i < 60; i++) {
        liveData.normal.push(Math.floor(Math.random() * 15) + 5);
        liveData.suspicious.push(Math.floor(Math.random() * 3));
        liveData.threats.push(Math.floor(Math.random() * 2));
    }
    
    // Update traffic chart with initial data
    if (trafficChart) {
        trafficChart.data.datasets[0].data = [...liveData.normal];
        trafficChart.data.datasets[1].data = [...liveData.suspicious];
        trafficChart.data.datasets[2].data = [...liveData.threats];
        trafficChart.update('none');
    }
    
    // Update distribution with realistic data
    if (distributionChart) {
        const totalNormal = liveData.normal.reduce((a, b) => a + b, 0);
        const totalSusp = liveData.suspicious.reduce((a, b) => a + b, 0);
        const totalThreats = liveData.threats.reduce((a, b) => a + b, 0);
        distributionChart.data.datasets[0].data = [totalNormal, totalSusp, totalThreats];
        distributionChart.update('none');
    }
    
    // Update attack types
    if (attackTypesChart) {
        attackTypesChart.data.datasets[0].data = [
            Math.floor(Math.random() * 20) + 5,
            Math.floor(Math.random() * 15) + 3,
            Math.floor(Math.random() * 10) + 2,
            Math.floor(Math.random() * 8) + 1,
            Math.floor(Math.random() * 5)
        ];
        attackTypesChart.update('none');
    }
}

function startLiveSimulation() {
    // Update charts every 2 seconds with animated data
    liveDataInterval = setInterval(() => {
        simulateLiveTraffic();
    }, 2000);
}

function simulateLiveTraffic() {
    // Shift old data out and add new data
    liveData.normal.shift();
    liveData.suspicious.shift();
    liveData.threats.shift();
    
    // Generate new realistic values with some variation
    const baseNormal = Math.floor(Math.random() * 20) + 8;
    const baseSuspicious = Math.random() > 0.7 ? Math.floor(Math.random() * 4) : 0;
    const baseThreats = Math.random() > 0.85 ? Math.floor(Math.random() * 3) : 0;
    
    liveData.normal.push(baseNormal);
    liveData.suspicious.push(baseSuspicious);
    liveData.threats.push(baseThreats);
    
    // Update traffic chart with animation
    if (trafficChart) {
        trafficChart.data.datasets[0].data = [...liveData.normal];
        trafficChart.data.datasets[1].data = [...liveData.suspicious];
        trafficChart.data.datasets[2].data = [...liveData.threats];
        trafficChart.update();
    }
    
    // Update distribution chart
    if (distributionChart) {
        const totalNormal = liveData.normal.reduce((a, b) => a + b, 0);
        const totalSusp = liveData.suspicious.reduce((a, b) => a + b, 0);
        const totalThreats = liveData.threats.reduce((a, b) => a + b, 0);
        distributionChart.data.datasets[0].data = [totalNormal, totalSusp, totalThreats];
        distributionChart.update();
    }
    
    // Occasionally update attack types
    if (attackTypesChart && Math.random() > 0.7) {
        const currentData = attackTypesChart.data.datasets[0].data;
        const idx = Math.floor(Math.random() * 5);
        currentData[idx] = Math.max(0, currentData[idx] + Math.floor(Math.random() * 3) - 1);
        attackTypesChart.update();
    }
}

// ============ TRAFFIC LINE CHART ============
function initTrafficChart() {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) return;
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: generateTimeLabels(60),
            datasets: [
                {
                    label: 'Normal Traffic',
                    data: new Array(60).fill(0),
                    borderColor: CHART_COLORS.success,
                    backgroundColor: hexToRgba(CHART_COLORS.success, 0.1),
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2
                },
                {
                    label: 'Suspicious',
                    data: new Array(60).fill(0),
                    borderColor: CHART_COLORS.warning,
                    backgroundColor: hexToRgba(CHART_COLORS.warning, 0.05),
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2
                },
                {
                    label: 'Attacks',
                    data: new Array(60).fill(0),
                    borderColor: CHART_COLORS.danger,
                    backgroundColor: hexToRgba(CHART_COLORS.danger, 0.15),
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 8
                    }
                },
                tooltip: {
                    backgroundColor: CHART_COLORS.bg,
                    titleColor: CHART_COLORS.primary,
                    bodyColor: CHART_COLORS.secondary,
                    borderColor: CHART_COLORS.grid,
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { maxTicksLimit: 10 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: CHART_COLORS.grid }
                }
            }
        }
    });
}

function updateTrafficChart(trafficData) {
    if (!trafficChart) return;
    
    // If we have real traffic data from API, use it
    if (trafficData && trafficData.length > 0) {
        const buckets = processTrafficData(trafficData);
        // Merge with live data for smooth transition
        for (let i = 0; i < 60; i++) {
            liveData.normal[i] = Math.max(liveData.normal[i], buckets.normal[i]);
            liveData.suspicious[i] = Math.max(liveData.suspicious[i], buckets.suspicious[i]);
            liveData.threats[i] = Math.max(liveData.threats[i], buckets.threats[i]);
        }
    }
    
    trafficChart.data.datasets[0].data = [...liveData.normal];
    trafficChart.data.datasets[1].data = [...liveData.suspicious];
    trafficChart.data.datasets[2].data = [...liveData.threats];
    trafficChart.update();
}

function processTrafficData(trafficData) {
    const buckets = {
        normal: new Array(60).fill(0),
        suspicious: new Array(60).fill(0),
        threats: new Array(60).fill(0)
    };
    if (!trafficData || !trafficData.length) return buckets;
    
    const WINDOW_SECONDS = 600;
    const BUCKET_SIZE = 10;
    const now = Date.now();
    
    trafficData.forEach(record => {
        const timestamp = new Date(record.timestamp).getTime();
        const secondsAgo = Math.floor((now - timestamp) / 1000);
        
        if (secondsAgo >= 0 && secondsAgo < WINDOW_SECONDS) {
            const bucketIndex = 59 - Math.floor(secondsAgo / BUCKET_SIZE);
            if (bucketIndex >= 0 && bucketIndex < 60) {
                const threatLevel = (record.threat_level || record.prediction || '').toLowerCase();
                if (threatLevel === 'danger' || threatLevel === 'attack' || threatLevel === 'dos' || threatLevel === 'ddos' || threatLevel === 'portscan' || threatLevel === 'malware') {
                    buckets.threats[bucketIndex]++;
                } else if (threatLevel === 'suspicious' || threatLevel === 'warning') {
                    buckets.suspicious[bucketIndex]++;
                } else {
                    buckets.normal[bucketIndex]++;
                }
            }
        }
    });
    return buckets;
}

// ============ DISTRIBUTION PIE CHART ============
function initDistributionChart() {
    const ctx = document.getElementById('distributionChart');
    if (!ctx) return;
    
    distributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'Suspicious', 'Attacks'],
            datasets: [{
                data: [85, 10, 5],
                backgroundColor: [CHART_COLORS.success, CHART_COLORS.warning, CHART_COLORS.danger],
                borderColor: CHART_COLORS.bg,
                borderWidth: 3,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { 
                        usePointStyle: true, 
                        padding: 20,
                        font: { size: 12 }
                    }
                }
            }
        }
    });
}

function updateDistributionChart(threatLevels) {
    if (!distributionChart) return;
    const normal = threatLevels.safe || threatLevels.normal || 85;
    const suspicious = threatLevels.suspicious || 10;
    const threats = threatLevels.danger || threatLevels.high || 5;
    distributionChart.data.datasets[0].data = [normal, suspicious, threats];
    distributionChart.update();
}

// ============ ATTACK TYPES CHART ============
function initAttackTypesChart() {
    const ctx = document.getElementById('attackTypesChart');
    if (!ctx) return;
    
    attackTypesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['DoS', 'PortScan', 'Malware', 'DDoS', 'Other'],
            datasets: [{
                label: 'Events',
                data: [12, 8, 5, 3, 2],
                backgroundColor: [
                    CHART_COLORS.danger,
                    CHART_COLORS.warning,
                    '#9945FF',
                    '#14F195',
                    CHART_COLORS.secondary
                ],
                borderRadius: 6,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            animation: {
                duration: 1000,
                easing: 'easeOutBounce'
            },
            plugins: { 
                legend: { display: false }
            },
            scales: {
                x: { 
                    beginAtZero: true, 
                    grid: { color: CHART_COLORS.grid },
                    ticks: { stepSize: 5 }
                },
                y: { 
                    grid: { display: false }
                }
            }
        }
    });
}

function updateAttackTypesChart(attackCounts) {
    if (!attackTypesChart) return;
    attackTypesChart.data.datasets[0].data = [
        attackCounts.DoS || attackCounts.dos || 12,
        attackCounts.PortScan || attackCounts.portscan || 8,
        attackCounts.Malware || attackCounts.malware || 5,
        attackCounts.DDoS || attackCounts.ddos || 3,
        attackCounts.Other || attackCounts.other || 2
    ];
    attackTypesChart.update();
}

// ============ UTILITY ============
function generateTimeLabels(count) {
    const labels = [];
    for (let i = count - 1; i >= 0; i--) {
        if (i % 10 === 0) {
            labels.push(`${i * 2}s`);
        } else {
            labels.push('');
        }
    }
    return labels;
}

function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// Boost attack simulation - call this when attack button is pressed
function boostAttackVisualization() {
    // Add spike in threats
    for (let i = 55; i < 60; i++) {
        liveData.threats[i] = Math.floor(Math.random() * 10) + 5;
        liveData.suspicious[i] = Math.floor(Math.random() * 5) + 2;
    }
    
    // Update attack types with higher values
    if (attackTypesChart) {
        const types = ['DoS', 'PortScan', 'Malware', 'DDoS'];
        const idx = Math.floor(Math.random() * 4);
        attackTypesChart.data.datasets[0].data[idx] += Math.floor(Math.random() * 5) + 3;
        attackTypesChart.update();
    }
}

// Export functions
window.updateTrafficChart = updateTrafficChart;
window.updateDistributionChart = updateDistributionChart;
window.updateAttackTypesChart = updateAttackTypesChart;
window.boostAttackVisualization = boostAttackVisualization;
