// SecureMail AI Dashboard Charts

document.addEventListener('DOMContentLoaded', () => {
    const pieCtx = document.getElementById('classificationChart');
    const lineCtx = document.getElementById('trendChart');
    
    if (!pieCtx || !lineCtx) return; // Exit if not on dashboard
    
    let classificationChart = null;
    let trendChart = null;
    
    // Fetch stats and render
    fetchChartsData();
    
    // Listen for theme change to update colors
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            // Give theme toggle a tiny moment to apply attributes
            setTimeout(updateChartThemes, 50);
        });
    }
    
    function getThemeColors() {
        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        return {
            textColor: isLight ? '#475569' : '#94a3b8',
            gridColor: isLight ? '#e2e8f0' : '#334155',
            tooltipBg: isLight ? '#0f172a' : '#1e293b'
        };
    }
    
    function fetchChartsData() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                renderCharts(data);
            })
            .catch(err => console.error('Error fetching dashboard stats:', err));
    }
    
    function renderCharts(data) {
        const colors = getThemeColors();
        
        // 1. Classification Pie Chart
        const pieData = data.pie_data;
        const total = pieData.values.reduce((a, b) => a + b, 0);
        
        // Default empty data visualization
        const values = total === 0 ? [1, 0, 0] : pieData.values;
        const labels = total === 0 ? ['No Scans', 'Spam', 'Phishing'] : pieData.labels;
        const bgColors = total === 0 ? ['#1e293b', '#f59e0b', '#ef4444'] : ['#10b981', '#f59e0b', '#ef4444'];
        
        classificationChart = new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: bgColors,
                    borderWidth: 2,
                    borderColor: 'transparent'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: colors.textColor,
                            font: { family: 'Outfit', size: 12 }
                        }
                    },
                    tooltip: {
                        enabled: total > 0, // Disable tooltips if no data
                        backgroundColor: colors.tooltipBg,
                        titleFont: { family: 'Outfit', weight: 'bold' },
                        bodyFont: { family: 'Outfit' }
                    }
                },
                cutout: '70%'
            }
        });
        
        // 2. Trend Line Chart
        const lineData = data.line_data;
        
        trendChart = new Chart(lineCtx, {
            type: 'line',
            data: {
                labels: lineData.labels,
                datasets: [{
                    label: 'Emails Scanned',
                    data: lineData.values,
                    borderColor: '#38bdf8', // Cyan
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: '#38bdf8',
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: colors.tooltipBg,
                        titleFont: { family: 'Outfit', weight: 'bold' },
                        bodyFont: { family: 'Outfit' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: colors.gridColor },
                        ticks: {
                            color: colors.textColor,
                            font: { family: 'Outfit' }
                        }
                    },
                    y: {
                        grid: { color: colors.gridColor },
                        ticks: {
                            color: colors.textColor,
                            font: { family: 'Outfit' },
                            stepSize: 1,
                            precision: 0
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    function updateChartThemes() {
        if (!classificationChart || !trendChart) return;
        
        const colors = getThemeColors();
        
        // Update Pie Chart options
        classificationChart.options.plugins.legend.labels.color = colors.textColor;
        classificationChart.options.plugins.tooltip.backgroundColor = colors.tooltipBg;
        classificationChart.update();
        
        // Update Line Chart options
        trendChart.options.plugins.tooltip.backgroundColor = colors.tooltipBg;
        trendChart.options.scales.x.grid.color = colors.gridColor;
        trendChart.options.scales.x.ticks.color = colors.textColor;
        trendChart.options.scales.y.grid.color = colors.gridColor;
        trendChart.options.scales.y.ticks.color = colors.textColor;
        trendChart.update();
    }
});
