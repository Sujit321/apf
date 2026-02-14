// ===== Enhanced Excel Analytics Module for APF Dashboard =====

let excelWorkbook = null;
let excelData = [];
let excelColumns = [];
let excelColumnTypes = {};
let activeCharts = [];

// ===== Auto-Filter State =====
let tableFilters = {};    // { colName: Set of selected values }
let tableSearchTerm = '';
let tablePage = 0;
const TABLE_PAGE_SIZE = 100;

// ===== Color Palette =====
const CHART_COLORS = [
    '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ef4444',
    '#06b6d4', '#f97316', '#ec4899', '#14b8a6', '#6366f1',
    '#84cc16', '#e11d48', '#0ea5e9', '#a855f7', '#22c55e',
    '#d946ef', '#eab308', '#64748b', '#fb923c', '#2dd4bf'
];

const CHART_PALETTES = {
    default: ['#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ef4444', '#06b6d4', '#f97316', '#ec4899', '#14b8a6', '#6366f1'],
    ocean: ['#0ea5e9', '#06b6d4', '#14b8a6', '#3b82f6', '#6366f1', '#8b5cf6', '#0284c7', '#0891b2', '#0d9488', '#2563eb'],
    sunset: ['#f59e0b', '#f97316', '#ef4444', '#e11d48', '#ec4899', '#d946ef', '#eab308', '#fb923c', '#dc2626', '#be185d'],
    forest: ['#10b981', '#059669', '#84cc16', '#22c55e', '#16a34a', '#15803d', '#4ade80', '#a3e635', '#65a30d', '#047857'],
    pastel: ['#93c5fd', '#a5b4fc', '#c4b5fd', '#f9a8d4', '#fca5a5', '#fcd34d', '#86efac', '#67e8f9', '#fdba74', '#d8b4fe'],
    mono: ['#f8fafc', '#e2e8f0', '#cbd5e1', '#94a3b8', '#64748b', '#475569', '#334155', '#1e293b', '#0f172a', '#020617'],
};

// Chart registry for per-chart customization
const chartRegistry = {};  // canvasId -> { chart, config, data, title }

function getColors(n) {
    const colors = [];
    for (let i = 0; i < n; i++) colors.push(CHART_COLORS[i % CHART_COLORS.length]);
    return colors;
}

// ===== Multi-Select Dropdown System =====
function toggleCtrlMulti(btn, selectId) {
    const dropdown = document.getElementById(selectId + '-dropdown');
    const select = document.getElementById(selectId);
    const isOpen = dropdown.classList.contains('show');

    // Close all other dropdowns first
    document.querySelectorAll('.ctrl-multi-dropdown.show').forEach(d => d.classList.remove('show'));
    document.querySelectorAll('.ctrl-multi-btn.open').forEach(b => b.classList.remove('open'));

    if (isOpen) return;

    // Build dropdown items from select options
    const options = [...select.options];
    dropdown.innerHTML = `
        <div class="ctrl-multi-dropdown-header">
            <button onclick="ctrlMultiAll('${selectId}', true)">Select All</button>
            <button onclick="ctrlMultiAll('${selectId}', false)">Clear All</button>
        </div>
        <div class="ctrl-multi-dropdown-list">
            ${options.map((o, i) => `
                <label class="ctrl-multi-item ${o.selected ? 'checked' : ''}">
                    <input type="checkbox" ${o.selected ? 'checked' : ''} 
                        onchange="ctrlMultiChange('${selectId}', ${i}, this.checked)">
                    <span>${o.text}</span>
                </label>
            `).join('')}
        </div>
    `;

    dropdown.classList.add('show');
    btn.classList.add('open');
    updateCtrlMultiLabel(btn, select);

    // Close on outside click
    setTimeout(() => {
        const handler = (e) => {
            if (!dropdown.contains(e.target) && !btn.contains(e.target)) {
                dropdown.classList.remove('show');
                btn.classList.remove('open');
                document.removeEventListener('click', handler);
            }
        };
        document.addEventListener('click', handler);
    }, 10);
}

function ctrlMultiChange(selectId, idx, checked) {
    const select = document.getElementById(selectId);
    select.options[idx].selected = checked;
    const item = document.querySelectorAll(`#${selectId}-dropdown .ctrl-multi-item`)[idx];
    if (item) item.classList.toggle('checked', checked);
    const btn = document.querySelector(`[onclick*="'${selectId}'"].ctrl-multi-btn`);
    if (btn) updateCtrlMultiLabel(btn, select);
}

function ctrlMultiAll(selectId, selectAll) {
    const select = document.getElementById(selectId);
    [...select.options].forEach(o => o.selected = selectAll);
    document.querySelectorAll(`#${selectId}-dropdown .ctrl-multi-item`).forEach(item => {
        item.classList.toggle('checked', selectAll);
        const cb = item.querySelector('input');
        if (cb) cb.checked = selectAll;
    });
    const btn = document.querySelector(`[onclick*="'${selectId}'"].ctrl-multi-btn`);
    if (btn) updateCtrlMultiLabel(btn, select);
}

function updateCtrlMultiLabel(btn, select) {
    const total = select.options.length;
    const selected = [...select.selectedOptions].length;
    const label = btn.querySelector('.ctrl-multi-label');
    const count = btn.querySelector('.ctrl-count');
    if (selected === 0) { label.textContent = 'None'; }
    else if (selected === total) { label.textContent = 'All Columns'; }
    else if (selected <= 2) { label.textContent = [...select.selectedOptions].map(o => o.text).join(', '); }
    else { label.textContent = `${selected} Selected`; }
    count.textContent = selected;
}

// ===== Chart Toolbar System =====
function buildChartToolbar(canvasId, chartType) {
    const types = [
        { type: 'bar', icon: 'fa-chart-bar', label: 'Bar' },
        { type: 'line', icon: 'fa-chart-line', label: 'Line' },
        { type: 'doughnut', icon: 'fa-circle-notch', label: 'Doughnut' },
        { type: 'polarArea', icon: 'fa-circle', label: 'Polar' },
        { type: 'pie', icon: 'fa-chart-pie', label: 'Pie' },
        { type: 'radar', icon: 'fa-crosshairs', label: 'Radar' },
    ];
    return `<div class="chart-toolbar">
        ${types.map(t => `<button class="chart-tool-btn ${t.type === chartType ? 'active' : ''}" 
            title="${t.label}" onclick="switchChartType('${canvasId}','${t.type}')">
            <i class="fas ${t.icon}"></i></button>`).join('')}
        <div class="chart-tool-sep"></div>
        <div class="chart-limit-ctrl">
            <select id="chartLimit-${canvasId}" onchange="changeChartLimit('${canvasId}')" title="Data limit">
                <option value="10">Top 10</option>
                <option value="15">Top 15</option>
                <option value="25" selected>Top 25</option>
                <option value="50">Top 50</option>
                <option value="100">Top 100</option>
                <option value="all">View All</option>
            </select>
        </div>
        <button class="chart-tool-btn" title="Filter" onclick="toggleChartFilter('${canvasId}')">
            <i class="fas fa-filter"></i></button>
        <button class="chart-tool-btn" title="Axes" onclick="toggleAxisBar('${canvasId}')">
            <i class="fas fa-sliders-h"></i></button>
        <button class="chart-tool-btn" title="Labels" onclick="toggleChartLabels('${canvasId}')">
            <i class="fas fa-tag"></i></button>
        <button class="chart-tool-btn" title="Palette" onclick="togglePaletteMenu('${canvasId}', this)">
            <i class="fas fa-palette"></i></button>
        <button class="chart-tool-btn" title="Download" onclick="downloadChart('${canvasId}')">
            <i class="fas fa-download"></i></button>
        <button class="chart-tool-btn" title="Fullscreen" onclick="fullscreenChart('${canvasId}')">
            <i class="fas fa-expand"></i></button>
    </div>`;
}

function buildChartAxisBar(canvasId, xCol, yCol, agg) {
    const allCols = excelColumns || [];
    const xOptions = allCols.map(c =>
        `<option value="${c}" ${c === xCol ? 'selected' : ''}>${c.length > 20 ? c.substring(0,17)+'...' : c}</option>`
    ).join('');
    const yOptions = `<option value="_count" ${(!yCol || agg === 'count') ? 'selected' : ''}>Count</option>` +
        allCols.map(c =>
            `<option value="${c}" ${c === yCol ? 'selected' : ''}>${c.length > 20 ? c.substring(0,17)+'...' : c}</option>`
        ).join('');
    return `<div class="chart-axis-bar" id="axisBar-${canvasId}" style="display:none;">
        <div class="axis-ctrl">
            <span class="axis-label"><i class="fas fa-arrows-alt-h"></i> X</span>
            <select id="axisX-${canvasId}" onchange="changeChartAxis('${canvasId}')">${xOptions}</select>
        </div>
        <div class="axis-ctrl">
            <span class="axis-label"><i class="fas fa-arrows-alt-v"></i> Y</span>
            <select id="axisY-${canvasId}" onchange="changeChartAxis('${canvasId}')">${yOptions}</select>
        </div>
        <div class="axis-ctrl">
            <span class="axis-label"><i class="fas fa-calculator"></i></span>
            <select id="axisAgg-${canvasId}" onchange="changeChartAxis('${canvasId}')">
                <option value="count" ${agg==='count'?'selected':''}>Count</option>
                <option value="sum" ${agg==='sum'?'selected':''}>Sum</option>
                <option value="average" ${agg==='average'?'selected':''}>Average</option>
            </select>
        </div>
    </div>`;
}

function toggleAxisBar(canvasId) {
    let bar = document.getElementById('axisBar-' + canvasId);
    
    // If no axis bar exists, dynamically create one
    if (!bar) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const card = canvas.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card');
        if (!card) return;
        
        // Determine current X/Y from registry or defaults
        const reg = chartRegistry[canvasId];
        const meta = reg?.meta || {};
        const xCol = meta.labelCol || (excelColumns.length > 0 ? excelColumns[0] : '');
        const yCol = meta.valueCol || null;
        const agg = meta.agg || 'count';
        
        // Insert axis bar before canvas
        const axisHtml = buildChartAxisBar(canvasId, xCol, yCol, agg);
        canvas.insertAdjacentHTML('beforebegin', axisHtml);
        bar = document.getElementById('axisBar-' + canvasId);
        if (!bar) return;
    }
    
    const isVisible = bar.style.display !== 'none';
    bar.style.display = isVisible ? 'none' : 'flex';
    const card = document.getElementById(canvasId)?.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card');
    if (card) {
        const btn = card.querySelector('[title="Axes"]');
        if (btn) btn.classList.toggle('active', !isVisible);
    }
}

function switchChartType(canvasId, newType) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;

    const chart = reg.chart;
    const isPieType = ['doughnut', 'pie', 'polarArea'].includes(newType);
    const wasPieType = ['doughnut', 'pie', 'polarArea'].includes(chart.config.type);
    const isRadarType = newType === 'radar';

    // Destroy and recreate for clean type switch
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    // Save current data
    const savedLabels = [...(chart.data.labels || [])];
    const savedDatasets = chart.data.datasets.map(ds => {
        const clone = {};
        Object.keys(ds).forEach(k => {
            if (!k.startsWith('_') && k !== '$context') {
                clone[k] = Array.isArray(ds[k]) ? [...ds[k]] : ds[k];
            }
        });
        return clone;
    });

    chart.destroy();

    // Adjust dataset properties based on target type
    savedDatasets.forEach(ds => {
        if (isPieType) {
            ds.backgroundColor = Array.isArray(ds.data) ? getColors(ds.data.length).map(c => c + 'cc') : ds.backgroundColor;
            ds.borderColor = '#1e2230';
            ds.borderWidth = 2;
            delete ds.fill;
            delete ds.tension;
            delete ds.pointRadius;
        } else if (newType === 'line') {
            ds.fill = false;
            ds.tension = 0.3;
            ds.pointRadius = 3;
            ds.borderWidth = 2;
            if (Array.isArray(ds.backgroundColor) && ds.backgroundColor.length > 1) {
                ds.borderColor = ds.backgroundColor[0]?.replace(/cc$/, '') || '#3b82f6';
                ds.backgroundColor = ds.borderColor + '20';
            }
        } else if (newType === 'bar') {
            ds.borderWidth = 1;
            ds.borderRadius = 4;
            delete ds.tension;
            delete ds.pointRadius;
            delete ds.fill;
        } else if (isRadarType) {
            const color = Array.isArray(ds.borderColor) ? ds.borderColor[0] : (ds.borderColor || '#f59e0b');
            ds.backgroundColor = color + '33';
            ds.borderColor = color;
            ds.borderWidth = 2;
            ds.pointBackgroundColor = color;
            delete ds.fill;
            delete ds.tension;
            delete ds.barPercentage;
            delete ds.categoryPercentage;
        }
    });

    // Build new options
    let scales = {};
    if (isPieType) {
        scales = {};
    } else if (isRadarType) {
        scales = { r: { ticks: { color: '#9ca3b8', backdropColor: 'transparent' }, grid: { color: 'rgba(255,255,255,0.08)' }, pointLabels: { color: '#9ca3b8', font: { size: 11 } } } };
    } else {
        scales = {
            x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
        };
    }

    const newChart = new Chart(canvas.getContext('2d'), {
        type: newType,
        data: { labels: savedLabels, datasets: savedDatasets },
        options: {
            responsive: true,
            plugins: {
                legend: { display: isPieType || isRadarType, position: isPieType ? 'bottom' : 'top', labels: { color: '#9ca3b8', padding: 8, font: { size: 10 } } },
            },
            scales
        }
    });

    // Update registry
    reg.chart = newChart;

    // Update active state
    const toolbar = canvas.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card, .chart-card-wrap');
    if (toolbar) {
        toolbar.querySelectorAll('.chart-tool-btn').forEach(b => {
            const onclick = b.getAttribute('onclick') || '';
            if (onclick.includes('switchChartType')) {
                b.classList.toggle('active', onclick.includes(`'${newType}'`));
            }
        });
    }
}

function toggleChartLabels(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;
    const chart = reg.chart;
    const show = !chart.options.plugins?.datalabels?.display;
    if (!chart.options.plugins) chart.options.plugins = {};
    // Use built-in tooltip enhancement as datalabels plugin may not be loaded
    chart.data.datasets.forEach(ds => {
        if (show) {
            ds._origPointRadius = ds.pointRadius;
            ds.pointRadius = ds.pointRadius ? ds.pointRadius + 2 : 4;
        } else if (ds._origPointRadius !== undefined) {
            ds.pointRadius = ds._origPointRadius;
        }
    });
    // Toggle persistent tooltip mode
    if (show) {
        chart.options.plugins.tooltip = { ...chart.options.plugins.tooltip, enabled: true, mode: 'index', intersect: false };
    } else {
        chart.options.plugins.tooltip = { ...chart.options.plugins.tooltip, mode: 'nearest', intersect: true };
    }
    chart.update();
    
    const btn = document.getElementById(canvasId)?.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card, .chart-card-wrap')?.querySelector('[title="Labels"]');
    if (btn) btn.classList.toggle('active', show);
}

function togglePaletteMenu(canvasId, btn) {
    const existing = btn.parentElement.querySelector('.chart-palette-menu');
    if (existing) { existing.remove(); return; }

    // Close all other palette menus
    document.querySelectorAll('.chart-palette-menu').forEach(m => m.remove());

    const menu = document.createElement('div');
    menu.className = 'chart-palette-menu show';
    menu.innerHTML = Object.entries(CHART_PALETTES).map(([name, colors]) => `
        <div class="chart-palette-option" onclick="applyChartPalette('${canvasId}','${name}'); this.closest('.chart-palette-menu').remove();">
            <div class="palette-dots">${colors.slice(0, 5).map(c => `<span style="background:${c}"></span>`).join('')}</div>
            <span>${name.charAt(0).toUpperCase() + name.slice(1)}</span>
        </div>
    `).join('');
    btn.style.position = 'relative';
    btn.appendChild(menu);

    setTimeout(() => {
        const handler = (e) => { if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener('click', handler); } };
        document.addEventListener('click', handler);
    }, 10);
}

function applyChartPalette(canvasId, paletteName) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;
    const palette = CHART_PALETTES[paletteName] || CHART_PALETTES.default;
    const chart = reg.chart;

    chart.data.datasets.forEach((ds, di) => {
        const isPie = ['doughnut', 'pie', 'polarArea'].includes(chart.config.type);
        if (isPie) {
            ds.backgroundColor = ds.data.map((_, i) => palette[i % palette.length] + 'cc');
        } else {
            const color = palette[di % palette.length];
            ds.backgroundColor = color + '99';
            ds.borderColor = color;
        }
    });
    chart.update();
}

function downloadChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = `chart-${canvasId}.png`;
    link.href = canvas.toDataURL('image/png', 1.0);
    link.click();
    showToast('Chart downloaded as PNG', 'success');
}

function fullscreenChart(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;
    const origCanvas = document.getElementById(canvasId);
    if (!origCanvas) return;

    const chart = reg.chart;
    const chartType = chart.config.type;

    // Safe deep clone of chart data (avoids circular refs / functions)
    function cloneDatasets(datasets) {
        return datasets.map(ds => {
            const clone = {};
            Object.keys(ds).forEach(key => {
                if (key.startsWith('_') || key === '$context') return;
                const val = ds[key];
                if (Array.isArray(val)) clone[key] = val.map(v => typeof v === 'object' && v !== null ? { ...v } : v);
                else if (typeof val !== 'function') clone[key] = val;
            });
            return clone;
        });
    }

    const clonedData = {
        labels: [...(chart.data.labels || [])],
        datasets: cloneDatasets(chart.data.datasets)
    };

    // Reconstruct options for the target type
    const isPie = ['doughnut', 'pie', 'polarArea'].includes(chartType);
    const isRadar = chartType === 'radar';
    let scales = {};
    if (isRadar) {
        scales = { r: { ticks: { color: '#9ca3b8', backdropColor: 'transparent' }, grid: { color: 'rgba(255,255,255,0.08)' }, pointLabels: { color: '#9ca3b8', font: { size: 12 } } } };
    } else if (!isPie) {
        scales = {
            x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            y: { ticks: { color: '#9ca3b8', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
        };
        // Preserve indexAxis if horizontal
        if (chart.options?.indexAxis === 'y') scales.x.beginAtZero = true;
    }

    const fsConfig = {
        type: chartType,
        data: clonedData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: chart.options?.indexAxis || 'x',
            plugins: {
                legend: { display: isPie || isRadar || clonedData.datasets.length > 1, position: isPie ? 'right' : 'top', labels: { color: '#9ca3b8', padding: 10, font: { size: 12 } } },
            },
            scales
        }
    };

    const overlay = document.createElement('div');
    overlay.className = 'chart-fullscreen-overlay';
    overlay.innerHTML = `
        <div class="chart-fullscreen-card">
            <button class="chart-fullscreen-close" onclick="this.closest('.chart-fullscreen-overlay').remove()">
                <i class="fas fa-times"></i>
            </button>
            <h4 style="font-size:18px;font-weight:700;color:var(--text-secondary);margin-bottom:16px;padding-right:40px;">${reg.title || 'Chart'}</h4>
            <div style="position:relative;height:65vh;">
                <canvas id="fullscreen-${canvasId}"></canvas>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('visible'));
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    // Create chart in fullscreen canvas
    setTimeout(() => {
        const fsCanvas = document.getElementById(`fullscreen-${canvasId}`);
        if (!fsCanvas) return;
        new Chart(fsCanvas.getContext('2d'), fsConfig);
    }, 80);

    // ESC to close
    const escHandler = (e) => { if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
}

function registerChart(canvasId, chart, title, meta) {
    chartRegistry[canvasId] = { chart, title, meta: meta || {}, filters: {}, limit: 25 };
}

function changeChartLimit(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg) return;
    const sel = document.getElementById(`chartLimit-${canvasId}`);
    if (!sel) return;
    reg.limit = sel.value === 'all' ? 'all' : parseInt(sel.value);
    rebuildChartWithFilters(canvasId);
}

function getChartLimit(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg) return 25;
    return reg.limit || 25;
}

// ===== Chart Filter System =====
function buildChartFilterBar(canvasId) {
    const allCols = excelColumns || [];
    const colOptions = allCols.map(c =>
        `<option value="${c}">${c.length > 25 ? c.substring(0,22)+'...' : c}</option>`
    ).join('');
    return `<div class="chart-filter-bar" id="filterBar-${canvasId}" style="display:none;">
        <div class="filter-bar-row">
            <div class="filter-col-select">
                <span class="axis-label"><i class="fas fa-filter"></i> Filter By</span>
                <select id="filterCol-${canvasId}" onchange="loadFilterValues('${canvasId}')">
                    <option value="">Select Column</option>
                    ${colOptions}
                </select>
            </div>
            <div class="filter-values-wrap" id="filterValuesWrap-${canvasId}"></div>
            <div class="filter-actions">
                <button class="filter-apply-btn" onclick="applyChartFilter('${canvasId}')" title="Apply Filter">
                    <i class="fas fa-check"></i> Apply
                </button>
                <button class="filter-clear-btn" onclick="clearChartFilter('${canvasId}')" title="Clear Filters">
                    <i class="fas fa-times"></i> Clear
                </button>
            </div>
        </div>
        <div class="active-filters" id="activeFilters-${canvasId}"></div>
    </div>`;
}

function toggleChartFilter(canvasId) {
    let bar = document.getElementById('filterBar-' + canvasId);
    if (!bar) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const filterHtml = buildChartFilterBar(canvasId);
        canvas.insertAdjacentHTML('beforebegin', filterHtml);
        bar = document.getElementById('filterBar-' + canvasId);
        if (!bar) return;
    }
    const isVisible = bar.style.display !== 'none';
    bar.style.display = isVisible ? 'none' : 'block';
    const card = document.getElementById(canvasId)?.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card');
    if (card) {
        const btn = card.querySelector('[title="Filter"]');
        if (btn) btn.classList.toggle('active', !isVisible);
    }
}

function loadFilterValues(canvasId) {
    const col = document.getElementById(`filterCol-${canvasId}`)?.value;
    const wrap = document.getElementById(`filterValuesWrap-${canvasId}`);
    if (!wrap) return;
    if (!col) { wrap.innerHTML = ''; return; }

    // Get unique values for the column
    const freq = {};
    excelData.forEach(r => {
        const v = r[col];
        if (v === null || v === undefined || v === '') return;
        const s = String(v).trim();
        freq[s] = (freq[s] || 0) + 1;
    });
    const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) { wrap.innerHTML = '<span class="filter-no-data">No values found</span>'; return; }

    // Check existing filters
    const reg = chartRegistry[canvasId];
    const existingFilters = reg?.filters?.[col] || [];

    const searchId = `filterSearch-${canvasId}`;
    let html = `<div class="filter-values-container">`;
    html += `<input type="text" class="filter-value-search" id="${searchId}" placeholder="Search values..." oninput="searchFilterValues('${canvasId}')">` ;
    html += `<div class="filter-select-all">`;
    html += `<label><input type="checkbox" id="filterSelectAll-${canvasId}" onchange="toggleAllFilterValues('${canvasId}')" checked> Select All (${sorted.length})</label>`;
    html += `</div>`;
    html += `<div class="filter-values-list" id="filterValuesList-${canvasId}">`;
    sorted.forEach(([val, count]) => {
        const checked = existingFilters.length === 0 || existingFilters.includes(val) ? 'checked' : '';
        const escaped = val.replace(/'/g, "\\'").replace(/"/g, '&quot;');
        html += `<label class="filter-value-item" data-value="${escaped}">
            <input type="checkbox" value="${escaped}" ${checked}>
            <span class="filter-val-text">${val.length > 30 ? val.substring(0,27)+'...' : val}</span>
            <span class="filter-val-count">${count}</span>
        </label>`;
    });
    html += `</div></div>`;
    wrap.innerHTML = html;
}

function searchFilterValues(canvasId) {
    const search = document.getElementById(`filterSearch-${canvasId}`)?.value?.toLowerCase() || '';
    const list = document.getElementById(`filterValuesList-${canvasId}`);
    if (!list) return;
    list.querySelectorAll('.filter-value-item').forEach(item => {
        const val = item.dataset.value?.toLowerCase() || '';
        item.style.display = val.includes(search) ? '' : 'none';
    });
}

function toggleAllFilterValues(canvasId) {
    const selectAll = document.getElementById(`filterSelectAll-${canvasId}`);
    const list = document.getElementById(`filterValuesList-${canvasId}`);
    if (!list || !selectAll) return;
    const checked = selectAll.checked;
    list.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        if (cb.closest('.filter-value-item').style.display !== 'none') cb.checked = checked;
    });
}

function applyChartFilter(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg) return;

    const col = document.getElementById(`filterCol-${canvasId}`)?.value;
    if (!col) return;

    const list = document.getElementById(`filterValuesList-${canvasId}`);
    if (!list) return;

    const selectedValues = [];
    list.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
        selectedValues.push(cb.value);
    });

    const allValues = [];
    list.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        allValues.push(cb.value);
    });

    // If all selected, remove filter for this column; else store selected values
    if (selectedValues.length === allValues.length || selectedValues.length === 0) {
        delete reg.filters[col];
    } else {
        reg.filters[col] = selectedValues;
    }

    // Show active filters
    renderActiveFilters(canvasId);

    // Re-render chart with filters applied
    rebuildChartWithFilters(canvasId);
}

function clearChartFilter(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg) return;
    reg.filters = {};
    renderActiveFilters(canvasId);

    // Reset checkboxes
    const list = document.getElementById(`filterValuesList-${canvasId}`);
    if (list) list.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
    const selectAll = document.getElementById(`filterSelectAll-${canvasId}`);
    if (selectAll) selectAll.checked = true;

    rebuildChartWithFilters(canvasId);
}

function renderActiveFilters(canvasId) {
    const reg = chartRegistry[canvasId];
    const container = document.getElementById(`activeFilters-${canvasId}`);
    if (!container || !reg) { if (container) container.innerHTML = ''; return; }

    const entries = Object.entries(reg.filters || {});
    if (entries.length === 0) { container.innerHTML = ''; return; }

    container.innerHTML = entries.map(([col, vals]) =>
        `<span class="active-filter-chip">
            <i class="fas fa-filter"></i> ${col}: ${vals.length <= 2 ? vals.join(', ') : vals.length + ' selected'}
            <button onclick="removeChartFilterCol('${canvasId}','${col.replace(/'/g, "\\'")}')" title="Remove">×</button>
        </span>`
    ).join('');
}

function removeChartFilterCol(canvasId, col) {
    const reg = chartRegistry[canvasId];
    if (!reg) return;
    delete reg.filters[col];
    renderActiveFilters(canvasId);

    // If the current filter dropdown is showing this column, reset checkboxes
    const filterCol = document.getElementById(`filterCol-${canvasId}`);
    if (filterCol?.value === col) loadFilterValues(canvasId);

    rebuildChartWithFilters(canvasId);
}

function rebuildChartWithFilters(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;

    const meta = reg.meta || {};
    const xCol = document.getElementById(`axisX-${canvasId}`)?.value || meta.labelCol;
    const yCol = document.getElementById(`axisY-${canvasId}`)?.value || meta.valueCol;
    const agg = document.getElementById(`axisAgg-${canvasId}`)?.value || meta.agg || 'count';
    if (!xCol) return;

    const useCount = (agg === 'count' || yCol === '_count');
    const filters = reg.filters || {};

    // Filter excelData based on active filters
    let filteredData = excelData;
    const filterEntries = Object.entries(filters);
    if (filterEntries.length > 0) {
        filteredData = excelData.filter(row => {
            return filterEntries.every(([col, vals]) => {
                const v = row[col];
                if (v === null || v === undefined || v === '') return false;
                return vals.includes(String(v).trim());
            });
        });
    }

    // Re-aggregate
    const freq = {};
    filteredData.forEach(row => {
        const label = String(row[xCol] ?? '').trim();
        if (!label) return;
        if (useCount) {
            freq[label] = (freq[label] || 0) + 1;
        } else {
            const val = parseFloat(row[yCol]);
            if (isNaN(val)) return;
            if (!freq[label]) freq[label] = { sum: 0, count: 0 };
            freq[label].sum += val;
            freq[label].count++;
        }
    });

    let entries;
    if (useCount) {
        entries = Object.entries(freq).sort((a, b) => b[1] - a[1]);
    } else {
        entries = Object.entries(freq).map(([k, v]) => {
            let aggVal = agg === 'average' ? v.sum / v.count : v.sum;
            return [k, Math.round(aggVal * 100) / 100];
        }).sort((a, b) => b[1] - a[1]);
    }

    const limit = getChartLimit(canvasId);
    if (limit !== 'all') entries = entries.slice(0, limit);
    if (entries.length === 0) {
        // No data after filtering — show empty state
        const chart = reg.chart;
        chart.data.labels = ['No data'];
        chart.data.datasets[0].data = [0];
        chart.update();
        return;
    }

    const labels = entries.map(e => e[0].length > 25 ? e[0].substring(0, 22) + '...' : e[0]);
    const values = entries.map(e => typeof e[1] === 'object' ? (e[1].count || e[1].sum) : e[1]);

    const chart = reg.chart;
    const chartType = chart.config.type;
    const isPie = ['doughnut', 'pie', 'polarArea'].includes(chartType);

    if (chart.data.datasets.length > 1) chart.data.datasets.length = 1;

    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.data.datasets[0].label = useCount ? 'Count' : `${agg} of ${yCol}`;
    chart.data.datasets[0].backgroundColor = isPie ? getColors(values.length).map(c => c + 'cc') : getColors(values.length).map(c => c + '99');
    chart.data.datasets[0].borderColor = isPie ? '#1e2230' : getColors(values.length);

    chart.update();

    // Update title with filter indicator
    const card = document.getElementById(canvasId)?.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card');
    if (card) {
        const h4 = card.querySelector('h4');
        const yLabel = useCount ? 'Count' : `${agg} of ${yCol}`;
        const filterCount = Object.keys(filters).length;
        const filterBadge = filterCount > 0 ? ` <span class="filter-badge">${filterCount} filter${filterCount > 1 ? 's' : ''}</span>` : '';
        if (h4) h4.innerHTML = `${yLabel} by ${xCol}${filterBadge}`;
    }
}

function changeChartAxis(canvasId) {
    const reg = chartRegistry[canvasId];
    if (!reg || !reg.chart) return;

    const xCol = document.getElementById(`axisX-${canvasId}`)?.value;
    const yCol = document.getElementById(`axisY-${canvasId}`)?.value;
    const agg = document.getElementById(`axisAgg-${canvasId}`)?.value || 'count';
    if (!xCol) return;

    const useCount = (agg === 'count' || yCol === '_count');

    // Apply active filters
    const filters = reg.filters || {};
    const filterEntries = Object.entries(filters);
    let sourceData = excelData;
    if (filterEntries.length > 0) {
        sourceData = excelData.filter(row => {
            return filterEntries.every(([col, vals]) => {
                const v = row[col];
                if (v === null || v === undefined || v === '') return false;
                return vals.includes(String(v).trim());
            });
        });
    }

    // Re-aggregate data
    const freq = {};
    sourceData.forEach(row => {
        const label = String(row[xCol] ?? '').trim();
        if (!label) return;
        if (useCount) {
            freq[label] = (freq[label] || 0) + 1;
        } else {
            const val = parseFloat(row[yCol]);
            if (isNaN(val)) return;
            if (!freq[label]) freq[label] = { sum: 0, count: 0 };
            freq[label].sum += val;
            freq[label].count++;
        }
    });

    let entries;
    if (useCount) {
        entries = Object.entries(freq).sort((a, b) => b[1] - a[1]);
    } else {
        entries = Object.entries(freq).map(([k, v]) => {
            let aggVal = agg === 'average' ? v.sum / v.count : v.sum;
            return [k, Math.round(aggVal * 100) / 100];
        }).sort((a, b) => b[1] - a[1]);
    }

    const limit = getChartLimit(canvasId);
    if (limit !== 'all') entries = entries.slice(0, limit);
    if (entries.length === 0) return;

    const labels = entries.map(e => e[0].length > 25 ? e[0].substring(0, 22) + '...' : e[0]);
    const values = entries.map(e => typeof e[1] === 'object' ? (e[1].count || e[1].sum) : e[1]);

    const chart = reg.chart;
    const chartType = chart.config.type;
    const isPie = ['doughnut', 'pie', 'polarArea'].includes(chartType);

    // Keep only the first dataset when changing axes (remove overlays like moving avg, normal curve)
    if (chart.data.datasets.length > 1) {
        chart.data.datasets.length = 1;
    }

    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.data.datasets[0].label = useCount ? 'Count' : `${agg} of ${yCol}`;
    chart.data.datasets[0].backgroundColor = isPie ? getColors(values.length).map(c => c + 'cc') : getColors(values.length).map(c => c + '99');
    chart.data.datasets[0].borderColor = isPie ? '#1e2230' : getColors(values.length);
    
    // Fix scales if switching from radar or missing scales
    if (!isPie && !['radar'].includes(chartType) && (!chart.options.scales || !chart.options.scales.x)) {
        chart.options.scales = {
            x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
            y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
        };
    }
    
    chart.update();

    // Update card title
    const card = document.getElementById(canvasId)?.closest('.excel-chart-card, .dist-chart-card, .trend-chart-card');
    if (card) {
        const h4 = card.querySelector('h4');
        const yLabel = useCount ? 'Count' : `${agg} of ${yCol}`;
        if (h4) h4.textContent = `${yLabel} by ${xCol}`;
        reg.title = h4?.textContent || reg.title;
    }
    
    // Update meta
    reg.meta = { labelCol: xCol, valueCol: useCount ? null : yCol, agg };
}

// ===== Show All Values Modal =====
function showAllValues(col) {
    const freq = {};
    let total = 0;
    excelData.forEach(r => {
        const v = r[col];
        if (v === null || v === undefined || v === '') return;
        const s = String(v).trim();
        freq[s] = (freq[s] || 0) + 1;
        total++;
    });
    const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) return;
    const maxCount = sorted[0][1];

    const overlay = document.createElement('div');
    overlay.className = 'chart-fullscreen-overlay';
    overlay.innerHTML = `
        <div class="all-values-modal">
            <div class="all-values-header">
                <div>
                    <h3><i class="fas fa-list-ol"></i> ${col}</h3>
                    <p>${sorted.length} unique values &bull; ${total.toLocaleString()} total records</p>
                </div>
                <div class="all-values-actions">
                    <input type="text" class="all-values-search" placeholder="Search values..." oninput="filterAllValues(this)">
                    <button class="chart-fullscreen-close" onclick="this.closest('.chart-fullscreen-overlay').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            <div class="all-values-table-wrap">
                <table class="all-values-table">
                    <thead>
                        <tr>
                            <th style="width:40px">#</th>
                            <th>Value</th>
                            <th style="width:200px">Distribution</th>
                            <th style="width:90px">Count</th>
                            <th style="width:60px">%</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${sorted.map(([val, cnt], i) => {
                            const pct = ((cnt / total) * 100).toFixed(1);
                            const barW = (cnt / maxCount) * 100;
                            return `<tr class="all-values-row">
                                <td class="av-rank">${i + 1}</td>
                                <td class="av-val" title="${val}">${val}</td>
                                <td><div class="av-bar-wrap"><div class="av-bar" style="width:${barW}%"></div></div></td>
                                <td class="av-count">${cnt.toLocaleString()}</td>
                                <td class="av-pct">${pct}%</td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('visible'));
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    const escHandler = (e) => { if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
}

function filterAllValues(input) {
    const term = input.value.toLowerCase();
    const rows = input.closest('.all-values-modal').querySelectorAll('.all-values-row');
    rows.forEach(row => {
        const val = row.querySelector('.av-val')?.textContent.toLowerCase() || '';
        row.style.display = val.includes(term) ? '' : 'none';
    });
}

// ===== APF Field Detection =====
const APF_FIELD_MAP = {
    school: /school|vidyalaya|shala/i,
    block: /block|taluk/i,
    district: /district|jilla/i,
    subject: /subject|vishay/i,
    class: /class|grade|standard/i,
    teacher: /teacher|shikshak/i,
    attendance: /attend|upasthiti/i,
    date: /date|tarikh|dinank/i,
    status: /status|sthiti/i,
    practice: /practice|abhyas/i,
    observation: /observation|avlokan/i,
    score: /score|ank|marks/i,
    rating: /rating|shreni/i
};

function detectAPFFields(columns) {
    const detected = {};
    columns.forEach(col => {
        const colLower = col.toLowerCase();
        for (const [field, regex] of Object.entries(APF_FIELD_MAP)) {
            if (regex.test(colLower)) {
                if (!detected[field]) detected[field] = [];
                detected[field].push(col);
            }
        }
    });
    return detected;
}

// ===== File Upload =====
function handleExcelUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    processFile(file);
}

// Drag and drop
document.addEventListener('DOMContentLoaded', () => {
    const zone = document.getElementById('excelUploadZone');
    if (!zone) return;

    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) processFile(file);
    });
});

function processFile(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        try {
            excelWorkbook = XLSX.read(e.target.result, { type: 'array', cellDates: true });
            const sheetNames = excelWorkbook.SheetNames;
            const fileSize = (file.size / 1024).toFixed(1);

            document.getElementById('excelUploadZone').style.display = 'none';
            document.getElementById('excelFileName').textContent = file.name;
            document.getElementById('excelFileInfo').textContent = `${sheetNames.length} sheet${sheetNames.length > 1 ? 's' : ''} • ${fileSize} KB`;
            document.getElementById('excelSheetSelector').style.display = 'flex';
            document.getElementById('clearExcelBtn').style.display = '';
            document.getElementById('generateReportBtn').style.display = '';

            // Sheet tabs
            const tabsEl = document.getElementById('excelSheetTabs');
            tabsEl.innerHTML = sheetNames.map((name, i) =>
                `<button class="sheet-tab ${i === 0 ? 'active' : ''}" onclick="selectSheet('${name}', this)">${name}</button>`
            ).join('');

            selectSheet(sheetNames[0]);
        } catch (err) {
            showToast('Error reading file: ' + err.message, 'error');
        }
    };
    reader.readAsArrayBuffer(file);
}

function selectSheet(name, btn) {
    if (btn) {
        document.querySelectorAll('.sheet-tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
    }

    const sheet = excelWorkbook.Sheets[name];
    const json = XLSX.utils.sheet_to_json(sheet, { defval: '' });
    if (json.length === 0) {
        showToast('This sheet is empty', 'error');
        return;
    }

    excelData = json;
    excelColumns = Object.keys(json[0]);
    excelColumnTypes = analyzeColumnTypes(json, excelColumns);

    // Reset filters for new sheet
    tableFilters = {};
    tableSearchTerm = '';
    tablePage = 0;

    document.getElementById('excelDashboard').style.display = 'block';

    // Populate builder dropdowns
    populateBuilderDropdowns();

    // Run all analyses
    renderSummaryBar();
    renderAutoInsights();
    renderAutoCharts();
    renderDataQuality();
    renderDataTable();
    renderStatistics();
    renderCorrelationMatrix();
    renderOutlierDetection();
    renderDistributionAnalysis();
    renderTrendAnalysis();

    // Show auto tab
    switchAnalysisTab('auto');
}

function clearExcelData() {
    excelWorkbook = null;
    excelData = [];
    excelColumns = [];
    activeCharts.forEach(c => c.destroy());
    activeCharts = [];
    document.getElementById('excelDashboard').style.display = 'none';
    document.getElementById('excelSheetSelector').style.display = 'none';
    document.getElementById('clearExcelBtn').style.display = 'none';
    document.getElementById('generateReportBtn').style.display = 'none';
    document.getElementById('excelUploadZone').style.display = '';
    document.getElementById('excelFileInput').value = '';
    showToast('Data cleared', 'info');
}

// ===== Tab Switching =====
function switchAnalysisTab(tab) {
    document.querySelectorAll('.excel-tab').forEach(t => t.classList.remove('active'));
    const btn = document.querySelector(`.excel-tab[data-tab="${tab}"]`);
    if (btn) btn.classList.add('active');
    document.querySelectorAll('.analysis-panel').forEach(p => p.classList.remove('active'));
    document.getElementById(`panel-${tab}`).classList.add('active');
}

// ===== Column Type Analysis =====
function analyzeColumnTypes(data, columns) {
    const types = {};
    const sampleSize = Math.min(data.length, 100);

    columns.forEach(col => {
        let numCount = 0, dateCount = 0, emptyCount = 0;

        for (let i = 0; i < sampleSize; i++) {
            const val = data[i][col];
            if (val === null || val === undefined || val === '') { emptyCount++; continue; }
            if (val instanceof Date) { dateCount++; continue; }
            if (typeof val === 'number' || (!isNaN(parseFloat(val)) && isFinite(val))) { numCount++; continue; }
        }

        const filledCount = sampleSize - emptyCount;
        if (filledCount === 0) { types[col] = 'empty'; return; }

        if (dateCount / filledCount > 0.6) types[col] = 'date';
        else if (numCount / filledCount > 0.6) types[col] = 'numeric';
        else {
            const uniqueVals = new Set(data.slice(0, sampleSize).map(r => String(r[col]).trim()).filter(Boolean));
            types[col] = uniqueVals.size <= Math.min(30, filledCount * 0.5) ? 'categorical' : 'text';
        }
    });
    return types;
}

function getNumericColumns() { return excelColumns.filter(c => excelColumnTypes[c] === 'numeric'); }
function getCategoricalColumns() { return excelColumns.filter(c => excelColumnTypes[c] === 'categorical'); }
function getDateColumns() { return excelColumns.filter(c => excelColumnTypes[c] === 'date'); }

// ===== Populate Builder Dropdowns =====
function populateBuilderDropdowns() {
    const allOptions = excelColumns.map(c => `<option value="${c}">${c} (${excelColumnTypes[c]})</option>`).join('');
    const catOptions = getCategoricalColumns().map(c => `<option value="${c}">${c}</option>`).join('');
    const numOptions = getNumericColumns().map(c => `<option value="${c}">${c}</option>`).join('');

    // Custom chart builder
    document.getElementById('customChartX').innerHTML = allOptions;
    document.getElementById('customChartY').innerHTML = allOptions;
    document.getElementById('customChartGroup').innerHTML = `<option value="">— None —</option>` + allOptions;

    // Pivot
    document.getElementById('pivotRow').innerHTML = allOptions;
    document.getElementById('pivotValue').innerHTML = allOptions;
    document.getElementById('pivotCol').innerHTML = `<option value="">— None —</option>` + allOptions;

    // Auto-select sensible defaults
    const cats = getCategoricalColumns();
    const nums = getNumericColumns();
    if (cats.length > 0) document.getElementById('customChartX').value = cats[0];
    if (nums.length > 0) document.getElementById('customChartY').value = nums[0];
    if (cats.length > 0) document.getElementById('pivotRow').value = cats[0];
    if (nums.length > 0) document.getElementById('pivotValue').value = nums[0];

    // Populate analysis tab controls
    populateTabControls();
}

function populateTabControls() {
    // Stats column filter
    const statsFilter = document.getElementById('statsColumnFilter');
    if (statsFilter) {
        statsFilter.innerHTML = excelColumns.map(c => `<option value="${c}" selected>${c}</option>`).join('');
        // Update the multi-select button label
        const btn = document.querySelector('[onclick*="statsColumnFilter"].ctrl-multi-btn');
        if (btn) updateCtrlMultiLabel(btn, statsFilter);
    }
}

// ===== Export Tab Data to CSV =====
function exportTabToCSV(tab) {
    let csvContent = '';
    const nums = getNumericColumns();

    if (tab === 'stats') {
        csvContent = 'Column,Type,Count,Missing,Mean,Median,Mode,StdDev,Min,Max,P25,P50,P75,Skewness,Kurtosis\n';
        nums.forEach(col => {
            const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
            if (vals.length === 0) return;
            const sorted = [...vals].sort((a, b) => a - b);
            const m = vals.reduce((a, b) => a + b, 0) / vals.length;
            const md = sorted[Math.floor(sorted.length / 2)];
            const sd = Math.sqrt(vals.reduce((s, v) => s + (v - m) ** 2, 0) / vals.length);
            const p = (arr, pct) => { const s = [...arr].sort((a, b) => a - b); const i = (pct / 100) * (s.length - 1); return s[Math.floor(i)]; };
            csvContent += `"${col}",numeric,${vals.length},${excelData.length - vals.length},${m.toFixed(2)},${md.toFixed(2)},,${sd.toFixed(2)},${sorted[0]},${sorted[sorted.length-1]},${p(vals,25).toFixed(2)},${p(vals,50).toFixed(2)},${p(vals,75).toFixed(2)},,\n`;
        });
    } else if (tab === 'correlation') {
        csvContent = 'Column A,Column B,Correlation\n';
        for (let i = 0; i < nums.length; i++) {
            for (let j = i + 1; j < nums.length; j++) {
                csvContent += `"${nums[i]}","${nums[j]}",${computeCorrelation(nums[i], nums[j]).toFixed(4)}\n`;
            }
        }
    } else if (tab === 'outliers') {
        csvContent = 'Column,IQR Outliers,Z-Score Outliers,Extreme Outliers,Total Values\n';
        nums.forEach(col => {
            const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
            if (vals.length < 4) return;
            const sorted = [...vals].sort((a, b) => a - b);
            const pct = (arr, p) => { const s = [...arr].sort((a, b) => a - b); const i = (p / 100) * (s.length - 1); return s[Math.floor(i)] + (s[Math.ceil(i)] - s[Math.floor(i)]) * (i - Math.floor(i)); };
            const q1 = pct(vals, 25), q3 = pct(vals, 75), iqr = q3 - q1;
            const mean = vals.reduce((a,b) => a + b, 0) / vals.length;
            const sd = Math.sqrt(vals.reduce((s,v) => s + (v - mean) ** 2, 0) / vals.length);
            const iqrO = vals.filter(v => v < q1 - 1.5 * iqr || v > q3 + 1.5 * iqr).length;
            const zO = sd > 0 ? vals.filter(v => Math.abs((v - mean) / sd) > 2.5).length : 0;
            const extO = vals.filter(v => v < q1 - 3 * iqr || v > q3 + 3 * iqr).length;
            csvContent += `"${col}",${iqrO},${zO},${extO},${vals.length}\n`;
        });
    }

    if (csvContent) {
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${tab}-analysis.csv`;
        a.click(); URL.revokeObjectURL(url);
        showToast(`${tab} analysis exported`, 'success');
    }
}

// ===== Summary Bar =====
function renderSummaryBar() {
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();
    const filled = excelData.reduce((sum, row) => {
        return sum + excelColumns.filter(c => row[c] !== null && row[c] !== undefined && row[c] !== '').length;
    }, 0);
    const completeness = ((filled / (excelData.length * excelColumns.length)) * 100).toFixed(1);

    const stats = [
        { icon: 'fa-table',        value: excelData.length.toLocaleString(), label: 'Rows',         color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
        { icon: 'fa-columns',      value: excelColumns.length,              label: 'Columns',      color: '#6366f1', bg: 'rgba(99,102,241,0.12)' },
        { icon: 'fa-hashtag',      value: nums.length,                      label: 'Numeric',      color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
        { icon: 'fa-font',         value: cats.length,                      label: 'Categorical',  color: '#ec4899', bg: 'rgba(236,72,153,0.12)' },
        { icon: 'fa-check-circle', value: completeness + '%',               label: 'Completeness', color: '#06b6d4', bg: 'rgba(6,182,212,0.12)' },
    ];

    document.getElementById('excelSummaryBar').innerHTML = stats.map(s =>
        `<div class="kpi-card" style="--kpi-color:${s.color};--kpi-bg:${s.bg}">
            <div class="kpi-icon"><i class="fas ${s.icon}"></i></div>
            <div class="kpi-body">
                <div class="kpi-value">${s.value}</div>
                <div class="kpi-label">${s.label}</div>
            </div>
        </div>`
    ).join('');
}

// ===== Auto Insights =====
function renderAutoInsights() {
    const insights = [];
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();
    const dates = getDateColumns();
    const apfFields = detectAPFFields(excelColumns);
    const fmt = v => v >= 100000 ? (v / 100000).toFixed(1) + ' L' : v >= 1000 ? (v / 1000).toFixed(1) + ' K' : typeof v === 'number' ? (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(1)) : v;

    // 1. Dataset overview
    const filled = excelData.reduce((s, row) => s + excelColumns.filter(c => row[c] !== null && row[c] !== undefined && row[c] !== '').length, 0);
    const completeness = ((filled / (excelData.length * excelColumns.length)) * 100).toFixed(1);
    insights.push({
        type: 'info', icon: 'fa-database', title: 'DATASET OVERVIEW',
        text: `${excelData.length.toLocaleString()} records × ${excelColumns.length} columns. Data completeness: ${completeness}%. Types: ${nums.length} numeric, ${cats.length} categorical, ${dates.length} date.`
    });

    // 2. Duplicate detection
    const rowKeys = excelData.map(r => excelColumns.map(c => String(r[c] ?? '')).join('|'));
    const uniqueRows = new Set(rowKeys).size;
    const dupes = excelData.length - uniqueRows;
    if (dupes > 0) {
        insights.push({
            type: 'warning', icon: 'fa-copy', title: 'DUPLICATE ROWS DETECTED',
            text: `${dupes.toLocaleString()} duplicate rows found (${((dupes / excelData.length) * 100).toFixed(1)}%). ${uniqueRows.toLocaleString()} unique records.`
        });
    } else {
        insights.push({
            type: 'success', icon: 'fa-check-double', title: 'NO DUPLICATES',
            text: `All ${excelData.length.toLocaleString()} rows are unique — clean dataset!`
        });
    }

    // 3. APF-specific insights (expanded)
    if (apfFields.school) {
        const col = apfFields.school[0];
        const schools = new Set(excelData.map(r => String(r[col]).trim()).filter(Boolean));
        const freq = {};
        excelData.forEach(r => { const v = String(r[col]).trim(); if (v) freq[v] = (freq[v] || 0) + 1; });
        const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
        const avgPerSchool = (excelData.length / schools.size).toFixed(1);
        insights.push({ type: 'apf', icon: 'fa-school', title: 'SCHOOLS COVERED', text: `${schools.size} unique schools. Avg ${avgPerSchool} records/school. Most data: "${sorted[0]?.[0]}" (${sorted[0]?.[1]} records)` });
    }
    if (apfFields.block) {
        const col = apfFields.block[0];
        const blocks = {};
        excelData.forEach(r => { const v = String(r[col]).trim(); if (v) blocks[v] = (blocks[v] || 0) + 1; });
        const sorted = Object.entries(blocks).sort((a, b) => b[1] - a[1]);
        insights.push({ type: 'apf', icon: 'fa-map-marker-alt', title: 'BLOCKS COVERED', text: `${sorted.length} blocks. Highest: "${sorted[0]?.[0]}" (${sorted[0]?.[1]}). Lowest: "${sorted[sorted.length-1]?.[0]}" (${sorted[sorted.length-1]?.[1]})` });
    }
    if (apfFields.district) {
        const col = apfFields.district[0];
        const districts = new Set(excelData.map(r => String(r[col]).trim()).filter(Boolean));
        insights.push({ type: 'apf', icon: 'fa-globe-asia', title: 'DISTRICTS', text: `${districts.size} district(s): ${[...districts].slice(0, 5).join(', ')}` });
    }
    if (apfFields.teacher) {
        const col = apfFields.teacher[0];
        const teachers = new Set(excelData.map(r => String(r[col]).trim()).filter(Boolean));
        insights.push({ type: 'apf', icon: 'fa-chalkboard-teacher', title: 'TEACHERS', text: `${teachers.size} unique teachers found in "${col}"` });
    }
    if (apfFields.subject) {
        const subjects = new Set(excelData.map(r => String(r[apfFields.subject[0]]).trim()).filter(Boolean));
        insights.push({ type: 'apf', icon: 'fa-book', title: 'SUBJECTS', text: `${subjects.size} subjects: ${[...subjects].slice(0, 6).join(', ')}${subjects.size > 6 ? '...' : ''}` });
    }
    if (apfFields.date) {
        const col = apfFields.date[0];
        const validDates = excelData.map(r => { let d = r[col]; if (!(d instanceof Date)) d = new Date(d); return d; }).filter(d => d instanceof Date && !isNaN(d)).sort((a, b) => a - b);
        if (validDates.length > 0) {
            const first = validDates[0], last = validDates[validDates.length - 1];
            const days = Math.ceil((last - first) / (1000 * 60 * 60 * 24));
            insights.push({ type: 'info', icon: 'fa-calendar-alt', title: 'DATE RANGE', text: `${first.toLocaleDateString('en-IN')} → ${last.toLocaleDateString('en-IN')} (${days} days span, ${validDates.length} dated records)` });
        }
    }

    // 4. Numeric statistics (enhanced)
    nums.forEach(col => {
        const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
        if (vals.length === 0) return;
        const min = Math.min(...vals), max = Math.max(...vals);
        const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
        const sorted = [...vals].sort((a, b) => a - b);
        const median = sorted[Math.floor(sorted.length / 2)];
        const sd = Math.sqrt(vals.reduce((s, v) => s + (v - avg) ** 2, 0) / vals.length);
        const cv = avg !== 0 ? ((sd / Math.abs(avg)) * 100).toFixed(1) : '∞';

        insights.push({
            type: 'stat', icon: 'fa-chart-bar', title: `${col} — STATISTICS`,
            text: `Min: ${fmt(min)} │ Max: ${fmt(max)} │ Avg: ${fmt(avg)} │ Median: ${fmt(median)} │ σ: ${fmt(sd)} │ CV: ${cv}%`
        });

        // Outliers
        const outliers = vals.filter(v => Math.abs(v - avg) > 2 * sd).length;
        if (outliers > 0 && sd > 0) {
            insights.push({
                type: 'warning', icon: 'fa-exclamation-triangle', title: `${col} — OUTLIERS`,
                text: `${outliers} values beyond 2σ (${((outliers / vals.length) * 100).toFixed(1)}%). Standard deviation: ${fmt(sd)}`
            });
        }

        // Distribution shape
        const n = vals.length;
        const skew = sd > 0 && n > 2 ? (n / ((n-1)*(n-2))) * vals.reduce((s, v) => s + ((v - avg)/sd)**3, 0) : 0;
        if (Math.abs(skew) > 1) {
            insights.push({
                type: 'info', icon: 'fa-wave-square', title: `${col} — SKEWED`,
                text: `Skewness: ${skew.toFixed(2)} → ${skew > 0 ? 'Right-skewed (tail toward higher values)' : 'Left-skewed (tail toward lower values)'}`
            });
        }

        // Zero or negative detection
        const zeros = vals.filter(v => v === 0).length;
        const negatives = vals.filter(v => v < 0).length;
        if (zeros > vals.length * 0.1) {
            insights.push({
                type: 'category', icon: 'fa-minus-circle', title: `${col} — ZERO VALUES`,
                text: `${zeros.toLocaleString()} zero values (${((zeros / vals.length) * 100).toFixed(1)}%)`
            });
        }
        if (negatives > 0) {
            insights.push({
                type: 'warning', icon: 'fa-minus', title: `${col} — NEGATIVE VALUES`,
                text: `${negatives.toLocaleString()} negative values found (min: ${fmt(min)})`
            });
        }
    });

    // 5. Categorical insights (enhanced)
    cats.forEach(col => {
        const freq = {};
        excelData.forEach(r => { const v = String(r[col]).trim(); if (v) freq[v] = (freq[v] || 0) + 1; });
        const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
        if (sorted.length === 0) return;

        const [topVal, topCount] = sorted[0];
        const pct = ((topCount / excelData.length) * 100).toFixed(0);
        insights.push({
            type: 'category', icon: 'fa-tag', title: `${col} — MOST COMMON`,
            text: `"${topVal}" appears ${topCount.toLocaleString()} times (${pct}%). ${sorted.length} unique values total.`
        });

        // Concentration / Diversity
        if (sorted.length > 1) {
            const top3Count = sorted.slice(0, 3).reduce((s, e) => s + e[1], 0);
            const top3Pct = ((top3Count / excelData.length) * 100).toFixed(0);
            if (top3Pct > 70) {
                insights.push({
                    type: 'info', icon: 'fa-compress-arrows-alt', title: `${col} — HIGH CONCENTRATION`,
                    text: `Top 3 values account for ${top3Pct}% of data: "${sorted.slice(0, 3).map(e => e[0]).join('", "')}"`
                });
            }
        }

        // Rare values (appearing only once)
        const singles = sorted.filter(([, c]) => c === 1).length;
        if (singles > sorted.length * 0.5 && sorted.length > 5) {
            insights.push({
                type: 'warning', icon: 'fa-snowflake', title: `${col} — MANY RARE VALUES`,
                text: `${singles} values appear only once (${((singles / sorted.length) * 100).toFixed(0)}% of unique values). Consider grouping.`
            });
        }

        // Cardinality warning
        const ratio = sorted.length / excelData.length;
        if (ratio > 0.9 && sorted.length > 20) {
            insights.push({
                type: 'warning', icon: 'fa-fingerprint', title: `${col} — HIGH CARDINALITY`,
                text: `${sorted.length.toLocaleString()} unique values in ${excelData.length.toLocaleString()} rows (${(ratio * 100).toFixed(0)}%). May be an ID column.`
            });
        }
    });

    // 6. Missing data patterns
    const missingCols = [];
    excelColumns.forEach(col => {
        const missing = excelData.filter(r => r[col] === null || r[col] === undefined || r[col] === '').length;
        const pct = (missing / excelData.length) * 100;
        if (pct > 0) missingCols.push({ col, missing, pct });
    });
    if (missingCols.length > 0) {
        const highMissing = missingCols.filter(m => m.pct > 10);
        if (highMissing.length > 0) {
            highMissing.forEach(m => {
                insights.push({
                    type: 'warning', icon: 'fa-exclamation-circle', title: `${m.col} — MISSING DATA`,
                    text: `${m.missing.toLocaleString()} missing values (${m.pct.toFixed(1)}%)`
                });
            });
        }
        const totalMissing = missingCols.reduce((s, m) => s + m.missing, 0);
        const totalCells = excelData.length * excelColumns.length;
        insights.push({
            type: 'info', icon: 'fa-th', title: 'MISSING DATA SUMMARY',
            text: `${totalMissing.toLocaleString()} missing cells across ${missingCols.length} columns (${((totalMissing / totalCells) * 100).toFixed(2)}% of all cells)`
        });
    } else {
        insights.push({
            type: 'success', icon: 'fa-check-circle', title: 'COMPLETE DATA',
            text: `No missing values in any column — perfectly complete dataset!`
        });
    }

    // 7. Correlations between numeric columns
    if (nums.length >= 2) {
        const corrPairs = [];
        for (let i = 0; i < Math.min(nums.length, 8); i++) {
            for (let j = i + 1; j < Math.min(nums.length, 8); j++) {
                const corr = computeCorrelation(nums[i], nums[j]);
                if (Math.abs(corr) > 0.5) corrPairs.push({ a: nums[i], b: nums[j], r: corr });
            }
        }
        corrPairs.sort((a, b) => Math.abs(b.r) - Math.abs(a.r));
        corrPairs.slice(0, 5).forEach(p => {
            insights.push({
                type: p.r > 0 ? 'success' : 'danger', icon: 'fa-project-diagram',
                title: `CORRELATION: r = ${p.r.toFixed(2)}`,
                text: `${p.a} ↔ ${p.b}: ${Math.abs(p.r) > 0.8 ? 'Strong' : 'Moderate'} ${p.r > 0 ? 'positive' : 'negative'} correlation`
            });
        });
    }

    // 8. Numeric range insights
    if (nums.length >= 2) {
        const ranges = nums.map(col => {
            const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
            if (vals.length === 0) return null;
            return { col, range: Math.max(...vals) - Math.min(...vals), avg: vals.reduce((a,b)=>a+b,0)/vals.length };
        }).filter(Boolean);
        const widest = ranges.sort((a, b) => b.range - a.range)[0];
        if (widest) {
            insights.push({
                type: 'stat', icon: 'fa-arrows-alt-h', title: 'WIDEST RANGE',
                text: `"${widest.col}" has the widest value range: ${fmt(widest.range)} (mean: ${fmt(widest.avg)})`
            });
        }
    }

    // 9. Cross-column insights (APF-specific)
    if (apfFields.school && apfFields.block) {
        const schoolBlock = {};
        excelData.forEach(r => {
            const s = String(r[apfFields.school[0]]).trim();
            const b = String(r[apfFields.block[0]]).trim();
            if (s && b) { if (!schoolBlock[b]) schoolBlock[b] = new Set(); schoolBlock[b].add(s); }
        });
        const blockSchoolCounts = Object.entries(schoolBlock).map(([b, s]) => ({ block: b, count: s.size })).sort((a, b) => b.count - a.count);
        if (blockSchoolCounts.length > 0) {
            insights.push({
                type: 'apf', icon: 'fa-sitemap', title: 'SCHOOL DISTRIBUTION',
                text: `${blockSchoolCounts[0].block}: ${blockSchoolCounts[0].count} schools • ${blockSchoolCounts[blockSchoolCounts.length-1].block}: ${blockSchoolCounts[blockSchoolCounts.length-1].count} schools`
            });
        }
    }

    // 10. Data type quality check
    const mixedTypeCols = excelColumns.filter(col => {
        const sample = excelData.slice(0, 100).map(r => r[col]).filter(v => v !== null && v !== undefined && v !== '');
        const numCount = sample.filter(v => typeof v === 'number' || (!isNaN(parseFloat(v)) && isFinite(v))).length;
        const ratio = numCount / (sample.length || 1);
        return ratio > 0.2 && ratio < 0.8;
    });
    if (mixedTypeCols.length > 0) {
        insights.push({
            type: 'danger', icon: 'fa-random', title: 'MIXED DATA TYPES',
            text: `${mixedTypeCols.length} column(s) have mixed numeric/text data: "${mixedTypeCols.slice(0, 3).join('", "')}". This may cause analysis issues.`
        });
    }

    const typeColors = { info: '#3b82f6', stat: '#10b981', warning: '#f59e0b', category: '#8b5cf6', apf: '#f97316', success: '#10b981', danger: '#ef4444' };
    const typeIcons = { info: 'fa-info-circle', stat: 'fa-chart-bar', warning: 'fa-exclamation-triangle', category: 'fa-tag', apf: 'fa-star', success: 'fa-check-circle', danger: 'fa-times-circle' };

    document.getElementById('excelInsightsPanel').innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
            <h3 style="display:flex;align-items:center;gap:8px;margin:0"><i class="fas fa-lightbulb" style="color:var(--accent)"></i> Auto-Generated Insights</h3>
            <span style="font-size:12px;color:var(--text-muted);background:var(--bg-primary);padding:4px 12px;border-radius:12px">${insights.length} insights found</span>
        </div>
        <div class="insights-grid">${insights.map(ins =>
        `<div class="insight-card" style="border-left:3px solid ${typeColors[ins.type] || '#6b7280'}">
                <div class="insight-type"><i class="fas ${ins.icon || typeIcons[ins.type] || 'fa-info-circle'}" style="color:${typeColors[ins.type] || '#6b7280'};margin-right:5px"></i>${ins.title}</div>
                <div class="insight-text">${ins.text}</div>
            </div>`
    ).join('')}</div>`;
}

function computeCorrelation(colA, colB) {
    const pairs = excelData.map(r => [parseFloat(r[colA]), parseFloat(r[colB])]).filter(p => !isNaN(p[0]) && !isNaN(p[1]));
    if (pairs.length < 5) return 0;
    const n = pairs.length;
    const sumX = pairs.reduce((s, p) => s + p[0], 0);
    const sumY = pairs.reduce((s, p) => s + p[1], 0);
    const sumXY = pairs.reduce((s, p) => s + p[0] * p[1], 0);
    const sumX2 = pairs.reduce((s, p) => s + p[0] * p[0], 0);
    const sumY2 = pairs.reduce((s, p) => s + p[1] * p[1], 0);
    const denom = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));
    return denom === 0 ? 0 : (n * sumXY - sumX * sumY) / denom;
}

// ===== Auto Charts =====
function renderAutoCharts() {
    const grid = document.getElementById('excelChartsGrid');
    grid.innerHTML = '';
    activeCharts.forEach(c => c.destroy());
    activeCharts = [];
    Object.keys(chartRegistry).forEach(k => delete chartRegistry[k]);

    const nums = getNumericColumns();
    const cats = getCategoricalColumns();
    const apfFields = detectAPFFields(excelColumns);
    let chartCount = 0;

    // APF: School/Block-wise distribution (if detected)
    if (apfFields.block && apfFields.block.length > 0) {
        const blockCol = apfFields.block[0];
        createAutoChart(grid, `Distribution by ${blockCol}`, blockCol, 'bar', 'count', null, 15);
        chartCount++;
    }

    if (apfFields.school && apfFields.school.length > 0 && nums.length > 0) {
        const schoolCol = apfFields.school[0];
        createAutoChart(grid, `${nums[0]} by School (Top 15)`, schoolCol, 'horizontalBar', 'sum', nums[0], 15);
        chartCount++;
    }

    if (apfFields.subject && apfFields.subject.length > 0) {
        createAutoChart(grid, `Subject Distribution`, apfFields.subject[0], 'doughnut', 'count', null, 20);
        chartCount++;
    }

    // Categorical columns — bar charts
    cats.forEach(col => {
        if (chartCount >= 10) return;
        if (apfFields.block && apfFields.block.includes(col)) return; // Already done
        if (apfFields.subject && apfFields.subject.includes(col)) return;
        createAutoChart(grid, `${col} Distribution`, col, 'bar', 'count', null, 12);
        chartCount++;
    });

    // Numeric columns — histogram-like distribution
    nums.forEach(col => {
        if (chartCount >= 12) return;
        createHistogramChart(grid, `${col} — Distribution`, col);
        chartCount++;
    });

    // Scatter plot if 2+ numeric columns
    if (nums.length >= 2) {
        createScatterChart(grid, `${nums[0]} vs ${nums[1]}`, nums[0], nums[1]);
        chartCount++;
    }

    // Radar chart if APF practice/score fields
    if (apfFields.practice && nums.length > 0) {
        createRadarChart(grid, `${nums[0]} by ${apfFields.practice[0]}`, apfFields.practice[0], nums[0]);
    }
}

function createAutoChart(container, title, labelCol, chartType, agg, valueCol, topN) {
    // Aggregate data
    const freq = {};
    excelData.forEach(row => {
        const label = String(row[labelCol]).trim();
        if (!label) return;
        if (agg === 'count') {
            freq[label] = (freq[label] || 0) + 1;
        } else {
            const val = parseFloat(row[valueCol]);
            if (isNaN(val)) return;
            if (!freq[label]) freq[label] = { sum: 0, count: 0, values: [] };
            freq[label].sum += val;
            freq[label].count++;
            freq[label].values.push(val);
        }
    });

    let entries;
    if (agg === 'count') {
        entries = Object.entries(freq).sort((a, b) => b[1] - a[1]);
    } else {
        entries = Object.entries(freq).map(([k, v]) => {
            let aggVal = v.sum;
            if (agg === 'average') aggVal = v.sum / v.count;
            return [k, Math.round(aggVal * 100) / 100];
        }).sort((a, b) => b[1] - a[1]);
    }

    if (topN && topN !== 'all') entries = entries.slice(0, topN);
    if (entries.length === 0) return;

    const labels = entries.map(e => e[0].length > 25 ? e[0].substring(0, 22) + '...' : e[0]);
    const values = entries.map(e => typeof e[1] === 'object' ? e[1].count || e[1].sum : e[1]);

    const id = 'chart-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
    const isHorizontal = chartType === 'horizontalBar';
    const isPie = chartType === 'doughnut' || chartType === 'pie';
    const realType = isHorizontal ? 'bar' : (isPie ? 'doughnut' : chartType);

    const card = document.createElement('div');
    card.className = 'excel-chart-card';
    card.innerHTML = `${buildChartToolbar(id, realType)}<h4>${title}</h4>${buildChartAxisBar(id, labelCol, valueCol, agg)}<canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');

    const config = {
        type: realType,
        data: {
            labels,
            datasets: [{
                label: agg === 'count' ? 'Count' : `${agg} of ${valueCol}`,
                data: values,
                backgroundColor: isPie ? getColors(values.length) : getColors(values.length).map(c => c + 'cc'),
                borderColor: isPie ? '#1e2230' : getColors(values.length),
                borderWidth: isPie ? 2 : 1,
            }]
        },
        options: {
            responsive: true,
            indexAxis: isHorizontal ? 'y' : 'x',
            plugins: {
                legend: { display: isPie, position: 'right', labels: { color: '#9ca3b8', padding: 8, font: { size: 11 } } },
            },
            scales: isPie ? {} : {
                x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#9ca3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    };

    const chartInst = new Chart(ctx, config);
    activeCharts.push(chartInst);
    registerChart(id, chartInst, title, { labelCol, valueCol, agg, topN });
}

function createHistogramChart(container, title, col) {
    const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
    if (vals.length < 2) return;

    const min = Math.min(...vals);
    const max = Math.max(...vals);
    const range = max - min;
    if (range === 0) return;
    const binCount = Math.min(20, Math.ceil(Math.sqrt(vals.length)));
    const binWidth = range / binCount;

    const bins = Array(binCount).fill(0);
    const binLabels = [];
    for (let i = 0; i < binCount; i++) {
        const lo = min + i * binWidth;
        const hi = lo + binWidth;
        binLabels.push(`${lo.toFixed(0)}-${hi.toFixed(0)}`);
    }
    vals.forEach(v => {
        let idx = Math.floor((v - min) / binWidth);
        if (idx >= binCount) idx = binCount - 1;
        bins[idx]++;
    });

    const id = 'hist-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
    const card = document.createElement('div');
    card.className = 'excel-chart-card';
    card.innerHTML = `${buildChartToolbar(id, 'bar')}<h4>${title}</h4>${buildChartAxisBar(id, col, null, 'count')}<canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    const histChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: binLabels,
            datasets: [{
                label: 'Frequency',
                data: bins,
                backgroundColor: 'rgba(59, 130, 246, 0.6)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
    activeCharts.push(histChart);
    registerChart(id, histChart, title, { labelCol: col, agg: 'count' });
}

function createScatterChart(container, title, colX, colY) {
    const points = excelData.map(r => ({
        x: parseFloat(r[colX]),
        y: parseFloat(r[colY])
    })).filter(p => !isNaN(p.x) && !isNaN(p.y));

    if (points.length < 2) return;
    const sample = points.length > 500 ? points.filter((_, i) => i % Math.ceil(points.length / 500) === 0) : points;

    const id = 'scatter-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
    const card = document.createElement('div');
    card.className = 'excel-chart-card';
    card.innerHTML = `${buildChartToolbar(id, 'scatter')}<h4>${title}</h4>${buildChartAxisBar(id, colX, colY, 'scatter')}<canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    const scatterChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: `${colX} vs ${colY}`,
                data: sample,
                backgroundColor: 'rgba(245, 158, 11, 0.5)',
                borderColor: '#f59e0b',
                pointRadius: 3,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { title: { display: true, text: colX, color: '#9ca3b8' }, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { title: { display: true, text: colY, color: '#9ca3b8' }, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
    activeCharts.push(scatterChart);
    registerChart(id, scatterChart, title, { labelCol: colX, valueCol: colY, agg: 'scatter' });
}

function createRadarChart(container, title, catCol, numCol) {
    const agg = {};
    excelData.forEach(r => {
        const label = String(r[catCol]).trim();
        const val = parseFloat(r[numCol]);
        if (!label || isNaN(val)) return;
        if (!agg[label]) agg[label] = { sum: 0, count: 0 };
        agg[label].sum += val;
        agg[label].count++;
    });

    const entries = Object.entries(agg).map(([k, v]) => [k, v.sum / v.count]).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (entries.length < 3) return;

    const id = 'radar-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
    const card = document.createElement('div');
    card.className = 'excel-chart-card';
    card.innerHTML = `${buildChartToolbar(id, 'radar')}<h4>${title}</h4>${buildChartAxisBar(id, catCol, numCol, 'average')}<canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    const radarChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: entries.map(e => e[0].length > 15 ? e[0].substring(0, 12) + '...' : e[0]),
            datasets: [{
                label: `Avg ${numCol}`,
                data: entries.map(e => Math.round(e[1] * 100) / 100),
                backgroundColor: 'rgba(245, 158, 11, 0.2)',
                borderColor: '#f59e0b',
                borderWidth: 2,
                pointBackgroundColor: '#f59e0b',
            }]
        },
        options: {
            responsive: true,
            scales: {
                r: { ticks: { color: '#9ca3b8', backdropColor: 'transparent' }, grid: { color: 'rgba(255,255,255,0.08)' }, pointLabels: { color: '#9ca3b8', font: { size: 11 } } }
            },
            plugins: { legend: { labels: { color: '#9ca3b8' } } }
        }
    });
    activeCharts.push(radarChart);
    registerChart(id, radarChart, title, { labelCol: catCol, valueCol: numCol, agg: 'average' });
}

// ===== Custom Chart Builder =====
function buildCustomChart() {
    const chartType = document.getElementById('customChartType').value;
    const xCol = document.getElementById('customChartX').value;
    const yCol = document.getElementById('customChartY').value;
    const agg = document.getElementById('customChartAgg').value;
    const groupCol = document.getElementById('customChartGroup').value;
    const topNVal = document.getElementById('customChartTopN').value;
    const topN = topNVal === 'all' ? Infinity : parseInt(topNVal);
    const output = document.getElementById('customChartOutput');

    if (chartType === 'scatter') {
        buildScatterCustom(output, xCol, yCol, groupCol);
        return;
    }
    if (chartType === 'histogram') {
        buildHistogramCustom(output, yCol);
        return;
    }

    // Aggregate data  
    const groups = {};
    excelData.forEach(row => {
        const xVal = String(row[xCol]).trim();
        if (!xVal) return;
        const yRaw = parseFloat(row[yCol]);
        const yVal = isNaN(yRaw) ? 1 : yRaw; // fallback to count
        const gVal = groupCol ? String(row[groupCol]).trim() : '__all__';

        if (!groups[xVal]) groups[xVal] = {};
        if (!groups[xVal][gVal]) groups[xVal][gVal] = { sum: 0, count: 0, min: Infinity, max: -Infinity };
        groups[xVal][gVal].sum += yVal;
        groups[xVal][gVal].count++;
        groups[xVal][gVal].min = Math.min(groups[xVal][gVal].min, yVal);
        groups[xVal][gVal].max = Math.max(groups[xVal][gVal].max, yVal);
    });

    const applyAgg = (o) => {
        switch (agg) {
            case 'sum': return o.sum;
            case 'average': return o.count ? o.sum / o.count : 0;
            case 'count': return o.count;
            case 'min': return o.min;
            case 'max': return o.max;
            default: return o.sum;
        }
    };

    // Get sorted labels
    let labels = Object.keys(groups);
    if (!groupCol || groupCol === '') {
        const sorted = labels.map(l => [l, applyAgg(groups[l]['__all__'])]).sort((a, b) => b[1] - a[1]);
        labels = sorted.slice(0, topN).map(s => s[0]);
    } else {
        labels = labels.slice(0, topN);
    }

    const displayLabels = labels.map(l => l.length > 30 ? l.substring(0, 27) + '...' : l);
    let datasets;

    if (groupCol && groupCol !== '') {
        const allGroups = [...new Set(excelData.map(r => String(r[groupCol]).trim()).filter(Boolean))];
        datasets = allGroups.slice(0, 10).map((g, i) => ({
            label: g,
            data: labels.map(l => groups[l] && groups[l][g] ? Math.round(applyAgg(groups[l][g]) * 100) / 100 : 0),
            backgroundColor: CHART_COLORS[i % CHART_COLORS.length] + 'cc',
            borderColor: CHART_COLORS[i % CHART_COLORS.length],
            borderWidth: 1,
        }));
    } else {
        const values = labels.map(l => Math.round(applyAgg(groups[l]['__all__']) * 100) / 100);
        datasets = [{
            label: `${agg} of ${yCol}`,
            data: values,
            backgroundColor: chartType === 'pie' || chartType === 'polarArea' || chartType === 'doughnut'
                ? getColors(values.length)
                : getColors(values.length).map(c => c + 'cc'),
            borderColor: chartType === 'pie' || chartType === 'polarArea' || chartType === 'doughnut'
                ? '#1e2230' : getColors(values.length),
            borderWidth: chartType === 'line' ? 2 : 1,
            fill: chartType === 'line' ? { target: 'origin', above: 'rgba(245,158,11,0.1)' } : undefined,
            tension: chartType === 'line' ? 0.4 : undefined,
            pointBackgroundColor: chartType === 'line' ? '#f59e0b' : undefined,
        }];
    }

    const id = 'custom-' + Date.now();
    const isPie = ['pie', 'doughnut', 'polarArea'].includes(chartType);
    const isHoriz = chartType === 'horizontalBar';
    const actualType = isHoriz ? 'bar' : (chartType === 'pie' ? 'doughnut' : chartType);

    output.innerHTML = `<div class="custom-chart-wrapper">
        <div class="chart-title"><i class="fas fa-chart-bar"></i> ${agg.charAt(0).toUpperCase() + agg.slice(1)} of ${yCol} by ${xCol}${groupCol ? ` (grouped by ${groupCol})` : ''}</div>
        <div class="chart-canvas-container"><canvas id="${id}"></canvas></div>
    </div>`;

    const ctx = document.getElementById(id).getContext('2d');
    const chart = new Chart(ctx, {
        type: actualType,
        data: { labels: displayLabels, datasets },
        options: {
            responsive: true,
            indexAxis: isHoriz ? 'y' : 'x',
            plugins: {
                legend: { display: datasets.length > 1 || isPie, position: isPie ? 'right' : 'top', labels: { color: '#9ca3b8', font: { size: 12 } } },
            },
            scales: isPie ? {} : {
                x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { ticks: { color: '#9ca3b8', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    });
    activeCharts.push(chart);
}

function buildScatterCustom(output, xCol, yCol, groupCol) {
    const id = 'scatter-custom-' + Date.now();

    let datasets;
    if (groupCol) {
        const groupVals = [...new Set(excelData.map(r => String(r[groupCol]).trim()).filter(Boolean))].slice(0, 10);
        datasets = groupVals.map((g, i) => ({
            label: g,
            data: excelData.filter(r => String(r[groupCol]).trim() === g)
                .map(r => ({ x: parseFloat(r[xCol]), y: parseFloat(r[yCol]) }))
                .filter(p => !isNaN(p.x) && !isNaN(p.y))
                .slice(0, 200),
            backgroundColor: CHART_COLORS[i % CHART_COLORS.length] + '88',
            borderColor: CHART_COLORS[i % CHART_COLORS.length],
            pointRadius: 3,
        }));
    } else {
        const points = excelData.map(r => ({ x: parseFloat(r[xCol]), y: parseFloat(r[yCol]) })).filter(p => !isNaN(p.x) && !isNaN(p.y));
        const sample = points.length > 1000 ? points.filter((_, i) => i % Math.ceil(points.length / 1000) === 0) : points;
        datasets = [{ label: `${xCol} vs ${yCol}`, data: sample, backgroundColor: 'rgba(245,158,11,0.5)', borderColor: '#f59e0b', pointRadius: 3 }];
    }

    output.innerHTML = `<div class="custom-chart-wrapper">
        <div class="chart-title"><i class="fas fa-braille"></i> Scatter: ${xCol} vs ${yCol}${groupCol ? ` (colored by ${groupCol})` : ''}</div>
        <div class="chart-canvas-container"><canvas id="${id}"></canvas></div>
    </div>`;

    activeCharts.push(new Chart(document.getElementById(id).getContext('2d'), {
        type: 'scatter',
        data: { datasets },
        options: {
            responsive: true,
            plugins: { legend: { display: datasets.length > 1, labels: { color: '#9ca3b8' } } },
            scales: {
                x: { title: { display: true, text: xCol, color: '#9ca3b8' }, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { title: { display: true, text: yCol, color: '#9ca3b8' }, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    }));
}

function buildHistogramCustom(output, col) {
    const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
    if (vals.length < 2) { output.innerHTML = '<p style="color:var(--text-muted)">Not enough numeric data</p>'; return; }

    const min = Math.min(...vals), max = Math.max(...vals), range = max - min;
    if (range === 0) { output.innerHTML = '<p style="color:var(--text-muted)">All values are the same</p>'; return; }

    const binCount = Math.min(30, Math.ceil(Math.sqrt(vals.length)));
    const binWidth = range / binCount;
    const bins = Array(binCount).fill(0);
    const binLabels = [];
    for (let i = 0; i < binCount; i++) {
        const lo = min + i * binWidth;
        binLabels.push(lo.toFixed(1));
    }
    vals.forEach(v => { let idx = Math.floor((v - min) / binWidth); if (idx >= binCount) idx = binCount - 1; bins[idx]++; });

    const id = 'histogram-custom-' + Date.now();
    output.innerHTML = `<div class="custom-chart-wrapper">
        <div class="chart-title"><i class="fas fa-chart-bar"></i> Histogram of ${col}</div>
        <div class="chart-canvas-container"><canvas id="${id}"></canvas></div>
    </div>`;

    activeCharts.push(new Chart(document.getElementById(id).getContext('2d'), {
        type: 'bar',
        data: {
            labels: binLabels,
            datasets: [{ label: 'Frequency', data: bins, backgroundColor: 'rgba(99, 102, 241, 0.6)', borderColor: '#6366f1', borderWidth: 1, borderRadius: 2, barPercentage: 1, categoryPercentage: 1 }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { title: { display: true, text: col, color: '#9ca3b8' }, ticks: { color: '#9ca3b8', maxRotation: 45 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                y: { title: { display: true, text: 'Frequency', color: '#9ca3b8' }, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
            }
        }
    }));
}

// ===== Pivot Table =====
function buildPivotTable() {
    const rowCol = document.getElementById('pivotRow').value;
    const valCol = document.getElementById('pivotValue').value;
    const aggType = document.getElementById('pivotAgg').value;
    const splitCol = document.getElementById('pivotCol').value;
    const output = document.getElementById('pivotOutput');

    if (!splitCol) {
        // Simple pivot
        const groups = {};
        excelData.forEach(row => {
            const key = String(row[rowCol]).trim();
            if (!key) return;
            const val = parseFloat(row[valCol]);
            if (!groups[key]) groups[key] = { sum: 0, count: 0, min: Infinity, max: -Infinity };
            if (!isNaN(val)) {
                groups[key].sum += val;
                groups[key].min = Math.min(groups[key].min, val);
                groups[key].max = Math.max(groups[key].max, val);
            }
            groups[key].count++;
        });

        const applyAgg = o => {
            switch (aggType) {
                case 'sum': return o.sum;
                case 'average': return o.count ? o.sum / o.count : 0;
                case 'count': return o.count;
                case 'min': return o.min === Infinity ? 0 : o.min;
                case 'max': return o.max === -Infinity ? 0 : o.max;
                default: return o.sum;
            }
        };

        const entries = Object.entries(groups).map(([k, v]) => [k, applyAgg(v)]).sort((a, b) => b[1] - a[1]);
        const total = entries.reduce((s, e) => s + e[1], 0);

        output.innerHTML = `
            <div class="excel-charts-grid">
                <div class="custom-chart-wrapper">
                    <div class="chart-title"><i class="fas fa-chart-bar"></i> ${aggType} of ${valCol} by ${rowCol}</div>
                    <canvas id="pivotChart"></canvas>
                </div>
                <div class="pivot-table-wrapper">
                    <table class="pivot-table">
                        <thead><tr><th>${rowCol}</th><th style="text-align:right">${aggType} of ${valCol}</th><th style="text-align:right">% of Total</th></tr></thead>
                        <tbody>
                            ${entries.map(([k, v]) => `<tr><td>${k}</td><td class="pivot-value">${v.toLocaleString(undefined, { maximumFractionDigits: 2 })}</td><td class="pivot-value">${total ? ((v / total) * 100).toFixed(1) + '%' : '-'}</td></tr>`).join('')}
                            <tr class="pivot-total-row"><td>TOTAL</td><td class="pivot-value">${total.toLocaleString(undefined, { maximumFractionDigits: 2 })}</td><td class="pivot-value">100%</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>`;

        // Pivot chart
        const topEntries = entries.slice(0, 20);
        activeCharts.push(new Chart(document.getElementById('pivotChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: topEntries.map(e => e[0].length > 20 ? e[0].substring(0, 17) + '...' : e[0]),
                datasets: [{ label: `${aggType} of ${valCol}`, data: topEntries.map(e => Math.round(e[1] * 100) / 100), backgroundColor: getColors(topEntries.length).map(c => c + 'cc'), borderColor: getColors(topEntries.length), borderWidth: 1 }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                    y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
                }
            }
        }));
    } else {
        // Cross-tabulation pivot
        const matrix = {};
        const colValues = new Set();
        excelData.forEach(row => {
            const rKey = String(row[rowCol]).trim();
            const cKey = String(row[splitCol]).trim();
            if (!rKey || !cKey) return;
            colValues.add(cKey);
            if (!matrix[rKey]) matrix[rKey] = {};
            if (!matrix[rKey][cKey]) matrix[rKey][cKey] = { sum: 0, count: 0, min: Infinity, max: -Infinity };
            const val = parseFloat(row[valCol]);
            if (!isNaN(val)) {
                matrix[rKey][cKey].sum += val;
                matrix[rKey][cKey].min = Math.min(matrix[rKey][cKey].min, val);
                matrix[rKey][cKey].max = Math.max(matrix[rKey][cKey].max, val);
            }
            matrix[rKey][cKey].count++;
        });

        const applyAgg = o => {
            if (!o) return 0;
            switch (aggType) {
                case 'sum': return o.sum;
                case 'average': return o.count ? o.sum / o.count : 0;
                case 'count': return o.count;
                case 'min': return o.min === Infinity ? 0 : o.min;
                case 'max': return o.max === -Infinity ? 0 : o.max;
                default: return o.sum;
            }
        };

        const cols = [...colValues].slice(0, 15);
        const rows = Object.keys(matrix).sort();

        output.innerHTML = `
            <div class="pivot-table-wrapper">
                <table class="pivot-table">
                    <thead><tr><th>${rowCol}</th>${cols.map(c => `<th style="text-align:right">${c}</th>`).join('')}<th style="text-align:right;color:var(--accent)">TOTAL</th></tr></thead>
                    <tbody>
                        ${rows.map(rKey => {
            const rowTotal = cols.reduce((s, c) => s + applyAgg(matrix[rKey][c]), 0);
            return `<tr><td>${rKey}</td>${cols.map(c => `<td class="pivot-value">${applyAgg(matrix[rKey][c]).toLocaleString(undefined, { maximumFractionDigits: 1 })}</td>`).join('')}<td class="pivot-value" style="color:var(--accent);font-weight:600">${rowTotal.toLocaleString(undefined, { maximumFractionDigits: 1 })}</td></tr>`;
        }).join('')}
                        <tr class="pivot-total-row"><td>TOTAL</td>${cols.map(c => {
            const colTotal = rows.reduce((s, r) => s + applyAgg(matrix[r][c]), 0);
            return `<td class="pivot-value">${colTotal.toLocaleString(undefined, { maximumFractionDigits: 1 })}</td>`;
        }).join('')}<td class="pivot-value">${rows.reduce((s, r) => s + cols.reduce((s2, c) => s2 + applyAgg(matrix[r][c]), 0), 0).toLocaleString(undefined, { maximumFractionDigits: 1 })}</td></tr>
                    </tbody>
                </table>
            </div>`;
    }
}

// ===== Statistical Deep Dive =====
function renderStatistics() {
    const output = document.getElementById('statsOutput');
    let nums = getNumericColumns();
    let cats = getCategoricalColumns();

    // Read custom controls
    const sortBy = document.getElementById('statsSortBy')?.value || 'name';
    const filterEl = document.getElementById('statsColumnFilter');
    if (filterEl && filterEl.selectedOptions.length > 0 && filterEl.selectedOptions.length < filterEl.options.length) {
        const selected = new Set([...filterEl.selectedOptions].map(o => o.value));
        nums = nums.filter(c => selected.has(c));
        cats = cats.filter(c => selected.has(c));
    }

    if (nums.length === 0 && cats.length === 0) {
        output.innerHTML = '<p style="color:var(--text-muted);padding:20px;">No analyzable columns found.</p>';
        return;
    }

    // Helper functions
    function getVals(col) { return excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v)); }
    function mean(arr) { return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0; }
    function median(arr) { const s = [...arr].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
    function mode(arr) {
        const f = {}; arr.forEach(v => f[v] = (f[v] || 0) + 1);
        const maxF = Math.max(...Object.values(f));
        const modes = Object.keys(f).filter(k => f[k] === maxF).map(Number);
        return modes.length === arr.length ? 'None' : modes.slice(0, 3).map(v => fmt(v)).join(', ');
    }
    function percentile(arr, p) { const s = [...arr].sort((a, b) => a - b); const i = (p / 100) * (s.length - 1); const lo = Math.floor(i); const hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); }
    function stdDev(arr) { const m = mean(arr); return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / arr.length); }
    function skewness(arr) {
        const n = arr.length, m = mean(arr), sd = stdDev(arr);
        if (sd === 0 || n < 3) return 0;
        return (n / ((n - 1) * (n - 2))) * arr.reduce((s, v) => s + ((v - m) / sd) ** 3, 0);
    }
    function kurtosis(arr) {
        const n = arr.length, m = mean(arr), sd = stdDev(arr);
        if (sd === 0 || n < 4) return 0;
        const k4 = arr.reduce((s, v) => s + ((v - m) / sd) ** 4, 0) / n;
        return k4 - 3; // excess kurtosis
    }
    function fmt(v) { return typeof v === 'number' ? (Math.abs(v) >= 1e6 ? (v / 1e6).toFixed(2) + 'M' : Math.abs(v) >= 1e3 ? (v / 1e3).toFixed(2) + 'K' : Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2)) : v; }
    function skLabel(sk) { return Math.abs(sk) < 0.5 ? 'Symmetric' : sk > 0 ? 'Right-skewed' : 'Left-skewed'; }
    function kurtLabel(k) { return Math.abs(k) < 0.5 ? 'Mesokurtic (Normal)' : k > 0 ? 'Leptokurtic (Heavy tails)' : 'Platykurtic (Light tails)'; }

    // Build numeric stats
    let numericHTML = '';
    if (nums.length > 0) {
        const colStats = nums.map(col => {
            const v = getVals(col);
            if (v.length === 0) return null;
            const sorted = [...v].sort((a, b) => a - b);
            const m = mean(v);
            const sd = stdDev(v);
            const sk = skewness(v);
            const kt = kurtosis(v);
            const p25 = percentile(v, 25), p50 = percentile(v, 50), p75 = percentile(v, 75);
            const iqr = p75 - p25;
            const cv = m !== 0 ? (sd / Math.abs(m)) * 100 : 0;
            return {
                col, count: v.length, missing: excelData.length - v.length,
                min: sorted[0], max: sorted[sorted.length - 1],
                mean: m, median: median(v), mode: mode(v),
                stdDev: sd, variance: sd * sd, range: sorted[sorted.length - 1] - sorted[0],
                p25, p50, p75, p90: percentile(v, 90), p95: percentile(v, 95), p99: percentile(v, 99),
                iqr, cv, skewness: sk, kurtosis: kt,
                sum: v.reduce((a, b) => a + b, 0),
                skLabel: skLabel(sk), kurtLabel: kurtLabel(kt)
            };
        }).filter(Boolean);

        // Apply sorting
        if (sortBy === 'mean') colStats.sort((a, b) => b.mean - a.mean);
        else if (sortBy === 'stddev') colStats.sort((a, b) => b.stdDev - a.stdDev);
        else if (sortBy === 'missing') colStats.sort((a, b) => b.missing - a.missing);
        else if (sortBy === 'cv') colStats.sort((a, b) => b.cv - a.cv);
        else colStats.sort((a, b) => a.col.localeCompare(b.col));

        numericHTML = `
        <div class="stats-section">
            <div class="stats-section-header">
                <div class="stats-section-icon" style="background:linear-gradient(135deg,#10b981,#059669)"><i class="fas fa-hashtag"></i></div>
                <div><h3>Numeric Column Statistics</h3><p>${colStats.length} numeric columns analyzed (sorted by ${sortBy})</p></div>
            </div>
            <div class="stats-cards-scroll">
                ${colStats.map(s => `
                <div class="stat-deep-card">
                    <div class="stat-deep-header">
                        <span class="stat-deep-name">${s.col}</span>
                        <span class="stat-deep-badge">${s.count.toLocaleString()} values</span>
                    </div>
                    <div class="stat-deep-grid">
                        <div class="stat-deep-group">
                            <div class="stat-deep-group-title"><i class="fas fa-crosshairs"></i> Central Tendency</div>
                            <div class="stat-deep-row"><span>Mean</span><strong>${fmt(s.mean)}</strong></div>
                            <div class="stat-deep-row"><span>Median</span><strong>${fmt(s.median)}</strong></div>
                            <div class="stat-deep-row"><span>Mode</span><strong>${s.mode}</strong></div>
                            <div class="stat-deep-row"><span>Sum</span><strong>${fmt(s.sum)}</strong></div>
                        </div>
                        <div class="stat-deep-group">
                            <div class="stat-deep-group-title"><i class="fas fa-expand-arrows-alt"></i> Spread</div>
                            <div class="stat-deep-row"><span>Std Dev</span><strong>${fmt(s.stdDev)}</strong></div>
                            <div class="stat-deep-row"><span>Variance</span><strong>${fmt(s.variance)}</strong></div>
                            <div class="stat-deep-row"><span>Range</span><strong>${fmt(s.range)}</strong></div>
                            <div class="stat-deep-row"><span>IQR</span><strong>${fmt(s.iqr)}</strong></div>
                            <div class="stat-deep-row"><span>CV</span><strong>${s.cv.toFixed(1)}%</strong></div>
                        </div>
                        <div class="stat-deep-group">
                            <div class="stat-deep-group-title"><i class="fas fa-ruler"></i> Percentiles</div>
                            <div class="stat-deep-row"><span>Min</span><strong>${fmt(s.min)}</strong></div>
                            <div class="stat-deep-row"><span>P25</span><strong>${fmt(s.p25)}</strong></div>
                            <div class="stat-deep-row"><span>P50</span><strong>${fmt(s.p50)}</strong></div>
                            <div class="stat-deep-row"><span>P75</span><strong>${fmt(s.p75)}</strong></div>
                            <div class="stat-deep-row"><span>P90</span><strong>${fmt(s.p90)}</strong></div>
                            <div class="stat-deep-row"><span>P95</span><strong>${fmt(s.p95)}</strong></div>
                            <div class="stat-deep-row"><span>P99</span><strong>${fmt(s.p99)}</strong></div>
                            <div class="stat-deep-row"><span>Max</span><strong>${fmt(s.max)}</strong></div>
                        </div>
                        <div class="stat-deep-group">
                            <div class="stat-deep-group-title"><i class="fas fa-wave-square"></i> Shape</div>
                            <div class="stat-deep-row"><span>Skewness</span><strong>${s.skewness.toFixed(3)}</strong></div>
                            <div class="stat-deep-row hint"><span>${s.skLabel}</span></div>
                            <div class="stat-deep-row"><span>Kurtosis</span><strong>${s.kurtosis.toFixed(3)}</strong></div>
                            <div class="stat-deep-row hint"><span>${s.kurtLabel}</span></div>
                            ${s.missing > 0 ? `<div class="stat-deep-row warning"><span>Missing</span><strong>${s.missing}</strong></div>` : ''}
                        </div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>`;
    }

    // Build categorical stats
    let catHTML = '';
    if (cats.length > 0) {
        catHTML = `
        <div class="stats-section" style="margin-top:24px;">
            <div class="stats-section-header">
                <div class="stats-section-icon" style="background:linear-gradient(135deg,#8b5cf6,#6d28d9)"><i class="fas fa-font"></i></div>
                <div><h3>Categorical Column Statistics</h3><p>${cats.length} categorical columns analyzed</p></div>
            </div>
            <div class="stats-cards-scroll">
                ${cats.map(col => {
                    const freq = {};
                    let total = 0, missing = 0;
                    excelData.forEach(r => {
                        const v = r[col];
                        if (v === null || v === undefined || v === '') { missing++; return; }
                        const s = String(v).trim();
                        freq[s] = (freq[s] || 0) + 1;
                        total++;
                    });
                    const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
                    const uniqueCount = sorted.length;
                    const top5 = sorted.slice(0, 5);
                    const entropy = sorted.reduce((s, [, c]) => { const p = c / total; return s - p * Math.log2(p); }, 0);
                    const maxEntropy = Math.log2(uniqueCount);
                    const dominance = sorted.length > 0 ? ((sorted[0][1] / total) * 100).toFixed(1) : 0;

                    return `
                    <div class="stat-deep-card">
                        <div class="stat-deep-header">
                            <span class="stat-deep-name">${col}</span>
                            <span class="stat-deep-badge" style="background:rgba(139,92,246,0.15);color:#a78bfa">${uniqueCount} unique</span>
                        </div>
                        <div class="stat-deep-grid">
                            <div class="stat-deep-group">
                                <div class="stat-deep-group-title"><i class="fas fa-info-circle"></i> Overview</div>
                                <div class="stat-deep-row"><span>Total</span><strong>${total.toLocaleString()}</strong></div>
                                <div class="stat-deep-row"><span>Unique</span><strong>${uniqueCount.toLocaleString()}</strong></div>
                                <div class="stat-deep-row"><span>Missing</span><strong>${missing.toLocaleString()}</strong></div>
                                <div class="stat-deep-row"><span>Entropy</span><strong>${entropy.toFixed(2)} bits</strong></div>
                                <div class="stat-deep-row"><span>Normalized</span><strong>${maxEntropy > 0 ? (entropy / maxEntropy * 100).toFixed(1) + '%' : 'N/A'}</strong></div>
                                <div class="stat-deep-row"><span>Dominance</span><strong>${dominance}%</strong></div>
                            </div>
                            <div class="stat-deep-group" style="grid-column: span 2;">
                                <div class="stat-deep-group-title"><i class="fas fa-trophy"></i> Top Values</div>
                                ${top5.map(([val, cnt], i) => `
                                <div class="stat-freq-row">
                                    <span class="freq-rank">#${i + 1}</span>
                                    <span class="freq-val">${val.length > 30 ? val.substring(0, 27) + '...' : val}</span>
                                    <div class="freq-bar-wrap"><div class="freq-bar" style="width:${(cnt / sorted[0][1]) * 100}%"></div></div>
                                    <span class="freq-count">${cnt.toLocaleString()} <small>(${((cnt / total) * 100).toFixed(1)}%)</small></span>
                                </div>`).join('')}
                                ${sorted.length > 5 ? `<div class="stat-show-all-row">
                                    <button class="show-all-values-btn" onclick="showAllValues('${col.replace(/'/g, "\\'")}')"><i class="fas fa-list"></i> Show all ${sorted.length} values</button>
                                </div>` : ''}
                            </div>
                        </div>
                    </div>`;
                }).join('')}
            </div>
        </div>`;
    }

    output.innerHTML = numericHTML + catHTML;
}

// ===== Correlation Matrix =====
function renderCorrelationMatrix() {
    const output = document.getElementById('correlationOutput');
    const nums = getNumericColumns();

    if (nums.length < 2) {
        output.innerHTML = '<div class="analysis-empty"><i class="fas fa-project-diagram"></i><p>Need at least 2 numeric columns for correlation analysis</p></div>';
        return;
    }

    // Read custom controls
    const maxCols = parseInt(document.getElementById('corrMaxCols')?.value || '15');
    const minThreshold = parseFloat(document.getElementById('corrMinThreshold')?.value || '0');

    const displayCols = nums.slice(0, maxCols);
    const matrix = [];
    for (let i = 0; i < displayCols.length; i++) {
        matrix[i] = [];
        for (let j = 0; j < displayCols.length; j++) {
            matrix[i][j] = i === j ? 1 : computeCorrelation(displayCols[i], displayCols[j]);
        }
    }

    // Find strongest correlations
    const pairs = [];
    for (let i = 0; i < displayCols.length; i++) {
        for (let j = i + 1; j < displayCols.length; j++) {
            pairs.push({ a: displayCols[i], b: displayCols[j], r: matrix[i][j] });
        }
    }
    pairs.sort((a, b) => Math.abs(b.r) - Math.abs(a.r));
    const strong = pairs.filter(p => Math.abs(p.r) >= minThreshold);
    const topPairs = (minThreshold > 0 ? strong : pairs).slice(0, 8);

    function corrColor(r) {
        const abs = Math.abs(r);
        if (abs < 0.1) return 'rgba(100,116,139,0.15)';
        if (r > 0) return `rgba(16,185,129,${0.15 + abs * 0.6})`;
        return `rgba(239,68,68,${0.15 + abs * 0.6})`;
    }
    function corrTextColor(r) {
        return Math.abs(r) > 0.6 ? '#fff' : 'var(--text-secondary)';
    }
    function strengthLabel(r) {
        const a = Math.abs(r);
        if (a >= 0.8) return 'Very Strong';
        if (a >= 0.6) return 'Strong';
        if (a >= 0.4) return 'Moderate';
        if (a >= 0.2) return 'Weak';
        return 'Very Weak';
    }

    const shortName = (n) => n.length > 10 ? n.substring(0, 8) + '..' : n;

    output.innerHTML = `
        <div class="corr-container">
            <div class="corr-matrix-wrap">
                <div class="stats-section-header" style="margin-bottom:16px;">
                    <div class="stats-section-icon" style="background:linear-gradient(135deg,#3b82f6,#1d4ed8)"><i class="fas fa-project-diagram"></i></div>
                    <div><h3>Correlation Matrix</h3><p>Pearson correlation coefficients for ${displayCols.length} numeric columns</p></div>
                </div>
                <div class="corr-matrix-scroll">
                    <table class="corr-matrix-table">
                        <thead><tr><th></th>${displayCols.map(c => `<th title="${c}">${shortName(c)}</th>`).join('')}</tr></thead>
                        <tbody>
                        ${displayCols.map((row, i) => `
                            <tr>
                                <th title="${row}">${shortName(row)}</th>
                                ${displayCols.map((_, j) => {
                                    const r = matrix[i][j];
                                    return `<td style="background:${corrColor(r)};color:${corrTextColor(r)}" title="${row} ↔ ${displayCols[j]}: ${r.toFixed(3)}">${r.toFixed(2)}</td>`;
                                }).join('')}
                            </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
                <div class="corr-legend">
                    <span style="color:#ef4444">◼ Negative</span>
                    <span style="color:#64748b">◼ None</span>
                    <span style="color:#10b981">◼ Positive</span>
                </div>
            </div>
            <div class="corr-insights">
                <h4><i class="fas fa-lightbulb" style="color:var(--accent)"></i> Key Correlations</h4>
                ${strong.length === 0 ? '<p class="text-muted" style="font-size:13px;">No strong correlations (|r| ≥ 0.5) found</p>' : ''}
                ${topPairs.map(p => {
                    const abs = Math.abs(p.r);
                    const sign = p.r > 0 ? '+' : '−';
                    const color = p.r > 0 ? '#10b981' : '#ef4444';
                    const barW = abs * 100;
                    return `
                    <div class="corr-pair">
                        <div class="corr-pair-names">${p.a} <span style="color:${color}">${sign === '+' ? '↗' : '↘'}</span> ${p.b}</div>
                        <div class="corr-pair-bar"><div style="width:${barW}%;background:${color};height:100%;border-radius:4px;transition:width 0.5s;"></div></div>
                        <div class="corr-pair-info"><span style="color:${color};font-weight:700">r = ${sign}${abs.toFixed(3)}</span><span class="text-muted">${strengthLabel(p.r)}</span></div>
                    </div>`;
                }).join('')}
            </div>
        </div>`;
}

// ===== Outlier Detection =====
function renderOutlierDetection() {
    const output = document.getElementById('outlierOutput');
    const nums = getNumericColumns();

    // Read custom controls
    const outlierMethod = document.getElementById('outlierMethod')?.value || 'iqr';
    const outlierShow = document.getElementById('outlierShow')?.value || 'all';

    if (nums.length === 0) {
        output.innerHTML = '<div class="analysis-empty"><i class="fas fa-exclamation-triangle"></i><p>No numeric columns found for outlier detection</p></div>';
        return;
    }

    function getVals(col) { return excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v)); }
    function percentile(arr, p) { const s = [...arr].sort((a, b) => a - b); const i = (p / 100) * (s.length - 1); const lo = Math.floor(i); const hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); }
    function fmt(v) { return typeof v === 'number' ? (Math.abs(v) >= 1e6 ? (v/1e6).toFixed(1)+'M' : Math.abs(v) >= 1e3 ? (v/1e3).toFixed(1)+'K' : v.toFixed(2)) : v; }

    let results = nums.map(col => {
        const vals = getVals(col);
        if (vals.length < 4) return null;
        const sorted = [...vals].sort((a, b) => a - b);
        const q1 = percentile(vals, 25);
        const q3 = percentile(vals, 75);
        const iqr = q3 - q1;
        const lowerFence = q1 - 1.5 * iqr;
        const upperFence = q3 + 1.5 * iqr;
        const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
        const sd = Math.sqrt(vals.reduce((s, v) => s + (v - mean) ** 2, 0) / vals.length);

        const iqrOutliers = vals.filter(v => v < lowerFence || v > upperFence);
        const zOutliers = sd > 0 ? vals.filter(v => Math.abs((v - mean) / sd) > 2.5) : [];
        const extremeOutliers = vals.filter(v => v < q1 - 3 * iqr || v > q3 + 3 * iqr);

        return {
            col, count: vals.length,
            min: sorted[0], max: sorted[sorted.length - 1],
            q1, q3, iqr, lowerFence, upperFence, mean, sd,
            iqrOutliers: iqrOutliers.length,
            zOutliers: zOutliers.length,
            extremeOutliers: extremeOutliers.length,
            iqrPct: ((iqrOutliers.length / vals.length) * 100).toFixed(1),
            topOutliers: [...new Set(iqrOutliers)].sort((a, b) => Math.abs(b - mean) - Math.abs(a - mean)).slice(0, 6),
            whiskerLow: Math.max(sorted[0], lowerFence),
            whiskerHigh: Math.min(sorted[sorted.length - 1], upperFence),
            median: percentile(vals, 50)
        };
    }).filter(Boolean);

    // Apply outlier method filter
    const methodKey = outlierMethod === 'zscore' ? 'zOutliers' : outlierMethod === 'extreme' ? 'extremeOutliers' : 'iqrOutliers';
    const methodLabel = outlierMethod === 'zscore' ? 'Z-Score (2.5σ)' : outlierMethod === 'extreme' ? 'Extreme (3×IQR)' : 'IQR (1.5×)';

    // Filter results based on outlierShow control
    if (outlierShow === 'with') {
        results = results.filter(r => r[methodKey] > 0);
    }

    const totalOutliers = results.reduce((s, r) => s + r[methodKey], 0);
    const worstCol = [...results].sort((a, b) => b[methodKey] - a[methodKey])[0];
    const worstPct = worstCol ? ((worstCol[methodKey] / worstCol.count) * 100).toFixed(1) : '0';

    output.innerHTML = `
        <div class="outlier-summary">
            <div class="kpi-card" style="--kpi-color:#ef4444;--kpi-bg:rgba(239,68,68,0.12)">
                <div class="kpi-icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="kpi-body"><div class="kpi-value">${totalOutliers.toLocaleString()}</div><div class="kpi-label">Total Outliers (${methodLabel})</div></div>
            </div>
            <div class="kpi-card" style="--kpi-color:#f59e0b;--kpi-bg:rgba(245,158,11,0.12)">
                <div class="kpi-icon"><i class="fas fa-columns"></i></div>
                <div class="kpi-body"><div class="kpi-value">${results.filter(r => r[methodKey] > 0).length} / ${results.length}</div><div class="kpi-label">Columns Affected</div></div>
            </div>
            <div class="kpi-card" style="--kpi-color:#8b5cf6;--kpi-bg:rgba(139,92,246,0.12)">
                <div class="kpi-icon"><i class="fas fa-bullseye"></i></div>
                <div class="kpi-body"><div class="kpi-value">${worstCol ? worstCol.col.substring(0, 12) : 'N/A'}</div><div class="kpi-label">Most Outliers (${worstPct}%)</div></div>
            </div>
        </div>
        <div class="outlier-grid">
            ${results.map(r => {
                const range = r.max - r.min || 1;
                const boxLeft = ((r.q1 - r.min) / range) * 100;
                const boxWidth = ((r.q3 - r.q1) / range) * 100;
                const medianPos = ((r.median - r.min) / range) * 100;
                const wLow = ((r.whiskerLow - r.min) / range) * 100;
                const wHigh = ((r.whiskerHigh - r.min) / range) * 100;
                const severity = r[methodKey] === 0 ? 'clean' : ((r[methodKey] / r.count) * 100) > 5 ? 'severe' : 'mild';
                const severityColor = severity === 'clean' ? '#10b981' : severity === 'severe' ? '#ef4444' : '#f59e0b';
                const activeCount = r[methodKey];
                const activePct = ((activeCount / r.count) * 100).toFixed(1);

                return `
                <div class="outlier-card ${severity}">
                    <div class="outlier-card-header">
                        <span class="outlier-col-name">${r.col}</span>
                        <span class="outlier-severity" style="color:${severityColor}">
                            <i class="fas ${severity === 'clean' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                            ${activeCount === 0 ? 'Clean' : `${activeCount} outliers (${activePct}%)`}
                        </span>
                    </div>
                    <div class="box-plot-visual">
                        <div class="box-plot-track">
                            <div class="box-whisker-line" style="left:${wLow}%;width:${wHigh - wLow}%"></div>
                            <div class="box-plot-box" style="left:${boxLeft}%;width:${Math.max(boxWidth, 1)}%"></div>
                            <div class="box-plot-median" style="left:${medianPos}%"></div>
                        </div>
                        <div class="box-plot-labels">
                            <span>${fmt(r.min)}</span>
                            <span>Q1: ${fmt(r.q1)}</span>
                            <span>Med: ${fmt(r.median)}</span>
                            <span>Q3: ${fmt(r.q3)}</span>
                            <span>${fmt(r.max)}</span>
                        </div>
                    </div>
                    <div class="outlier-stats-row">
                        <div><span class="text-muted">IQR Method</span><strong>${r.iqrOutliers}</strong></div>
                        <div><span class="text-muted">Z-Score (2.5σ)</span><strong>${r.zOutliers}</strong></div>
                        <div><span class="text-muted">Extreme (3×IQR)</span><strong>${r.extremeOutliers}</strong></div>
                        <div><span class="text-muted">Fences</span><strong>[${fmt(r.lowerFence)}, ${fmt(r.upperFence)}]</strong></div>
                    </div>
                    ${r.topOutliers.length > 0 ? `
                    <div class="outlier-values">
                        <span class="text-muted" style="font-size:11px">Top outlier values:</span>
                        ${r.topOutliers.map(v => `<span class="outlier-chip">${fmt(v)}</span>`).join('')}
                    </div>` : ''}
                </div>`;
            }).join('')}
        </div>`;
}

// ===== Distribution & Frequency Analysis =====
function renderDistributionAnalysis() {
    const output = document.getElementById('distributionOutput');
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();

    // Read custom controls
    const distBinSetting = document.getElementById('distBinCount')?.value || 'auto';
    const distTopNSetting = document.getElementById('distTopN')?.value || '10';
    const topNCount = distTopNSetting === 'all' ? 9999 : parseInt(distTopNSetting);

    if (nums.length === 0 && cats.length === 0) {
        output.innerHTML = '<div class="analysis-empty"><i class="fas fa-wave-square"></i><p>No columns found for distribution analysis</p></div>';
        return;
    }

    let html = '';

    // Numeric distributions with histograms
    if (nums.length > 0) {
        html += `<div class="stats-section-header" style="margin-bottom:16px;">
            <div class="stats-section-icon" style="background:linear-gradient(135deg,#06b6d4,#0891b2)"><i class="fas fa-wave-square"></i></div>
            <div><h3>Numeric Distributions</h3><p>Frequency distributions and shape analysis</p></div>
        </div>
        <div class="dist-charts-grid">`;

        nums.slice(0, 12).forEach(col => {
            const id = 'dist-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
            html += `<div class="dist-chart-card" data-dist-col="${col}" data-chart-id="${id}">
                ${buildChartToolbar(id, 'bar')}
                <h4>${col}</h4>
                <canvas id="${id}"></canvas>
                <div class="dist-stats" id="distStats-${id}"></div>
            </div>`;
        });
        html += `</div>`;
    }

    // Categorical frequency tables
    if (cats.length > 0) {
        html += `<div class="stats-section-header" style="margin:24px 0 16px;">
            <div class="stats-section-icon" style="background:linear-gradient(135deg,#ec4899,#be185d)"><i class="fas fa-list-ol"></i></div>
            <div><h3>Categorical Frequencies</h3><p>Value distribution for categorical columns</p></div>
        </div>
        <div class="dist-freq-grid">`;

        cats.forEach(col => {
            const freq = {};
            let total = 0;
            excelData.forEach(r => {
                const v = r[col];
                if (v === null || v === undefined || v === '') return;
                const s = String(v).trim();
                freq[s] = (freq[s] || 0) + 1;
                total++;
            });
            const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
            const top10 = sorted.slice(0, topNCount);
            const maxCount = top10.length > 0 ? top10[0][1] : 1;

            html += `
            <div class="dist-freq-card">
                <div class="dist-freq-header">
                    <span>${col}</span>
                    <span class="text-muted">${sorted.length} unique values</span>
                </div>
                <div class="dist-freq-body">
                    ${top10.map(([val, cnt]) => {
                        const pct = ((cnt / total) * 100).toFixed(1);
                        const barW = (cnt / maxCount) * 100;
                        return `
                        <div class="dist-freq-item">
                            <div class="dist-freq-label">${val.length > 25 ? val.substring(0, 22) + '...' : val}</div>
                            <div class="dist-freq-bar-wrap"><div class="dist-freq-bar" style="width:${barW}%"></div></div>
                            <div class="dist-freq-count">${cnt.toLocaleString()} <small>(${pct}%)</small></div>
                        </div>`;
                    }).join('')}
                    ${sorted.length > topNCount ? `<div class="stat-show-all-row">
                        <button class="show-all-values-btn" onclick="showAllValues('${col.replace(/'/g, "\\'")}')"><i class="fas fa-list"></i> Show all ${sorted.length} values</button>
                    </div>` : ''}
                </div>
            </div>`;
        });
        html += `</div>`;
    }

    output.innerHTML = html;

    // Now render charts after DOM is ready
    if (nums.length > 0) {
        setTimeout(() => {
            nums.slice(0, 12).forEach(col => {
                const card = document.querySelector(`[data-dist-col="${col}"]`);
                if (!card) return;
                const chartId = card.getAttribute('data-chart-id');
                const canvas = document.getElementById(chartId);
                if (!canvas) return;

                const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
                if (vals.length < 2) return;

                const sorted = [...vals].sort((a, b) => a - b);
                const min = sorted[0], max = sorted[sorted.length - 1], range = max - min;
                if (range === 0) return;

                const binCount = distBinSetting === 'auto' ? Math.min(25, Math.max(5, Math.ceil(Math.sqrt(vals.length)))) : parseInt(distBinSetting);
                const binWidth = range / binCount;
                const bins = Array(binCount).fill(0);
                const binLabels = [];
                for (let i = 0; i < binCount; i++) {
                    const lo = min + i * binWidth;
                    binLabels.push(lo.toFixed(range > 100 ? 0 : 1));
                }
                vals.forEach(v => { let idx = Math.floor((v - min) / binWidth); if (idx >= binCount) idx = binCount - 1; bins[idx]++; });

                // Normality test (Jarque-Bera approximation)
                const n = vals.length;
                const mean = vals.reduce((a, b) => a + b, 0) / n;
                const sd = Math.sqrt(vals.reduce((s, v) => s + (v - mean) ** 2, 0) / n);
                const skew = sd > 0 ? (vals.reduce((s, v) => s + ((v - mean) / sd) ** 3, 0) / n) : 0;
                const kurt = sd > 0 ? (vals.reduce((s, v) => s + ((v - mean) / sd) ** 4, 0) / n - 3) : 0;
                const jb = (n / 6) * (skew ** 2 + (kurt ** 2) / 4);
                const normalish = jb < 6;

                // Stats below chart
                const statsEl = document.getElementById('distStats-' + chartId);
                if (statsEl) {
                    statsEl.innerHTML = `
                        <span><b>μ</b> ${mean.toFixed(2)}</span>
                        <span><b>σ</b> ${sd.toFixed(2)}</span>
                        <span><b>Skew</b> ${skew.toFixed(2)}</span>
                        <span title="Jarque-Bera: ${jb.toFixed(1)}"><b>Normal?</b> <span style="color:${normalish ? '#10b981' : '#f59e0b'}">${normalish ? 'Likely' : 'Unlikely'}</span></span>
                    `;
                }

                // Normal curve overlay
                const normalData = binLabels.map((_, i) => {
                    const x = min + (i + 0.5) * binWidth;
                    if (sd === 0) return 0;
                    const z = (x - mean) / sd;
                    return (vals.length * binWidth) * (1 / (sd * Math.sqrt(2 * Math.PI))) * Math.exp(-0.5 * z * z);
                });

                const ctx = canvas.getContext('2d');
                const distChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: binLabels,
                        datasets: [
                            {
                                label: 'Frequency',
                                data: bins,
                                backgroundColor: 'rgba(6,182,212,0.5)',
                                borderColor: '#06b6d4',
                                borderWidth: 1,
                                borderRadius: 2,
                                barPercentage: 1,
                                categoryPercentage: 1,
                                order: 2
                            },
                            {
                                label: 'Normal Curve',
                                data: normalData,
                                type: 'line',
                                borderColor: '#f59e0b',
                                backgroundColor: 'transparent',
                                borderWidth: 2,
                                pointRadius: 0,
                                tension: 0.4,
                                order: 1
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 9 } }, grid: { display: false } },
                            y: { ticks: { color: '#9ca3b8', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' } }
                        }
                    }
                });
                activeCharts.push(distChart);
                registerChart(chartId, distChart, `${col} Distribution`);
            });
        }, 50);
    }
}

// ===== Trend & Time-Series Analysis =====
function renderTrendAnalysis() {
    const output = document.getElementById('trendsOutput');
    const dateCols = getDateColumns();
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();

    // Read custom controls
    const trendGroupBySetting = document.getElementById('trendGroupBy')?.value || 'auto';
    const trendMAWindowSetting = document.getElementById('trendMAWindow')?.value || 'auto';

    // Also try to detect date-like strings
    const potentialDateCols = [...dateCols];
    excelColumns.forEach(col => {
        if (potentialDateCols.includes(col)) return;
        if (excelColumnTypes[col] === 'text' || excelColumnTypes[col] === 'categorical') {
            const sample = excelData.slice(0, 20).map(r => r[col]).filter(Boolean);
            const dateCount = sample.filter(v => {
                const d = new Date(v);
                return d instanceof Date && !isNaN(d) && d.getFullYear() > 1900 && d.getFullYear() < 2100;
            }).length;
            if (dateCount > sample.length * 0.6) potentialDateCols.push(col);
        }
    });

    if (potentialDateCols.length === 0) {
        // No dates — show Pareto analysis instead
        output.innerHTML = renderParetoAnalysis();
        return;
    }

    let html = `<div class="stats-section-header" style="margin-bottom:16px;">
        <div class="stats-section-icon" style="background:linear-gradient(135deg,#f59e0b,#d97706)"><i class="fas fa-chart-line"></i></div>
        <div><h3>Trend & Time-Series Analysis</h3><p>Patterns over time with moving averages</p></div>
    </div>
    <div class="trend-charts-grid">`;

    const dateCol = potentialDateCols[0];

    // Parse and sort by date
    const dated = excelData.map(r => {
        let d = r[dateCol];
        if (!(d instanceof Date)) d = new Date(d);
        return { date: d, row: r };
    }).filter(r => r.date instanceof Date && !isNaN(r.date))
      .sort((a, b) => a.date - b.date);

    if (dated.length < 3) {
        output.innerHTML = '<div class="analysis-empty"><i class="fas fa-chart-line"></i><p>Not enough dated records for trend analysis</p></div>';
        return;
    }

    // Time range info
    const firstDate = dated[0].date;
    const lastDate = dated[dated.length - 1].date;
    const daySpan = Math.ceil((lastDate - firstDate) / (1000 * 60 * 60 * 24));
    const groupBy = trendGroupBySetting !== 'auto' ? trendGroupBySetting : (daySpan > 365 * 2 ? 'year' : daySpan > 90 ? 'month' : daySpan > 14 ? 'week' : 'day');

    function dateKey(d) {
        if (groupBy === 'year') return d.getFullYear().toString();
        if (groupBy === 'month') return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        if (groupBy === 'week') {
            const start = new Date(d.getFullYear(), 0, 1);
            const week = Math.ceil(((d - start) / 86400000 + start.getDay() + 1) / 7);
            return `${d.getFullYear()}-W${String(week).padStart(2, '0')}`;
        }
        return d.toISOString().split('T')[0];
    }

    // 1. Record count over time
    const countByPeriod = {};
    dated.forEach(r => {
        const k = dateKey(r.date);
        countByPeriod[k] = (countByPeriod[k] || 0) + 1;
    });
    const periods = Object.keys(countByPeriod).sort();
    const counts = periods.map(p => countByPeriod[p]);

    // Moving average
    function movingAvg(arr, window) {
        return arr.map((_, i) => {
            const start = Math.max(0, i - window + 1);
            const slice = arr.slice(start, i + 1);
            return slice.reduce((a, b) => a + b, 0) / slice.length;
        });
    }
    const maWindow = trendMAWindowSetting !== 'auto' ? parseInt(trendMAWindowSetting) : Math.max(3, Math.floor(periods.length / 5));
    const ma = movingAvg(counts, maWindow);

    // Growth rate
    const growth = counts.map((v, i) => i === 0 ? 0 : ((v - counts[i - 1]) / (counts[i - 1] || 1) * 100));
    const avgGrowth = growth.length > 1 ? (growth.slice(1).reduce((a, b) => a + b, 0) / (growth.length - 1)).toFixed(1) : '0';
    const trend = counts.length > 1 ? (counts[counts.length - 1] >= counts[0] ? 'Upward' : 'Downward') : 'Flat';

    const countChartId = 'trend-count-' + Date.now();
    html += `
        <div class="trend-chart-card wide">
            ${buildChartToolbar(countChartId, 'line')}
            <div class="trend-chart-header">
                <h4><i class="fas fa-chart-area"></i> Records Over Time (by ${groupBy})</h4>
                <div class="trend-meta">
                    <span class="trend-tag"><i class="fas fa-calendar"></i> ${periods.length} ${groupBy}s</span>
                    <span class="trend-tag" style="color:${trend === 'Upward' ? '#10b981' : '#ef4444'}"><i class="fas fa-arrow-${trend === 'Upward' ? 'up' : 'down'}"></i> ${trend}</span>
                    <span class="trend-tag"><i class="fas fa-percentage"></i> Avg ${avgGrowth}% / ${groupBy}</span>
                </div>
            </div>
            <canvas id="${countChartId}"></canvas>
        </div>`;

    // 2. Numeric column trends
    const trendNums = nums.slice(0, 4);
    trendNums.forEach(numCol => {
        const aggByPeriod = {};
        dated.forEach(r => {
            const k = dateKey(r.date);
            const v = parseFloat(r.row[numCol]);
            if (isNaN(v)) return;
            if (!aggByPeriod[k]) aggByPeriod[k] = { sum: 0, count: 0 };
            aggByPeriod[k].sum += v;
            aggByPeriod[k].count++;
        });
        const tPeriods = periods.filter(p => aggByPeriod[p]);
        if (tPeriods.length < 2) return;
        const tAvgs = tPeriods.map(p => aggByPeriod[p] ? (aggByPeriod[p].sum / aggByPeriod[p].count) : 0);
        const tMA = movingAvg(tAvgs, maWindow);

        const chartId = 'trend-num-' + Date.now() + '-' + Math.random().toString(36).substr(2, 4);
        html += `
        <div class="trend-chart-card">
            ${buildChartToolbar(chartId, 'line')}
            <h4><i class="fas fa-chart-line"></i> ${numCol} — Avg by ${groupBy}</h4>
            <canvas id="${chartId}" data-trend-periods='${JSON.stringify(tPeriods)}' data-trend-values='${JSON.stringify(tAvgs)}' data-trend-ma='${JSON.stringify(tMA)}' data-trend-label="${numCol}"></canvas>
        </div>`;
    });

    // 3. Categorical breakdown over time (top category by period)
    if (cats.length > 0) {
        const catCol = cats[0];
        const catByPeriod = {};
        dated.forEach(r => {
            const k = dateKey(r.date);
            const v = String(r.row[catCol]).trim();
            if (!v) return;
            if (!catByPeriod[k]) catByPeriod[k] = {};
            catByPeriod[k][v] = (catByPeriod[k][v] || 0) + 1;
        });

        // Get top 5 categories overall
        const overallFreq = {};
        dated.forEach(r => { const v = String(r.row[catCol]).trim(); if (v) overallFreq[v] = (overallFreq[v] || 0) + 1; });
        const topCats = Object.entries(overallFreq).sort((a, b) => b[1] - a[1]).slice(0, 5).map(e => e[0]);

        const stackedId = 'trend-stacked-' + Date.now();
        html += `
        <div class="trend-chart-card wide">
            ${buildChartToolbar(stackedId, 'bar')}
            <h4><i class="fas fa-layer-group"></i> ${catCol} — Breakdown Over Time</h4>
            <canvas id="${stackedId}" data-trend-cat-col="${catCol}" data-trend-cats='${JSON.stringify(topCats)}' data-trend-cat-data='${JSON.stringify(catByPeriod)}' data-trend-cat-periods='${JSON.stringify(periods)}'></canvas>
        </div>`;
    }

    html += `</div>`;
    output.innerHTML = html;

    // Render all trend charts after DOM is ready
    setTimeout(() => {
        // Count chart
        const countCanvas = document.getElementById(countChartId);
        if (countCanvas) {
            const countChart = new Chart(countCanvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: periods.map(p => p.length > 7 ? p.substring(5) : p),
                    datasets: [
                        { label: 'Count', data: counts, borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.3, pointRadius: periods.length > 30 ? 0 : 3 },
                        { label: 'Moving Avg', data: ma, borderColor: '#f59e0b', borderDash: [5, 3], borderWidth: 2, pointRadius: 0, tension: 0.4, fill: false }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { labels: { color: '#9ca3b8' } } },
                    scales: {
                        x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 10 }, maxTicksLimit: 20 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                        y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
                    }
                }
            });
            activeCharts.push(countChart);
            registerChart(countChartId, countChart, 'Records Over Time');
        }

        // Numeric trend charts
        document.querySelectorAll('canvas[data-trend-periods]').forEach(canvas => {
            const p = JSON.parse(canvas.getAttribute('data-trend-periods'));
            const v = JSON.parse(canvas.getAttribute('data-trend-values'));
            const m = JSON.parse(canvas.getAttribute('data-trend-ma'));
            const label = canvas.getAttribute('data-trend-label');
            const trendNumChart = new Chart(canvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: p.map(x => x.length > 7 ? x.substring(5) : x),
                    datasets: [
                        { label: `Avg ${label}`, data: v.map(x => Math.round(x * 100) / 100), borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.1)', fill: true, tension: 0.3, pointRadius: p.length > 30 ? 0 : 3 },
                        { label: 'Moving Avg', data: m.map(x => Math.round(x * 100) / 100), borderColor: '#f59e0b', borderDash: [5, 3], borderWidth: 2, pointRadius: 0, tension: 0.4, fill: false }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { labels: { color: '#9ca3b8' } } },
                    scales: {
                        x: { ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 9 }, maxTicksLimit: 15 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                        y: { ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
                    }
                }
            });
            activeCharts.push(trendNumChart);
            registerChart(canvas.id, trendNumChart, `${label} Trend`);
        });

        // Stacked category chart
        const stackedCanvas = document.querySelector('canvas[data-trend-cat-col]');
        if (stackedCanvas) {
            const topCats = JSON.parse(stackedCanvas.getAttribute('data-trend-cats'));
            const catByPeriod = JSON.parse(stackedCanvas.getAttribute('data-trend-cat-data'));
            const allPeriods = JSON.parse(stackedCanvas.getAttribute('data-trend-cat-periods'));
            const stackedChart = new Chart(stackedCanvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: allPeriods.map(p => p.length > 7 ? p.substring(5) : p),
                    datasets: topCats.map((cat, i) => ({
                        label: cat.length > 20 ? cat.substring(0, 17) + '...' : cat,
                        data: allPeriods.map(p => (catByPeriod[p] && catByPeriod[p][cat]) || 0),
                        backgroundColor: CHART_COLORS[i % CHART_COLORS.length] + 'cc',
                        borderColor: CHART_COLORS[i % CHART_COLORS.length],
                        borderWidth: 1
                    }))
                },
                options: {
                    responsive: true,
                    plugins: { legend: { labels: { color: '#9ca3b8', font: { size: 11 } } } },
                    scales: {
                        x: { stacked: true, ticks: { color: '#9ca3b8', maxRotation: 45, font: { size: 9 }, maxTicksLimit: 20 }, grid: { color: 'rgba(255,255,255,0.04)' } },
                        y: { stacked: true, ticks: { color: '#9ca3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }
                    }
                }
            });
            activeCharts.push(stackedChart);
            registerChart(stackedCanvas.id, stackedChart, 'Category Breakdown Over Time');
        }
    }, 50);
}

// ===== Pareto & Top-N Analysis (fallback when no dates) =====
function renderParetoAnalysis() {
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();

    let html = `<div class="stats-section-header" style="margin-bottom:16px;">
        <div class="stats-section-icon" style="background:linear-gradient(135deg,#f59e0b,#d97706)"><i class="fas fa-sort-amount-down"></i></div>
        <div><h3>Pareto & Top-N Analysis</h3><p>80/20 rule analysis — no date columns detected, showing ranking insights instead</p></div>
    </div>
    <div class="pareto-grid">`;

    // For each categorical column with a numeric value, do Pareto
    if (cats.length > 0 && nums.length > 0) {
        cats.slice(0, 4).forEach(catCol => {
            const numCol = nums[0];
            const agg = {};
            excelData.forEach(r => {
                const label = String(r[catCol]).trim();
                const val = parseFloat(r[numCol]);
                if (!label || isNaN(val)) return;
                agg[label] = (agg[label] || 0) + val;
            });
            const sorted = Object.entries(agg).sort((a, b) => b[1] - a[1]);
            const total = sorted.reduce((s, e) => s + e[1], 0);
            let cumulative = 0;
            const top20Count = Math.ceil(sorted.length * 0.2);
            const top20Sum = sorted.slice(0, top20Count).reduce((s, e) => s + e[1], 0);
            const top20Pct = ((top20Sum / total) * 100).toFixed(1);

            const top10 = sorted.slice(0, 10).map(([k, v]) => {
                cumulative += v;
                return { label: k, value: v, pct: ((v / total) * 100).toFixed(1), cumPct: ((cumulative / total) * 100).toFixed(1) };
            });

            html += `
            <div class="pareto-card">
                <div class="pareto-header">
                    <h4>${catCol} → ${numCol}</h4>
                    <div class="pareto-rule">Top 20% (${top20Count}) = <strong>${top20Pct}%</strong> of total</div>
                </div>
                <div class="pareto-table">
                    <div class="pareto-row head"><span>#</span><span>Category</span><span>Value</span><span>%</span><span>Cum %</span></div>
                    ${top10.map((r, i) => `
                    <div class="pareto-row${parseFloat(r.cumPct) <= 80 ? ' highlight' : ''}">
                        <span>${i + 1}</span>
                        <span title="${r.label}">${r.label.length > 18 ? r.label.substring(0, 15) + '...' : r.label}</span>
                        <span>${Number(r.value).toLocaleString(undefined, { maximumFractionDigits: 1 })}</span>
                        <span>${r.pct}%</span>
                        <span><strong>${r.cumPct}%</strong></span>
                    </div>`).join('')}
                </div>
                ${sorted.length > 10 ? `<div class="text-muted" style="text-align:center;font-size:12px;margin-top:8px">+ ${sorted.length - 10} more categories</div>` : ''}
            </div>`;
        });
    } else if (cats.length > 0) {
        // Just frequency Pareto
        cats.slice(0, 4).forEach(catCol => {
            const freq = {};
            excelData.forEach(r => { const v = String(r[catCol]).trim(); if (v) freq[v] = (freq[v] || 0) + 1; });
            const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
            const total = sorted.reduce((s, e) => s + e[1], 0);
            let cumulative = 0;
            const top10 = sorted.slice(0, 10).map(([k, v]) => {
                cumulative += v;
                return { label: k, value: v, pct: ((v / total) * 100).toFixed(1), cumPct: ((cumulative / total) * 100).toFixed(1) };
            });

            html += `
            <div class="pareto-card">
                <div class="pareto-header"><h4>${catCol} — Frequency Ranking</h4></div>
                <div class="pareto-table">
                    <div class="pareto-row head"><span>#</span><span>Value</span><span>Count</span><span>%</span><span>Cum %</span></div>
                    ${top10.map((r, i) => `
                    <div class="pareto-row${parseFloat(r.cumPct) <= 80 ? ' highlight' : ''}">
                        <span>${i + 1}</span><span>${r.label.length > 18 ? r.label.substring(0, 15) + '...' : r.label}</span>
                        <span>${r.value.toLocaleString()}</span><span>${r.pct}%</span><span><strong>${r.cumPct}%</strong></span>
                    </div>`).join('')}
                </div>
            </div>`;
        });
    }

    html += `</div>`;
    return html;
}

// ===== Data Quality =====
function renderDataQuality() {
    const output = document.getElementById('dataQualityOutput');
    const totalCells = excelData.length * excelColumns.length;

    const colStats = excelColumns.map(col => {
        const missing = excelData.filter(r => r[col] === null || r[col] === undefined || r[col] === '').length;
        const filled = excelData.length - missing;
        const completeness = ((filled / excelData.length) * 100);
        const unique = new Set(excelData.map(r => String(r[col]).trim())).size;
        const type = excelColumnTypes[col];
        return { col, missing, filled, completeness, unique, type };
    });

    const totalFilled = colStats.reduce((s, c) => s + c.filled, 0);
    const overallCompleteness = ((totalFilled / totalCells) * 100).toFixed(1);
    const duplicateRows = excelData.length - new Set(excelData.map(r => JSON.stringify(r))).size;

    const qualityClass = (pct) => pct >= 90 ? 'good' : pct >= 70 ? 'medium' : 'poor';
    const scoreColor = parseFloat(overallCompleteness) >= 90 ? '#10b981' : parseFloat(overallCompleteness) >= 70 ? '#f59e0b' : '#ef4444';

    output.innerHTML = `
        <div class="dq-hero">
            <div class="dq-hero-ring" style="--ring-color:${scoreColor}">
                <div class="dq-hero-score" style="color:${scoreColor}">${overallCompleteness}<span>%</span></div>
                <div class="dq-hero-label">Data Quality</div>
            </div>
            <div class="dq-hero-stats">
                <div class="dq-hero-stat">
                    <div class="dq-hero-stat-value">${excelData.length.toLocaleString()}</div>
                    <div class="dq-hero-stat-label">Total Records</div>
                </div>
                <div class="dq-hero-stat">
                    <div class="dq-hero-stat-value" style="color:${duplicateRows > 0 ? '#f59e0b' : '#10b981'}">${duplicateRows.toLocaleString()}</div>
                    <div class="dq-hero-stat-label">Duplicate Rows</div>
                </div>
                <div class="dq-hero-stat">
                    <div class="dq-hero-stat-value">${excelColumns.length}</div>
                    <div class="dq-hero-stat-label">Total Fields</div>
                </div>
            </div>
        </div>
        <div class="quality-grid">
            ${colStats.sort((a, b) => a.completeness - b.completeness).map(s => `
                <div class="quality-card">
                    <h4><span style="color:var(--accent)">${s.col}</span> <span style="font-weight:400;font-size:11px;color:var(--text-muted)">(${s.type})</span></h4>
                    <div class="quality-bar"><div class="quality-bar-fill ${qualityClass(s.completeness)}" style="width:${s.completeness}%"></div></div>
                    <div class="quality-stat"><span>Completeness</span><span class="value">${s.completeness.toFixed(1)}%</span></div>
                    <div class="quality-stat"><span>Missing values</span><span class="value">${s.missing.toLocaleString()}</span></div>
                    <div class="quality-stat"><span>Unique values</span><span class="value">${s.unique.toLocaleString()}</span></div>
                    <div class="quality-stat"><span>Filled rows</span><span class="value">${s.filled.toLocaleString()} / ${excelData.length.toLocaleString()}</span></div>
                </div>
            `).join('')}
        </div>`;
}

// ===== Data Table =====
function getFilteredData() {
    return excelData.filter(row => {
        // Apply column filters
        for (const col in tableFilters) {
            if (tableFilters[col].size === 0) continue;
            let val = row[col];
            if (val instanceof Date) val = val.toLocaleDateString('en-IN');
            else if (val === null || val === undefined) val = '(Blank)';
            else val = String(val);
            if (!tableFilters[col].has(val)) return false;
        }
        // Apply global search
        if (tableSearchTerm) {
            const term = tableSearchTerm.toLowerCase();
            const match = excelColumns.some(c => {
                let v = row[c];
                if (v === null || v === undefined) return false;
                return String(v).toLowerCase().includes(term);
            });
            if (!match) return false;
        }
        return true;
    });
}

function getUniqueValues(col) {
    const counts = {};
    excelData.forEach(row => {
        let val = row[col];
        if (val instanceof Date) val = val.toLocaleDateString('en-IN');
        else if (val === null || val === undefined) val = '(Blank)';
        else val = String(val);
        counts[val] = (counts[val] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

function toggleFilterDropdown(col) {
    const existing = document.getElementById('filter-dropdown-' + CSS.escape(col));
    // Close all other dropdowns
    document.querySelectorAll('.filter-dropdown').forEach(d => {
        if (d.id !== 'filter-dropdown-' + CSS.escape(col)) d.remove();
    });
    if (existing) { existing.remove(); return; }

    const th = document.querySelector(`[data-filter-col="${CSS.escape(col)}"]`);
    if (!th) return;

    const uniqueVals = getUniqueValues(col);
    const activeSet = tableFilters[col] || new Set();
    const allSelected = activeSet.size === 0;

    const dropdown = document.createElement('div');
    dropdown.className = 'filter-dropdown';
    dropdown.id = 'filter-dropdown-' + CSS.escape(col);
    dropdown.innerHTML = `
        <div class="filter-dropdown-search">
            <input type="text" placeholder="Search..." class="filter-search-input" />
        </div>
        <div class="filter-dropdown-actions">
            <button class="filter-action-btn" onclick="filterSelectAll('${col.replace(/'/g, "\\'")}')">Select All</button>
            <button class="filter-action-btn" onclick="filterClearAll('${col.replace(/'/g, "\\'")}')">Clear</button>
        </div>
        <div class="filter-dropdown-list">
            ${uniqueVals.map(([val, count]) => {
                const checked = allSelected || activeSet.has(val) ? 'checked' : '';
                const escaped = val.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
                return `<label class="filter-option">
                    <input type="checkbox" ${checked} data-filter-val="${escaped}" />
                    <span class="filter-option-text">${escaped}</span>
                    <span class="filter-option-count">${count.toLocaleString()}</span>
                </label>`;
            }).join('')}
        </div>
        <div class="filter-dropdown-footer">
            <button class="filter-apply-btn" onclick="applyFilter('${col.replace(/'/g, "\\'")}')">Apply</button>
        </div>
    `;

    th.style.position = 'relative';
    th.appendChild(dropdown);

    // Search within dropdown
    const searchInput = dropdown.querySelector('.filter-search-input');
    searchInput.focus();
    searchInput.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        dropdown.querySelectorAll('.filter-option').forEach(opt => {
            const text = opt.querySelector('.filter-option-text').textContent.toLowerCase();
            opt.style.display = text.includes(term) ? '' : 'none';
        });
    });

    // Close on click outside
    setTimeout(() => {
        const closeHandler = (e) => {
            if (!dropdown.contains(e.target) && e.target !== th.querySelector('.filter-icon')) {
                dropdown.remove();
                document.removeEventListener('click', closeHandler);
            }
        };
        document.addEventListener('click', closeHandler);
    }, 10);
}

function filterSelectAll(col) {
    const dd = document.querySelector(`#filter-dropdown-${CSS.escape(col)}`);
    if (dd) dd.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = true);
}

function filterClearAll(col) {
    const dd = document.querySelector(`#filter-dropdown-${CSS.escape(col)}`);
    if (dd) dd.querySelectorAll('input[type=checkbox]').forEach(cb => cb.checked = false);
}

function applyFilter(col) {
    const dd = document.querySelector(`#filter-dropdown-${CSS.escape(col)}`);
    if (!dd) return;
    const checked = [...dd.querySelectorAll('input[type=checkbox]:checked')].map(cb => cb.getAttribute('data-filter-val').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&quot;/g, '"'));
    const total = dd.querySelectorAll('input[type=checkbox]').length;

    if (checked.length === total || checked.length === 0) {
        delete tableFilters[col];
    } else {
        tableFilters[col] = new Set(checked);
    }
    tablePage = 0;
    dd.remove();
    renderDataTable();
}

function clearAllFilters() {
    tableFilters = {};
    tableSearchTerm = '';
    tablePage = 0;
    const si = document.getElementById('tableGlobalSearch');
    if (si) si.value = '';
    renderDataTable();
}

function renderDataTable() {
    const filtered = getFilteredData();
    const totalPages = Math.max(1, Math.ceil(filtered.length / TABLE_PAGE_SIZE));
    if (tablePage >= totalPages) tablePage = totalPages - 1;
    const start = tablePage * TABLE_PAGE_SIZE;
    const displayData = filtered.slice(start, start + TABLE_PAGE_SIZE);

    const activeFilterCount = Object.keys(tableFilters).filter(k => tableFilters[k].size > 0).length;
    const countLabel = filtered.length === excelData.length
        ? `Showing ${start + 1}–${start + displayData.length} of ${excelData.length.toLocaleString()} rows`
        : `Showing ${start + 1}–${start + displayData.length} of ${filtered.length.toLocaleString()} filtered (${excelData.length.toLocaleString()} total)`;
    document.getElementById('excelRowCount').textContent = countLabel;

    // Build filter bar
    const filterBar = `<div class="table-filter-bar">
        <div class="table-search-wrap">
            <i class="fas fa-search"></i>
            <input type="text" id="tableGlobalSearch" class="table-search-input" placeholder="Search all columns..." value="${tableSearchTerm.replace(/"/g, '&quot;')}" />
        </div>
        <div class="table-filter-info">
            ${activeFilterCount > 0 ? `<span class="active-filter-badge">${activeFilterCount} filter${activeFilterCount > 1 ? 's' : ''} active</span>
            <button class="clear-filters-btn" onclick="clearAllFilters()"><i class="fas fa-times"></i> Clear All</button>` : ''}
        </div>
    </div>`;

    // Build column headers with filter icons
    const headers = excelColumns.map(c => {
        const isFiltered = tableFilters[c] && tableFilters[c].size > 0;
        return `<th data-filter-col="${c.replace(/"/g, '&quot;')}">
            <div class="th-filter-wrap">
                <span>${c}</span>
                <button class="filter-icon ${isFiltered ? 'active' : ''}" onclick="event.stopPropagation(); toggleFilterDropdown('${c.replace(/'/g, "\\'")}')" title="Filter ${c}">
                    <i class="fas fa-filter"></i>
                </button>
            </div>
        </th>`;
    }).join('');

    // Build pagination
    const pagination = totalPages > 1 ? `<div class="table-pagination">
        <button class="table-page-btn" onclick="tablePage=0; renderDataTable()" ${tablePage === 0 ? 'disabled' : ''}><i class="fas fa-angle-double-left"></i></button>
        <button class="table-page-btn" onclick="tablePage--; renderDataTable()" ${tablePage === 0 ? 'disabled' : ''}><i class="fas fa-angle-left"></i></button>
        <span class="table-page-info">Page ${tablePage + 1} of ${totalPages}</span>
        <button class="table-page-btn" onclick="tablePage++; renderDataTable()" ${tablePage >= totalPages - 1 ? 'disabled' : ''}><i class="fas fa-angle-right"></i></button>
        <button class="table-page-btn" onclick="tablePage=${totalPages - 1}; renderDataTable()" ${tablePage >= totalPages - 1 ? 'disabled' : ''}><i class="fas fa-angle-double-right"></i></button>
    </div>` : '';

    const table = `${filterBar}
    <table class="excel-data-table">
        <thead><tr>${headers}</tr></thead>
        <tbody>${displayData.map(row =>
        `<tr>${excelColumns.map(c => {
            let val = row[c];
            if (val instanceof Date) val = val.toLocaleDateString('en-IN');
            else if (val === null || val === undefined) val = '';
            return `<td>${String(val).substring(0, 80)}</td>`;
        }).join('')}</tr>`
    ).join('')}</tbody>
    </table>
    ${pagination}`;

    document.getElementById('excelTableContainer').innerHTML = table;

    // Attach global search handler
    const searchEl = document.getElementById('tableGlobalSearch');
    if (searchEl) {
        searchEl.addEventListener('input', (e) => {
            tableSearchTerm = e.target.value;
            tablePage = 0;
            renderDataTable();
        });
        // Restore focus and cursor position after re-render
        if (tableSearchTerm) {
            searchEl.focus();
            searchEl.setSelectionRange(searchEl.value.length, searchEl.value.length);
        }
    }
}

// ===== Data Export =====
function exportAllDataToExcel() {
    const wb = XLSX.utils.book_new();

    // Visits
    const visits = DB.get('visits');
    if (visits.length > 0) {
        const ws = XLSX.utils.json_to_sheet(visits.map(v => ({
            School: v.school, Block: v.block, Date: v.date, Status: v.status,
            Purpose: v.purpose, Notes: v.notes, 'Follow Up': v.followUp
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Visits');
    }

    // Trainings
    const trainings = DB.get('trainings');
    if (trainings.length > 0) {
        const ws = XLSX.utils.json_to_sheet(trainings.map(t => ({
            Title: t.title, Topic: t.topic, Date: t.date, Duration: t.duration,
            Venue: t.venue, Status: t.status, Attendees: t.attendees,
            Target: t.target, Notes: t.notes, Feedback: t.feedback
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Trainings');
    }

    // Observations
    const observations = DB.get('observations');
    if (observations.length > 0) {
        const ws = XLSX.utils.json_to_sheet(observations.map(o => ({
            School: o.school, Teacher: o.teacher, Date: o.date,
            Class: o.class, Subject: o.subject, Topic: o.topic,
            'Engagement Rating': o.engagement, 'Methodology Rating': o.methodology,
            'TLM Usage Rating': o.tlm, Strengths: o.strengths,
            'Areas of Improvement': o.areas, Suggestions: o.suggestions
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Observations');
    }

    // Resources
    const resources = DB.get('resources');
    if (resources.length > 0) {
        const ws = XLSX.utils.json_to_sheet(resources.map(r => ({
            Title: r.title, Type: r.type, Subject: r.subject,
            Grade: r.grade, Source: r.source, Description: r.description,
            Tags: (r.tags || []).join(', ')
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Resources');
    }

    // Notes
    const notes = DB.get('notes');
    if (notes.length > 0) {
        const ws = XLSX.utils.json_to_sheet(notes.map(n => ({
            Title: n.title, Content: n.content, Color: n.color, 'Created At': n.createdAt
        })));
        XLSX.utils.book_append_sheet(wb, ws, 'Notes');
    }

    if (wb.SheetNames.length === 0) {
        showToast('No data to export', 'error');
        return;
    }

    XLSX.writeFile(wb, `APF_Dashboard_Export_${new Date().toISOString().split('T')[0]}.xlsx`);
    showToast('Dashboard data exported successfully!');
}

// ===== Smart Report Generator =====
function generateSmartReport() {
    if (!excelData || excelData.length === 0) {
        showToast('No data loaded for report', 'error');
        return;
    }

    const nums = getNumericColumns();
    const cats = getCategoricalColumns();
    const dates = getDateColumns();
    const fileName = document.getElementById('excelFileName')?.textContent || 'Data';
    const now = new Date();
    const dateStr = now.toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' });
    const timeStr = now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
    const fmt = v => typeof v === 'number' ? (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(2)) : v;

    // Data completeness
    const filled = excelData.reduce((s, row) => s + excelColumns.filter(c => row[c] !== null && row[c] !== undefined && row[c] !== '').length, 0);
    const totalCells = excelData.length * excelColumns.length;
    const completeness = ((filled / totalCells) * 100).toFixed(1);
    const missingCells = totalCells - filled;

    // Duplicates
    const rowKeys = excelData.map(r => excelColumns.map(c => String(r[c] ?? '')).join('|'));
    const uniqueRows = new Set(rowKeys).size;
    const dupes = excelData.length - uniqueRows;

    // Per-column missing
    const colMissing = {};
    excelColumns.forEach(col => {
        const missing = excelData.filter(r => r[col] === null || r[col] === undefined || r[col] === '').length;
        colMissing[col] = missing;
    });

    // Numeric stats
    const numStats = {};
    nums.forEach(col => {
        const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
        if (vals.length === 0) return;
        const sorted = [...vals].sort((a, b) => a - b);
        const sum = vals.reduce((a, b) => a + b, 0);
        const mean = sum / vals.length;
        const min = sorted[0], max = sorted[sorted.length - 1];
        const median = sorted.length % 2 === 0 ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2 : sorted[Math.floor(sorted.length / 2)];
        const sd = Math.sqrt(vals.reduce((s, v) => s + (v - mean) ** 2, 0) / vals.length);
        const q1 = sorted[Math.floor(sorted.length * 0.25)];
        const q3 = sorted[Math.floor(sorted.length * 0.75)];
        const iqr = q3 - q1;
        const outliers = vals.filter(v => v < q1 - 1.5 * iqr || v > q3 + 1.5 * iqr).length;
        const cv = mean !== 0 ? ((sd / Math.abs(mean)) * 100).toFixed(1) : 'N/A';
        const skewness = vals.length > 2 ? (vals.reduce((s, v) => s + ((v - mean) / sd) ** 3, 0) / vals.length).toFixed(2) : 'N/A';
        numStats[col] = { count: vals.length, sum, mean, median, min, max, sd, q1, q3, iqr, outliers, cv, skewness, range: max - min };
    });

    // Categorical stats
    const catStats = {};
    cats.forEach(col => {
        const freq = {};
        let total = 0;
        excelData.forEach(r => {
            const v = r[col];
            if (v === null || v === undefined || v === '') return;
            const s = String(v).trim();
            freq[s] = (freq[s] || 0) + 1;
            total++;
        });
        const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
        catStats[col] = { unique: sorted.length, total, top5: sorted.slice(0, 5), mode: sorted[0]?.[0] || 'N/A', modeCount: sorted[0]?.[1] || 0 };
    });

    // Correlation (top pairs)
    const corrPairs = [];
    for (let i = 0; i < nums.length; i++) {
        for (let j = i + 1; j < nums.length; j++) {
            const col1 = nums[i], col2 = nums[j];
            const pairs = excelData.map(r => [parseFloat(r[col1]), parseFloat(r[col2])]).filter(p => !isNaN(p[0]) && !isNaN(p[1]));
            if (pairs.length < 3) continue;
            const n = pairs.length;
            const sumX = pairs.reduce((s, p) => s + p[0], 0), sumY = pairs.reduce((s, p) => s + p[1], 0);
            const sumXY = pairs.reduce((s, p) => s + p[0] * p[1], 0);
            const sumX2 = pairs.reduce((s, p) => s + p[0] ** 2, 0), sumY2 = pairs.reduce((s, p) => s + p[1] ** 2, 0);
            const denom = Math.sqrt((n * sumX2 - sumX ** 2) * (n * sumY2 - sumY ** 2));
            if (denom === 0) continue;
            const r = (n * sumXY - sumX * sumY) / denom;
            corrPairs.push({ col1, col2, r: Math.round(r * 1000) / 1000 });
        }
    }
    corrPairs.sort((a, b) => Math.abs(b.r) - Math.abs(a.r));
    const strongCorrs = corrPairs.filter(p => Math.abs(p.r) >= 0.5);

    // APF fields
    const apfFields = detectAPFFields(excelColumns);

    // Build chart images from existing canvases
    const chartImages = [];
    Object.entries(chartRegistry).forEach(([id, reg]) => {
        if (!reg.chart) return;
        try {
            const canvas = document.getElementById(id);
            if (canvas) chartImages.push({ title: reg.title || 'Chart', src: canvas.toDataURL('image/png', 0.9) });
        } catch(e) {}
    });

    // === BUILD HTML REPORT ===
    let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Smart Report — ${fileName}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
    .report { max-width: 960px; margin: 0 auto; padding: 40px 32px; }
    @media print { body { background: #fff; } .report { padding: 20px; } .no-print { display: none !important; } .page-break { page-break-before: always; } }

    /* Header */
    .report-header { text-align: center; padding: 40px 20px; background: linear-gradient(135deg, #1e293b, #334155); color: #fff; border-radius: 16px; margin-bottom: 32px; position: relative; overflow: hidden; }
    .report-header::before { content: ''; position: absolute; top: -50%; right: -20%; width: 300px; height: 300px; background: rgba(245,158,11,0.1); border-radius: 50%; }
    .report-header h1 { font-size: 28px; font-weight: 800; margin-bottom: 4px; }
    .report-header .subtitle { font-size: 14px; color: #94a3b8; }
    .report-header .meta { display: flex; justify-content: center; gap: 24px; margin-top: 16px; flex-wrap: wrap; }
    .report-header .meta span { font-size: 12px; color: #cbd5e1; display: flex; align-items: center; gap: 6px; }

    /* Action bar */
    .action-bar { display: flex; gap: 10px; justify-content: flex-end; margin-bottom: 20px; }
    .action-btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; font-family: inherit; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }
    .action-btn.primary { background: #f59e0b; color: #000; }
    .action-btn.primary:hover { background: #d97706; }
    .action-btn.secondary { background: #e2e8f0; color: #475569; }
    .action-btn.secondary:hover { background: #cbd5e1; }

    /* Section */
    .section { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .section-title { font-size: 16px; font-weight: 700; color: #1e293b; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; padding-bottom: 10px; border-bottom: 2px solid #f1f5f9; }
    .section-title .icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0; }
    .icon-amber { background: #fef3c7; color: #d97706; }
    .icon-blue { background: #dbeafe; color: #2563eb; }
    .icon-green { background: #d1fae5; color: #059669; }
    .icon-purple { background: #ede9fe; color: #7c3aed; }
    .icon-red { background: #fee2e2; color: #dc2626; }
    .icon-teal { background: #ccfbf1; color: #0d9488; }

    /* KPI Grid */
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .kpi { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; text-align: center; }
    .kpi .value { font-size: 28px; font-weight: 800; color: #1e293b; }
    .kpi .label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-top: 2px; }

    /* Table */
    .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .data-table th { background: #f1f5f9; color: #475569; font-weight: 700; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; padding: 10px 12px; text-align: left; border-bottom: 2px solid #e2e8f0; }
    .data-table td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; color: #334155; }
    .data-table tbody tr:hover { background: #fefce8; }
    .data-table .num { text-align: right; font-variant-numeric: tabular-nums; }

    /* Bar */
    .bar-wrap { display: flex; align-items: center; gap: 8px; }
    .bar-track { flex: 1; height: 8px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #f59e0b, #f97316); }
    .bar-fill.blue { background: linear-gradient(90deg, #3b82f6, #6366f1); }
    .bar-fill.green { background: linear-gradient(90deg, #10b981, #059669); }
    .bar-fill.red { background: linear-gradient(90deg, #ef4444, #dc2626); }

    /* Insight chip */
    .insight-chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 8px; font-size: 12px; font-weight: 500; margin: 3px; }
    .chip-green { background: #d1fae5; color: #065f46; }
    .chip-amber { background: #fef3c7; color: #92400e; }
    .chip-red { background: #fee2e2; color: #991b1b; }
    .chip-blue { background: #dbeafe; color: #1e40af; }
    .chip-purple { background: #ede9fe; color: #5b21b6; }

    /* Correlation badge */
    .corr-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .corr-strong-pos { background: #d1fae5; color: #059669; }
    .corr-strong-neg { background: #fee2e2; color: #dc2626; }
    .corr-moderate { background: #fef3c7; color: #d97706; }

    /* Charts grid */
    .charts-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; margin-top: 16px; }
    .chart-img-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; text-align: center; }
    .chart-img-card img { max-width: 100%; height: auto; border-radius: 6px; }
    .chart-img-card .chart-label { font-size: 12px; font-weight: 600; color: #475569; margin-top: 8px; }

    /* Footer */
    .report-footer { text-align: center; padding: 24px; color: #94a3b8; font-size: 11px; margin-top: 20px; }
</style>
</head>
<body>
<div class="report">`;

    // Action bar
    html += `<div class="action-bar no-print">
        <button class="action-btn secondary" onclick="window.print()">🖨️ Print / Save PDF</button>
        <button class="action-btn primary" onclick="downloadReportHTML()">⬇️ Download HTML</button>
    </div>`;

    // Header
    html += `<div class="report-header">
        <h1>📊 Smart Data Report</h1>
        <div class="subtitle">${fileName}</div>
        <div class="meta">
            <span>📅 ${dateStr} at ${timeStr}</span>
            <span>📋 ${excelData.length.toLocaleString()} records</span>
            <span>📐 ${excelColumns.length} columns</span>
        </div>
    </div>`;

    // 1. Dataset Overview
    html += `<div class="section">
        <div class="section-title"><span class="icon icon-amber">📋</span> Dataset Overview</div>
        <div class="kpi-grid">
            <div class="kpi"><div class="value">${excelData.length.toLocaleString()}</div><div class="label">Total Rows</div></div>
            <div class="kpi"><div class="value">${excelColumns.length}</div><div class="label">Columns</div></div>
            <div class="kpi"><div class="value">${nums.length}</div><div class="label">Numeric</div></div>
            <div class="kpi"><div class="value">${cats.length}</div><div class="label">Categorical</div></div>
            <div class="kpi"><div class="value">${dates.length}</div><div class="label">Date</div></div>
            <div class="kpi"><div class="value">${completeness}%</div><div class="label">Completeness</div></div>
        </div>
        <div style="margin-top:10px;">
            ${dupes > 0 ? `<span class="insight-chip chip-amber">⚠️ ${dupes} duplicate rows found</span>` : `<span class="insight-chip chip-green">✅ No duplicate rows</span>`}
            ${missingCells > 0 ? `<span class="insight-chip chip-red">🔴 ${missingCells.toLocaleString()} missing cells</span>` : `<span class="insight-chip chip-green">✅ No missing data</span>`}
            <span class="insight-chip chip-blue">📊 ${nums.length} numeric, ${cats.length} categorical, ${dates.length} date columns</span>
        </div>
    </div>`;

    // 2. Column Profile
    html += `<div class="section">
        <div class="section-title"><span class="icon icon-blue">📐</span> Column Profile</div>
        <table class="data-table">
            <thead><tr><th>#</th><th>Column Name</th><th>Type</th><th>Filled</th><th>Missing</th><th>Completeness</th></tr></thead>
            <tbody>`;
    excelColumns.forEach((col, i) => {
        const miss = colMissing[col];
        const total = excelData.length;
        const pct = ((total - miss) / total * 100).toFixed(1);
        const barColor = pct >= 90 ? 'green' : pct >= 70 ? '' : 'red';
        html += `<tr>
            <td>${i + 1}</td>
            <td><strong>${col}</strong></td>
            <td>${excelColumnTypes[col] || 'unknown'}</td>
            <td class="num">${(total - miss).toLocaleString()}</td>
            <td class="num">${miss > 0 ? miss.toLocaleString() : '—'}</td>
            <td><div class="bar-wrap"><div class="bar-track"><div class="bar-fill ${barColor}" style="width:${pct}%"></div></div><span style="font-size:11px;font-weight:600;min-width:40px;text-align:right;">${pct}%</span></div></td>
        </tr>`;
    });
    html += `</tbody></table></div>`;

    // 3. Numeric Statistics
    if (nums.length > 0) {
        html += `<div class="section page-break">
            <div class="section-title"><span class="icon icon-green">📈</span> Numeric Statistics</div>
            <table class="data-table">
                <thead><tr><th>Column</th><th class="num">Count</th><th class="num">Min</th><th class="num">Max</th><th class="num">Mean</th><th class="num">Median</th><th class="num">Std Dev</th><th class="num">CV%</th><th class="num">Outliers</th></tr></thead>
                <tbody>`;
        nums.forEach(col => {
            const s = numStats[col];
            if (!s) return;
            html += `<tr>
                <td><strong>${col}</strong></td>
                <td class="num">${s.count.toLocaleString()}</td>
                <td class="num">${fmt(s.min)}</td>
                <td class="num">${fmt(s.max)}</td>
                <td class="num">${fmt(s.mean)}</td>
                <td class="num">${fmt(s.median)}</td>
                <td class="num">${fmt(s.sd)}</td>
                <td class="num">${s.cv}%</td>
                <td class="num">${s.outliers > 0 ? `<span style="color:#dc2626;font-weight:700;">${s.outliers}</span>` : '0'}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
    }

    // 4. Categorical Summary
    if (cats.length > 0) {
        html += `<div class="section">
            <div class="section-title"><span class="icon icon-purple">🏷️</span> Categorical Summary</div>`;
        cats.forEach(col => {
            const s = catStats[col];
            if (!s) return;
            html += `<div style="margin-bottom:20px;">
                <h4 style="font-size:13px;font-weight:700;color:#334155;margin-bottom:8px;">${col} <span style="font-size:11px;font-weight:500;color:#94a3b8;">(${s.unique} unique values)</span></h4>
                <table class="data-table" style="max-width:500px;">
                    <thead><tr><th>Value</th><th class="num">Count</th><th>Share</th></tr></thead>
                    <tbody>`;
            s.top5.forEach(([val, count]) => {
                const pct = ((count / s.total) * 100).toFixed(1);
                html += `<tr><td>${val.length > 40 ? val.substring(0,37)+'...' : val}</td><td class="num">${count.toLocaleString()}</td>
                    <td><div class="bar-wrap"><div class="bar-track"><div class="bar-fill blue" style="width:${pct}%"></div></div><span style="font-size:11px;font-weight:600;min-width:40px;text-align:right;">${pct}%</span></div></td></tr>`;
            });
            if (s.unique > 5) html += `<tr><td colspan="3" style="color:#94a3b8;font-style:italic;">... and ${s.unique - 5} more values</td></tr>`;
            html += `</tbody></table></div>`;
        });
        html += `</div>`;
    }

    // 5. Correlation Analysis
    if (strongCorrs.length > 0) {
        html += `<div class="section">
            <div class="section-title"><span class="icon icon-teal">🔗</span> Notable Correlations</div>
            <table class="data-table" style="max-width:600px;">
                <thead><tr><th>Variable 1</th><th>Variable 2</th><th class="num">Correlation (r)</th><th>Strength</th></tr></thead>
                <tbody>`;
        strongCorrs.slice(0, 10).forEach(p => {
            const abs = Math.abs(p.r);
            const cls = p.r >= 0.7 ? 'corr-strong-pos' : p.r <= -0.7 ? 'corr-strong-neg' : 'corr-moderate';
            const label = abs >= 0.8 ? 'Strong' : abs >= 0.6 ? 'Moderate' : 'Notable';
            const dir = p.r > 0 ? '↑ Positive' : '↓ Negative';
            html += `<tr><td>${p.col1}</td><td>${p.col2}</td><td class="num"><span class="corr-badge ${cls}">${p.r.toFixed(3)}</span></td><td>${label} ${dir}</td></tr>`;
        });
        html += `</tbody></table></div>`;
    }

    // 6. Key Findings & Recommendations
    html += `<div class="section">
        <div class="section-title"><span class="icon icon-amber">💡</span> Key Findings & Recommendations</div>
        <div style="display:flex;flex-direction:column;gap:8px;">`;

    // Auto-generate findings
    if (completeness < 80) {
        html += `<span class="insight-chip chip-red">⚠️ Data completeness is ${completeness}% — consider cleaning missing values before analysis</span>`;
    } else if (completeness >= 95) {
        html += `<span class="insight-chip chip-green">✅ Excellent data quality — ${completeness}% completeness</span>`;
    }

    if (dupes > 0) {
        html += `<span class="insight-chip chip-amber">🔁 ${dupes} duplicate rows (${((dupes/excelData.length)*100).toFixed(1)}%) — review for potential data entry errors</span>`;
    }

    nums.forEach(col => {
        const s = numStats[col];
        if (!s) return;
        if (s.outliers > 0 && s.outliers / s.count > 0.05) {
            html += `<span class="insight-chip chip-red">📊 "${col}" has ${s.outliers} outliers (${((s.outliers/s.count)*100).toFixed(1)}%) — may need investigation</span>`;
        }
        if (parseFloat(s.cv) > 100) {
            html += `<span class="insight-chip chip-amber">📉 "${col}" has very high variability (CV: ${s.cv}%)</span>`;
        }
    });

    strongCorrs.slice(0, 3).forEach(p => {
        const dir = p.r > 0 ? 'positively' : 'negatively';
        html += `<span class="insight-chip chip-blue">🔗 "${p.col1}" and "${p.col2}" are ${dir} correlated (r = ${p.r.toFixed(2)})</span>`;
    });

    excelColumns.forEach(col => {
        if (colMissing[col] / excelData.length > 0.3) {
            html += `<span class="insight-chip chip-amber">⚠️ "${col}" has ${((colMissing[col]/excelData.length)*100).toFixed(0)}% missing values</span>`;
        }
    });

    html += `</div></div>`;

    // 7. Charts
    if (chartImages.length > 0) {
        html += `<div class="section page-break">
            <div class="section-title"><span class="icon icon-blue">📊</span> Charts & Visualizations</div>
            <div class="charts-grid">`;
        chartImages.slice(0, 12).forEach(img => {
            html += `<div class="chart-img-card"><img src="${img.src}" alt="${img.title}"><div class="chart-label">${img.title}</div></div>`;
        });
        html += `</div></div>`;
    }

    // Footer
    html += `<div class="report-footer">
        Generated by <strong>APF Resource Person Dashboard</strong> — Smart Report Engine<br>
        ${dateStr} at ${timeStr} • ${excelData.length.toLocaleString()} records analyzed
    </div>`;

    // Download script
    html += `<script>
    function downloadReportHTML() {
        const blob = new Blob([document.documentElement.outerHTML], { type: 'text/html' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'Smart_Report_${fileName.replace(/[^a-zA-Z0-9]/g, '_')}_${now.toISOString().split('T')[0]}.html';
        a.click();
        URL.revokeObjectURL(a.href);
    }
    <\/script>`;

    html += `</div></body></html>`;

    // Open in new tab
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    showToast('Smart Report generated — opened in new tab!', 'success');
}
