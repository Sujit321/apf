// ===== Enhanced Excel Analytics Module for APF Dashboard =====

let excelWorkbook = null;
let excelData = [];
let excelColumns = [];
let excelColumnTypes = {};
let activeCharts = [];

// ===== Color Palette =====
const CHART_COLORS = [
    '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ef4444',
    '#06b6d4', '#f97316', '#ec4899', '#14b8a6', '#6366f1',
    '#84cc16', '#e11d48', '#0ea5e9', '#a855f7', '#22c55e',
    '#d946ef', '#eab308', '#64748b', '#fb923c', '#2dd4bf'
];

function getColors(n) {
    const colors = [];
    for (let i = 0; i < n; i++) colors.push(CHART_COLORS[i % CHART_COLORS.length]);
    return colors;
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

    document.getElementById('excelDashboard').style.display = 'block';

    // Populate builder dropdowns
    populateBuilderDropdowns();

    // Run all analyses
    renderSummaryBar();
    renderAutoInsights();
    renderAutoCharts();
    renderDataQuality();
    renderDataTable();

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
    document.getElementById('excelUploadZone').style.display = '';
    document.getElementById('excelFileInput').value = '';
    showToast('Data cleared', 'info');
}

// ===== Tab Switching =====
function switchAnalysisTab(tab) {
    document.querySelectorAll('.analysis-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.analysis-tab[data-tab="${tab}"]`).classList.add('active');
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
        { icon: 'fa-table', value: excelData.length.toLocaleString(), label: 'ROWS' },
        { icon: 'fa-columns', value: excelColumns.length, label: 'COLUMNS' },
        { icon: 'fa-hashtag', value: nums.length, label: 'NUMERIC' },
        { icon: 'fa-font', value: cats.length, label: 'CATEGORICAL' },
        { icon: 'fa-check-circle', value: completeness + '%', label: 'COMPLETENESS' },
    ];

    document.getElementById('excelSummaryBar').innerHTML = stats.map(s =>
        `<div class="summary-stat-card"><i class="fas ${s.icon}"></i><div class="stat-value">${s.value}</div><div class="stat-label">${s.label}</div></div>`
    ).join('');
}

// ===== Auto Insights =====
function renderAutoInsights() {
    const insights = [];
    const nums = getNumericColumns();
    const cats = getCategoricalColumns();
    const apfFields = detectAPFFields(excelColumns);

    // Dataset overview
    insights.push({
        type: 'info', title: 'DATASET OVERVIEW',
        text: `${excelData.length.toLocaleString()} records with ${excelColumns.length} fields across this sheet`
    });

    // APF-specific insights
    if (apfFields.school) {
        const schools = new Set(excelData.map(r => String(r[apfFields.school[0]]).trim()).filter(Boolean));
        insights.push({ type: 'apf', title: 'SCHOOLS COVERED', text: `${schools.size} unique schools found in "${apfFields.school[0]}"` });
    }
    if (apfFields.block) {
        const blocks = new Set(excelData.map(r => String(r[apfFields.block[0]]).trim()).filter(Boolean));
        insights.push({ type: 'apf', title: 'BLOCKS COVERED', text: `${blocks.size} unique blocks found in "${apfFields.block[0]}"` });
    }
    if (apfFields.subject) {
        const subjects = new Set(excelData.map(r => String(r[apfFields.subject[0]]).trim()).filter(Boolean));
        insights.push({ type: 'apf', title: 'SUBJECTS', text: `${subjects.size} subjects: ${[...subjects].slice(0, 5).join(', ')}${subjects.size > 5 ? '...' : ''}` });
    }

    // Numeric statistics
    nums.forEach(col => {
        const vals = excelData.map(r => parseFloat(r[col])).filter(v => !isNaN(v));
        if (vals.length === 0) return;
        const min = Math.min(...vals);
        const max = Math.max(...vals);
        const avg = (vals.reduce((a, b) => a + b, 0) / vals.length);
        const sorted = [...vals].sort((a, b) => a - b);
        const median = sorted[Math.floor(sorted.length / 2)];
        const fmt = v => v >= 100000 ? (v / 100000).toFixed(1) + ' L' : v >= 1000 ? (v / 1000).toFixed(1) + ' K' : v.toFixed(1);

        insights.push({
            type: 'stat', title: `${col} — STATISTICS`,
            text: `Min: ${fmt(min)} │ Max: ${fmt(max)} │ Avg: ${fmt(avg)} │ Median: ${fmt(median)}`
        });

        // Outliers
        const mean = avg;
        const stdDev = Math.sqrt(vals.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / vals.length);
        const outliers = vals.filter(v => Math.abs(v - mean) > 2 * stdDev).length;
        if (outliers > 0 && stdDev > 0) {
            insights.push({
                type: 'warning', title: `${col} — OUTLIERS DETECTED`,
                text: `${outliers} values beyond 2 standard deviations (σ=${fmt(stdDev)})`
            });
        }
    });

    // Categorical most common
    cats.forEach(col => {
        const freq = {};
        excelData.forEach(r => {
            const v = String(r[col]).trim();
            if (v) freq[v] = (freq[v] || 0) + 1;
        });
        const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
        if (sorted.length > 0) {
            const [topVal, topCount] = sorted[0];
            const pct = ((topCount / excelData.length) * 100).toFixed(0);
            insights.push({
                type: 'category', title: `${col} — MOST COMMON`,
                text: `"${topVal}" appears ${topCount.toLocaleString()} times (${pct}%) out of ${sorted.length} unique values`
            });
        }
    });

    // Missing data
    excelColumns.forEach(col => {
        const missing = excelData.filter(r => r[col] === null || r[col] === undefined || r[col] === '').length;
        const pct = ((missing / excelData.length) * 100).toFixed(1);
        if (pct > 10) {
            insights.push({
                type: 'warning', title: `${col} — MISSING DATA`,
                text: `${missing.toLocaleString()} missing values (${pct}%)`
            });
        }
    });

    // Correlations between numeric columns
    if (nums.length >= 2) {
        for (let i = 0; i < Math.min(nums.length, 5); i++) {
            for (let j = i + 1; j < Math.min(nums.length, 5); j++) {
                const corr = computeCorrelation(nums[i], nums[j]);
                if (Math.abs(corr) > 0.6) {
                    insights.push({
                        type: corr > 0 ? 'success' : 'warning',
                        title: `CORRELATION DETECTED`,
                        text: `${nums[i]} ↔ ${nums[j]}: r = ${corr.toFixed(2)} (${Math.abs(corr) > 0.8 ? 'strong' : 'moderate'} ${corr > 0 ? 'positive' : 'negative'})`
                    });
                }
            }
        }
    }

    const typeColors = { info: '#3b82f6', stat: '#10b981', warning: '#f59e0b', category: '#8b5cf6', apf: '#f97316', success: '#10b981' };

    document.getElementById('excelInsightsPanel').innerHTML = `
        <h3 style="margin-bottom:12px;display:flex;align-items:center;gap:8px;"><i class="fas fa-lightbulb" style="color:var(--accent)"></i> Auto-Generated Insights</h3>
        <div class="insights-grid">${insights.map(ins =>
        `<div class="insight-card" style="border-left:3px solid ${typeColors[ins.type] || '#6b7280'}">
                <div class="insight-type">${ins.title}</div>
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
    const card = document.createElement('div');
    card.className = 'excel-chart-card';
    card.innerHTML = `<h4>${title}</h4><canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    const isHorizontal = chartType === 'horizontalBar';
    const isPie = chartType === 'doughnut' || chartType === 'pie';

    const config = {
        type: isHorizontal ? 'bar' : (isPie ? 'doughnut' : chartType),
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

    activeCharts.push(new Chart(ctx, config));
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
    card.innerHTML = `<h4>${title}</h4><canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    activeCharts.push(new Chart(ctx, {
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
    }));
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
    card.innerHTML = `<h4>${title}</h4><canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    activeCharts.push(new Chart(ctx, {
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
    }));
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
    card.innerHTML = `<h4>${title}</h4><canvas id="${id}"></canvas>`;
    container.appendChild(card);

    const ctx = document.getElementById(id).getContext('2d');
    activeCharts.push(new Chart(ctx, {
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
    }));
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

// ===== Data Quality =====
function renderDataQuality() {
    const output = document.getElementById('dataQualityOutput');
    const totalCells = excelData.length * excelColumns.length;

    // Per-column quality
    const colStats = excelColumns.map(col => {
        const missing = excelData.filter(r => r[col] === null || r[col] === undefined || r[col] === '').length;
        const filled = excelData.length - missing;
        const completeness = ((filled / excelData.length) * 100);
        const unique = new Set(excelData.map(r => String(r[col]).trim())).size;
        const type = excelColumnTypes[col];
        return { col, missing, filled, completeness, unique, type };
    });

    // Overall quality score
    const totalFilled = colStats.reduce((s, c) => s + c.filled, 0);
    const overallCompleteness = ((totalFilled / totalCells) * 100).toFixed(1);
    const duplicateRows = excelData.length - new Set(excelData.map(r => JSON.stringify(r))).size;

    const qualityClass = (pct) => pct >= 90 ? 'good' : pct >= 70 ? 'medium' : 'poor';

    output.innerHTML = `
        <div class="quality-grid">
            <div class="quality-card" style="grid-column: 1 / -1;">
                <h4><i class="fas fa-heartbeat" style="color:var(--accent)"></i> Overall Data Quality Score</h4>
                <div style="display:flex;gap:32px;flex-wrap:wrap;">
                    <div style="flex:1;min-width:200px;">
                        <div style="font-size:42px;font-weight:800;color:${parseFloat(overallCompleteness) >= 90 ? 'var(--success)' : parseFloat(overallCompleteness) >= 70 ? 'var(--warning)' : 'var(--danger)'}">${overallCompleteness}%</div>
                        <div style="color:var(--text-secondary)">Data Completeness</div>
                    </div>
                    <div style="flex:1;min-width:150px;">
                        <div style="font-size:42px;font-weight:800;color:var(--text-primary)">${excelData.length.toLocaleString()}</div>
                        <div style="color:var(--text-secondary)">Total Records</div>
                    </div>
                    <div style="flex:1;min-width:150px;">
                        <div style="font-size:42px;font-weight:800;color:${duplicateRows > 0 ? 'var(--warning)' : 'var(--success)'}">${duplicateRows.toLocaleString()}</div>
                        <div style="color:var(--text-secondary)">Duplicate Rows</div>
                    </div>
                    <div style="flex:1;min-width:150px;">
                        <div style="font-size:42px;font-weight:800;color:var(--info)">${excelColumns.length}</div>
                        <div style="color:var(--text-secondary)">Total Fields</div>
                    </div>
                </div>
            </div>
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
function renderDataTable() {
    const maxRows = 100;
    const displayData = excelData.slice(0, maxRows);
    document.getElementById('excelRowCount').textContent = `Showing ${Math.min(maxRows, excelData.length)} of ${excelData.length.toLocaleString()} rows`;

    const table = `<table class="excel-data-table">
        <thead><tr>${excelColumns.map(c => `<th>${c}</th>`).join('')}</tr></thead>
        <tbody>${displayData.map(row =>
        `<tr>${excelColumns.map(c => {
            let val = row[c];
            if (val instanceof Date) val = val.toLocaleDateString('en-IN');
            else if (val === null || val === undefined) val = '';
            return `<td>${String(val).substring(0, 80)}</td>`;
        }).join('')}</tr>`
    ).join('')}</tbody>
    </table>`;

    document.getElementById('excelTableContainer').innerHTML = table;
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
