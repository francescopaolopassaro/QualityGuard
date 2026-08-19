using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace QualityGuard.Cli.ReportHTML
{
    // --- report model ---
    public class ReportData
    {
        [JsonPropertyName("qualityGateStatus")]
        public string QualityGateStatus { get; set; } = "Unknown";

        [JsonPropertyName("conditions")]
        public List<QGCondition> Conditions { get; set; } = new();

        [JsonPropertyName("issues")]
        public List<Issue> Issues { get; set; } = new();

        [JsonPropertyName("summary")]
        public Summary Summary { get; set; } = new();

        [JsonPropertyName("folders")]
        public List<FolderStats> Folders { get; set; } = new();
    }

    public class QGCondition
    {
        [JsonPropertyName("metric")] public string Metric { get; set; } = "";
        [JsonPropertyName("actual")] public string Actual { get; set; } = "";
        [JsonPropertyName("expected")] public string Expected { get; set; } = "";
        [JsonPropertyName("status")] public string Status { get; set; } = "";
    }

    public class Issue
    {
        [JsonPropertyName("severity")] public string Severity { get; set; } = "";
        [JsonPropertyName("rule")] public string Rule { get; set; } = "";
        [JsonPropertyName("message")] public string Message { get; set; } = "";
        [JsonPropertyName("file")] public string File { get; set; } = "";
        [JsonPropertyName("line")] public int Line { get; set; }
        [JsonPropertyName("flow")] public List<string> Flow { get; set; } = new();
    }

    public class Summary
    {
        [JsonPropertyName("files")] public int Files { get; set; }
        [JsonPropertyName("ncloc")] public int Ncloc { get; set; }
        [JsonPropertyName("complexity")] public int Complexity { get; set; }
        [JsonPropertyName("duplicated")] public double Duplicated { get; set; }
        [JsonPropertyName("techDebt")] public string TechDebt { get; set; } = "0d";
        [JsonPropertyName("techDebtRatio")] public double TechDebtRatio { get; set; }

        [JsonPropertyName("bugs")] public MetricDetail Bugs { get; set; } = new();
        [JsonPropertyName("vulnerabilities")] public MetricDetail Vulnerabilities { get; set; } = new();
        [JsonPropertyName("securityHotspots")] public MetricDetail SecurityHotspots { get; set; } = new();
        [JsonPropertyName("codeSmells")] public MetricDetail CodeSmells { get; set; } = new();
    }

    public class MetricDetail
    {
        [JsonPropertyName("count")] public int Count { get; set; }
        [JsonPropertyName("rating")] public string Rating { get; set; } = "A";
        [JsonPropertyName("category")] public string Category { get; set; } = "";
        [JsonPropertyName("breakdown")] public Dictionary<string, int> Breakdown { get; set; } = new();
        [JsonPropertyName("frequentRules")] public List<RuleInfo> FrequentRules { get; set; } = new();
    }

    public class RuleInfo
    {
        [JsonPropertyName("id")] public string Id { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("count")] public int Count { get; set; }
    }

    public class FolderStats
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("files")] public int Files { get; set; }
        [JsonPropertyName("ncloc")] public int Ncloc { get; set; }
        [JsonPropertyName("bugs")] public int Bugs { get; set; }
        [JsonPropertyName("vuln")] public int Vuln { get; set; }
        [JsonPropertyName("smells")] public int Smells { get; set; }
    }

    // --- report writer ---
    public static class ReportGenerator
    {
        public static void Generate(string outputPath, ReportData data)
        {
            var jsonOptions = new JsonSerializerOptions 
            { 
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase, 
                WriteIndented = false // minified: the payload travels inside the page
            };
            
            string jsonData = JsonSerializer.Serialize(data, jsonOptions);
            string htmlContent = HtmlTemplate.Value.Replace("/*__REPORT_DATA__*/", jsonData);
            
            File.WriteAllText(outputPath, htmlContent);
            Console.WriteLine($"  HTML report written to {Path.GetFullPath(outputPath)}");
        }

        // One page with its stylesheet, its script and its logo inline, so the file a user saves keeps
        // working with no network and no companion files.
        private static class HtmlTemplate
        {
            public static string Value => """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QualityGuard Report</title>
<style>
:root{--bg:#f8fafc;--card:#fff;--text:#0f172a;--sub:#64748b;--green:#10b981;--red:#ef4444;--orange:#f59e0b;--blue:#0284c7;--teal:#0f766e;--border:#e2e8f0}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:0;line-height:1.5}
.container{max-width:1200px;margin:0 auto;padding:24px}
header{background:var(--card);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.logo-container{width:260px;height:60px}.logo-container svg{width:100%;height:100%}
.badge{padding:6px 16px;border-radius:20px;font-weight:700;color:#fff;font-size:13px;letter-spacing:.5px;text-transform:uppercase}
.badge.pass{background:var(--green);box-shadow:0 2px 8px rgba(16,185,129,.3)}.badge.fail{background:var(--red);box-shadow:0 2px 8px rgba(239,68,68,.3)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:30px 0}
.card{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.05);border-left:4px solid var(--blue);transition:all .2s ease}
.card.clickable{cursor:pointer;border-left-color:var(--sub)}.card.clickable:hover{transform:translateY(-4px);box-shadow:0 8px 16px rgba(0,0,0,.08);border-left-color:var(--blue)}
.card.clickable.active{border-left-color:var(--blue);background:#f0f9ff;box-shadow:0 0 0 2px var(--blue)}
.card h3{margin:0 0 8px;font-size:12px;color:var(--sub);text-transform:uppercase;font-weight:700;letter-spacing:.5px}
.card .value{font-size:32px;font-weight:800;color:var(--text);line-height:1;margin-bottom:8px}
.card .sub{font-size:13px;color:var(--sub);display:flex;align-items:center;gap:8px}
.rating{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:6px;color:#fff;font-weight:800;font-size:13px}
.rating.A{background:var(--green)}.rating.B{background:#84cc16}.rating.C{background:var(--orange)}.rating.D{background:var(--red)}.rating.E{background:#7f1d1d}
#detail-panel{background:var(--card);border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.08);margin-bottom:30px;overflow:hidden;display:none;animation:slideDown .3s ease-out;border:1px solid var(--border)}
@keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.panel-header{background:#f8fafc;padding:16px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.panel-header h2{margin:0;font-size:18px;color:var(--text)}.close-btn{background:none;border:none;font-size:24px;color:var(--sub);cursor:pointer;padding:0 8px}.close-btn:hover{color:var(--red)}
.panel-content{padding:24px;display:grid;grid-template-columns:1fr 1fr;gap:32px}
.breakdown-item{margin-bottom:16px}.breakdown-label{display:flex;justify-content:space-between;font-size:13px;font-weight:600;margin-bottom:6px}
.progress-bg{background:#e2e8f0;height:8px;border-radius:4px;overflow:hidden}.progress-fill{height:100%;border-radius:4px;transition:width .5s ease}
.fill-critical{background:var(--red)}.fill-major{background:var(--orange)}.fill-minor{background:var(--blue)}
.rule-item{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);font-size:14px}.rule-item:last-child{border-bottom:none}
.rule-id{font-family:monospace;background:#f1f5f9;padding:2px 6px;border-radius:4px;color:var(--blue);font-weight:600}.rule-count{font-weight:700;color:var(--text)}
.section{background:var(--card);padding:24px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.05);margin-bottom:24px}
.section h2{margin-top:0;border-bottom:2px solid var(--border);padding-bottom:12px;font-size:18px;font-weight:700}
table{width:100%;border-collapse:collapse;margin-top:10px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--border);font-size:14px}
th{background:#f8fafc;font-weight:700;color:var(--sub);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.issue-block{background:#fef2f2;border-left:4px solid var(--red);padding:16px;margin-bottom:12px;border-radius:6px}
.issue-title{font-weight:700;color:var(--red);margin-bottom:4px;font-size:15px}
.issue-file{font-family:monospace;font-size:13px;color:var(--sub);background:#fff;padding:2px 6px;border-radius:4px;border:1px solid var(--border)}
.flow{font-size:12px;color:var(--sub);margin-left:16px;margin-top:8px;font-family:monospace;border-left:2px solid #cbd5e1;padding-left:10px}
.chart-container{width:100%;margin-top:24px;overflow-x:auto}
.coverage-table{width:100%;border-collapse:collapse}.coverage-table td{padding:8px 0;border-bottom:1px solid var(--border)}.coverage-table .status{font-weight:700;text-transform:uppercase}
.status.passed{color:var(--green)}.status.failed{color:var(--red)}
@media(max-width:768px){.panel-content{grid-template-columns:1fr}header{flex-direction:column;gap:16px;align-items:flex-start}.logo-container{width:200px;height:auto}}
</style>
</head>
<body>
<header>
    <div class="logo-container">
        <svg viewBox="0 0 520 120" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="qg-primary-grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#0284C7"/><stop offset="100%" stop-color="#0F766E"/></linearGradient>
            <linearGradient id="qg-accent-grad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="#10B981"/><stop offset="100%" stop-color="#0284C7"/></linearGradient>
            <filter id="subtle-shadow" x="-10%" y="-10%" width="120%" height="120%"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#0F172A" flood-opacity="0.06"/></filter>
          </defs>
          <rect width="100%" height="100%" fill="#FFFFFF"/>
          <g transform="translate(75, 60) scale(0.42)" filter="url(#subtle-shadow)">
            <path d="M 0,-105 L 75,-70 C 75,20 45,75 0,105 C -45,75 -75,20 -75,-70 Z" fill="none" stroke="url(#qg-primary-grad)" stroke-width="7" stroke-linejoin="round"/>
            <path d="M 0,-85 L 58,-57 C 58,12 35,58 0,82 C -35,58 -58,12 -58,-57 Z" fill="none" stroke="#CBD5E1" stroke-width="4" stroke-dasharray="6 4"/>
            <path d="M -35,-20 L -15,10 L 0,-10" fill="none" stroke="url(#qg-accent-grad)" stroke-width="5" stroke-linecap="round"/>
            <path d="M 35,-20 L 15,10 L 0,-10" fill="none" stroke="url(#qg-accent-grad)" stroke-width="5" stroke-linecap="round"/>
            <circle cx="-35" cy="-20" r="6" fill="#0284C7"/><circle cx="35" cy="-20" r="6" fill="#0284C7"/><circle cx="0" cy="-10" r="7" fill="#10B981"/>
            <path d="M -22,25 L -35,38 L -22,51" fill="none" stroke="#0F172A" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M -5,56 L 5,20" fill="none" stroke="url(#qg-primary-grad)" stroke-width="6" stroke-linecap="round"/>
            <path d="M 22,25 L 35,38 L 22,51" fill="none" stroke="#0F172A" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
            <circle cx="0" cy="70" r="5" fill="#10B981"/>
          </g>
          <g transform="translate(330, 0)">
            <text x="0" y="62" text-anchor="middle" font-family="system-ui,-apple-system,'Segoe UI',Roboto,sans-serif" font-weight="800" font-size="32" letter-spacing="4" fill="#0F172A">QUALITY<tspan fill="url(#qg-primary-grad)">GUARD</tspan></text>
            <text x="0" y="88" text-anchor="middle" font-family="system-ui,-apple-system,'Segoe UI',Roboto,sans-serif" font-weight="700" font-size="11" letter-spacing="6" fill="#475569">CODE <tspan fill="#0284C7">•</tspan> API <tspan fill="#10B981">•</tspan> SECURITY</text>
          </g>
        </svg>
    </div>
    <div id="qg-badge" class="badge">Loading...</div>
</header>

<div class="container">
    <div id="summary-grid" class="grid"></div>
    <div id="detail-panel">
        <div class="panel-header"><h2 id="panel-title">Details</h2><button class="close-btn" onclick="closePanel()">×</button></div>
        <div class="panel-content">
            <div id="panel-breakdown"></div>
            <div id="panel-rules"><h3 style="margin-top:0;font-size:14px;text-transform:uppercase;color:var(--sub)">Rules and details</h3><div id="rules-list"></div></div>
        </div>
    </div>
    <div class="section">
        <h2>🚨 Critical Issues & Security</h2>
        <div id="issues-list"></div>
    </div>
    <div class="section">
        <h2>📁 Folder Breakdown</h2>
        <table id="folder-table"><thead><tr><th>Folder</th><th>Files</th><th>NCLOC</th><th>Bugs</th><th>Vuln</th><th>Smells</th></tr></thead><tbody></tbody></table>
        <div id="folder-chart" class="chart-container"></div>
    </div>
</div>

<script id="report-data" type="application/json">/*__REPORT_DATA__*/</script>
<script>
const data = JSON.parse(document.getElementById('report-data').textContent);
let activePanel = null;

const badge = document.getElementById('qg-badge');
badge.textContent = 'Quality Gate: ' + data.qualityGateStatus;
badge.classList.add(data.qualityGateStatus.toLowerCase() === 'passed' ? 'pass' : 'fail');

const s = data.summary;
const cardsConfig = [
    { id: 'coverage', title: 'Coverage', val: s.coverage || 'N/A', sub: 'Quality Gate', rating: null, color: '#0284c7' },
    { id: 'bugs', title: 'Bugs', val: s.bugs.count, sub: 'Reliability', rating: s.bugs.rating, color: '#f59e0b' },
    { id: 'vulnerabilities', title: 'Vulnerabilities', val: s.vulnerabilities.count, sub: 'Security', rating: s.vulnerabilities.rating, color: '#ef4444' },
    { id: 'codeSmells', title: 'Code Smells', val: s.codeSmells.count, sub: 'Maintainability', rating: s.codeSmells.rating, color: '#0284c7' }
];

const grid = document.getElementById('summary-grid');
cardsConfig.forEach(c => {
    const div = document.createElement('div');
    div.className = 'card clickable';
    div.dataset.id = c.id;
    div.onclick = () => togglePanel(c.id);
    div.innerHTML = '<h3>' + c.title + '</h3><div class="value">' + c.val + '</div><div class="sub">' + c.sub + (c.rating ? ' <span class="rating ' + c.rating + '">' + c.rating + '</span>' : '') + '</div>';
    grid.appendChild(div);
});

function togglePanel(id) {
    const panel = document.getElementById('detail-panel');
    const cards = document.querySelectorAll('.card.clickable');
    if (activePanel === id) { closePanel(); return; }
    activePanel = id;
    cards.forEach(c => c.classList.toggle('active', c.dataset.id === id));
    
    document.getElementById('panel-title').textContent = id.charAt(0).toUpperCase() + id.slice(1).replace(/([A-Z])/g, ' $1').trim() + ' - Details';
    const bdContainer = document.getElementById('panel-breakdown');
    const rulesContainer = document.getElementById('rules-list');

    if (id === 'coverage') {
        let html = '<table class="coverage-table">';
        data.conditions.forEach(c => {
            const statusClass = c.status.toLowerCase() === 'passed' ? 'passed' : 'failed';
            html += '<tr><td><strong>' + c.metric + '</strong></td><td>' + c.actual + ' vs ' + c.expected + '</td><td class="status ' + statusClass + '">' + c.status + '</td></tr>';
        });
        html += '</table>';
        bdContainer.innerHTML = html;
        rulesContainer.innerHTML = '<p style="color:var(--sub);font-size:14px">Quality gate conditions for this scan.</p>';
    } else {
        const metric = data.summary[id];
        const bd = metric.breakdown;
        const total = metric.count || 1;
        let bdHtml = '';
        const levels = [{ key: 'critical', label: 'Critical', colorClass: 'fill-critical' }, { key: 'major', label: 'Major', colorClass: 'fill-major' }, { key: 'minor', label: 'Minor', colorClass: 'fill-minor' }];
        levels.forEach(l => {
            if (bd[l.key] !== undefined) {
                const pct = ((bd[l.key] / total) * 100).toFixed(1);
                bdHtml += '<div class="breakdown-item"><div class="breakdown-label"><span>' + l.label + '</span><span>' + bd[l.key] + ' (' + pct + '%)</span></div><div class="progress-bg"><div class="progress-fill ' + l.colorClass + '" style="width: ' + pct + '%"></div></div></div>';
            }
        });
        bdContainer.innerHTML = bdHtml || '<p style="color:var(--sub)">No breakdown available.</p>';

        const rules = metric.frequentRules || [];
        let rulesHtml = '';
        if (rules.length > 0) {
            rules.forEach(r => { rulesHtml += '<div class="rule-item"><div><span class="rule-id">' + r.id + '</span><span style="margin-left:8px;color:var(--text)">' + r.name + '</span></div><span class="rule-count">' + r.count + '</span></div>'; });
        } else {
            rulesHtml = '<p style="color:var(--sub);font-size:14px">No rule reported more than once.</p>';
        }
        rulesContainer.innerHTML = rulesHtml;
    }
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closePanel() {
    activePanel = null;
    document.getElementById('detail-panel').style.display = 'none';
    document.querySelectorAll('.card.clickable').forEach(c => c.classList.remove('active'));
}

const issuesList = document.getElementById('issues-list');
if (data.issues.length === 0) {
    issuesList.innerHTML = '<p style="color:var(--sub)">No critical issue found.</p>';
} else {
    data.issues.forEach(issue => {
        const div = document.createElement('div');
        div.className = 'issue-block';
        let flowHtml = issue.flow.map(f => '<div class="flow">↳ ' + f + '</div>').join('');
        div.innerHTML = '<div class="issue-title">' + issue.severity + ': ' + issue.rule + '</div><div style="margin-bottom:6px">' + issue.message + '</div><div><span class="issue-file">' + issue.file + ':' + issue.line + '</span></div>' + flowHtml;
        issuesList.appendChild(div);
    });
}

const tbody = document.querySelector('#folder-table tbody');
data.folders.forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td style="font-family:monospace;font-size:13px">' + f.name + '</td><td>' + f.files + '</td><td>' + f.ncloc.toLocaleString() + '</td><td style="color:var(--red);font-weight:600">' + f.bugs + '</td><td style="color:var(--red);font-weight:600">' + f.vuln + '</td><td>' + f.smells + '</td>';
    tbody.appendChild(tr);
});

function renderBarChart(containerId, datasets, labels) {
    const container = document.getElementById(containerId);
    const width = 800, height = 300, padding = 50;
    const colors = ['#ef4444', '#f59e0b', '#0284c7'];
    let maxVal = 0;
    datasets.forEach(ds => ds.data.forEach(v => { if (v > maxVal) maxVal = v; }));
    if (maxVal === 0) maxVal = 1;
    const chartWidth = width - padding * 2, chartHeight = height - padding * 2;
    const barGroupWidth = chartWidth / labels.length;
    const barWidth = (barGroupWidth * 0.7) / datasets.length;

    let svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" style="width:100%;height:auto;font-family:sans-serif">';
    for (let i = 0; i <= 4; i++) {
        const y = padding + (chartHeight / 4) * i;
        const val = Math.round(maxVal - (maxVal / 4) * i);
        svg += '<line x1="' + padding + '" y1="' + y + '" x2="' + (width - padding) + '" y2="' + y + '" stroke="#e2e8f0" stroke-width="1"/>';
        svg += '<text x="' + (padding - 10) + '" y="' + (y + 4) + '" font-size="11" text-anchor="end" fill="#94a3b8">' + val + '</text>';
    }
    svg += '<line x1="' + padding + '" y1="' + padding + '" x2="' + padding + '" y2="' + (height - padding) + '" stroke="#cbd5e1" stroke-width="2"/>';
    svg += '<line x1="' + padding + '" y1="' + (height - padding) + '" x2="' + (width - padding) + '" y2="' + (height - padding) + '" stroke="#cbd5e1" stroke-width="2"/>';

    labels.forEach((label, i) => {
        const groupX = padding + (i * barGroupWidth) + (barGroupWidth * 0.15);
        datasets.forEach((ds, j) => {
            const val = ds.data[i];
            const barHeight = (val / maxVal) * chartHeight;
            const x = groupX + (j * barWidth);
            const y = height - padding - barHeight;
            svg += '<path d="M ' + x + ' ' + (y + 4) + ' Q ' + x + ' ' + y + ' ' + (x + 4) + ' ' + y + ' L ' + (x + barWidth - 6) + ' ' + y + ' Q ' + (x + barWidth - 2) + ' ' + y + ' ' + (x + barWidth - 2) + ' ' + (y + 4) + ' L ' + (x + barWidth - 2) + ' ' + (height - padding) + ' L ' + x + ' ' + (height - padding) + ' Z" fill="' + colors[j] + '" opacity="0.9"><title>' + ds.label + ': ' + val + '</title></path>';
            if (val > 0) svg += '<text x="' + (x + (barWidth / 2) - 1) + '" y="' + (y - 5) + '" font-size="10" text-anchor="middle" fill="#64748b" font-weight="600">' + val + '</text>';
        });
        svg += '<text x="' + (groupX + (barWidth * datasets.length / 2)) + '" y="' + (height - padding + 20) + '" font-size="11" text-anchor="middle" fill="#64748b">' + label.split('/').pop() + '</text>';
    });
    datasets.forEach((ds, i) => {
        const lx = padding + (i * 100);
        svg += '<rect x="' + lx + '" y="15" width="12" height="12" fill="' + colors[i] + '" rx="2"/><text x="' + (lx + 18) + '" y="25" font-size="12" fill="#334155" font-weight="500">' + ds.label + '</text>';
    });
    svg += '</svg>';
    container.innerHTML = svg;
}
renderBarChart('folder-chart', [
    { label: 'Bugs', data: data.folders.map(f => f.bugs) },
    { label: 'Vuln', data: data.folders.map(f => f.vuln) },
    { label: 'Smells', data: data.folders.map(f => f.smells) }
], data.folders.map(f => f.name));
</script>
</body>
</html>
""";
        }
    }
}