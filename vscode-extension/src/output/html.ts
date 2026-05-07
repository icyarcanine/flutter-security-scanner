/**
 * Standalone HTML report emitter (QW-47 / IN-9).
 *
 * Single-file, dependency-free output with inline CSS/JS so it can be attached
 * to tickets or opened from CI artifacts without a local server.
 */
import { FindingSeverity } from '../models/finding';
import { ProjectScanReport } from '../scanner/scanner';

export function toHtmlReport(report: ProjectScanReport): string {
  const files = Array.from(new Set(report.findings.map(f => f.filePath).filter(Boolean) as string[])).sort();
  const rules = Array.from(new Set(report.findings.map(f => f.code))).sort();
  const rows = report.findings.map((f) => {
    const severity = f.severity ?? FindingSeverity.low;
    const file = f.filePath ?? '';
    const line = f.line != null ? String(f.line) : '';
    return `<article class="finding" data-severity="${escAttr(severity)}" data-rule="${escAttr(f.code)}" data-file="${escAttr(file)}">
      <div class="finding-head">
        <span class="sev sev-${escAttr(severity)}">${esc(severity.toUpperCase())}</span>
        <h2>${esc(f.message)}</h2>
      </div>
      <dl>
        <dt>Rule</dt><dd>${esc(f.code)}</dd>
        <dt>Location</dt><dd>${esc(file)}${line ? ':' + esc(line) : ''}</dd>
        <dt>Confidence</dt><dd>${esc(f.confidence ?? 'unknown')}</dd>
        ${f.cwe ? `<dt>CWE</dt><dd>${esc(Array.isArray(f.cwe) ? f.cwe.join(', ') : f.cwe)}</dd>` : ''}
      </dl>
      ${f.risk ? `<p class="risk"><strong>Risk:</strong> ${esc(f.risk)}</p>` : ''}
      <p class="fix"><strong>Fix:</strong> ${esc(f.fix)}</p>
      ${f.pathSteps && f.pathSteps.length > 0 ? `<ol class="flow">${f.pathSteps.map(step => `<li>${esc(step.label)} <span>${esc(String(step.line))}</span></li>`).join('')}</ol>` : ''}
    </article>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SAST Scan Report</title>
  <style>
    :root { color-scheme: light dark; --bg: #f7f8fa; --panel: #ffffff; --text: #1f2937; --muted: #667085; --line: #d9dee7; --high: #b42318; --medium: #b54708; --low: #175cd3; }
    @media (prefers-color-scheme: dark) { :root { --bg: #111827; --panel: #172033; --text: #eef2f7; --muted: #a8b3c7; --line: #2d3a52; } }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--text); }
    header { padding: 28px 32px 16px; border-bottom: 1px solid var(--line); background: var(--panel); }
    h1 { margin: 0 0 14px; font-size: 24px; line-height: 1.2; }
    .stats { display: flex; flex-wrap: wrap; gap: 10px; padding: 0; margin: 0; list-style: none; }
    .stats li, .filters label { border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; background: var(--panel); }
    .filters { position: sticky; top: 0; z-index: 1; display: flex; flex-wrap: wrap; gap: 10px; padding: 14px 32px; border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--panel) 92%, transparent); backdrop-filter: blur(8px); }
    .filters label { display: grid; gap: 4px; min-width: 180px; color: var(--muted); font-size: 12px; }
    select, input { min-height: 34px; border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; background: var(--bg); color: var(--text); }
    main { display: grid; gap: 14px; padding: 20px 32px 36px; }
    .finding { border: 1px solid var(--line); border-radius: 8px; padding: 16px; background: var(--panel); }
    .finding[hidden] { display: none; }
    .finding-head { display: flex; gap: 10px; align-items: flex-start; }
    .finding h2 { margin: 0; font-size: 16px; line-height: 1.35; }
    .sev { flex: 0 0 auto; border-radius: 999px; padding: 3px 8px; color: white; font-size: 12px; font-weight: 700; }
    .sev-high { background: var(--high); } .sev-medium { background: var(--medium); } .sev-low { background: var(--low); }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 12px; margin: 12px 0; color: var(--muted); }
    dt { font-weight: 700; color: var(--text); }
    dd { margin: 0; overflow-wrap: anywhere; }
    p { margin: 8px 0 0; line-height: 1.45; }
    .flow { margin: 12px 0 0; padding-left: 22px; color: var(--muted); }
    .empty { padding: 24px 32px; color: var(--muted); }
  </style>
</head>
<body>
  <header>
    <h1>SAST Scan Report</h1>
    <ul class="stats">
      <li><strong>${report.findings.length}</strong> findings</li>
      <li><strong>${report.highCount}</strong> high</li>
      <li><strong>${report.mediumCount}</strong> medium</li>
      <li><strong>${report.lowCount}</strong> low</li>
      <li><strong>${report.totalFiles}</strong> files scanned</li>
      <li><strong>${report.scanDurationMs}ms</strong> duration</li>
    </ul>
  </header>
  <section class="filters" aria-label="Report filters">
    <label>Severity
      <select id="severity"><option value="">All</option><option>high</option><option>medium</option><option>low</option></select>
    </label>
    <label>Rule
      <select id="rule"><option value="">All</option>${rules.map(r => `<option>${esc(r)}</option>`).join('')}</select>
    </label>
    <label>File
      <select id="file"><option value="">All</option>${files.map(f => `<option>${esc(f)}</option>`).join('')}</select>
    </label>
    <label>Search
      <input id="search" type="search" placeholder="Message, rule, file">
    </label>
  </section>
  <main id="findings">${rows || '<p class="empty">No findings.</p>'}</main>
  <script>
    const controls = ['severity', 'rule', 'file', 'search'].map(id => document.getElementById(id));
    const findings = Array.from(document.querySelectorAll('.finding'));
    function applyFilters() {
      const severity = document.getElementById('severity').value;
      const rule = document.getElementById('rule').value;
      const file = document.getElementById('file').value;
      const search = document.getElementById('search').value.toLowerCase();
      for (const item of findings) {
        const visible = (!severity || item.dataset.severity === severity) &&
          (!rule || item.dataset.rule === rule) &&
          (!file || item.dataset.file === file) &&
          (!search || item.textContent.toLowerCase().includes(search));
        item.hidden = !visible;
      }
    }
    for (const control of controls) control.addEventListener('input', applyFilters);
  </script>
</body>
</html>`;
}

function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escAttr(value: unknown): string {
  return esc(value).replace(/`/g, '&#96;');
}
