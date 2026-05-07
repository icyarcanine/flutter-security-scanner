// @ts-ignore - REPORT_DATA is injected by the extension
const data = typeof REPORT_DATA !== 'undefined' ? REPORT_DATA : { findings: [], issueCount: 0, suggestionCount: 0 };

document.addEventListener('DOMContentLoaded', () => {
  renderSummary();
  renderStats();
  renderAstWarning();
  renderFindings();
  setupFilters();
  setupGrouping();
});

// ─── Tiny DOM helpers — replaces all innerHTML usage ─────────────────────
//
// Why: this is a security tool. innerHTML + escapeHtml is correct *if*
// every contributor remembers to escape. el(...) makes the safe thing
// the easy thing — text content is auto-escaped by the DOM, attributes
// can't be mistaken for raw HTML, and there is no template-string concat
// for an XSS bug to hide in.

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') node.className = String(v);
      else if (k === 'dataset') {
        for (const [dk, dv] of Object.entries(v)) {
          if (dv != null) node.dataset[dk] = String(dv);
        }
      }
      else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2), v);
      }
      else node.setAttribute(k, String(v));
    }
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    if (typeof child === 'string' || typeof child === 'number') {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// ─── Renderers ────────────────────────────────────────────────────────────

function renderSummary() {
  const summaryBar = document.getElementById('summary-bar');
  if (!summaryBar) return;
  clear(summaryBar);

  const total = data.issueCount + data.suggestionCount;
  if (total === 0) {
    summaryBar.appendChild(el('span', null, 'No issues found.'));
    return;
  }

  summaryBar.appendChild(el('span', null, el('strong', null, String(total)), ' total findings'));
  if (data.highCount > 0)        summaryBar.appendChild(el('span', { class: 'badge badge-high' },        `${data.highCount} HIGH`));
  if (data.mediumCount > 0)      summaryBar.appendChild(el('span', { class: 'badge badge-medium' },      `${data.mediumCount} MEDIUM`));
  if (data.lowCount > 0)         summaryBar.appendChild(el('span', { class: 'badge badge-low' },         `${data.lowCount} LOW`));
  if (data.suggestionCount > 0)  summaryBar.appendChild(el('span', { class: 'badge badge-suggestion' }, `${data.suggestionCount} SUGGESTIONS`));
}

function renderStats() {
  const statsBar = document.getElementById('stats-bar');
  if (!statsBar) return;
  clear(statsBar);

  const parts = [];
  if (typeof data.totalFiles === 'number')      parts.push(`${data.totalFiles} files`);
  if (typeof data.scanDurationMs === 'number')  parts.push(`${data.scanDurationMs}ms`);
  if (typeof data.astSuccessRate === 'number')  parts.push(`AST ${data.astSuccessRate}%`);

  if (parts.length > 0) {
    statsBar.appendChild(el('span', { class: 'stats-text' }, parts.join(' · ')));
  }
}

function getGroupBy() {
  const radios = document.querySelectorAll('#group-selector input[type="radio"]');
  for (const r of Array.from(radios)) {
    if (r.checked) return r.value;
  }
  return 'file';
}

function renderFindings() {
  const list = document.getElementById('findings-list');
  const emptyState = document.getElementById('empty-state');
  if (!list || !emptyState) return;
  clear(list);

  const checkboxes = document.querySelectorAll('#severity-filters input[type="checkbox"]');
  const activeFilters = new Set(Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value));

  const visibleFindings = data.findings.filter((f) => {
    if (f.isSuggestion) return activeFilters.has('suggestion');
    if (f.category === 'bug') return activeFilters.has('bug');
    if (f.category === 'secrets') return activeFilters.has('secrets');
    return activeFilters.has(f.severity || 'low');
  });

  if (visibleFindings.length === 0) {
    emptyState.classList.remove('hidden');
    return;
  }
  emptyState.classList.add('hidden');

  const groupBy = getGroupBy();
  if (groupBy === 'none') {
    for (const f of visibleFindings) list.appendChild(renderCard(f));
  } else {
    const groups = groupFindings(visibleFindings, groupBy);
    for (const [groupName, groupFindings] of groups) {
      const header = el('div', { class: 'group-header' },
        el('span', { class: 'group-toggle' }, '▼'),
        el('span', { class: 'group-name' }, groupName),
        el('span', { class: 'group-count' }, String(groupFindings.length)),
      );
      const body = el('div', { class: 'group-body' }, ...groupFindings.map(renderCard));
      const group = el('div', { class: 'finding-group' }, header, body);
      header.addEventListener('click', () => group.classList.toggle('collapsed'));
      list.appendChild(group);
    }
  }
}

function groupFindings(findings, groupBy) {
  const groups = new Map();
  for (const f of findings) {
    const key = groupBy === 'file' ? (f.filePath || '(unknown)') : (f.severity || 'info').toUpperCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  return groups;
}

function renderCard(f) {
  // Severity / suggestion / category badges.
  let badgeClass = 'badge-suggestion';
  let badgeText = 'SUGGESTION';
  if (!f.isSuggestion) {
    const sev = f.severity || 'low';
    badgeClass = `badge-${sev}`;
    badgeText = sev.toUpperCase();
  }
  const badges = el('div', { class: 'finding-badges' },
    el('span', { class: `badge ${badgeClass}` }, badgeText),
    el('span', { class: 'category-tag' }, String(f.category || '').toUpperCase()),
    !f.isSuggestion && f.confidence
      ? el('span', { class: 'category-tag' }, `CONFIDENCE: ${f.confidence.toUpperCase()}`)
      : null,
    f.astUsed === true
      ? el('span', { class: 'category-tag ast-tag' }, 'AST')
      : f.astUsed === false ? el('span', { class: 'category-tag regex-tag' }, 'REGEX') : null,
  );

  // Clickable file:line.
  let locationNode = null;
  if (f.filePath) {
    locationNode = el('span', {
      class: 'finding-location',
      dataset: { file: f.absolutePath || f.filePath, line: f.line || 1 },
    }, f.filePath, f.line ? `:${f.line}` : '');
    locationNode.addEventListener('click', () => {
      // @ts-ignore — `vscode` is from acquireVsCodeApi() in panelProvider.
      vscode.postMessage({
        command: 'openFile',
        filePath: locationNode.dataset.file,
        line: parseInt(locationNode.dataset.line || '1', 10),
      });
    });
  }

  const header = el('div', { class: 'finding-header' }, badges, locationNode);
  const message = el('div', { class: 'finding-message' }, f.message || '');

  // Details rows.
  const detailRows = [];
  if (f.fix)  detailRows.push(detailRow('Fix:',  f.fix));
  if (f.risk) detailRows.push(detailRow('Risk:', f.risk));
  if (f.cwe) {
    const cwes = Array.isArray(f.cwe) ? f.cwe : [f.cwe];
    const linkRow = el('div', { class: 'detail-row' }, el('span', { class: 'detail-label' }, 'CWE: '));
    cwes.forEach((c, i) => {
      if (i > 0) linkRow.appendChild(document.createTextNode(', '));
      const num = String(c).replace(/^CWE-/, '');
      linkRow.appendChild(el('a', {
        class: 'cwe-link',
        href: `https://cwe.mitre.org/data/definitions/${num}.html`,
        target: '_blank',
        rel: 'noopener',
      }, String(c)));
    });
    detailRows.push(linkRow);
  }
  if (Array.isArray(f.pathSteps) && f.pathSteps.length > 0) {
    const list = el('ol', { class: 'path-steps' });
    for (const s of f.pathSteps) {
      const loc = `${s.filePath || ''}:${s.line}${s.column ? ':' + s.column : ''}`;
      list.appendChild(el('li', null,
        el('span', { class: 'path-line' }, loc),
        ` — ${s.label || ''}`,
      ));
    }
    detailRows.push(el('div', { class: 'detail-row' },
      el('span', { class: 'detail-label' }, 'Data flow:'),
      list,
    ));
  }
  if (f.confidenceReason) {
    const why = el('span', { class: 'detail-label why-toggle' },
      `Why ${(f.confidence || '').toUpperCase()}? `,
      el('span', { class: 'toggle-icon' }, '▼'),
    );
    const whyContent = el('div', { class: 'why-content hidden' }, f.confidenceReason);
    why.addEventListener('click', () => whyContent.classList.toggle('hidden'));
    detailRows.push(el('div', { class: 'detail-row why-toggle-container' }, why, whyContent));
  }
  const details = el('div', { class: 'finding-details' }, ...detailRows);

  return el('div', { class: 'finding-card' }, header, message, details);
}

function detailRow(label, value) {
  return el('div', { class: 'detail-row' },
    el('span', { class: 'detail-label' }, label + ' '),
    String(value),
  );
}

function setupFilters() {
  const checkboxes = document.querySelectorAll('#severity-filters input[type="checkbox"]');
  checkboxes.forEach(cb => cb.addEventListener('change', renderFindings));
}

function setupGrouping() {
  const radios = document.querySelectorAll('#group-selector input[type="radio"]');
  radios.forEach(r => r.addEventListener('change', renderFindings));
}

function renderAstWarning() {
  const warningEl = document.getElementById('ast-warning');
  if (!warningEl) return;
  const rate = data.astSuccessRate;
  if (typeof rate === 'number' && rate < 80) {
    warningEl.classList.remove('hidden');
  }
}
