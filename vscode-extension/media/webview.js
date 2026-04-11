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

function renderSummary() {
  const summaryBar = document.getElementById('summary-bar');
  if (!summaryBar) return;

  const total = data.issueCount + data.suggestionCount;
  if (total === 0) {
    summaryBar.innerHTML = '<span>No issues found.</span>';
    return;
  }

  let html = `<span><strong>${total}</strong> total findings</span>`;
  if (data.highCount > 0) html += `<span class="badge badge-high">${data.highCount} HIGH</span>`;
  if (data.mediumCount > 0) html += `<span class="badge badge-medium">${data.mediumCount} MEDIUM</span>`;
  if (data.lowCount > 0) html += `<span class="badge badge-low">${data.lowCount} LOW</span>`;
  if (data.suggestionCount > 0) html += `<span class="badge badge-suggestion">${data.suggestionCount} SUGGESTIONS</span>`;

  summaryBar.innerHTML = html;
}

function renderStats() {
  const statsBar = document.getElementById('stats-bar');
  if (!statsBar) return;

  const parts = [];
  if (typeof data.totalFiles === 'number') parts.push(`${data.totalFiles} files`);
  if (typeof data.scanDurationMs === 'number') parts.push(`${data.scanDurationMs}ms`);
  if (typeof data.astSuccessRate === 'number') parts.push(`AST ${data.astSuccessRate}%`);

  if (parts.length > 0) {
    statsBar.innerHTML = `<span style="font-size:12px;opacity:0.7">${parts.join(' · ')}</span>`;
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

  const checkboxes = document.querySelectorAll('#severity-filters input[type="checkbox"]');
  const activeFilters = new Set(Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value));

  const visibleFindings = data.findings.filter((f) => {
    if (f.isSuggestion) return activeFilters.has('suggestion');
    if (f.category === 'bug') return activeFilters.has('bug');
    if (f.category === 'secrets') return activeFilters.has('secrets');
    return activeFilters.has(f.severity || 'low');
  });

  if (visibleFindings.length === 0) {
    list.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  const groupBy = getGroupBy();

  if (groupBy === 'none') {
    list.innerHTML = visibleFindings.map(renderCard).join('');
  } else {
    const groups = groupFindings(visibleFindings, groupBy);
    let html = '';
    for (const [groupName, groupFindings] of groups) {
      html += `
        <div class="finding-group">
          <div class="group-header" onclick="this.parentElement.classList.toggle('collapsed')">
            <span class="group-toggle">▼</span>
            <span class="group-name">${escapeHtml(groupName)}</span>
            <span class="group-count">${groupFindings.length}</span>
          </div>
          <div class="group-body">
            ${groupFindings.map(renderCard).join('')}
          </div>
        </div>
      `;
    }
    list.innerHTML = html;
  }

  // Add click listeners to location elements
  document.querySelectorAll('.finding-location').forEach(el => {
    el.addEventListener('click', (e) => {
      const target = e.currentTarget;
      const filePath = target.getAttribute('data-file');
      const line = parseInt(target.getAttribute('data-line') || '1', 10);
      if (filePath) {
        // @ts-ignore
        vscode.postMessage({ command: 'openFile', filePath, line });
      }
    });
  });
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
  let badgeClass = 'badge-suggestion';
  let badgeText = 'SUGGESTION';
  if (!f.isSuggestion) {
    const sev = f.severity || 'low';
    badgeClass = `badge-${sev}`;
    badgeText = sev.toUpperCase();
  }

  const confBadge = (!f.isSuggestion && f.confidence) ? `<span class="category-tag">CONFIDENCE: ${f.confidence.toUpperCase()}</span>` : '';
  const astBadge = (f.astUsed === true) ? '<span class="category-tag" style="background:#2d7d46">AST</span>' :
                   (f.astUsed === false) ? '<span class="category-tag" style="background:#8b6914">REGEX</span>' : '';

  let locationHtml = '';
  if (f.filePath) {
    const lineText = f.line ? `:${f.line}` : '';
    locationHtml = `<span class="finding-location" data-file="${escapeHtml(f.absolutePath || f.filePath)}" data-line="${f.line || 1}">${escapeHtml(f.filePath)}${lineText}</span>`;
  }

  let detailsHtml = '';
  if (f.fix) detailsHtml += `<div class="detail-row"><span class="detail-label">Fix:</span> ${escapeHtml(f.fix)}</div>`;
  if (f.risk) detailsHtml += `<div class="detail-row"><span class="detail-label">Risk:</span> ${escapeHtml(f.risk)}</div>`;
  if (f.confidenceReason) {
    detailsHtml += `
      <div class="detail-row why-toggle-container">
        <span class="detail-label why-toggle" onclick="this.nextElementSibling.classList.toggle('hidden')">
          Why ${escapeHtml(f.confidence || '').toUpperCase()}? <span class="toggle-icon">▼</span>
        </span>
        <div class="why-content hidden">
          ${escapeHtml(f.confidenceReason)}
        </div>
      </div>
    `;
  }

  return `
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-badges">
          <span class="badge ${badgeClass}">${badgeText}</span>
          <span class="category-tag">${f.category.toUpperCase()}</span>
          ${confBadge}
          ${astBadge}
        </div>
        ${locationHtml}
      </div>
      <div class="finding-message">${escapeHtml(f.message)}</div>
      <div class="finding-details">
        ${detailsHtml}
      </div>
    </div>
  `;
}

function setupFilters() {
  const checkboxes = document.querySelectorAll('#severity-filters input[type="checkbox"]');
  checkboxes.forEach(cb => {
    cb.addEventListener('change', () => {
      renderFindings();
    });
  });
}

function setupGrouping() {
  const radios = document.querySelectorAll('#group-selector input[type="radio"]');
  radios.forEach(r => {
    r.addEventListener('change', () => {
      renderFindings();
    });
  });
}

function renderAstWarning() {
  const warningEl = document.getElementById('ast-warning');
  if (!warningEl) return;
  const rate = data.astSuccessRate;
  if (typeof rate === 'number' && rate < 80) {
    warningEl.classList.remove('hidden');
  }
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return '';
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
