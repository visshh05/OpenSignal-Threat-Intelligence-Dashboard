const form = document.querySelector('#lookup-form');
const targetInput = document.querySelector('#target-input');
const submitButton = document.querySelector('#submit-button');
const errorBox = document.querySelector('#form-error');
const resultSection = document.querySelector('#results');
const emptyState = document.querySelector('#empty-state');
const historyList = document.querySelector('#history-list');
const recentSection = document.querySelector('#recent-section');

const demoPayload = {
  target: 'demo.example.net',
  target_type: 'domain',
  demo: true,
  results: [
    { provider: 'VirusTotal', status: 'ok', malicious: 2, suspicious: 1, harmless: 71, undetected: 4, reputation: -12, last_analysis_date: '2026-10-15T08:12:00Z' },
    { provider: 'Shodan', status: 'not_applicable', message: 'Shodan host lookup requires an IP address.' },
    { provider: 'crt.sh', status: 'ok', count: 18, certificates: [
      { name: 'login.demo.example.net', issuer: "C=US, O=Let's Encrypt, CN=R11", issued: '2026-10-11', expires: '2027-01-09' },
      { name: '*.demo.example.net', issuer: "C=US, O=Let's Encrypt, CN=R11", issued: '2026-09-29', expires: '2026-12-28' },
      { name: 'mail.demo.example.net', issuer: 'C=US, O=DigiCert Inc, CN=G2', issued: '2026-08-03', expires: '2027-08-03' }
    ] }
  ]
};

const ipDemoPayload = {
  target: '198.51.100.24',
  target_type: 'ip',
  demo: true,
  results: [
    { provider: 'VirusTotal', status: 'ok', malicious: 0, suspicious: 1, harmless: 68, undetected: 5, reputation: 4, last_analysis_date: '2026-10-15T08:12:00Z' },
    { provider: 'Shodan', status: 'ok', ip: '198.51.100.24', organization: 'Example Networks', country: 'United States', city: 'Example City', ports: [22, 443], hostnames: ['demo.example.net'], vulnerabilities: [], last_update: '2026-10-15T07:40:00Z' },
    { provider: 'crt.sh', status: 'not_applicable', message: 'Certificate transparency search requires a domain.' }
  ]
};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeHtml(value) : date.toISOString().slice(0, 10);
}

function getResult(data, provider) {
  return data.results.find(item => item.provider === provider) || { provider, status: 'error', message: 'No provider result returned.' };
}

function providerPanel(data, provider, letter, logoClass, wide = false) {
  const item = getResult(data, provider);
  const state = escapeHtml(item.status.replaceAll('_', ' '));
  let body = `<div class="provider-message">${escapeHtml(item.message || 'No details available.')}</div>`;
  if (item.status === 'ok' && provider === 'VirusTotal') {
    body = `<div class="metric-row"><div class="metric"><strong>${escapeHtml(item.malicious)}</strong><span>Malicious</span></div><div class="metric"><strong>${escapeHtml(item.suspicious)}</strong><span>Suspicious</span></div><div class="metric"><strong>${escapeHtml(item.harmless)}</strong><span>Harmless</span></div><div class="metric"><strong>${escapeHtml(item.undetected)}</strong><span>Undetected</span></div></div><div class="detail-line">Reputation <b>${escapeHtml(item.reputation ?? '—')}</b>${item.last_analysis_date ? ` &nbsp;·&nbsp; Last analysis <b>${formatDate(item.last_analysis_date)}</b>` : ''}</div>`;
  }
  if (item.status === 'ok' && provider === 'Shodan') {
    const ports = item.ports.length ? item.ports.map(port => `<span class="data-tag">${escapeHtml(port)}/tcp</span>`).join('') : '<span class="provider-message">No open ports reported</span>';
    const vulns = item.vulnerabilities.length ? item.vulnerabilities.map(vuln => `<span class="data-tag vuln">${escapeHtml(vuln)}</span>`).join('') : '';
    const hostnames = item.hostnames.length ? item.hostnames.map(hostname => `<span class="data-tag hostname">${escapeHtml(hostname)}</span>`).join('') : '';
    const addressDetails = Array.isArray(item.ips) && item.ips.length
      ? ` &nbsp;·&nbsp; IPs <b>${escapeHtml(item.ips.join(', '))}</b>`
      : item.ip ? ` &nbsp;·&nbsp; IP <b>${escapeHtml(item.ip)}</b>` : '';
    body = `<div class="detail-line" style="margin:0 0 10px">Data source <b>${escapeHtml(item.source || 'Shodan')}</b>${addressDetails}</div><div class="metric-row"><div class="metric"><strong>${item.ports.length}</strong><span>Open ports</span></div><div class="metric"><strong>${item.vulnerabilities.length}</strong><span>Known CVEs</span></div><div class="metric"><strong>${escapeHtml(item.country)}</strong><span>Location</span></div></div><div class="detail-line">Organization <b>${escapeHtml(item.organization)}</b>${item.city ? ` &nbsp;·&nbsp; <b>${escapeHtml(item.city)}</b>` : ''}${item.last_update ? ` &nbsp;·&nbsp; Last seen <b>${escapeHtml(item.last_update)}</b>` : ''}</div><div class="tag-list">${ports}${vulns}${hostnames}</div>`;
  }
  if (item.status === 'ok' && provider === 'crt.sh') {
    const rows = item.certificates.length ? item.certificates.map(cert => `<div class="cert-row"><span class="cert-name">${escapeHtml(cert.name)}</span><span class="cert-issuer">${escapeHtml(cert.issuer)}</span><span class="cert-date">${formatDate(cert.issued)} → ${formatDate(cert.expires)}</span></div>`).join('') : '<div class="provider-message">No certificates found for this query.</div>';
    body = `<div class="detail-line" style="margin:0 0 8px">${escapeHtml(item.count)} distinct certificate records</div><div class="cert-list">${rows}</div>`;
  }
  return `<article class="provider-panel${wide ? ' wide' : ''}"><header class="provider-head"><span class="provider-name"><span class="source-logo ${logoClass}">${letter}</span>${provider}</span><span class="provider-state ${escapeHtml(item.status)}">${state}</span></header><div class="provider-body">${body}</div></article>`;
}

function renderResults(data) {
  const vt = getResult(data, 'VirusTotal');
  const shodan = getResult(data, 'Shodan');
  const cert = getResult(data, 'crt.sh');
  const malicious = vt.status === 'ok' ? Number(vt.malicious || 0) : null;
  const suspicious = vt.status === 'ok' ? Number(vt.suspicious || 0) : null;
  const reputation = vt.status === 'ok'
    ? (vt.reputation != null ? escapeHtml(vt.reputation) : 'Not reported')
    : (vt.status === 'needs_key' ? 'API key needed' : 'Unavailable');
  const reputationDetails = vt.status === 'ok'
    ? `${malicious} malicious · ${suspicious} suspicious`
    : escapeHtml(vt.message || `VirusTotal ${vt.status.replaceAll('_', ' ')}`);
  const vulnerabilityCount = shodan.status === 'ok' ? shodan.vulnerabilities.length : null;
  const portCount = shodan.status === 'ok' ? shodan.ports.length : null;
  const portsSummary = shodan.status === 'ok'
    ? escapeHtml(portCount)
    : (shodan.status === 'needs_key' ? 'API key needed' : shodan.status === 'not_applicable' ? 'IP required' : shodan.status === 'clear' ? 'No data found' : 'Unavailable');
  const portDetails = shodan.status === 'ok'
    ? (shodan.ports.length ? shodan.ports.map(port => `${escapeHtml(port)}/tcp`).join(' · ') : 'No open ports reported')
    : escapeHtml(shodan.message || `Shodan ${shodan.status.replaceAll('_', ' ')}`);
  const certCount = cert.status === 'ok' ? Number(cert.count || 0) : null;
  const coverageCount = [vt.status === 'ok', shodan.status === 'ok'].filter(Boolean).length;
  const signalCount = (malicious || 0) + (suspicious || 0) + (vulnerabilityCount || 0);
  const assessment = signalCount > 0
    ? { title: 'Signals observed', className: 'signal-warning' }
    : coverageCount === 2
      ? { title: 'No flagged provider signals', className: 'signal-clear' }
      : { title: 'Limited coverage', className: 'signal-limited' };
  const checkedAt = data.checked_at || new Date().toISOString();
  resultSection.innerHTML = `<div class="result-heading"><div><h2>${escapeHtml(data.target)}</h2><p>${escapeHtml(data.target_type.toUpperCase())} INDICATOR &nbsp;·&nbsp; ${escapeHtml(checkedAt.replace('T', ' ').slice(0, 19))} UTC</p></div><div class="result-heading-tools"><div class="result-badges">${data.demo ? '<span class="result-badge demo">DEMO DATA</span>' : '<span class="result-badge">LIVE LOOKUP</span>'}</div><div class="result-actions"><button class="action-button" type="button" data-action="copy">Copy indicator</button><button class="action-button primary-action" type="button" data-action="export">Export JSON</button></div></div></div>
    <div class="assessment-strip ${assessment.className}"><div><span class="assessment-kicker">EVIDENCE SUMMARY</span><strong>${assessment.title}</strong><p>Reported detections and CVEs only; this is not a composite risk score.</p></div><div class="assessment-facts"><span>${coverageCount}/2 risk sources returned data</span><span>${malicious ?? '—'} malicious · ${suspicious ?? '—'} suspicious · ${vulnerabilityCount ?? '—'} CVEs</span></div></div>
    <div class="summary-grid"><div class="summary-tile"><div class="tile-label">Reputation score</div><div class="tile-value${vt.status === 'ok' && vt.reputation != null ? '' : ' unavailable'}">${reputation}</div><div class="tile-note">${reputationDetails}</div></div><div class="summary-tile"><div class="tile-label">Exposed ports</div><div class="tile-value${shodan.status === 'ok' ? '' : ' unavailable'}">${portsSummary}${portCount === null ? '' : '<small>PORTS</small>'}</div><div class="tile-note">${portDetails}</div></div><div class="summary-tile"><div class="tile-label">Certificates</div><div class="tile-value">${certCount ?? '—'}${certCount === null ? '' : '<small>RECORDS</small>'}</div></div></div>
    <div class="provider-grid">${providerPanel(data, 'VirusTotal', 'V', 'vt')}${providerPanel(data, 'Shodan', 'S', 'sh')}${providerPanel(data, 'crt.sh', 'C', 'crt', true)}</div>`;
  resultSection.dataset.target = data.target;
  resultSection.dataset.result = JSON.stringify(data);
  resultSection.hidden = false;
  emptyState.classList.add('results-hidden');
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function copyIndicator(target, button) {
  try {
    await navigator.clipboard.writeText(target);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Copy unavailable';
  }
  window.setTimeout(() => { button.textContent = 'Copy indicator'; }, 1400);
}

function exportReport(data) {
  const report = {
    report_type: 'OpenSignal public threat intelligence report',
    exported_at: new Date().toISOString(),
    ...data
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `opensignal-${data.target.replace(/[^a-z0-9.-]/gi, '_')}.json`;
  document.body.appendChild(link);
  link.click();
  window.setTimeout(() => {
    link.remove();
    URL.revokeObjectURL(url);
  }, 1000);
}

function readHistory() {
  try {
    const history = JSON.parse(localStorage.getItem('opensignal-history') || '[]');
    return Array.isArray(history)
      ? history.filter(target => typeof target === 'string').slice(0, 8)
      : [];
  } catch {
    return [];
  }
}

function renderHistory() {
  const history = readHistory();
  recentSection.hidden = history.length === 0;
  historyList.innerHTML = history.map(target => `<button class="history-entry" type="button" data-target="${escapeHtml(target)}"><span>↗</span><span>${escapeHtml(target)}</span></button>`).join('');
}

function saveHistory(target) {
  const history = [target, ...readHistory().filter(item => item !== target)].slice(0, 8);
  localStorage.setItem('opensignal-history', JSON.stringify(history));
  renderHistory();
}

async function lookup(target) {
  errorBox.hidden = true;
  submitButton.disabled = true;
  submitButton.querySelector('span').textContent = 'Querying sources';
  resultSection.hidden = false;
  resultSection.innerHTML = '<div class="loading-row"><span class="spinner"></span>Querying public intelligence sources...</div>';
  emptyState.classList.add('results-hidden');
  try {
    const response = await fetch('/api/lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The lookup could not be completed.');
    renderResults(data);
    saveHistory(data.target);
  } catch (error) {
    resultSection.hidden = true;
    emptyState.classList.remove('results-hidden');
    errorBox.textContent = error.message || 'Unable to reach the dashboard service.';
    errorBox.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.querySelector('span').textContent = 'Analyze indicator';
  }
}

form.addEventListener('submit', event => {
  event.preventDefault();
  lookup(targetInput.value);
});
document.querySelector('#demo-button').addEventListener('click', () => {
  targetInput.value = demoPayload.target;
  renderResults(demoPayload);
});
document.querySelector('#ip-demo-button').addEventListener('click', () => {
  targetInput.value = ipDemoPayload.target;
  renderResults(ipDemoPayload);
});
historyList.addEventListener('click', event => {
  const button = event.target.closest('[data-target]');
  if (button) {
    targetInput.value = button.dataset.target;
    lookup(button.dataset.target);
  }
});
resultSection.addEventListener('click', event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const data = JSON.parse(resultSection.dataset.result || 'null');
  if (!data) return;
  if (button.dataset.action === 'copy') copyIndicator(data.target, button);
  if (button.dataset.action === 'export') exportReport(data);
});
document.querySelector('#clear-history').addEventListener('click', () => {
  localStorage.removeItem('opensignal-history');
  renderHistory();
});

renderHistory();
targetInput.value = ipDemoPayload.target;
renderResults(ipDemoPayload);