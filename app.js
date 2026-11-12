export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy', 'cutt.ly', 'shorturl.at'
]);

export const TRACKER_PARAMS = new Set([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'fbclid', 'gclid', 'dclid', 'msclkid', 'mc_cid', 'mc_eid', 'igshid', '_hsenc', '_hsmi'
]);

export const SUSPICIOUS_EXTENSIONS = /\.(exe|scr|bat|cmd|ps1|vbs|msi|apk|jar|dll)(\?|$)/i;

export const isIPv4 = (host) => {
  const parts = host.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
};

export function inspectUrl(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) throw new Error('Enter a web address to inspect.');
  const candidate = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(raw) ? raw : `https://${raw}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('Enter a valid web address, such as https://example.com.');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS web addresses can be inspected.');
  }

  const host = parsed.hostname.toLowerCase();
  const checks = [];
  const add = (level, heading, detail, weight = 0) => checks.push({ level, heading, detail, weight });

  if (parsed.protocol === 'http:') {
    add('warn', 'Unencrypted HTTP connection', 'Information sent to this address is not protected by TLS in transit.', 2);
  } else {
    add('good', 'HTTPS transport used', 'The URL specifies HTTPS, encrypting traffic in transit (though HTTPS alone never guarantees site legitimacy).', 0);
  }

  const authorityChunk = raw.replace(/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//, '').split('/')[0];
  if (parsed.username || parsed.password || authorityChunk.includes('@')) {
    add('bad', 'Credentials or @ sign in authority section', 'Attackers can place a trusted brand before an @ sign while the browser actually connects to the host after @.', 3);
  }

  if (host.startsWith('xn--') || host.split('.').some((part) => part.startsWith('xn--'))) {
    add('warn', 'Punycode / internationalized domain label', 'Labels starting with xn-- encode Unicode characters that may visually mimic ASCII letters (homoglyph risk).', 2);
  }

  if (isIPv4(host) || host.startsWith('[')) {
    add('warn', 'Direct IP address used instead of domain', 'Public consumer services rarely instruct users to log in via a raw IP address.', 2);
  }

  if (SHORTENERS.has(host)) {
    add('warn', 'Known URL shortener domain', 'Shortened links mask the final destination host until followed.', 2);
  }

  if (host.split('.').length > 4) {
    add('warn', 'Deeply nested subdomain chain', 'Multiple subdomains can push the real registered domain out of view. Read hostnames right-to-left.', 1);
  }

  if (parsed.port) {
    add('warn', `Non-standard port (${parsed.port})`, `Explicit port ${parsed.port} is specified. Confirm this service is expected.`, 1);
  }

  if (SUSPICIOUS_EXTENSIONS.test(parsed.pathname)) {
    add('bad', 'Executable or installer file extension in path', 'The path ends in a binary/script extension. Verify the source before downloading or running.', 3);
  }

  if (raw.length > 120) {
    add('warn', 'Unusually long URL', 'Long URLs can obscure the registered host among tracking tokens or encoded redirect parameters.', 1);
  }

  const queryParams = [];
  const cleanUrlObj = new URL(parsed.toString());
  let trackerCount = 0;
  for (const [key, val] of parsed.searchParams.entries()) {
    const isTracker = TRACKER_PARAMS.has(key.toLowerCase()) || key.toLowerCase().startsWith('utm_');
    if (isTracker) {
      trackerCount++;
      cleanUrlObj.searchParams.delete(key);
    }
    queryParams.push({ key, value: val, isTracker });
  }

  if (trackerCount > 0) {
    add('good', `${trackerCount} tracking parameter(s) identified`, 'Marketing or attribution parameters (e.g. utm_*, fbclid) were detected and can be stripped cleanly.', 0);
  }

  if (!checks.some((item) => item.weight > 0)) {
    add('good', 'No listed structural warning signs detected', 'Basic structural heuristics did not fire. Still verify sender identity and context.', 0);
  }

  const total = checks.reduce((sum, item) => sum + item.weight, 0);
  const signalCount = checks.filter((item) => item.weight > 0).length;

  return {
    rawInput: raw,
    normalizedUrl: parsed.toString(),
    cleanUrl: cleanUrlObj.toString(),
    trackerCount,
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    host,
    port: parsed.port || (parsed.protocol === 'https:' ? '443 (default)' : '80 (default)'),
    pathname: parsed.pathname || '/',
    hash: parsed.hash || 'None',
    queryParams,
    checks,
    total,
    signalCount,
    inspectedAt: new Date().toISOString()
  };
}

if (typeof document !== 'undefined') {
  const form = document.getElementById('scanForm');
  const input = document.getElementById('urlInput');
  const result = document.getElementById('result');
  const checksBox = document.getElementById('checks');
  const title = document.getElementById('resultTitle');
  const summary = document.getElementById('resultSummary');
  const score = document.getElementById('scoreValue');
  const hostValue = document.getElementById('hostValue');
  const anatomyGrid = document.getElementById('anatomyGrid');
  const queryBox = document.getElementById('queryBox');
  const queryList = document.getElementById('queryList');
  const copyCleanBtn = document.getElementById('copyCleanBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');
  const historyPanel = document.getElementById('historyPanel');
  const historyList = document.getElementById('historyList');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');

  let lastInspection = null;
  const history = [];

  function renderHistory() {
    if (!history.length) {
      historyPanel.hidden = true;
      return;
    }
    historyPanel.hidden = false;
    historyList.replaceChildren();
    history.slice(0, 6).forEach((item) => {
      const row = document.createElement('div');
      row.className = 'history-row';
      const urlSpan = document.createElement('span');
      urlSpan.className = 'url';
      urlSpan.textContent = item.normalizedUrl;
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = `${item.signalCount} signal(s)`;
      row.append(urlSpan, badge);
      row.addEventListener('click', () => {
        input.value = item.rawInput;
        render(item);
      });
      historyList.append(row);
    });
  }

  function render(data) {
    lastInspection = data;
    checksBox.replaceChildren();
    data.checks.forEach((item) => {
      const card = document.createElement('article');
      card.className = `check ${item.level}`;
      const mark = document.createElement('span');
      mark.className = 'mark';
      mark.textContent = item.level === 'good' ? '✓' : item.level === 'warn' ? '!' : '×';
      const copy = document.createElement('div');
      const heading = document.createElement('strong');
      heading.textContent = item.heading;
      const detail = document.createElement('p');
      detail.textContent = item.detail;
      copy.append(heading, detail);
      card.append(mark, copy);
      checksBox.append(card);
    });

    score.textContent = String(data.signalCount);
    hostValue.textContent = data.host;

    if (data.total >= 5) {
      title.textContent = 'Multiple structural warning signs found';
      summary.textContent = 'Pause and verify this destination through an independent bookmark or official channel before opening.';
    } else if (data.total > 0) {
      title.textContent = 'Review the structural signals';
      summary.textContent = 'One or more heuristics triggered. Treat these as inspection prompts, not proof of malicious intent.';
    } else {
      title.textContent = 'Basic structural checks look clear';
      summary.textContent = 'No listed heuristic patterns triggered. Always verify the sender independently.';
    }

    anatomyGrid.replaceChildren();
    [
      ['PROTOCOL', data.protocol],
      ['HOSTNAME', data.host],
      ['PORT', data.port],
      ['PATH', data.pathname],
      ['TRACKERS', String(data.trackerCount)],
      ['FRAGMENT', data.hash]
    ].forEach(([k, v]) => {
      const cell = document.createElement('div');
      cell.className = 'anatomy-item';
      const label = document.createElement('span');
      label.textContent = k;
      const code = document.createElement('code');
      code.textContent = v;
      cell.append(label, code);
      anatomyGrid.append(cell);
    });

    if (data.queryParams.length) {
      queryBox.hidden = false;
      queryList.replaceChildren();
      data.queryParams.forEach((qp) => {
        const pill = document.createElement('span');
        pill.className = `query-pill${qp.isTracker ? ' tracker' : ''}`;
        pill.textContent = `${qp.key}=${qp.value}${qp.isTracker ? ' (tracker)' : ''}`;
        queryList.append(pill);
      });
    } else {
      queryBox.hidden = true;
    }

    copyCleanBtn.hidden = data.trackerCount === 0;
    copyCleanBtn.textContent = 'Copy Clean URL (No Trackers)';
    result.hidden = false;
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      const inspected = inspectUrl(input.value);
      if (!history.some((h) => h.normalizedUrl === inspected.normalizedUrl)) {
        history.unshift(inspected);
      }
      render(inspected);
      renderHistory();
    } catch (error) {
      result.hidden = false;
      checksBox.replaceChildren();
      anatomyGrid.replaceChildren();
      queryBox.hidden = true;
      copyCleanBtn.hidden = true;
      title.textContent = 'Address could not be inspected';
      summary.textContent = error.message;
      score.textContent = '—';
      hostValue.textContent = 'Not available';
    }
  });

  document.querySelectorAll('[data-sample]').forEach((btn) => {
    btn.addEventListener('click', () => {
      input.value = btn.dataset.sample;
      input.focus();
      form.requestSubmit();
    });
  });

  copyCleanBtn.addEventListener('click', async () => {
    if (!lastInspection) return;
    try {
      await navigator.clipboard.writeText(lastInspection.cleanUrl);
      copyCleanBtn.textContent = 'Copied Clean URL!';
    } catch {
      copyCleanBtn.textContent = lastInspection.cleanUrl;
    }
  });

  exportReportBtn.addEventListener('click', () => {
    if (!lastInspection) return;
    const blob = new Blob([JSON.stringify(lastInspection, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'linklens-inspection.json';
    a.click();
    URL.revokeObjectURL(url);
  });

  clearHistoryBtn.addEventListener('click', () => {
    history.length = 0;
    renderHistory();
  });
}
