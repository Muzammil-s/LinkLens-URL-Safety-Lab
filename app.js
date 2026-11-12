(() => {
  const form = document.getElementById('scanForm');
  const input = document.getElementById('urlInput');
  const sample = document.getElementById('sampleBtn');
  const result = document.getElementById('result');
  const checksBox = document.getElementById('checks');
  const title = document.getElementById('resultTitle');
  const summary = document.getElementById('resultSummary');
  const score = document.getElementById('scoreValue');
  const hostValue = document.getElementById('hostValue');

  const isIPv4 = (host) => {
    const parts = host.split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
  };

  function inspectUrl(rawValue) {
    const raw = rawValue.trim();
    const candidate = /^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(raw) ? raw : `https://${raw}`;
    let parsed;
    try { parsed = new URL(candidate); } catch { throw new Error('Enter a valid web address, such as https://example.com.'); }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only HTTP and HTTPS web addresses can be inspected.');
    }

    const host = parsed.hostname.toLowerCase();
    const checks = [];
    const add = (level, heading, detail, weight = 0) => checks.push({ level, heading, detail, weight });

    if (parsed.protocol === 'http:') add('warn', 'The connection is not encrypted', 'This address uses HTTP. Information sent to the site may not be protected in transit.', 2);
    else add('good', 'HTTPS is used', 'The address uses HTTPS. This protects the connection in transit, but does not prove the site itself is trustworthy.');

    if (parsed.username || parsed.password || /@/.test(raw.split('/')[2] || '')) add('bad', 'Credentials or an @ sign appear in the authority', 'URLs can use an @ sign to make the text before it look like the destination. Read the parsed hostname carefully.', 3);
    if (host.startsWith('xn--') || host.split('.').some((part) => part.startsWith('xn--'))) add('warn', 'Internationalised domain label detected', 'A punycode label may represent non-Latin characters. Check the displayed domain carefully for lookalike characters.', 2);
    if (isIPv4(host) || host.startsWith('[')) add('warn', 'The host is an IP address', 'A direct IP address is not automatically malicious, but it is less typical for a public consumer website.', 2);
    if (host.split('.').length > 4) add('warn', 'Many subdomain levels', 'Several subdomains can make the true registered domain harder to notice. Read the hostname from right to left.', 1);
    if (parsed.port) add('warn', 'A non-default port is present', `The address uses port ${parsed.port}. This can be legitimate, but check whether you expected it.`, 1);
    if (raw.length > 120) add('warn', 'The URL is unusually long', 'Long URLs can hide the important destination among many parameters. Inspect the domain and query string separately.', 1);
    if (!checks.some((item) => item.weight > 0)) add('good', 'No listed indicators were detected', 'The basic checks did not find the patterns this tool looks for. This is not a guarantee of safety.');

    const total = checks.reduce((sum, item) => sum + item.weight, 0);
    return { host, checks, total };
  }

  function render(data) {
    checksBox.replaceChildren();
    data.checks.forEach((item) => {
      const card = document.createElement('article');
      card.className = `check ${item.level}`;
      const mark = document.createElement('span'); mark.className = 'mark'; mark.textContent = item.level === 'good' ? '✓' : item.level === 'warn' ? '!' : '×';
      const copy = document.createElement('div');
      const heading = document.createElement('strong'); heading.textContent = item.heading;
      const detail = document.createElement('p'); detail.textContent = item.detail;
      copy.append(heading, detail); card.append(mark, copy); checksBox.append(card);
    });
    score.textContent = String(data.checks.filter((item) => item.weight > 0).length);
    hostValue.textContent = data.host;
    if (data.total >= 5) { title.textContent = 'Several warning signs found'; summary.textContent = 'Pause and verify this destination through a trusted, independent source before proceeding.'; }
    else if (data.total > 0) { title.textContent = 'Review the warning signs'; summary.textContent = 'One or more patterns deserve a closer look. They are indicators, not proof of malicious activity.'; }
    else { title.textContent = 'Basic checks look clear'; summary.textContent = 'No listed warning patterns were detected. A clear result cannot establish that the website is safe.'; }
    result.hidden = false;
    result.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    try { render(inspectUrl(input.value)); }
    catch (error) { result.hidden = false; checksBox.replaceChildren(); title.textContent = 'Address could not be inspected'; summary.textContent = error.message; score.textContent = '—'; hostValue.textContent = 'Not available'; }
  });

  sample.addEventListener('click', () => {
    input.value = 'http://192.0.2.10:8080/account/verify?session=example';
    input.focus();
    form.requestSubmit();
  });
})();
