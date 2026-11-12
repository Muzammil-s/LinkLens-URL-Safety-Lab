import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectUrl, isIPv4 } from '../app.js';

test('isIPv4 validates IPv4 addresses accurately', () => {
  assert.equal(isIPv4('192.0.2.10'), true);
  assert.equal(isIPv4('999.0.0.1'), false);
  assert.equal(isIPv4('example.com'), false);
});

test('inspectUrl flags HTTP, IP host, non-standard port, and strips trackers', () => {
  const res = inspectUrl('http://192.0.2.10:8080/login?utm_source=test&id=42');
  assert.equal(res.protocol, 'HTTP');
  assert.equal(res.host, '192.0.2.10');
  assert.equal(res.trackerCount, 1);
  assert.equal(res.cleanUrl, 'http://192.0.2.10:8080/login?id=42');
  assert.ok(res.signalCount >= 3);
});

test('inspectUrl detects embedded @ authority spoofing and executable extensions', () => {
  const res = inspectUrl('https://trusted.example@198.51.100.2/payload/update.exe');
  assert.equal(res.host, '198.51.100.2');
  assert.ok(res.total >= 6);
});

test('inspectUrl rejects non-HTTP protocols', () => {
  assert.throws(() => inspectUrl('javascript:alert(1)'), /Only HTTP and HTTPS/);
  assert.throws(() => inspectUrl('ftp://files.example.com/archive.zip'), /Only HTTP and HTTPS/);
});
