/**
 * Plain-JS checks against the built package, so they run on every Node version
 * in `engines` — the TypeScript suite needs type stripping and only runs on 24+.
 *
 *   npm run build && node --test test/smoke.mjs
 */
import assert from 'node:assert/strict';
import test from 'node:test';

const { lintSource, JsScanError } = await import('../dist/index.js');

test('flags postMessage(data, "*")', () => {
  const findings = lintSource(`win.postMessage(data, '*');`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'PM001');
});

test('flags a message handler that never checks event.origin', () => {
  const findings = lintSource(`window.addEventListener('message', (e) => { use(e.data); });`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'PM002');
});

test('flags event.origin.includes(...) as an unsound check', () => {
  const findings = lintSource(
    `window.addEventListener('message', (e) => { if (e.origin.includes('x.com')) go(e.data); });`,
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'PM003');
});

test('a well-formed handler and well-formed send produce no findings', () => {
  const src = [
    `const ALLOWED = ['https://a.example'];`,
    `window.addEventListener('message', function (e) {`,
    `  if (!ALLOWED.includes(e.origin)) return;`,
    `  if (e.source !== frame.contentWindow) return;`,
    `  console.log(e.data);`,
    `});`,
    `frame.contentWindow.postMessage('hi', 'https://a.example');`,
  ].join('\n');
  assert.deepEqual(lintSource(src), []);
});

test('refuses an unterminated string instead of guessing', () => {
  assert.throws(() => lintSource("const x = 'never closes;"), JsScanError);
});
