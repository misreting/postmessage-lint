import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { lint, lintSource, JsScanError } from '../src/index.ts';

function fixture(name: string): string {
  return fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
}

function read(name: string): string {
  return readFileSync(fixture(name), 'utf8');
}

test('PM001: flags postMessage(data, "*")', () => {
  const findings = lint([{ file: 'f.js', source: read('wildcard-broadcast.js') }]);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM001'],
  );
  assert.equal(findings[0]!.confidence, 'certain');
  assert.equal(findings[0]!.severity, 'warning');
});

test('PM001: also flags the { targetOrigin: "*" } options-object form', () => {
  const src = `frame.contentWindow.postMessage(payload, { targetOrigin: '*' });`;
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM001'],
  );
});

test('PM002: flags a handler that never checks event.origin', () => {
  const findings = lint([{ file: 'f.js', source: read('missing-origin-check.js') }]);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM002'],
  );
  assert.equal(findings[0]!.severity, 'error');
});

test('PM002: flags a handler with no parameter at all', () => {
  const src = `window.addEventListener('message', function () { doStuff(); });`;
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM002'],
  );
});

test('PM002: flags destructuring that omits origin', () => {
  const src = `window.addEventListener('message', ({ data }) => { use(data); });`;
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM002'],
  );
});

test('PM003: flags event.origin.includes(...) as an unsound check', () => {
  const findings = lint([{ file: 'f.js', source: read('unsound-origin-check.js') }]);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM003'],
  );
  assert.match(findings[0]!.message, /includes/);
});

test('PM003: also flags .startsWith and .indexOf', () => {
  for (const method of ['startsWith', 'indexOf']) {
    const src = `window.addEventListener('message', (e) => { if (e.origin.${method}('https://a')) go(); });`;
    const findings = lintSource(src);
    assert.deepEqual(
      findings.map((f) => f.rule),
      ['PM003'],
      `expected PM003 for .${method}`,
    );
  }
});

test('PM003: does NOT flag allowlist.includes(event.origin) (origin is the argument, not the receiver)', () => {
  const src = `window.addEventListener('message', (e) => { if (ALLOWED.includes(e.origin)) go(); });`;
  assert.deepEqual(lintSource(src), []);
});

test('PM004: flags event.source used without any identity comparison', () => {
  const findings = lint([{ file: 'f.js', source: read('unverified-source.js') }]);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM004'],
  );
});

test('PM004: does not flag event.source when compared against a known window', () => {
  const src = [
    `window.addEventListener('message', function (event) {`,
    `  if (event.origin !== 'https://trusted.example') return;`,
    `  if (event.source !== frame.contentWindow) return;`,
    `  event.source.postMessage('ack', event.origin);`,
    `});`,
  ].join('\n');
  assert.deepEqual(lintSource(src), []);
});

test('PM005: flags event.data (via a one-hop alias) reaching innerHTML', () => {
  const findings = lint([{ file: 'f.js', source: read('tainted-sink.js') }]);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM005'],
  );
});

test('PM005: flags event.data reaching eval() directly', () => {
  const src = [
    `window.addEventListener('message', function (event) {`,
    `  if (event.origin !== 'https://trusted.example') return;`,
    `  eval(event.data);`,
    `});`,
  ].join('\n');
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM005'],
  );
});

test('PM005: does not flag event.data used only for something inert', () => {
  const src = [
    `window.addEventListener('message', function (event) {`,
    `  if (event.origin !== 'https://trusted.example') return;`,
    `  console.log(event.data);`,
    `});`,
  ].join('\n');
  assert.deepEqual(lintSource(src), []);
});

test('PM006: an unresolvable handler reference is silent by default, reported with includePossible', () => {
  const source = read('unanalyzable-handler.js');
  assert.deepEqual(lint([{ file: 'f.js', source }]), []);
  const findings = lint([{ file: 'f.js', source }], { includePossible: true });
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM006'],
  );
  assert.equal(findings[0]!.confidence, 'possible');
});

test('resolves a named function handler declared elsewhere in the file', () => {
  const src = [
    `function onMsg(event) {`,
    `  console.log(event.data);`,
    `}`,
    `window.addEventListener('message', onMsg);`,
  ].join('\n');
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM002'],
  );
});

test('resolves a handler assigned via onmessage =', () => {
  const src = [`self.onmessage = function (event) {`, `  console.log(event.data);`, `};`].join('\n');
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM002'],
  );
});

test('a well-formed handler and well-formed sends produce no findings', () => {
  assert.deepEqual(lintSource(read('correct/safe.js')), []);
});

test('TypeScript syntax (type annotations, generics) does not confuse the scanner', () => {
  assert.deepEqual(lintSource(read('correct/typed-handler.ts')), []);
});

test('refuses an unterminated string instead of guessing', () => {
  assert.throws(() => lintSource(read('broken.js')), JsScanError);
});

test('refuses an unterminated template literal', () => {
  assert.throws(() => lintSource('const x = `unterminated;'), JsScanError);
});

test('a comment or string mentioning postMessage(data, "*") is not itself flagged', () => {
  const src = [
    `// example: win.postMessage(data, '*') is unsafe`,
    `const note = "call postMessage(data, '*') never";`,
  ].join('\n');
  assert.deepEqual(lintSource(src), []);
});

test('template-literal interpolation is scanned as real code (data reaching innerHTML through a template)', () => {
  const src = [
    `window.addEventListener('message', function (event) {`,
    `  if (event.origin !== 'https://trusted.example') return;`,
    `  el.innerHTML = \`<b>\${event.data}</b>\`;`,
    `});`,
  ].join('\n');
  const findings = lintSource(src);
  assert.deepEqual(
    findings.map((f) => f.rule),
    ['PM005'],
  );
});
