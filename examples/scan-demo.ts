/**
 * Lints one deliberately broken handler file and one fixed version, and
 * prints the real findings.
 *
 *   node examples/scan-demo.ts
 */
import { lint } from '../src/index.ts';

const broken = `
window.addEventListener('message', function (event) {
  // no origin check at all
  const cmd = event.data;
  document.getElementById('widget').innerHTML = cmd.html;
});

function broadcastStatus(win, status) {
  win.postMessage(status, '*');
}
`;

const fixed = `
const TRUSTED_ORIGINS = ['https://app.example.com'];

window.addEventListener('message', function (event) {
  if (!TRUSTED_ORIGINS.includes(event.origin)) return;
  if (event.source !== widgetFrame.contentWindow) return;

  const text = document.createTextNode(String(event.data.html));
  document.getElementById('widget').replaceChildren(text);
});

function broadcastStatus(win, status) {
  win.postMessage(status, 'https://app.example.com');
}
`;

function report(label: string, findings: ReturnType<typeof lint>): void {
  console.log(`\n${label}`);
  if (findings.length === 0) {
    console.log('  no findings');
    return;
  }
  for (const f of findings) {
    const tag = f.confidence === 'possible' ? `${f.severity}?` : f.severity;
    console.log(`  ${f.line}:${f.column}  ${tag.padEnd(8)} [${f.rule}] ${f.message}`);
  }
}

report('widget.js, as written (missing origin check, wildcard broadcast, tainted innerHTML)', lint([{ file: 'widget.js', source: broken }]));

report('widget.js, fixed', lint([{ file: 'widget.js', source: fixed }]));
