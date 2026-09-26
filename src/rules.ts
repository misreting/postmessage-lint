import { matchBracket, splitTopLevelCommas, trimSpan, offsetToLineColumn, escapeRegExp } from './scanner.ts';
import { RULES, SINK_ASSIGN_PROPS } from './model.ts';

export type Severity = 'error' | 'warning';

/**
 * `certain` findings are provable from the source text alone once a message
 * handler's function body is actually found: it either reads `event.origin`
 * somewhere or it does not, a `.startsWith`/`.indexOf`/`.includes` chained
 * directly on it either appears or it doesn't. `possible` is reserved for the
 * one case this tool cannot see into at all — a handler passed by a
 * reference this scanner can't resolve to a definition in the same file —
 * and is only reported when the caller opts in, so the default output isn't
 * dominated by "couldn't check this" noise. See README, "What this can
 * prove, and what it can only flag as unanalyzable."
 */
export type Confidence = 'certain' | 'possible';

export interface Finding {
  rule: string;
  message: string;
  file: string;
  line: number;
  column: number;
  severity: Severity;
  confidence: Confidence;
}

export interface LintOptions {
  /**
   * Also report `message`-event handlers this tool could not resolve to a
   * function body in the same file (PM006) — imported handlers, handlers
   * built dynamically, member-expression handlers, and the like. Off by
   * default: on a typical project using a shared `dispatch(event)` imported
   * from another module, this would fire on most registrations.
   */
  includePossible?: boolean;
}

export interface LintFile {
  file: string;
  masked: string;
  source: string;
}

function push(
  findings: Finding[],
  file: string,
  source: string,
  offset: number,
  rule: string,
  severity: Severity,
  confidence: Confidence,
  message: string,
): void {
  const { line, column } = offsetToLineColumn(source, offset);
  findings.push({ rule, message, file, line, column, severity, confidence });
}

// ---------------------------------------------------------------------------
// PM001 — postMessage(data, '*') / postMessage(data, { targetOrigin: '*' })
// ---------------------------------------------------------------------------

function checkBroadcasts(file: string, source: string, masked: string, findings: Finding[]): void {
  const re = /\bpostMessage\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(masked))) {
    const openParen = m.index + m[0].length - 1;
    const closeParen = matchBracket(masked, openParen, file, source);
    const args = splitTopLevelCommas(masked, openParen + 1, closeParen);
    if (args.length < 2) continue;
    const [s, e] = trimSpan(source, args[1]![0], args[1]![1]);
    const text = source.slice(s, e);

    if (text === "'*'" || text === '"*"') {
      pushBroadcast(file, source, s, findings);
      continue;
    }
    if (text.startsWith('{') && /targetOrigin\s*:\s*(['"])\*\1/.test(text)) {
      pushBroadcast(file, source, s, findings);
    }
  }
}

function pushBroadcast(file: string, source: string, offset: number, findings: Finding[]): void {
  push(
    findings,
    file,
    source,
    offset,
    RULES.PM001.code,
    RULES.PM001.severity,
    'certain',
    `targetOrigin is "*" — this message is delivered to whatever origin the target window ` +
      `currently has. Per the HTML Standard, "*" means no origin restriction is applied to the ` +
      `send at all; per MDN's postMessage security guidance, always specify an exact target ` +
      `origin instead, because the target window's location can change (e.g. via navigation) ` +
      `without the sender knowing.`,
  );
}

// ---------------------------------------------------------------------------
// Locating and reading `message`-event handler bodies.
// ---------------------------------------------------------------------------

export interface HandlerBody {
  /** The raw text between a function/arrow's parentheses, e.g. `event` or `{ origin, data }`. */
  paramText: string;
  /** Offsets into `source`/`masked` spanning the handler's body (inclusive of `{`/`}` for a block body). */
  bodyStart: number;
  bodyEnd: number;
}

type HandlerResolution =
  | { kind: 'resolved'; body: HandlerBody }
  | { kind: 'identifier'; name: string }
  | { kind: 'unresolved' };

/**
 * Classify the JS expression at `masked[start..boundHint)` as a message
 * handler this tool can read into. `boundHint` is the known (or, for a bare
 * assignment, best-guess) end of the expression — used as the body's end for
 * an arrow function with an implicit-return (brace-less) body, and as the
 * search window for a bare-identifier reference.
 */
function classifyHandlerExpr(
  file: string,
  source: string,
  masked: string,
  start: number,
  boundHint: number,
): HandlerResolution {
  let p = start;
  while (p < boundHint && /\s/.test(masked[p]!)) p++;
  if (p >= boundHint) return { kind: 'unresolved' };

  let q = p;
  let isAsync = false;
  if (/^async\b/.test(masked.slice(q, Math.min(q + 6, masked.length)))) {
    isAsync = true;
    q += 5;
    while (q < masked.length && /\s/.test(masked[q]!)) q++;
  }

  // function [name]? ( params ) { body }
  if (/^function\b/.test(masked.slice(q, Math.min(q + 9, masked.length)))) {
    q += 8;
    while (q < masked.length && /\s/.test(masked[q]!)) q++;
    while (q < masked.length && /[\w$]/.test(masked[q]!)) q++; // optional function name
    while (q < masked.length && /\s/.test(masked[q]!)) q++;
    if (masked[q] !== '(') return { kind: 'unresolved' };
    const paramOpen = q;
    const paramClose = matchBracket(masked, paramOpen, file, source);
    let b = paramClose + 1;
    while (b < masked.length && /\s/.test(masked[b]!)) b++;
    if (masked[b] !== '{') return { kind: 'unresolved' };
    const bodyOpen = b;
    const bodyClose = matchBracket(masked, bodyOpen, file, source);
    return {
      kind: 'resolved',
      body: { paramText: source.slice(paramOpen + 1, paramClose), bodyStart: bodyOpen, bodyEnd: bodyClose + 1 },
    };
  }

  // ( params ) => ...   or   ident => ...
  let paramText: string | undefined;
  let afterParams = -1;
  if (masked[q] === '(') {
    const paramOpen = q;
    const paramClose = matchBracket(masked, paramOpen, file, source);
    paramText = source.slice(paramOpen + 1, paramClose);
    afterParams = paramClose + 1;
  } else if (/[\w$]/.test(masked[q] ?? '')) {
    const identStart = q;
    let e = q;
    while (e < boundHint && /[\w$]/.test(masked[e]!)) e++;
    paramText = source.slice(identStart, e);
    afterParams = e;
  }

  if (paramText !== undefined) {
    let a = afterParams;
    while (a < masked.length && /\s/.test(masked[a]!)) a++;
    if (masked[a] === '=' && masked[a + 1] === '>') {
      a += 2;
      while (a < masked.length && /\s/.test(masked[a]!)) a++;
      if (masked[a] === '{') {
        const bodyOpen = a;
        const bodyClose = matchBracket(masked, bodyOpen, file, source);
        return { kind: 'resolved', body: { paramText, bodyStart: bodyOpen, bodyEnd: bodyClose + 1 } };
      }
      // Expression-bodied arrow: the implicit return is the whole remaining span.
      return { kind: 'resolved', body: { paramText, bodyStart: a, bodyEnd: boundHint } };
    }
  }

  // A bare identifier and nothing else: a reference to a handler defined elsewhere.
  const trimmedWhole = masked.slice(p, boundHint).trim();
  if (!isAsync && /^[A-Za-z_$][\w$]*$/.test(trimmedWhole)) {
    return { kind: 'identifier', name: trimmedWhole };
  }

  return { kind: 'unresolved' };
}

/** Depth-aware scan for the first top-level `;` (or `limit`) from `start` — no bracket-matching needed. */
function findStatementEnd(masked: string, start: number, limit: number): number {
  let depth = 0;
  for (let i = start; i < limit; i++) {
    const ch = masked[i];
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1);
    else if (ch === ';' && depth === 0) return i;
  }
  return limit;
}

/** Resolve a bare handler identifier to a function/arrow body declared anywhere in the same file. */
function resolveIdentifierInFile(file: string, source: string, masked: string, name: string): HandlerBody | undefined {
  const esc = escapeRegExp(name);

  const fnMatch = new RegExp(`\\bfunction\\s+${esc}\\s*\\(`).exec(masked);
  if (fnMatch) {
    const paramOpen = fnMatch.index + fnMatch[0].length - 1;
    const paramClose = matchBracket(masked, paramOpen, file, source);
    let b = paramClose + 1;
    while (b < masked.length && /\s/.test(masked[b]!)) b++;
    if (masked[b] === '{') {
      const bodyOpen = b;
      const bodyClose = matchBracket(masked, bodyOpen, file, source);
      return { paramText: source.slice(paramOpen + 1, paramClose), bodyStart: bodyOpen, bodyEnd: bodyClose + 1 };
    }
  }

  const assignMatch = new RegExp(`\\b(?:const|let|var)\\s+${esc}\\s*=\\s*`).exec(masked);
  if (assignMatch) {
    const rhsStart = assignMatch.index + assignMatch[0].length;
    const looseEnd = findStatementEnd(masked, rhsStart, masked.length);
    const resolution = classifyHandlerExpr(file, source, masked, rhsStart, looseEnd);
    if (resolution.kind === 'resolved') return resolution.body;
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Reading event.origin / event.source / event.data out of a handler body,
// whichever of the two shapes real code uses to bind them.
// ---------------------------------------------------------------------------

interface Accessor {
  /** A regex *source fragment* matching exactly how this value is referenced in this body. */
  accessSrc: string;
}

function resolveAccessor(
  key: 'origin' | 'source' | 'data',
  isDestructured: boolean,
  paramTrimmed: string,
  paramName: string | undefined,
  bodyMasked: string,
): Accessor | undefined {
  if (isDestructured) {
    const m = new RegExp(`\\b${key}\\b\\s*(?::\\s*([A-Za-z_$][\\w$]*))?`).exec(paramTrimmed);
    if (!m) return undefined;
    const bound = m[1] ?? key;
    return { accessSrc: `\\b${escapeRegExp(bound)}\\b` };
  }

  if (!paramName) return undefined;

  const dottedSrc = `${escapeRegExp(paramName)}\\s*\\.\\s*${key}\\b`;
  if (new RegExp(dottedSrc).test(bodyMasked)) return { accessSrc: dottedSrc };

  // Fallback: `const { origin } = event;` (or `source`/`data`) inside the body itself.
  const destructureMatch = new RegExp(
    `\\{[^{}]*\\b${key}\\b(?:\\s*:\\s*([A-Za-z_$][\\w$]*))?[^{}]*\\}\\s*=\\s*${escapeRegExp(paramName)}\\b`,
  ).exec(bodyMasked);
  if (destructureMatch) {
    const bound = destructureMatch[1] ?? key;
    return { accessSrc: `\\b${escapeRegExp(bound)}\\b` };
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// PM002 / PM003 / PM004 / PM005 — analysis of one resolved handler body.
// ---------------------------------------------------------------------------

function analyzeHandler(file: string, source: string, masked: string, body: HandlerBody, findings: Finding[]): void {
  const { paramText, bodyStart, bodyEnd } = body;
  const paramTrimmed = paramText.trim();
  const bodyMasked = masked.slice(bodyStart, bodyEnd);

  const isDestructured = paramTrimmed.startsWith('{');
  const paramName =
    !isDestructured && paramTrimmed !== '' ? /^[A-Za-z_$][\w$]*/.exec(paramTrimmed)?.[0] : undefined;

  // PM002 / PM003 — event.origin.
  const origin = resolveAccessor('origin', isDestructured, paramTrimmed, paramName, bodyMasked);
  if (!origin) {
    const why =
      paramTrimmed === ''
        ? 'this handler takes no parameter at all, so it has no way to read event.origin'
        : isDestructured
          ? `this handler destructures its event parameter (${collapseWhitespace(paramTrimmed)}) but never pulls out "origin"`
          : `this handler never reads "${paramName}.origin" (and never destructures "origin" from "${paramName}") anywhere in its body`;
    push(
      findings,
      file,
      source,
      bodyStart,
      RULES.PM002.code,
      RULES.PM002.severity,
      'certain',
      `This "message" handler never checks event.origin — ${why}. Per the HTML Standard, any ` +
        `window or worker can call postMessage on this one; per MDN's postMessage security ` +
        `guidance, without an origin check this handler accepts instructions from any origin, ` +
        `not just the one it was written to trust.`,
    );
  } else {
    const unsoundMatch = new RegExp(`(?:${origin.accessSrc})\\s*\\.\\s*(startsWith|indexOf|includes)\\s*\\(`).exec(
      bodyMasked,
    );
    if (unsoundMatch) {
      push(
        findings,
        file,
        source,
        bodyStart + unsoundMatch.index,
        RULES.PM003.code,
        RULES.PM003.severity,
        'certain',
        `event.origin is checked with ".${unsoundMatch[1]}(...)" — a substring/prefix test, not an ` +
          `exact match. Per MDN's postMessage security guidance, this is unsound: checking for ` +
          `"yoursite.com" this way also matches "https://evil-yoursite.com" (".includes"/` +
          `".indexOf" find it anywhere in the string) or a same-prefixed attacker subdomain like ` +
          `"yoursite.com.evil.tld" (".startsWith" only checks the front). Compare with "===" ` +
          `against one known origin, or call ".includes(event.origin)" ON an allowlist array — ` +
          `with the origin as the argument, not as the receiver.`,
      );
    }
  }

  // PM004 — event.source used but never verified.
  const src = resolveAccessor('source', isDestructured, paramTrimmed, paramName, bodyMasked);
  if (src) {
    const usedMatch = new RegExp(src.accessSrc).exec(bodyMasked);
    const comparedAnywhere = new RegExp(
      `(?:(?:${src.accessSrc})\\s*(?:===|!==|==|!=))|(?:(?:===|!==|==|!=)\\s*(?:${src.accessSrc}))`,
    ).test(bodyMasked);
    if (usedMatch && !comparedAnywhere) {
      push(
        findings,
        file,
        source,
        bodyStart + usedMatch.index,
        RULES.PM004.code,
        RULES.PM004.severity,
        'certain',
        `event.source is used here but this handler never compares it against a known window or ` +
          `port (no "==="/"!==" on it anywhere in the body). Per the HTML Standard, source is ` +
          `"the ... object that is the message's sender" — without verifying it is the specific ` +
          `window this handler expects (e.g. "=== iframe.contentWindow"), replying to event.source ` +
          `sends that reply to whatever sent the message, trusted or not.`,
      );
    }
  }

  // PM005 — event.data flowing into an HTML/script sink.
  const data = resolveAccessor('data', isDestructured, paramTrimmed, paramName, bodyMasked);
  if (data) {
    const taintPatterns = buildTaintPatterns(data.accessSrc, bodyMasked);
    checkSinks(file, source, masked, bodyStart, bodyMasked, taintPatterns, findings);
  }
}

function collapseWhitespace(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

/** The base access expression, plus every one-hop local alias assigned directly from it. */
function buildTaintPatterns(accessSrc: string, bodyMasked: string): RegExp[] {
  const patterns = [new RegExp(accessSrc)];
  const aliasRe = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:${accessSrc})\\b`, 'g');
  let m: RegExpExecArray | null;
  while ((m = aliasRe.exec(bodyMasked))) {
    patterns.push(new RegExp(`\\b${escapeRegExp(m[1]!)}\\b`));
  }
  return patterns;
}

const CALL_SINKS: Array<{ re: RegExp; label: string }> = [
  { re: /\beval\s*\(/g, label: 'eval(...)' },
  { re: /\bnew\s+Function\s*\(/g, label: 'new Function(...)' },
  { re: /\.insertAdjacentHTML\s*\(/g, label: 'insertAdjacentHTML(...)' },
  { re: /\bdocument\s*\.\s*write\s*\(/g, label: 'document.write(...)' },
  { re: /\bdocument\s*\.\s*writeln\s*\(/g, label: 'document.writeln(...)' },
];

function checkSinks(
  file: string,
  source: string,
  masked: string,
  bodyStart: number,
  bodyMasked: string,
  taintPatterns: RegExp[],
  findings: Finding[],
): void {
  const isTainted = (text: string) => taintPatterns.some((p) => p.test(text));

  for (const prop of SINK_ASSIGN_PROPS) {
    const re = new RegExp(`\\.${prop}\\s*=(?!=)`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(bodyMasked))) {
      const rhsStart = m.index + m[0].length;
      const rhsEnd = findStatementEnd(bodyMasked, rhsStart, bodyMasked.length);
      if (isTainted(bodyMasked.slice(rhsStart, rhsEnd))) {
        pushSink(file, source, bodyStart + m.index, `.${prop} = ...`, findings);
      }
    }
  }

  for (const { re, label } of CALL_SINKS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(bodyMasked))) {
      const openParenAbs = bodyStart + m.index + m[0].length - 1;
      const closeParenAbs = matchBracket(masked, openParenAbs, file, source);
      const argsText = masked.slice(openParenAbs + 1, closeParenAbs);
      if (isTainted(argsText)) {
        pushSink(file, source, bodyStart + m.index, label, findings);
      }
    }
  }
}

function pushSink(file: string, source: string, offset: number, label: string, findings: Finding[]): void {
  push(
    findings,
    file,
    source,
    offset,
    RULES.PM005.code,
    RULES.PM005.severity,
    'certain',
    `Data received from a "message" event flows into ${label}. Per MDN's postMessage security ` +
      `guidance ("do not use eval() to parse the data of an incoming message" — the same warning ` +
      `generalizes to innerHTML/outerHTML/insertAdjacentHTML/document.write), a message's data is ` +
      `attacker-controlled unless the sender's origin was verified first — passing it into ` +
      `${label} lets a malicious sender run script or inject markup in this page's origin.`,
  );
}

// ---------------------------------------------------------------------------
// Finding `message`-event handler registrations and dispatching to the above.
// ---------------------------------------------------------------------------

function resolveAndAnalyze(
  file: string,
  source: string,
  masked: string,
  exprStart: number,
  exprEnd: number,
  registrationIndex: number,
  findings: Finding[],
  options: LintOptions,
): void {
  const resolution = classifyHandlerExpr(file, source, masked, exprStart, exprEnd);
  if (resolution.kind === 'resolved') {
    analyzeHandler(file, source, masked, resolution.body, findings);
    return;
  }

  let name: string | undefined;
  if (resolution.kind === 'identifier') {
    name = resolution.name;
    const body = resolveIdentifierInFile(file, source, masked, name);
    if (body) {
      analyzeHandler(file, source, masked, body, findings);
      return;
    }
  }

  if (!options.includePossible) return;
  push(
    findings,
    file,
    source,
    registrationIndex,
    RULES.PM006.code,
    RULES.PM006.severity,
    'possible',
    name
      ? `This "message" handler is a reference to "${name}", which this tool could not find a ` +
        `function/arrow definition for in this file (imported, computed, or reassigned) — ` +
        `PM002–PM005 could not be checked for it.`
      : `This "message" handler is not a plain function/arrow expression or a same-file named ` +
        `reference (it's a member expression, a call, or another dynamic value) — PM002–PM005 ` +
        `could not be checked for it.`,
  );
}

function checkHandlers(file: string, source: string, masked: string, findings: Finding[], options: LintOptions): void {
  const aelRe = /\baddEventListener\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = aelRe.exec(masked))) {
    const openParen = m.index + m[0].length - 1;
    const closeParen = matchBracket(masked, openParen, file, source);
    const args = splitTopLevelCommas(masked, openParen + 1, closeParen);
    if (args.length < 2) continue;
    const [t0s, t0e] = trimSpan(source, args[0]![0], args[0]![1]);
    const eventNameText = source.slice(t0s, t0e);
    if (eventNameText !== "'message'" && eventNameText !== '"message"') continue;
    const [hs, he] = trimSpan(source, args[1]![0], args[1]![1]);
    resolveAndAnalyze(file, source, masked, hs, he, m.index, findings, options);
  }

  const omRe = /\bonmessage\s*=(?!=)/g;
  while ((m = omRe.exec(masked))) {
    const rhsStart = m.index + m[0].length;
    const looseEnd = findStatementEnd(masked, rhsStart, masked.length);
    resolveAndAnalyze(file, source, masked, rhsStart, looseEnd, m.index, findings, options);
  }
}

/**
 * Run every rule over one already-masked file and return its findings,
 * sorted by position.
 */
export function lintFile(file: LintFile, options: LintOptions = {}): Finding[] {
  const findings: Finding[] = [];
  checkBroadcasts(file.file, file.source, file.masked, findings);
  checkHandlers(file.file, file.source, file.masked, findings, options);
  findings.sort((a, b) => a.line - b.line || a.column - b.column);
  return findings;
}
