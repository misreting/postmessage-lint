import { JsScanError } from './errors.ts';

/**
 * A hand-written lexical scanner for JS/TS — not a parser. It does not build
 * an AST or understand statements, declarations, or types. Its only job is to
 * tell strings, template literals, comments, and regex literals apart from
 * real code, so that a later regex-based search for `.postMessage(`,
 * `.origin`, `addEventListener(` and the like isn't fooled by those same
 * words appearing inside a comment or a string.
 *
 * TypeScript's extra syntax (`: Type`, `<T>`, `as X`, decorators) is never
 * inspected — it passes through untouched, which is exactly what a lexical
 * (not grammatical) scanner needs to do, and is why this file works unchanged
 * on `.ts` as well as `.js`.
 */

/**
 * Produce a same-length "masked" copy of `source` in which every string
 * literal, template literal, comment, and regex literal's *content* is
 * replaced with spaces (newlines preserved, so line numbers stay correct).
 * Real code — including the code inside a template literal's `${ }`
 * interpolation — is left untouched. Offsets into the masked text index the
 * exact same characters in `source`, so callers slice `source` (never the
 * masked text) to recover real text such as a string literal's value.
 *
 * Throws {@link JsScanError} on a construct this scanner cannot safely get
 * past: an unterminated string, template literal, comment, or regex literal,
 * or a bracket that never closes (checked lazily by {@link matchBracket}).
 */
export function maskSource(source: string, file: string): string {
  const out: string[] = new Array(source.length);
  const n = source.length;
  let i = 0;

  // Whether a `/` at the current position would start a regex literal
  // (true) or is a division operator (false). Updated after every token this
  // scanner recognizes. This is the same last-significant-token heuristic
  // used by other hand-rolled JS lexers (e.g. Esprima's tokenizer notes):
  // there is no fully correct answer without full parsing, but "which kind
  // of token came before" gets it right for ordinary code.
  let regexAllowed = true;

  // A single nesting stack for template literals and their `${ }`
  // interpolations, in strict LIFO order. Its *top* alone determines the
  // current mode:
  //   - top is `{ kind: 'template' }`      → scanning template *text*
  //   - top is `{ kind: 'templateExpr' }`  → scanning *code* inside a `${ }`
  //   - stack empty                        → scanning top-level *code*
  // Two separate counters (one for backtick nesting, one for `${` nesting)
  // cannot tell these apart once a template literal nests inside another
  // template's interpolation (`` `outer ${ `inner ${x}` }` ``) — only the
  // actual nesting order, i.e. a single stack, gets that right.
  type Frame = { kind: 'template'; line: number; column: number } | { kind: 'templateExpr'; depth: number };
  const stack: Frame[] = [];
  const topIsTemplateText = () => stack.length > 0 && stack[stack.length - 1]!.kind === 'template';
  const topExprFrame = () => {
    const top = stack[stack.length - 1];
    return top && top.kind === 'templateExpr' ? top : undefined;
  };

  let line = 1;
  let column = 1;

  function advance(): string {
    const ch = source[i]!;
    i++;
    if (ch === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
    return ch;
  }

  function fail(message: string, atLine = line, atColumn = column): never {
    throw new JsScanError(message, file, atLine, atColumn);
  }

  function emitMasked(count: number): void {
    for (let k = 0; k < count; k++) {
      const idx = i;
      const ch = advance();
      out[idx] = ch === '\n' ? '\n' : ' ';
    }
  }

  function emitRaw(count: number): void {
    for (let k = 0; k < count; k++) {
      const idx = i;
      out[idx] = advance();
    }
  }

  function isIdentPart(ch: string): boolean {
    return /[\w$]/.test(ch);
  }

  const REGEX_ALLOWING_KEYWORDS = new Set([
    'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
    'throw', 'case', 'do', 'else', 'yield', 'await',
  ]);

  while (i < n) {
    const ch = source[i]!;
    const next = source[i + 1];

    // Inside a template literal's literal text (not one of its `${ }`
    // interpolations) — checked *first*, unconditionally, because a `'`, a
    // `//`, or any other code-mode-only character inside template text is
    // just literal text, not the start of a string or comment.
    if (topIsTemplateText()) {
      if (ch === '\\') {
        emitMasked(1);
        if (i < n) emitMasked(1);
        continue;
      }
      if (ch === '`') {
        stack.pop();
        emitRaw(1);
        regexAllowed = false; // the template literal just produced a value
        continue;
      }
      if (ch === '$' && next === '{') {
        emitRaw(2);
        stack.push({ kind: 'templateExpr', depth: 0 });
        regexAllowed = true;
        continue;
      }
      emitMasked(1);
      continue;
    }

    // Line comment.
    if (ch === '/' && next === '/') {
      emitRaw(2);
      while (i < n && source[i] !== '\n') emitMasked(1);
      // regexAllowed unchanged: a comment doesn't produce a value.
      continue;
    }

    // Block comment.
    if (ch === '/' && next === '*') {
      const startLine = line;
      const startColumn = column;
      emitRaw(2);
      let closed = false;
      while (i < n) {
        if (source[i] === '*' && source[i + 1] === '/') {
          emitRaw(2);
          closed = true;
          break;
        }
        emitMasked(1);
      }
      if (!closed) fail('unterminated block comment ("/*" with no matching "*/")', startLine, startColumn);
      continue;
    }

    // Single/double-quoted string.
    if (ch === "'" || ch === '"') {
      const quote = ch;
      const startLine = line;
      const startColumn = column;
      emitRaw(1);
      let closed = false;
      while (i < n) {
        const c = source[i];
        if (c === '\\') {
          emitRaw(1);
          if (i < n) emitRaw(1);
          continue;
        }
        if (c === quote) {
          emitRaw(1);
          closed = true;
          break;
        }
        if (c === '\n') break; // unterminated: real JS strings can't hold a raw newline
        emitMasked(1);
      }
      if (!closed) fail(`unterminated string literal (missing closing ${quote})`, startLine, startColumn);
      regexAllowed = false;
      continue;
    }

    // Template literal start (top-level, or nested inside a `${ }`).
    if (ch === '`') {
      stack.push({ kind: 'template', line, column });
      emitRaw(1);
      continue;
    }

    // Regex literal (heuristic: only when the previous token allows one).
    if (ch === '/' && regexAllowed) {
      const startLine = line;
      const startColumn = column;
      emitRaw(1);
      let inClass = false;
      let closed = false;
      while (i < n) {
        const c = source[i];
        if (c === '\\') {
          emitRaw(1);
          if (i < n) emitRaw(1);
          continue;
        }
        if (c === '\n') break; // unterminated
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) {
          emitRaw(1);
          closed = true;
          break;
        }
        emitMasked(1);
      }
      if (!closed) fail('unterminated regular expression literal (missing closing "/")', startLine, startColumn);
      // Trailing flags, e.g. `/x/gi`.
      while (i < n && /[a-z]/i.test(source[i]!)) emitMasked(1);
      regexAllowed = false;
      continue;
    }

    // A `}` may close the innermost `${ }` interpolation frame.
    {
      const frame = topExprFrame();
      if (frame && ch === '}') {
        if (frame.depth === 0) {
          stack.pop();
          emitRaw(1);
          regexAllowed = false; // the interpolation's value was just produced
          continue;
        }
        frame.depth--;
        emitRaw(1);
        regexAllowed = true;
        continue;
      }
      if (frame && ch === '{') {
        frame.depth++;
        emitRaw(1);
        regexAllowed = true;
        continue;
      }
    }

    // Ordinary code character.
    if (isIdentPart(ch)) {
      const start = i;
      while (i < n && isIdentPart(source[i]!)) emitRaw(1);
      const word = source.slice(start, i);
      regexAllowed = /^\d/.test(word) ? false : REGEX_ALLOWING_KEYWORDS.has(word);
      continue;
    }

    if (ch === ')' || ch === ']') {
      emitRaw(1);
      regexAllowed = false;
      continue;
    }
    if (/\s/.test(ch)) {
      emitRaw(1); // whitespace never changes regexAllowed
      continue;
    }
    // Any other punctuation/operator character: a value cannot end here, so
    // a following `/` is (almost always) a regex, not division.
    emitRaw(1);
    regexAllowed = true;
  }

  for (let k = stack.length - 1; k >= 0; k--) {
    const frame = stack[k]!;
    if (frame.kind === 'template') {
      fail('unterminated template literal (missing closing "`")', frame.line, frame.column);
    }
  }
  if (stack.length > 0) {
    // Every `templateExpr` frame is opened right after a `${` that is itself
    // inside a `template` frame, so an all-`templateExpr` stack here would
    // mean a `${` interpolation never closed even though its enclosing
    // template literal did — structurally unreachable, but fail loudly
    // rather than silently accepting a malformed result if it ever happens.
    fail('unterminated "${" interpolation', line, column);
  }

  return out.join('');
}

const CLOSERS: Record<string, string> = { '(': ')', '{': '}', '[': ']' };

/**
 * Given `masked` text (see {@link maskSource}) and the index of an opening
 * `(`, `{`, or `[`, return the index of its matching closer. Scans the
 * masked text only, so brackets that appear inside a string, template
 * literal, comment, or regex are already gone and can't be mistaken for
 * structure.
 *
 * Throws {@link JsScanError} if the brackets are unbalanced or never close —
 * refusing here, rather than returning a best-guess index, avoids silently
 * attributing a `postMessage(...)` call's arguments to the wrong span.
 */
export function matchBracket(masked: string, openIndex: number, file: string, source: string): number {
  const openChar = masked[openIndex];
  const closer = openChar ? CLOSERS[openChar] : undefined;
  if (!closer) {
    throw new JsScanError(`internal error: index ${openIndex} is not an opening bracket`, file, 1, 1);
  }
  const stack: string[] = [closer];
  let i = openIndex + 1;
  while (i < masked.length) {
    const ch = masked[i]!;
    if (ch === '(' || ch === '{' || ch === '[') {
      stack.push(CLOSERS[ch]!);
    } else if (ch === ')' || ch === '}' || ch === ']') {
      const expected = stack.pop();
      if (expected !== ch) {
        const { line, column } = offsetToLineColumn(source, i);
        throw new JsScanError(`mismatched bracket: expected "${expected ?? 'nothing'}", found "${ch}"`, file, line, column);
      }
      if (stack.length === 0) return i;
    }
    i++;
  }
  const { line, column } = offsetToLineColumn(source, openIndex);
  throw new JsScanError(`unterminated "${openChar}" (missing closing "${closer}")`, file, line, column);
}

/**
 * Split `masked.slice(start, end)` on top-level commas (depth 0 within that
 * span) and return the `[start, end)` offset of each segment, in `source`
 * coordinates. Used to pull apart a call's argument list without needing to
 * parse expression grammar.
 */
export function splitTopLevelCommas(masked: string, start: number, end: number): Array<[number, number]> {
  const parts: Array<[number, number]> = [];
  let depth = 0;
  let segStart = start;
  let i = start;
  let sawAnyNonSpace = false;
  for (; i < end; i++) {
    const ch = masked[i]!;
    if (ch === '(' || ch === '{' || ch === '[') depth++;
    else if (ch === ')' || ch === '}' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) {
      parts.push([segStart, i]);
      segStart = i + 1;
      continue;
    }
    if (!/\s/.test(ch)) sawAnyNonSpace = true;
  }
  if (sawAnyNonSpace || parts.length > 0) parts.push([segStart, end]);
  return parts.filter(([s, e]) => masked.slice(s, e).trim() !== '');
}

/** Trim a `[start, end)` span so it no longer includes leading/trailing whitespace. */
export function trimSpan(text: string, start: number, end: number): [number, number] {
  let s = start;
  let e = end;
  while (s < e && /\s/.test(text[s]!)) s++;
  while (e > s && /\s/.test(text[e - 1]!)) e--;
  return [s, e];
}

/** Precompute nothing; just scan for the line/column of a given offset. Fine for CLI-sized files. */
export function offsetToLineColumn(source: string, offset: number): { line: number; column: number } {
  let line = 1;
  let column = 1;
  const stop = Math.min(offset, source.length);
  for (let i = 0; i < stop; i++) {
    if (source[i] === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
