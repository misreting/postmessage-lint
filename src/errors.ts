/** Base class for every error this library throws. */
export class PostMessageLintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The source could not be scanned well enough to lint safely.
 *
 * This library is a hand-written scanner over JS/TS lexical structure —
 * strings, template literals, comments, regex literals, and bracket nesting —
 * not a full ECMAScript parser. It tracks just enough to find `postMessage(`
 * calls and message-event handlers without being fooled by a brace inside a
 * string or a comment mentioning `.origin`. When that tracking breaks down
 * (an unterminated string, an unbalanced bracket, a template literal that
 * never closes) it refuses rather than guessing: silently mis-scanning a file
 * can turn a real "no origin check" finding invisible, which is worse than
 * refusing to scan it at all.
 */
export class JsScanError extends PostMessageLintError {
  file: string;
  line: number;
  column: number;

  constructor(message: string, file: string, line: number, column: number) {
    super(`${file}:${line}:${column}: ${message}`);
    this.file = file;
    this.line = line;
    this.column = column;
  }
}
