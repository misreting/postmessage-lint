import { maskSource } from './scanner.ts';
import { lintFile } from './rules.ts';
import type { Finding, LintOptions } from './rules.ts';

export * from './errors.ts';
export type { Finding, Severity, Confidence, LintOptions } from './rules.ts';
export { maskSource } from './scanner.ts';

export interface SourceFile {
  file: string;
  source: string;
}

/**
 * Lint one or more JS/TS files for `window.postMessage`/`message`-handler
 * mistakes that never throw: broadcasting with `targetOrigin: '*'`, a
 * handler that never checks `event.origin`, an origin check a crafted
 * subdomain defeats, an unverified `event.source`, and message data flowing
 * into `innerHTML`/`eval`/`new Function`. See the README for exactly what
 * each rule can prove and what it can only flag as unanalyzable.
 *
 * Each file is scanned independently — unlike some sibling tools in this
 * series, no fact here depends on more than one file, so there's no reason
 * to pool them first.
 */
export function lint(files: SourceFile[], options: LintOptions = {}): Finding[] {
  const findings: Finding[] = [];
  for (const f of files) {
    const masked = maskSource(f.source, f.file);
    findings.push(...lintFile({ file: f.file, source: f.source, masked }, options));
  }
  return findings;
}

/** Convenience wrapper around {@link lint} for a single file. */
export function lintSource(source: string, file = '<input>', options: LintOptions = {}): Finding[] {
  return lint([{ file, source }], options);
}

export default lint;
