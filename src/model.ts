/**
 * `postMessage` security facts this tool encodes, each cited to MDN's
 * postMessage security guidance and the HTML Standard, so a wrong finding can
 * be checked back against the actual rule rather than against this file's
 * intuition.
 *
 * - MDN, `Window.postMessage()`, "Security concerns":
 *   https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns
 *   "Always specify an exact target origin, not *, when using postMessage to
 *   send data to other windows... A malicious site can change the location of
 *   the window without your knowledge, and therefore it can intercept the
 *   data sent using postMessage." and, on receiving: "Always verify the
 *   sender's identity using the origin and possibly source properties...
 *   Any window (including, for example, http://evil.example.com) can send a
 *   message to any other window, and you have no guarantees that an unknown
 *   sender will not send malicious messages."
 * - HTML Standard, "Posting messages" / cross-document messaging:
 *   https://html.spec.whatwg.org/multipage/web-messaging.html#dom-window-postmessage
 *   `postMessage(message, targetOrigin, transfer)` — "If the origin of the
 *   recipient window's Document does not match ... targetOrigin, do nothing."
 *   `targetOrigin` is `*` only when the caller has *no* origin restriction to
 *   apply — every other value narrows delivery to exactly that origin.
 * - HTML Standard, `MessageEvent`:
 *   https://html.spec.whatwg.org/multipage/comms.html#the-messageevent-interface
 *   `origin` is "the Unicode serialization of the origin of the message's
 *   sender" and `source` is "the WindowProxy, MessagePort, or
 *   MessageEventSource object that is the message's sender" — the *only* two
 *   properties `MessageEvent` gives a receiver to authenticate a message.
 */

/** Method names whose receiver being the message's `origin` string is unsound: substring/prefix tests, not equality. */
export const UNSOUND_ORIGIN_METHODS = new Set(['startsWith', 'indexOf', 'includes']);

/**
 * Sinks that turn attacker-controlled string data into script execution or
 * markup parsing. `innerHTML`/`outerHTML` per the HTML spec's "innerHTML"
 * setter parse the assigned string as HTML, running any `<script>`-adjacent
 * handler markup it contains; `eval` and `new Function` compile and run the
 * string as JavaScript directly
 * (https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns:
 * "Do not use eval() to parse the data of an incoming message" is MDN's own
 * example of the same mistake this rule generalizes).
 */
export const SINK_ASSIGN_PROPS = ['innerHTML', 'outerHTML'] as const;
export const SINK_CALL_NAMES = ['insertAdjacentHTML', 'eval', 'Function', 'write', 'writeln'] as const;

export interface RuleMeta {
  code: string;
  slug: string;
  severity: 'error' | 'warning';
}

export const RULES = {
  PM001: { code: 'PM001', slug: 'wildcard-target-origin', severity: 'warning' } as RuleMeta,
  PM002: { code: 'PM002', slug: 'missing-origin-check', severity: 'error' } as RuleMeta,
  PM003: { code: 'PM003', slug: 'unsound-origin-check', severity: 'error' } as RuleMeta,
  PM004: { code: 'PM004', slug: 'unverified-event-source', severity: 'warning' } as RuleMeta,
  PM005: { code: 'PM005', slug: 'tainted-data-sink', severity: 'error' } as RuleMeta,
  PM006: { code: 'PM006', slug: 'unanalyzable-handler', severity: 'warning' } as RuleMeta,
} as const;
