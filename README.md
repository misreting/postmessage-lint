# postmessage-lint

Finds `window.postMessage`/`message`-handler mistakes that never throw: a
broadcast to `'*'`, a handler that never checks `event.origin`, an origin
check a crafted subdomain defeats, an unverified `event.source`, and message
data reaching `innerHTML` or `eval`.

```
widget.js, as written (missing origin check, wildcard broadcast, tainted innerHTML)
  2:53  error    [PM002] This "message" handler never checks event.origin — this handler
                 never reads "event.origin" ... without an origin check this handler accepts
                 instructions from any origin, not just the one it was written to trust.
  5:36  error    [PM005] Data received from a "message" event flows into .innerHTML = ... —
                 a message's data is attacker-controlled unless the sender's origin was
                 verified first ...
  9:27  warning  [PM001] targetOrigin is "*" — this message is delivered to whatever origin
                 the target window currently has ...

widget.js, fixed
  no findings
```

That's `node examples/scan-demo.ts`, trimmed for width — the tool's own output isn't wrapped.

## The problem

`postMessage` is the only sanctioned way for two different origins (or a page
and its worker) to talk to each other in a browser, and it fails open in both
directions:

- **Sending with `targetOrigin: '*'`** delivers to whatever origin the target
  window happens to have *right now* — which a malicious page can change out
  from under you by navigating an iframe you handed a reference to, well
  after your code decided to trust it.
- **Receiving with no `event.origin` check** accepts a message from
  literally any page on the internet that can get a reference to your
  window (an iframe you embed, a window you `window.open`ed, anything with
  `window.opener`). This is the shape that becomes account takeover: a
  handler that does `if (event.data.type === 'SET_TOKEN') localStorage.token
  = event.data.token` with no origin check will run for a message from
  `https://evil.example`, not just your own frontend.

None of this throws, logs a warning, or shows up in DevTools. The code runs
exactly as written; it just also runs for senders it was never meant to
trust. You find out from an incident report, not a stack trace.

### Why "just add an origin check" isn't the whole fix

The obvious remediation — "check `event.origin`" — is itself easy to get
subtly wrong, and the wrong version looks identical to the right one at a
glance:

```js
// looks like a check. is not one.
if (event.origin.includes('yoursite.com')) { ... }
```

`"https://evil-yoursite.com".includes('yoursite.com')` is `true` — the
hyphen doesn't break a substring match. `.indexOf(...)` has the identical
problem, and `.startsWith('https://yoursite.com')` has the same shape once
someone controls a subdomain: `"https://yoursite.com.evil.tld"` starts with
exactly that string. The only sound receiving-side checks are an exact
`===`/`!==` against one known origin, or `allowlistArray.includes(event.origin)`
— origin as the *argument*, not the receiver. **This distinction —
`x.includes(origin)` sound, `origin.includes(x)` unsound — is the one this
tool exists to catch, because it is very easy to write the wrong one and have
it look exactly as reassuring as the right one in a diff.**

## Before building this: what already exists

Time-boxed npm/registry research, not exhaustive:

- **[`eslint-plugin-no-wildcard-postmessage`](https://www.npmjs.com/package/eslint-plugin-no-wildcard-postmessage)**
  (Mozilla, `mozfreddyb`) is a real, small, current ESLint plugin that does
  exactly one thing: flags `postMessage(data, '*')`. That's this tool's
  PM001, and if you already run ESLint, that plugin covers it with less
  ceremony than adding a second tool for one rule. **It does not** touch the
  receiving side at all — no origin-check-soundness analysis, no
  `event.source` check, no data-flow to a sink — which is the bulk of what
  this tool does and the reason it exists as more than a wrapper around that
  plugin.
- **`eslint-plugin-security`** — checked its actual rule list (fetched via
  `npm view`, not from memory): 14 rules, none of them about `postMessage`,
  `event.origin`, or `event.source`. Closest in spirit is
  `detect-eval-with-expression` (flags `eval(variable)` generically, with no
  idea whether `variable` came from a `message` event or anywhere else).
- **`eslint-plugin-no-unsanitized`** — checked its actual README (same way):
  two rules, `method` and `property`, disallowing unescaped data reaching
  sinks like `innerHTML` or `insertAdjacentHTML` *in general*. This is the
  same sink family PM005 checks, but generic — it has no concept of
  `postMessage`, doesn't know `event.data` is a distinct kind of untrusted
  input, and (like `eslint-plugin-security`) requires ESLint's full parse
  and rule infrastructure rather than running standalone.
- **A registry search for other `postMessage`/origin-specific linters**
  turned up nothing else real — general ESLint infrastructure packages
  (`@typescript-eslint/*`, `eslint-scope`, etc.) and unrelated packages
  matching on the word "postmessage" (a Storybook channel, a LINE LIFF SDK
  wrapper). If something more specific exists that this search missed, it
  wasn't found in the time budgeted for looking.

Net: the wildcard-broadcast check (PM001) already has a small dedicated
tool. The origin-check-soundness analysis, the `event.source` check, and the
`postMessage`-aware taint check (PM002–PM005) did not turn up an existing
equivalent in this search, and are where this tool's value is.

## Install

```sh
npm install --save-dev postmessage-lint
```

Node >= 20.6. No runtime dependencies.

## Use

As a CLI:

```sh
npx postmessage-lint src/**/*.js src/**/*.ts
```

(Your shell expands the glob before this program sees it — there's no
bundled glob engine.) Exits `1` if any `error`-severity finding was reported,
`0` otherwise, `2` if a file couldn't be scanned.

As a library:

```ts
import { lint } from 'postmessage-lint';

const findings = lint([
  { file: 'widget.js', source: readFileSync('widget.js', 'utf8') },
]);

for (const f of findings) {
  console.log(`${f.file}:${f.line}:${f.column} [${f.rule}] ${f.message}`);
}
```

Each file is scanned independently — nothing here depends on facts from a
second file, so there's no reason to batch them the way a project-wide CSS
check would.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `includePossible` (CLI: `--include-possible`) | `false` | Also report `message` handlers this tool could not resolve to a function body (PM006) — see below. Off by default because a project that dispatches through a shared, imported handler would otherwise get one of these per registration. |

CLI-only: `--strict` (exit non-zero on warnings too), `--json` (machine-readable output).

## What this can prove, and what it can only flag as unanalyzable

Every finding carries a `confidence`: `'certain'` or `'possible'`. This tool
does not have a "probably, but I'm not sure" bucket the way the CSS tools in
this series do (a DOM ancestor is sometimes genuinely unknowable from CSS
alone) — here, once a handler's actual body is found, whether it reads
`event.origin`, compares `event.source`, or lets `event.data` reach a sink is
literally text present or absent in that body. The undecidable part is
earlier: **finding** the body in the first place.

**`certain`** — every one of PM001–PM005, always on:

- **PM001** `wildcard-target-origin` — `postMessage(data, '*')`, including
  the `{ targetOrigin: '*' }` options-object form.
- **PM002** `missing-origin-check` — a `message` handler whose body (once
  resolved — see below) never reads `event.origin`, whether directly
  (`e.origin`) or via destructuring (`{ origin }`), anywhere.
- **PM003** `unsound-origin-check` — `.startsWith(`, `.indexOf(`, or
  `.includes(` called *on* the origin value. Calling `.includes(` *with* the
  origin as the argument (`allowlist.includes(event.origin)`) is the sound
  form and is not flagged — see "Why 'just add an origin check' isn't the
  whole fix," above, for exactly which shape is unsound and why.
- **PM004** `unverified-event-source` — `event.source` is read somewhere in
  the handler, but the handler never compares it (`===`/`!==`) against
  anything, anywhere in the body.
- **PM005** `tainted-data-sink` — `event.data` (directly, via destructuring,
  or through one local `const`/`let`/`var` alias assigned straight from it)
  reaches `.innerHTML =`, `.outerHTML =`, `insertAdjacentHTML(`, `eval(`,
  `new Function(`, `document.write(`, or `document.writeln(` — including
  through a template literal's `${ }` interpolation.

**`possible`** — only reported with `includePossible: true` (default off):

- **PM006** `unanalyzable-handler` — the handler registered for a `message`
  event is not an inline function/arrow expression, and not a plain
  identifier this tool can resolve to a `function`/`const`/`let`/`var`
  declaration in the *same file* (it's imported, computed, a member
  expression, or reassigned elsewhere). PM002–PM005 are silently **not**
  checked for that handler — this finding is the only signal that a gap
  exists, and it's opt-in specifically because most real projects dispatch
  through a shared, imported handler, and reporting it by default would fire
  on most registrations rather than the unusual ones.

## Zero dependencies, how

This scans JS/TS the way [`cancelsafe`](https://github.com/agentscope-java/cancelsafe)
scans Python and [`redis-lua-lint`](https://github.com/agentscope-java/redis-lua-lint)
scans Lua: a hand-written scanner, not a full parser. Concretely, `src/scanner.ts`
is a single-pass lexer that tells strings, template literals (including
nested `${ }` interpolation), comments, and regex literals apart from real
code — masking out only their *contents* — so that a later regex search for
`.postMessage(`, `.origin`, `addEventListener(`, and the sink names isn't
fooled by those same words sitting inside a comment or a string, and so a
handler embedded inside a template literal's `${ }` is still read as real
code. It never builds an AST, understands statements, or resolves scope —
`src/rules.ts` finds handler bodies with the same kind of bracket-matching
the scanner exposes (`matchBracket`, `splitTopLevelCommas`), not a symbol
table.

**Refuses loudly, rather than guessing, on:** an unterminated string,
template literal, block comment, or regex literal; and a bracket that never
finds its match. Continuing to scan past one of these would risk silently
mis-locating a handler's body (or its end), which can turn a real "no origin
check" finding invisible — worse than refusing the whole file outright.

## Evidence

A registry/dependency grep across a handful of real, unrelated local
projects for `postMessage`/`addEventListener('message'` found meaningful
usage in exactly one file outside this repo: the generated
`mockServiceWorker.js` from [`msw`](https://github.com/mswjs/msw) (a widely
used HTTP-mocking library), vendored into a project's `public/` directory.
Real output, unedited except shortening the path:

```
$ node dist/cli.js mockServiceWorker.js --include-possible
mockServiceWorker.js
  23:52   error    [PM002] This "message" handler never checks event.origin ...
  24:32   warning  [PM004] event.source is used here but this handler never compares it ...
  292:42  error    [PM002] This "message" handler never checks event.origin ...

2 errors, 1 warning
```

Read against the actual source, by hand:

- **Line 23's PM002 is a true positive by the rule's own contract** — the
  service worker's top-level `message` handler genuinely never reads
  `event.origin` — but a service worker can only ever be reached by clients
  of its *own* registration origin in the first place, so the practical risk
  here is lower than the same finding would be on a page embedding untrusted
  iframes. The rule can't see that distinction; it only knows the text isn't
  there.
- **Line 24's PM004 is a true positive by the same contract, with a real
  mitigating idiom this tool can't recognize**: `event.source` (a `Client`)
  is never compared with `===`, but its `id` is looked up via
  `self.clients.get(clientId)` — a registry lookup that only succeeds for a
  currently-real client — which is a meaningfully different (and reasonable)
  way to establish trust than an identity comparison. A known,
  documented gap: PM004 only recognizes the comparison-operator shape.
- **Line 292's PM002 is this tool's cleanest false positive, and a real,
  common idiom**: `channel.port1.onmessage = (event) => { ... }` is a
  handler on a *privately created* `MessageChannel` port, handed directly to
  one specific client via a `transfer` list — never broadcast, never
  reachable by an arbitrary origin. The trust boundary here is "who received
  this port," not `event.origin` (which isn't even meaningful the same way
  on a dedicated channel port). This tool has no way to distinguish a port
  registered this way from a `window`/`self` listener that really does need
  an origin check — a real, identified false-positive shape, not a
  hypothetical one.

Net for this run: 1 defensible-but-lower-real-risk true positive, 1 true
positive with a mitigation this tool can't see, and 1 genuine false positive
from a single identified idiom (`MessageChannel` ports). Three findings from
one small file isn't a statistically meaningful sample, and this search
didn't turn up a second, larger real codebase to run in the time budgeted —
said plainly rather than padded out. Treat every finding the way the
sibling tools in this series ask you to: as a prompt to go read the code,
not a verdict.

## What it does not do

- **No data-flow or type analysis beyond one hop.** `const x = event.data;
  sink(x)` is caught; `const x = event.data; const y = x.value; sink(y)` is
  not — only a direct local alias of the base access is tracked, once.
- **No cross-function tracking.** A handler that calls `verifyOrigin(event.origin)`
  is treated as "origin checked" — this tool has no way to know whether
  that helper is actually sound, and doesn't try; that's a deliberate,
  documented false-negative rather than guessing at a helper's body.
- **Order-insensitive.** A comparison of `event.source` (or a read of
  `event.origin`) anywhere in the handler body counts, even if it happens
  *after* the sensitive use it should have guarded. This tool checks
  presence, not sequence.
- **No `MessageChannel`-vs-`window`/`self` distinction.** As the Evidence
  section shows, a handler on a privately-transferred `MessagePort` gets the
  same PM002/PM004 treatment as a `window.addEventListener('message', ...)`
  that really is reachable by anyone — a known, real false-positive shape.
- **Regex-literal detection is heuristic**, using the preceding token to
  decide whether a `/` starts a regex or is division — the standard approach
  for a hand-rolled JS lexer, and like any such heuristic, has edge cases
  (e.g. right after a `}` that closed an object literal rather than a block)
  it can get wrong.
- **Not a general security or `eval` linter.** No opinions on anything
  outside these five `postMessage`-shaped mistakes; see "Before building
  this," above, for tools that cover generic `eval`/`innerHTML` risks.

## Develop

Tests are TypeScript run directly by Node's test runner — no build, no install:

```sh
node --test "test/*.test.ts"    # full suite, needs node 24+ for type stripping
node examples/scan-demo.ts

npm run build && npm run test:dist   # what CI runs against node 20 and 22
```

## License

MIT
