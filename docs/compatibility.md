# foxguard Compatibility

Fast local security guard for changed files, built-in rules, Semgrep-compatible YAML, and Coccinelle semantic patches.

foxguard supports a focused Semgrep-compatible YAML subset for local rule loading and an additive Coccinelle bridge for C semantic patches.

That supported subset is regression-tested in-repo and parity-checked in CI against the real `semgrep` CLI.

The product default is still built-in rules. Compatibility mode exists to help teams adopt foxguard without throwing away existing rule work on day one.

## Recommended usage

Built-ins first:

```sh
foxguard .
foxguard secrets .
foxguard --rules ./rules .
foxguard --changed .
```

External-rules-only compatibility run:

```sh
foxguard --no-builtins --rules ./rules .
```

Coccinelle-backed C rule:

```sh
foxguard --rules ./kernel-rules .
```

Adoption baseline:

```sh
foxguard baseline --output .foxguard/baseline.json
foxguard --baseline .foxguard/baseline.json .
```

## Supported today

Top-level structure:

- `rules`
- `id`
- `message`
- `severity`
- `languages`
- `metadata.cwe`
- `fix` — autofix suggestion template.  When present, foxguard performs simple
  token substitution of metavariable names (e.g. `$X`) with the text bound by
  the matching pattern and emits the result as `fix_suggestion` on the finding.
  Unbound metavariable tokens are left as-is.  The suggestion is informational
  only — foxguard does not auto-apply it to the source file.
  `fix-regex:` is not supported and is silently ignored.

Pattern operators:

- `pattern`
- `pattern-regex`
- `pattern-either`
- `pattern-not`
- `pattern-not-regex`
- `pattern-not-inside`
- `pattern-inside`
- `patterns`

Rule scoping:

- `paths.include`
- `paths.exclude`

Metavariable filtering:

- `metavariable-regex`
- `focus-metavariable` (inside a `patterns:` block): shifts the reported finding range to point at the named metavariable's binding span instead of the full enclosing match. Accepts a single string (`"$X"`) or a list (`["$X", "$Y"]`) — when a list is given, the first metavar in the list that is bound in a given match determines the range. If none of the listed metavariables are bound, the finding is still emitted at the full match range (no drop). Only supported inside `patterns:`; has no effect at the top-level rule scope.
- `metavariable-comparison` — supported subset:
  - Expression shape: `$VAR <op> <number>` or `<number> <op> $VAR`
  - Operators: `<`, `<=`, `>`, `>=`, `==`, `!=`
  - Literals: decimal integers, floats, hex (`0x…`), binary (`0b…`); C-style suffixes (`L`, `UL`, `LL`, etc.) are stripped automatically
  - If the bound metavariable text is not parseable as a number the constraint evaluates to false (no match) — identical to Semgrep behaviour
  - `base: 10` (or absent) accepted; any other `base:` value is warn-skipped for that constraint entry only
  - `strip:` field is accepted in YAML (not rejected) but is not required for correctness since suffix-stripping is always applied; unsupported `strip: true` behaviour beyond suffix stripping is silently ignored
- `metavariable-analysis` (inside a `patterns:` block): the named metavariable's
  bound text is analysed by a named analyzer.
  - `analyzer: entropy` — **supported**. The constraint matches when the
    metavar's bound text has Shannon entropy ≥ **3.5 bits/char**. This threshold
    is a documented approximation of Semgrep's internal Gaussian-mixture entropy
    model: it flags random secrets / tokens (e.g. an AWS-style key
    `"AKIA1234567890ABCDEF"` scores ≈ 4.0 bits/char) while passing low-entropy
    words (e.g. `"password"` scores ≈ 2.75 bits/char). The threshold is defined
    as `ENTROPY_THRESHOLD` in `semgrep_compat.rs` and can be adjusted in one
    place if calibration is needed.
  - `analyzer: redos` — **warn-skipped** (constraint dropped, sibling
    clauses/rules unaffected). A sound, cheap ReDoS heuristic is not yet
    implemented. The rule loads and other constraints are fully active.
  - Any other analyzer — **warn-skipped** in the same way (graceful
    degradation consistent with other warn-skipped operators).
- `metavariable-pattern` (inside a `patterns:` block): the named metavariable's
  bound text is re-parsed as a snippet in the rule's language and matched against
  a nested sub-pattern. Supported nested forms: `pattern:`, `pattern-regex:`, and
  `pattern-either:` of those. Unparseable binding text evaluates to no match.
  Warn-skipped (constraint dropped, sibling clauses/rules unaffected):
  - `language:` override inside `metavariable-pattern:` — foxguard always uses the
    rule's top-level language to re-parse the binding
  - Nested `patterns:` or `metavariable-pattern:` inside the sub-pattern block

Taint rules (`mode: taint`):

- `mode: taint` for Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, PHP, C#, Bash, Solidity, Scala, Apex, and Swift; taint rules targeting other languages are skipped with a warning
- `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` — each entry may be a single `pattern:` string, a `pattern-either:` list (nested `pattern-either:` is supported and flattens recursively), or a `patterns:` AND-block (see below)
- **`patterns:` AND-blocks inside source/sink/sanitizer entries** — foxguard extracts all `pattern:` and `pattern-either:` sub-items as expressible node-shape matchers. Several constraint-only operators are now **enforced** rather than dropped: **`pattern-not:` / `pattern-not-regex:`** (a finding whose sink node falls inside a negative match is suppressed), **`pattern-inside:`** (a finding is kept only if its sink node is contained by the required region), **`metavariable-regex:`** on callee/method/receiver metavariables (the compiled matcher enforces the name regex), and **`focus-metavariable:`** for the parameter-source and focus-call-argument shapes. The remaining constraint-only sub-items (`pattern-not-inside:`, `metavariable-comparison:`, `metavariable-pattern:`, `metavariable-analysis:`, `metavariable-type:`, source-side `pattern-not:`/`pattern-inside:`) are still **dropped with a per-key warning** — findings carry a sink byte range but no source byte range, and some constraints need matcher primitives the taint engine does not yet express. Dropping a narrowing constraint makes the compiled matcher **slightly broader** than the original Semgrep rule, so foxguard may over-report on those; this is intentional (better to over-report than silently drop the rule). A `patterns:` block that produces no expressible matcher (only unsupported constraint-only sub-items) is warn-skipped without aborting sibling entries. If all source or sink entries are warn-skipped and none survive, the whole rule is skipped.
- **Parameter-as-source shape (`focus-metavariable` + a function-signature `pattern-inside`/`pattern`)** — a `pattern-sources` `patterns:` block of the form "a metavariable `$X` that is a parameter of an enclosing function" (i.e. a `focus-metavariable: $X` or bare `pattern: $X` together with a function-definition context whose parameter list contains `$X`) is recognised and compiled to an **any-function-parameter** taint source. Every parameter of every function/method in the file is seeded as tainted (matching Semgrep's any-parameter semantics for this shape). Supported for Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, and PHP; C# carries *this* (any-parameter) source inertly — but C# does seed parameters for the narrower typed-metavariable (`(Type $MV)`) and signature-first-parameter (`$T $M($INPUT, ...)`) source shapes documented below. The recognition is bounded: the seed metavariable must genuinely appear inside the first parameter list of a function-definition pattern in the same block, so an unrelated focus metavariable (e.g. `focus-metavariable: $X` over `pattern: get_input($X)`) is *not* treated as a parameter source and falls through to the normal graceful-degradation extraction.
- **Focus-on-call-argument sink shape (`focus-metavariable` / bare `pattern: $X` + a call-context `pattern-inside`/`pattern`)** — the sink-side analog of the parameter-as-source shape. A `pattern-sinks`/`pattern-sanitizers` `patterns:` block of the form "the focused metavariable `$X` is an argument of a named call" (i.e. a `focus-metavariable: $X` or bare `pattern: $X` together with a call-context pattern such as `pattern-inside: $POOL.query($X, ...)`, `pattern: assert($X, ...)`, or `pattern: $DC.$METHOD($X, ...)`) is recognised and compiled to the existing `Call`/`MethodName` sink matcher for the call's callee. A concrete callee (`assert`, `redirect_to`, `YAML.load`) compiles to one `Call`; a `$RECV.$METH(...)` callee whose method is pinned by an anchored-alternation `metavariable-regex` (`^(query|execute)$`, `\b(include|require)\b`) compiles to one `MethodName` (or `Call`, for a `$FUNC(...)` callee) **per listed name**. These reuse the existing taint-gated call sinks, which only fire when a tracked-tainted value reaches the call's arguments — so the compiled sink is bounded to the concrete callee/method name AND tainted data, never an over-broad bare-node sink. The recognition is bounded: the focused metavariable must appear in the call's argument list (or the call must have a wildcard `...`/metavariable argument list), and a call whose callee/method is a free metavariable with **no** pinning `metavariable-regex` produces no matcher (we never invent a name) — such a block falls through to the normal graceful-degradation extraction. Supported for all taint languages (Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, PHP); non-call contexts (binops, dict/object literals, subscript/property assignments) are not recognised by this shape.
- **Regex-bounded bare-metavariable callee sink shape (bare `pattern: $F(...)` / `$OBJ.$M(...)` + a pinning `metavariable-regex`)** — a `pattern-sinks`/`pattern-sanitizers` `patterns:` block that pairs a *bare-metavariable callee* call pattern with a `metavariable-regex` constraining that callee/method metavariable, e.g. `pattern: $EXEC(...)` + `metavariable-regex: { metavariable: $EXEC, regex: ^(system|exec|IO.popen)$ }`, or `pattern: $WRITER.$WRITE(...)` + `metavariable-regex: { metavariable: $WRITE, regex: ^(writerow|writerows|writeheader)$ }`. Without the regex, a bare-metavariable callee would match *every* call (universal → false-positive-unsafe) and is refused; **with** the `metavariable-regex` the match is bounded to callees/methods whose name matches, so the block is compiled to a name-constrained matcher that **enforces the regex at match time**: a bare `$F(...)` callee → a `CallRegex` matcher (the regex is tested against the *full callee text*, so dotted alternatives such as `IO.popen` match), and a `$OBJ.$M(...)` method callee → a `MethodNameRegex` matcher (the regex is tested against the *final method name*, any receiver). Any regex form is accepted (anchored alternations, fuzzy patterns such as `(?i)(.*password.*)`, and PCRE lookaround via `fancy-regex`). Like the other call sinks, these only fire when a tracked-tainted value reaches the call's arguments, so the compiled sink is bounded to a name-matching callee/method AND tainted data. The refusal is preserved: a bare-metavariable callee with **no** pinning `metavariable-regex` still compiles to nothing (the sink role empties and the rule is skipped) — foxguard never invents a callee name. Sink/sanitizer only (a call argument is a data-flow destination, not a taint origin); the regex matchers are matched by the shared call-sink resolver, so all taint languages benefit.
- **Focus-argument-of-call source shape (`focus-metavariable: $X` / bare `pattern: $X` + a call-context pattern binding `$X` as a call argument)** — the source-side dual of the focus-on-call-argument *sink* shape above. A `pattern-sources` `patterns:` block of the form "`$X` is an argument of a named call" (e.g. `pattern: $RNG.NextBytes($X)` + `focus-metavariable: $X`) is compiled to a `CallArgSource { method, arg_index }` matcher: the value written into argument position *arg_index* of a call to *method* is seeded as tainted. The recognition is position-precise — `NextBytes($SEED, $KEY)` focused on the first argument seeds only `$SEED`, not `$KEY` — and the method name must be concrete (a free-metavariable callee is refused, same as the sink dual). Currently exercised C#-gated (`use_weak_rng_for_keygeneration`, whose companion `new AesGcm($KEY)` constructor sink is compiled via the C#-gated `new Type(...)` → `Call { canonical }` recognizer); the matcher is carried inertly by the other engines.
- **C# typed-metavariable source shape (`(Type $MV)`)** — a `pattern-sources` `pattern: (SomeType $X)` seeds every `SomeType`-typed parameter/local as tainted (the C# dual of the Java/Go typed-metavariable sources, compiled to `TypedName { type_name }`, C#-gated). Type-precise: only exact-type-name bindings are seeded. A separate **signature-first-parameter source** (`$T $M($INPUT, ...) { ... }` with no focus) compiles to `FirstParamSource`, seeding the first parameter of every method (used by `xpath-injection`, whose sink is the concat-in-call shape below).
- **Concat-argument call sink shape (`$RECV.Method("..." + $X + "...")`)** — a `pattern-sinks` pattern whose argument is a string **concatenation** carrying tainted data into a named method (`.Compile`/`.Select`/`.Evaluate`) is compiled to `CallArgConcat { method }`. The concatenation is enforced at match time: a *direct* tainted argument with no `+` concatenation (`nav.Compile(input)`) does **not** fire — only a concatenated argument does — so the deliberately-broad signature source stays precise (C#-gated, `xpath-injection`).
- **PHP comparison-equality / tainted-class-name / tainted-subscript-key sink shapes** — three PHP-gated sink primitives: (a) `LooseEquality` — a *loose* `$A == $B` / `$A != $B` comparison with a tainted operand (PHP type-juggling, `md5-loose-equality`); the strict `===`/`!==` form is refused. (b) `TaintedCallee` — the taint is the **class-name selector** of an object creation (`new $SINK(...)` + `pattern: $SINK`, unsafe reflection, `tainted-object-instantiation`); a constructor-*argument* focus is refused so the ordinary argument-sink path keeps ownership. (c) `TaintedSubscriptKey { base }` — the taint is the **index/key** of a superglobal write (`$_SESSION[$KEY] = $VAL` + `pattern: $KEY`, session poisoning, `tainted-session`); a value focus is refused. Each is proven to fire on its positive and stay silent on the discriminating near-miss (strict equality, concrete class name, literal key).
- **String-literal and string-literal-regex sources** — a `pattern-sources` `pattern: "..."` (or a regex-constrained literal) compiles to `LiteralString { regex }`, seeding matching string literals as tainted (e.g. `http://`-prefixed literals for SSRF `request-with-http` rules). A fully-literal non-matching string never seeds. On Go, a `[]byte("...")` conversion of a string literal (`pattern-inside: []byte("$F")`) also seeds `LiteralString` — the hardcoded-key shape behind `hardcoded-jwt-key`; a `[]byte(os.Getenv(...))` (non-literal) does not seed.
- **Constructor-argument and property-assignment sinks with metavariable-regex enumeration (`csharp-sqli`)** — two C#-gated sink primitives that ENUMERATE a block-level `metavariable-regex` anchored alternation into a concrete name set: (a) `ConstructorArgSink { class_names, arg_index }` — `new $PATTERN($CMD,...)` + `focus: $CMD`, `metavariable-regex $PATTERN = ^(SqlCommand|OleDbCommand|…)$` → fires only when the instantiated class name is in the enumerated set AND the argument at `arg_index` (the focused position) carries taint (`new SafeThing(userInput)` and taint at a non-focused position both stay silent). (b) `PropertyAssignSink { property_names }` — `$CMD.$PATTERN = $VALUE` + `focus: $VALUE`, same regex enumeration on the property name → fires only when the LHS property name is enumerated AND the RHS carries taint (`cmd.SomeOther = userInput` stays silent). This is the arg/assignment-target analogue of the `CallRegex`/`MethodNameRegex` name-enumeration already used for call-name sinks.
- **Positional method-argument sink (`MethodArgSink { methods, arg_index }`)** — a Java-gated positionally-precise sink: `$RECV.getSession().$FUNC($NAME, $VALUE)` + `metavariable-regex $FUNC = ^(setAttribute|putValue)$` + `focus: $VALUE` fires only when the method name is enumerated AND the argument at `arg_index` carries taint. Unlike `MethodName` (fires on ANY tainted argument), this discriminates by position: `setAttribute(taintedKey, "literal")` stays silent (focus is the value at index 1), `setAttribute("literal", taintedValue)` fires — the `tainted-session-from-http-request` trust-boundary rule, where only a tainted VALUE (never a tainted KEY) is the sink.
- **Receiver-provenance call source (`ReceiverProvenanceCall`)** — a Java-gated binding-linked source: `$MD.digest(...)` where `pattern-inside: $TYPE $MD = MessageDigest.getInstance("MD5")` fires only when the receiver's in-scope declaration initializes it with `MessageDigest.getInstance("MD5")`. The `"MD5"` string literal is the discriminator — a receiver from `getInstance("SHA-256")` does not match, so `sha.digest()` stays clean (`md5-used-as-password`). The source taints the `.digest()` call result (the hash bytes), not the receiver variable.
- Supported `pattern:` shapes:
  - bare identifier (`request`) — a source-only shape compiled to a parameter-name match
  - dotted attribute chain (`request.data`, `request.json`) — nested chains flatten to `leftmost root + outermost field` (matches the engine's one-level attribute propagation)
  - call forms with any arguments (`pickle.loads($X)`, `pickle.loads(...)`, `pickle.loads()`, `eval($X)`) — arguments are stripped, the dotted callee path is what matches
  - **metavariable-receiver call** (`$CONN.executeQuery($X)`, `$OBJ.escape($X)`) — a single Semgrep metavariable (`$UPPER_NAME`) as receiver followed by exactly one plain identifier method name; compiled to a `MethodName` matcher that matches any invocation of that method regardless of receiver. Valid only as a **sink or sanitizer** shape (rejected as a source). The metavariable itself is discarded; only the method name is matched. Supported for Python, JavaScript/TypeScript, Go, Java, and Kotlin. For C the matcher is included in the compiled spec but the C engine only matches bare call expressions, so it will never fire on C code.
  - **metavariable-receiver assignment** (`$EL.innerHTML = $X`, `$EL.outerHTML = $X`, `$FORM.action = $X`) — a Semgrep metavariable (`$UPPER_NAME`) as receiver, a single plain identifier property name, and a `=` assignment operator (not `==`, `!=`, `<=`, `>=`); compiled to a `MemberAssign { field }` matcher. Valid only as a **sink or sanitizer** shape (rejected as a source). This covers DOM-XSS property-assignment sinks common in JavaScript taint rules. The matcher is only active for **JavaScript/TypeScript** rules — the JS engine matches `element.field = tainted` assignment expressions via `NodeMatcher::MemberAssign` (`taint_engine.rs`); other language engines include the matcher in the compiled spec but silently ignore it (no property-assignment semantics in Python, Go, Java, C, or Kotlin).
- Severity mapping matches the pattern-rule bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium) and `metadata.cwe` is propagated to findings
- Rules that use anything outside this subset (unsupported pattern shapes, `pattern-inside:` / `metavariable-pattern:` as *standalone* top-level source/sink entries rather than inside a `patterns:` block, unsupported languages, missing sources or sinks) are skipped with a warning — other rules in the same file still load. Entries with unsupported keys are dropped individually so a single bad entry will not disable sibling entries in the same block.
- Java taint rules match `Call { canonical }` patterns via receiver+method (e.g. `request.getParameter($X)` matches any method invocation where the receiver contains `request` and the method is `getParameter`); `Attribute` matchers are also accepted and compiled but the Java engine resolves them via method-invocation chains
- C taint rules match `Call { canonical }` patterns as bare function-call callees (e.g. `getenv($X)` matches any `call_expression` whose callee identifier is `getenv`); the C engine recognises `argv` as a `ParamName` source and all libc/POSIX input functions as `Call` sources
- Kotlin taint rules match `Call { canonical }` patterns using a receiver-substring rule (e.g. `call.receiveText($X)` matches any `call_expression` whose receiver contains `call` and whose method is `receiveText`); constructor-style calls (`Runtime`, `URL`, `ProcessBuilder`) are matched as bare `canonical` names; `Attribute` matchers are accepted and compiled but are reserved for forward compatibility (no current Kotlin rule uses them); language tag `kt` is accepted as an alias for `kotlin`
- Apex taint rules (`tree-sitter-sfapex`, node vocabulary close to Java) match `Call { canonical }` sinks via receiver-substring + method name (e.g. `Database.query($SINK)` matches any `method_invocation` whose receiver contains `Database` and whose method is `query`); the any-parameter source shape (`$M(..., String $P, ...) { ... }` + `focus-metavariable: $P`) seeds every method parameter as tainted; the chained request-read source `ApexPage.getCurrentPage().getParameters().get($URLPARAM)` is compiled to a `Call { canonical: "ApexPage.get" }` source (root identifier + final method); `String.escapeSingleQuotes(...)` sanitizers clear taint. The Semgrep `by-side-effect:` source flag is accepted (treated as a no-op marker; the companion `pattern:`/`patterns:` compiles normally) and trailing statement `;` is stripped from patterns. A SOQL rule whose source is a literal-constant assignment (`...String $X = 'Authorization';`, the `named-credentials-constant-match` rule) is **not** a data-flow taint shape and is still skipped with an `unsupported shape` warning.
- Swift taint rules (`tree-sitter-swift`) compile the rule's string-interpolation/concatenation source patterns (`"...\($X)..."`, `$SQL = "..." + $X`, `$SQL = $X + "..."`) to a sentinel source the Swift engine interprets as "any string built by interpolation or by concatenation with a non-literal operand is a (low-confidence) tainted value"; `Call { canonical }` sinks (`sqlite3_exec`, `sqlite3_prepare_v2`) fire when that constructed string reaches a `call_expression` argument. A fully-literal string never triggers the source.

Language mapping:

- JavaScript / TypeScript (`.ts` and `.tsx` use dedicated TypeScript/TSX parsers, then map onto the JavaScript-compatible rule surface)
- Python
- Go
- HCL / Terraform (`.tf`, `.hcl`, `.tfvars`; the `hcl` and `terraform` language selectors both map to the HCL parser. This unlocks the Semgrep registry's `terraform/` rule pack — predominantly `pattern-regex` and `pattern` + `metavariable-regex` rules.)

Other languages mapped by the `languages:` selector: Ruby, Java, PHP, Rust, C#, Swift, Kotlin, C.

Rule loading:

- load a single YAML file
- load a directory recursively
- deduplicate language aliases that map to the same foxguard parser

## Generic mode (`languages: [generic]`)

Semgrep's `generic` mode (a.k.a. spacegrep) is AST-less: it matches a tokenized
pattern against the raw text of a file. foxguard routes any rule whose
`languages` includes `generic` (or the `regex` alias) to a dedicated text
matcher (`src/rules/generic_mode.rs`), separate from the tree-sitter pattern
bridge. This is what lets the config-file rule packs (nginx, apache, dockerfile,
generic secret patterns) actually match.

```yaml
rules:
  - id: weak-ssl-protocols
    pattern: ssl_protocols ...
    message: weak ssl_protocols directive
    severity: WARNING
    languages: [generic]
```

Supported in generic mode:

- `pattern` — tokenized literal matching
- `pattern-either` — OR over multiple generic patterns; an arm may itself be a `patterns:` AND-block
- `pattern-not` — drops candidates whose span overlaps a negative match
- `pattern-regex` — passthrough regex match against the raw text
- `pattern-not-regex` — file-level negative (drops all candidates if it matches anywhere)
- `...` ellipsis — matches any run of tokens, including across whitespace and newlines
- `$METAVAR` — binds a single token span, with equality enforcement (the same metavariable must bind the same text)
- **Metavariable constraints over named regex captures** — when a `pattern-regex` declares named capture groups (`(?P<NAME>…)` / `(?<NAME>…)`) inside a `patterns:` block, a sibling `metavariable-regex` or `metavariable-comparison` that references `$NAME` is **enforced** against the captured group's text at match time (regex: the captured text must match; comparison: the captured text is parsed as a number and the `$VAR <op> number` / `int($VAR) < n` comparison is evaluated). A candidate is reported only if every such constraint passes — the constraint is enforced, not dropped. `focus-metavariable: $NAME` narrows the reported span to that capture's range. This is what lets the package-manager "minimum release age / dependency cooldown" rules (`bun-`, `npm-`, `uv-`) load and fire correctly (e.g. flag `minimumReleaseAge = 100` but not `= 604800`).
- `paths.include` / `paths.exclude` — same path scoping as the AST bridge
- `metadata.cwe` and `severity` mapping (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium)

Limits (parity-honest):

- Tokenization is word/punctuation based (a "word" is a run of ASCII alphanumerics and underscores; every other non-whitespace character is its own token). It is close to, but not byte-identical with, spacegrep's tokenizer.
- `metavariable-comparison` / `metavariable-regex` are applied **only** over named regex captures (the case above). A `metavariable-*` constraint over a spacegrep `$METAVAR` token binding is dropped (the rule loads broadened) at the top level.
- `metavariable-pattern` and `metavariable-analysis` (e.g. `entropy`) cannot be enforced in generic mode. A `pattern-either` arm that is a `patterns:` block carrying one of these **refuses to load** rather than silently dropping the constraint and broadening into false positives; if that arm is the rule's only expressible matcher, the rule is skipped (this is why `use-absolute-workdir` and `detected-private-key`'s entropy narrowing remain unsupported). A top-level `patterns:` block keeps the legacy load-broadened behaviour for backward compatibility.
- `pattern-inside` / `pattern-not-inside` are not applied in generic mode (generic mode treats the file as a flat token stream, not a brace-nested structure).
- A generic rule only runs on files foxguard already recognizes (the languages above plus the config formats). Files with no detected language are not scanned, so a generic rule will not fire on an arbitrary extension the way upstream `semgrep` would. Scope generic rules with `paths:` and target recognized files.
- Match line numbers are parity-checked against upstream `semgrep` in CI (`tests/semgrep_parity_generic.rs`, gated on `semgrep` being installed); exact end-column spans may differ because ellipsis greediness is approximated.

## Coccinelle bridge

Rules with `engine: coccinelle` are loaded from the same `--rules` YAML files or directories as Semgrep-compatible rules:

```yaml
rules:
  - id: kernel/dirty-frag-inplace-crypto-no-cow
    engine: coccinelle
    severity: high
    languages: [c]
    metadata:
      cwe: CWE-362
    message: In-place crypto on skb data without a preceding copy-on-write gate.
    script_path: dirty-frag-inplace-crypto-no-cow.cocci
```

Supported Coccinelle rule keys:

- `id`
- `engine: coccinelle`
- `message`
- `severity` (`critical`, `high`, `medium`, `low`, plus Semgrep-style `ERROR`, `WARNING`, `INFO`)
- `languages: [c]`
- `metadata.cwe`
- `script` for inline SmPL
- `script_path` for a `.cocci` file relative to the YAML file

Execution model:

- foxguard shells out to upstream `spatch`; whatever SmPL surface your installed `spatch` accepts is the supported SmPL surface.
- Coccinelle currently scans `.c` and `.h` files.
- Findings are normalized into the same `Finding` shape used by built-in and Semgrep-compatible rules, so terminal, JSON, SARIF, CBOM, and baselines work through the existing report path.
- If `spatch` is missing, foxguard emits one warning and skips Coccinelle rules while continuing the rest of the scan.

## CodeQL bridge

Rules with `engine: codeql` are loaded from the same `--rules` YAML files or directories as Semgrep-compatible rules. foxguard expects a pre-built CodeQL database and shells out to the installed `codeql` CLI:

```yaml
rules:
  - id: kernel/codeql-dirty-frag
    engine: codeql
    severity: high
    metadata:
      cwe: CWE-362
    message: CodeQL query matched dirty-frag behavior.
    query: queries/dirty-frag.ql
```

Supported CodeQL rule keys:

- `id`
- `engine: codeql`
- `message`
- `severity` (`critical`, `high`, `medium`, `low`, plus Semgrep-style `ERROR`, `WARNING`, `INFO`)
- `metadata.cwe`
- `query` for a `.ql` file relative to the YAML file
- `database` for a per-rule pre-built CodeQL database path, optionally `${FOXGUARD_CODEQL_DB}`

Database selection priority is:

1. rule-level `database`
2. CLI `--codeql-db /path/to/database`
3. environment `FOXGUARD_CODEQL_DB`
4. **Auto-build**: if `codeql` is on PATH and none of the above are set, foxguard creates an ephemeral database scoped to the scan target via `codeql database create --language=<lang> --source-root=<target> --overwrite`. The temp DB is cleaned up when the scan exits. Query language is inferred from the top-level `import <lang>` line in the `.ql` file, falling back to source-root file extensions.

Example:

```bash
# Auto-build path (codeql on PATH, no DB flag):
foxguard --rules ./kernel-rules /path/to/linux

# Manual DB path (still supported):
foxguard --rules ./kernel-rules --codeql-db /path/to/linux.codeql .
```

Execution model:

- foxguard runs `codeql database analyze <db> <query.ql> --format=sarif-latest --output <tmp>.sarif`.
- SARIF results are normalized into the same `Finding` shape used by built-in, Semgrep-compatible, and Coccinelle rules.
- If `codeql` is missing from PATH, foxguard emits a single warning and skips CodeQL rules while continuing the rest of the scan.
- If `codeql database create` fails (e.g. no compilable source under the scan target, or the qlpack language family isn't installed), foxguard emits a per-rule warning and continues. Set `FOXGUARD_CODEQL_CREATE_TIMEOUT_SECS` to override the default 15-minute build timeout.
- `foxguard diff` does not run the CodeQL bridge yet. Accurate diffing needs a base/current database strategy rather than a single current database.

## Important limitations

foxguard does **not** claim full Semgrep or OpenGrep compatibility.

If a feature is not listed in the supported section above, assume it is either unsupported or only partially supported today.

That includes more advanced Semgrep/OpenGrep capabilities such as:

- the broader rule syntax beyond the subset above
- the full ecosystem of published registry rules
- engine behaviors that depend on features foxguard does not implement yet

## Product stance

The intended model is:

- foxguard built-ins are the default product
- external YAML is the adoption bridge
- Semgrep and OpenGrep remain the reference tools for the broadest rule ecosystems

This keeps the promise clear:

- use foxguard for fast local feedback
- bring in compatible YAML where it helps
- do not assume full drop-in equivalence
