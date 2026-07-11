//! Shared types and utilities for the JS/Python/Go taint engines.
//!
//! Each language-specific engine (`javascript_taint`, `python_taint`,
//! `go_taint`) re-exports these types so existing consumers are
//! unaffected.

use crate::rules::cross_file::{FunctionTaintSummary, ParamSinkFlow};
use std::collections::{BTreeSet, HashMap, HashSet};
use tree_sitter::Node;

/// Visit descendants of `scope` without crossing nested language scopes.
///
/// Language engines provide their own scope-boundary predicate because the
/// relevant tree-sitter node kinds differ between grammars. The scope node
/// itself is not visited; nested scope nodes and their descendants are
/// skipped. This keeps intra-procedural taint walks from leaking into nested
/// functions, methods, constructors, or lambdas.
pub(crate) fn walk_scope_nodes<'tree>(
    scope: Node<'tree>,
    source: &str,
    is_scope_node: impl Fn(&str) -> bool + Copy,
    visitor: &mut impl FnMut(Node<'tree>, &str),
) {
    fn walk_node<'tree>(
        node: Node<'tree>,
        source: &str,
        is_scope_node: impl Fn(&str) -> bool + Copy,
        visitor: &mut impl FnMut(Node<'tree>, &str),
    ) {
        if is_scope_node(node.kind()) {
            return;
        }
        visitor(node, source);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_node(child, source, is_scope_node, visitor);
        }
    }

    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        walk_node(child, source, is_scope_node, visitor);
    }
}

// ─── Core types ──────────────────────────────────────────────────────────

/// A pattern that matches an AST node for taint analysis.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match a member-expression access like `req.body` or `request.query`.
    ///
    /// Triggers whenever the *leftmost* identifier in a chain equals `root`
    /// and the *final* property segment equals `field`.
    Attribute {
        root: String,
        field: String,
        description: String,
    },

    /// Match a call whose callee resolves (raw or via the alias table) to
    /// `canonical`.
    Call {
        canonical: String,
        description: String,
    },

    /// Match any use of a function parameter whose name is in this list.
    ParamName {
        names: Vec<String>,
        description: String,
    },

    /// Match any method call whose final property name equals `method`,
    /// regardless of receiver. Only meaningful as a sink matcher.
    MethodName { method: String, description: String },

    /// Match a call whose *callee text* matches a compiled regex. Compiled
    /// from a taint source/sink/sanitizer `patterns:` AND-block pairing a
    /// bare-metavariable callee pattern (`$F(...)`) with a `metavariable-regex`
    /// pinning that metavariable, e.g.
    ///
    /// ```yaml
    /// - pattern: $EXEC(...)
    /// - metavariable-regex: { metavariable: $EXEC, regex: ^(system|exec)$ }
    /// ```
    ///
    /// The regex (NOT a dropped constraint) is what bounds the match: without
    /// it the bare-metavar callee would match every call (universal → FP) and
    /// is refused. The matcher fires only for calls whose callee name matches
    /// the regex, so it is name-constrained and FP-safe. The full callee text
    /// is tested (so dotted alternatives such as `IO.popen` match), matching
    /// Semgrep's binding of the callee metavariable to the whole callee.
    /// Sink/sanitizer only — a call argument is a destination, not an origin.
    CallRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Match any method call whose *final method name* matches a compiled
    /// regex, regardless of receiver. Compiled from a `patterns:` AND-block
    /// pairing a `$OBJ.$M(...)` pattern with a `metavariable-regex` pinning the
    /// method metavariable `$M`, e.g.
    ///
    /// ```yaml
    /// - pattern: $WRITER.$WRITE(...)
    /// - metavariable-regex: { metavariable: $WRITE, regex: ^(writerow)$ }
    /// ```
    ///
    /// The any-receiver analogue of [`NodeMatcher::CallRegex`], bounded by the
    /// method-name regex. Sink/sanitizer only.
    MethodNameRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Match any call whose callee's leftmost/root identifier equals
    /// `receiver`, regardless of the method name — e.g. `os.$METHOD(...)`,
    /// `subprocess.$FUNC(...)`, `Kernel.$X(...)`. Compiled from a Semgrep
    /// callee of the form `receiver.$METAVAR` where `receiver` is a concrete
    /// identifier and the method is a metavariable. Sink/sanitizer only.
    ReceiverCall {
        receiver: String,
        description: String,
    },

    /// Match a member/property/attribute READ `<anything>.field` regardless
    /// of receiver — e.g. `req.body`, `request.query`, `ctx.headers`.
    /// Compiled from Semgrep patterns of the form `$METAVAR.field` (a
    /// metavariable receiver and a plain identifier field).
    ///
    /// This is the any-receiver analogue of [`NodeMatcher::Attribute`]
    /// (which requires a concrete `root`). Meaningful for object/property
    /// languages (Python, JS/TS, Go, Java, Kotlin, Ruby, PHP, C#); for C the
    /// matcher is carried in the spec but the engine no-ops it (no
    /// property-read sources exist in plain C).
    FieldName { field: String, description: String },

    /// Match a subscript / index access `base[...]`.
    ///
    /// `base = Some(name)` matches a subscript whose indexed operand's final
    /// segment equals `name` (e.g. `params[...]`, `request.POST[...]` →
    /// `POST`, `flask.request.args[...]` → `args`). `base = None` matches any
    /// subscript regardless of base (compiled from a metavariable base like
    /// `$VALS[$INDEX]`).
    ///
    /// Meaningful for object/property languages; the C engine no-ops it.
    Subscript {
        base: Option<String>,
        description: String,
    },

    /// Match an assignment where the LHS is a member expression whose
    /// property name equals `field`. JS-specific: covers the
    /// `element.innerHTML = tainted` pattern, which is not a call and so
    /// cannot be expressed as `Call`.
    MemberAssign { field: String, description: String },

    /// Match a string-building SINK: a binary `+`/`%` concatenation, an
    /// interpolated/format string (`f"...{x}..."`), or a format call
    /// (`fmt.Sprintf("...", x)`, `sprintf("...", x)`) where one operand is a
    /// string literal/format AND a tainted value flows into another operand.
    ///
    /// Compiled from Semgrep sink patterns such as `"$SQL" + $EXPR`,
    /// `$M % $M`, `$A + $B`, `f"...{$X}..."`, `Kernel::sprintf("$FMT", ...)`.
    /// This maps to SQL-injection / command-string sinks. To avoid false
    /// positives the engine only treats a node as a `BinopFormat` sink when one
    /// operand is a string literal/format; a plain numeric or variable-only
    /// concatenation never fires. Sink/sanitizer only.
    BinopFormat { description: String },

    /// Match an object/dictionary literal *construction* one of whose value
    /// positions is a tainted expression — e.g. the JS object literal
    /// `{ role: "system", content: tainted }` or the Python dict
    /// `{"role": "system", "content": tainted}`.
    ///
    /// Compiled from Semgrep sink patterns such as
    /// `{role: "system", content: $SINK}` (LLM system-prompt-injection rules).
    /// The bridge drops the literal key/value constraints (`role: "system"`),
    /// so the compiled sink fires whenever an object/dict literal is built with
    /// a tainted value in any field. Only meaningful as a sink/sanitizer shape
    /// for JavaScript/TypeScript (`object`) and Python (`dictionary`); for all
    /// other engines the matcher is carried in the spec but never queried.
    ObjectLiteralValue { description: String },

    /// Match a `return` statement whose returned expression is tainted — e.g.
    /// `return tainted`. Compiled from Semgrep sink patterns of the form
    /// `return $METAVAR` (LLM "unsanitized return" / directly-returned-format
    /// rules where the sink is the function's return value).
    ///
    /// The bridge drops the surrounding `pattern-inside` constraints, so the
    /// compiled sink fires whenever a `return` statement returns a tainted
    /// value. Bounded to return position (not a universal bare-metavar sink).
    /// Only meaningful as a sink/sanitizer shape for Python; for other engines
    /// the matcher is carried in the spec but never queried.
    ReturnValue { description: String },

    /// Match any parameter or local variable whose DECLARED TYPE's final
    /// segment equals `type_name` — the Semgrep "typed metavariable" source
    /// `(HttpServletRequest $REQ)` ("any variable of type
    /// `HttpServletRequest` is a taint source"). The variable is seeded as
    /// tainted at scope entry (parameter) or at its declaration (local),
    /// after which the engine's normal propagation carries the taint through
    /// reads and method calls on it — so `(HttpServletRequest $REQ).$FUNC(...)`
    /// reduces to the same matcher (the trailing method read is droppable).
    ///
    /// The type is matched by its final `.`-segment so both a bare
    /// `HttpServletRequest` and a fully-qualified
    /// `javax.servlet.http.HttpServletRequest` declaration match. This is
    /// deliberately type-specific (NOT "seed every parameter"): only variables
    /// of the named type become sources, preserving precision.
    ///
    /// Compiled solely for the Java engine by the bridge; other engines carry
    /// the matcher in the spec but no-op it (their `seed`/`match_source` paths
    /// never inspect declared types).
    TypedName {
        type_name: String,
        description: String,
    },

    /// Match an ASSIGNMENT or DECLARATION SINK whose left-hand side is a
    /// variable of declared type whose final `.`-segment equals `type_name`
    /// AND whose right-hand side carries taint — the Semgrep "typed
    /// assignment" sink `(java.io.File $FILE) = ...` ("a tainted value
    /// assigned into a variable of type `File` is the sink", e.g. building a
    /// `File` from an untrusted path is a path-traversal sink).
    ///
    /// This is the SINK-position dual of [`NodeMatcher::TypedName`]: rather
    /// than seeding a typed variable as a source, it fires when a tainted RHS
    /// is written into a typed LHS. Faithfulness (the whole point): the sink
    /// fires ONLY when BOTH (a) the assignment target's declared type matches
    /// `type_name` AND (b) the reaching RHS is tainted — never on a bare
    /// `x = y`. A literal RHS (`File f = new File("/static")`) and a wrong-type
    /// LHS (`String s = taintedPath`) are both correctly silent.
    ///
    /// The type is matched by its final `.`-segment so both `File` and
    /// `java.io.File` match. Sink/sanitizer only — a typed write is a
    /// destination, not a taint origin. Compiled solely for the Java engine
    /// (`variable_declarator` / `assignment_expression` LHS types); other
    /// engines carry the matcher in the spec but no-op it.
    TypedAssignTarget {
        type_name: String,
        description: String,
    },

    /// Match any STRING-LITERAL node as a taint SOURCE — the Semgrep
    /// ellipsis-string source `"..."` ("a string literal is the taint
    /// source"). Compiled from a bare `pattern-sources: - pattern: "..."`
    /// entry, this seeds every string-literal expression as tainted; the
    /// engine's existing propagation then carries that taint to the sink,
    /// so a hardcoded literal reaching a JWT signer / crypto / credential
    /// sink fires while a value read from the environment (a non-literal
    /// identifier or call result) stays clean.
    ///
    /// Faithfulness (the whole point): this matches ONLY string-literal AST
    /// nodes — never identifiers, calls, or other expressions — so a
    /// hardcoded-secret rule fires on `sign(p, "secret")` but is silent on
    /// `sign(p, secretFromEnv)`. The literal node kinds are grammar-specific
    /// (`string`/`concatenated_string` in Python, `string`/`template_string`
    /// in JS/TS); each engine that supports string-literal sources matches
    /// its own kinds. Source only — a literal is a taint origin, not a
    /// destination. Only the Python and JavaScript engines consult it today
    /// (the only registry rules with this source shape target those langs);
    /// other engines carry it in the spec but no-op it.
    ///
    /// `regex` optionally constrains WHICH literals are seeded: when
    /// `Some(pattern)`, only a string literal whose text matches the compiled
    /// regex is a source (`None` = any literal, the original behavior). This
    /// carries the Semgrep `pattern: "$URL"` + `metavariable-pattern`/
    /// `metavariable-regex` shape (a literal whose *content* matches a regex),
    /// e.g. the `requests` `http://` SSRF/cleartext rules whose source is "a
    /// string literal matching `http://` and not localhost/127.0.0.1". The
    /// stored value is the (fancy-regex-compatible) regex SOURCE string; the
    /// engine compiles it via `semgrep_compat::compile_regex` at match time.
    /// Faithfulness: with the regex present a non-matching literal
    /// (`"https://safe"`, `"localhost"`) is NOT seeded, so the rule fires only
    /// on the constrained literals — never every string.
    LiteralString {
        description: String,
        regex: Option<String>,
    },

    /// Match a LOOSE-EQUALITY comparison SINK — a binary `==` or `!=`
    /// expression (PHP type-juggling) where one operand is tainted. Compiled
    /// from Semgrep sink patterns `$VAR1 == $VAR2` / `$VAR1 != $VAR2`
    /// (the `md5-loose-equality` rule: comparing a hash with `==` allows
    /// magic-hash type-juggling bypasses).
    ///
    /// Faithfulness (the whole point): this matches ONLY the loose `==`/`!=`
    /// operators — NEVER the strict `===`/`!==` — because strict comparison is
    /// exactly the safe form the rule tells you to use. The operator token is
    /// checked by its exact grammar kind (`==` / `!=` are distinct node kinds
    /// from `===` / `!==`), and the sink fires only when a tracked-tainted
    /// value reaches one operand, so a strict comparison or an untainted loose
    /// comparison is silent. Sink/sanitizer only — a comparison is a data-flow
    /// destination, not a taint origin. Compiled solely for the PHP engine
    /// (type-juggling is PHP-specific); other engines carry the matcher in the
    /// spec but no-op it.
    LooseEquality { description: String },

    /// Match an object-creation SINK whose CLASS-NAME / CALLEE selector is
    /// tainted — the Semgrep unsafe-reflection sink `new $SINK(...)` bounded to
    /// its class-name metavariable (`pattern-inside: new $SINK(...)` + focus
    /// `pattern: $SINK`, the `tainted-object-instantiation` rule). Instantiating
    /// an attacker-controlled class name allows arbitrary class instantiation /
    /// remote code execution (CWE-470).
    ///
    /// Faithfulness (the whole point): this fires ONLY when the CLASS NAME being
    /// instantiated carries taint — NEVER when a constructor ARGUMENT is tainted
    /// (that is a different, ordinary call-argument sink). `new $tainted(...)`
    /// fires; `new SafeClass($tainted)` does NOT (the class name `SafeClass` is a
    /// concrete identifier, not a tainted value), and `new $x()` where `$x` holds
    /// a string literal is silent (the class-name variable is untainted). The PHP
    /// engine inspects the class-name operand of an `object_creation_expression`
    /// only. Sink/sanitizer only — an instantiation is a data-flow destination,
    /// not a taint origin. Compiled solely for the PHP engine (unsafe reflection
    /// via a dynamic class name is the PHP shape); other engines carry the
    /// matcher in the spec but no-op it.
    TaintedCallee { description: String },

    /// Match an assignment-target SUBSCRIPT-KEY SINK — a write
    /// `$_SESSION[$KEY] = $VAL` whose INDEX / KEY expression is tainted (the
    /// Semgrep `tainted-session` session-poisoning sink:
    /// `pattern-inside: $_SESSION[$KEY] = $VAL;` + focus `pattern: $KEY`).
    /// An attacker-controlled session key lets the user write any session
    /// variable (CWE-284, broken access control).
    ///
    /// `base = Some(name)` bounds the write target's base to a concrete
    /// superglobal whose final segment equals `name` (e.g. `_SESSION`);
    /// `base = None` matches any subscript-assignment target (a metavariable
    /// base in the pattern).
    ///
    /// Faithfulness (the whole point): this fires ONLY when the KEY / index of
    /// the assignment target carries taint — NEVER when the assigned VALUE is
    /// tainted (`$_SESSION["safe"] = $tainted` is a different flow). It also
    /// requires the assignment TARGET base to be the configured superglobal, so
    /// a nested `$_SESSION["prefix"][$tainted] = …` (whose outer base is
    /// `$_SESSION["prefix"]`, not `$_SESSION`) does NOT fire. The PHP engine
    /// inspects the key operand of an assignment-LHS `subscript_expression`
    /// only. Sink/sanitizer only — a write target is a data-flow destination,
    /// not a taint origin. Compiled solely for the PHP engine; other engines
    /// carry the matcher in the spec but no-op it.
    TaintedSubscriptKey {
        base: Option<String>,
        description: String,
    },

    /// Match a value written into the focused ARGUMENT POSITION of a named CALL
    /// as a taint SOURCE — the Semgrep "focus a call argument" source
    /// `pattern-inside: (System.Random $RNG).NextBytes($KEY); ...` + focus/bare
    /// `pattern: $KEY` (the `use_weak_rng_for_keygeneration` rule: bytes filled
    /// by a weak RNG's `NextBytes(key)` become the untrusted key material).
    ///
    /// This is the SOURCE-position dual of [`NodeMatcher::MethodName`]/the
    /// focus-call SINK shape: rather than firing when a tainted value reaches a
    /// call, it SEEDS the identifier sitting in the focused argument position of
    /// a matching call, so the engine's normal propagation then carries that
    /// taint to the sink. `method` is the call's final method-name segment
    /// (`NextBytes`); `arg_index` is the zero-based position of the focused
    /// metavariable in the call's argument list (0 for `NextBytes($KEY)`).
    ///
    /// Faithfulness (the whole point): this seeds ONLY the identifier in the
    /// focused argument position of a call whose final method name equals
    /// `method` — `rng.NextBytes(key)` seeds `key`; an unrelated `otherCall(key)`
    /// seeds nothing; `rng.NextBytes(seed, key)` seeds only position-`arg_index`
    /// (`seed` for `arg_index == 0`); and an unfilled buffer that never reaches a
    /// matching call is not a source. Source only — a call argument fill is a
    /// taint origin, not a destination. Compiled solely for the C# engine (the
    /// only registry rule with this source shape is C#); other engines carry the
    /// matcher in the spec but no-op it.
    CallArgSource {
        method: String,
        arg_index: usize,
        description: String,
    },

    /// Seed the enclosing method's FIRST parameter as a taint SOURCE — the
    /// Semgrep C# signature source `$T $M($INPUT,...) {...}` ("a method's first
    /// parameter is untrusted"; the metavariable `$INPUT` binds the first
    /// parameter, `...` the rest). This is a *signature* source with NO focus
    /// metavariable: it is deliberately broad (every method's first parameter),
    /// and the rule relies on a SPECIFIC sink (see [`NodeMatcher::CallArgConcat`])
    /// to stay precise.
    ///
    /// Faithfulness: seeds ONLY the first parameter — NOT every parameter (that
    /// would be the wildcard [`NodeMatcher::ParamName`]) and NOT by declared type
    /// (that is [`NodeMatcher::TypedName`]). A method's second/third parameters
    /// are left unseeded. Source only. Seeded by the C# engine; other engines
    /// carry it in the spec but no-op it (only C# registry rules use this shape).
    FirstParamSource { description: String },

    /// Seed EVERY parameter of a function that is DECORATED by a call whose
    /// final method-name segment equals `decorator` — the Semgrep MCP-handler
    /// source shape
    ///
    /// ```yaml
    /// pattern-sources:
    ///   - patterns:
    ///       - pattern: |
    ///           @$SERVER.tool()
    ///           def $FUNC(..., $PARAM, ...):
    ///               ...
    ///       - focus-metavariable: $PARAM
    /// ```
    ///
    /// where `@$SERVER.tool()` binds any `<recv>.tool(...)` decorator (`decorator
    /// == "tool"`) and the focused `$PARAM` matches any parameter (`..., $PARAM,
    /// ...`). The decorator is the precision anchor: parameters are seeded ONLY
    /// inside functions carrying a matching decorator, so a plain (undecorated)
    /// helper's parameters are never tainted.
    ///
    /// Faithfulness: this is NOT the any-parameter wildcard
    /// ([`NodeMatcher::ParamName`] with the wildcard sentinel) — it seeds a
    /// parameter only when its enclosing function is decorated by a
    /// `<x>.<decorator>(...)` call, so `def helper(cmd): os.system(cmd)` with NO
    /// `@x.tool()` decorator is silent (the discriminator the MCP rule relies on).
    /// Source only — a parameter is a taint origin. Seeded by the Python engine
    /// (the MCP rules are Python); other engines carry it in the spec but no-op it.
    DecoratedParamSource {
        decorator: String,
        description: String,
    },

    /// Match a CALL whose final method-name segment equals `method` AND one of
    /// whose arguments is a string CONCATENATION (`+`) that carries tainted
    /// data — the Semgrep C# xpath-injection sink
    /// `$NAV.Compile("..." + $INPUT + "...")` (and the `.Select` / `.Evaluate`
    /// variants). The concatenation shape is the precision anchor together with
    /// the method name: a DIRECT tainted argument with no concatenation
    /// (`nav.Compile(input)`) does NOT match, so seeding a broad signature source
    /// does not turn every `.Compile(input)` into a finding.
    ///
    /// Faithfulness: fires only when (a) the call's final method name equals
    /// `method`, and (b) an argument is a `+` binary expression carrying taint.
    /// A tainted non-concatenated argument, an untainted concatenation, and a
    /// call to a different method are all silent. Sink/sanitizer only. Matched by
    /// the C# engine; other engines carry it in the spec but no-op it.
    CallArgConcat { method: String, description: String },

    /// Match a CONSTRUCTOR-ARGUMENT sink — a `new <Class>(arg0, ...)` object
    /// creation whose instantiated class name is one of `class_names` AND whose
    /// argument at position `arg_index` carries taint. Compiled from the Semgrep
    /// C# `csharp-sqli` sink arm `new $PATTERN($CMD,...)` + `focus-metavariable:
    /// $CMD`, gated by `metavariable-regex` on `$PATTERN`
    /// (`^(SqlCommand|OleDbCommand|OdbcCommand|OracleCommand|...)$`): the
    /// anchored-alternation regex is ENUMERATED into `class_names`, and the
    /// focused first constructor argument is the tainted-value position (`new
    /// SqlCommand(userInput)` is SQL injection).
    ///
    /// Faithfulness (the whole point): this fires ONLY when (a) the instantiated
    /// class name is in the enumerated set — `new SafeThing(userInput)` is
    /// silent (the class name is not enumerated) — AND (b) the argument at
    /// `arg_index` (the focused position) carries taint — `new SqlCommand(literal,
    /// userInput)` with taint at position 1 does NOT fire for `arg_index == 0`,
    /// matching Semgrep's `focus-metavariable: $CMD` binding to the FIRST
    /// argument. A concrete (never-enumerated) class name and an untainted focus
    /// argument are both silent. Sink/sanitizer only — a construction is a
    /// data-flow destination, not a taint origin. Compiled solely for the C#
    /// engine; other engines carry the matcher in the spec but no-op it.
    ConstructorArgSink {
        class_names: Vec<String>,
        arg_index: usize,
        description: String,
    },

    /// Match a CALL to a named method whose argument at a SPECIFIC POSITION
    /// carries taint — the Semgrep positional-`focus-metavariable` sink
    /// `(HttpServletRequest $REQ).getSession().$FUNC($NAME, $VALUE)` +
    /// `metavariable-regex: { $FUNC: ^(putValue|setAttribute)$ }` +
    /// `focus-metavariable: $VALUE` (the `tainted-session-from-http-request`
    /// trust-boundary rule: only a tainted VALUE written into the session is the
    /// sink, never a tainted KEY).
    ///
    /// This is the positionally-precise analogue of [`NodeMatcher::MethodName`]
    /// (which fires when ANY argument is tainted): it fires ONLY when the method
    /// name is one of `methods` AND the argument at `arg_index` (zero-based)
    /// carries taint. `setAttribute(taintedKey, "literal")` is therefore SILENT
    /// (the focus is the value at index 1, not the key at index 0), while
    /// `setAttribute("literal", taintedValue)` fires — the exact discriminator
    /// the rule's `focus-metavariable: $VALUE` encodes.
    ///
    /// The receiver context (`request.getSession()`) is a droppable narrowing:
    /// the sink is bounded by the method-name set and the tainted-argument
    /// position, so a `setAttribute`/`putValue` on any receiver with a tainted
    /// value at `arg_index` fires. Sink/sanitizer only — a call argument is a
    /// data-flow destination, not a taint origin. Compiled solely for the Java
    /// engine (the only registry rule with this shape is Java); other engines
    /// carry the matcher in the spec but no-op it.
    MethodArgSink {
        methods: Vec<String>,
        arg_index: usize,
        description: String,
    },

    /// Match a PROPERTY-ASSIGNMENT sink — an assignment `<expr>.<Prop> = <RHS>`
    /// whose assigned property name is one of `property_names` AND whose
    /// right-hand side carries taint. Compiled from the Semgrep C# `csharp-sqli`
    /// sink arm `$CMD.$PATTERN = $VALUE;` + `focus-metavariable: $VALUE`, gated
    /// by `metavariable-regex` on `$PATTERN`
    /// (`^(CommandText|SqlCommand|...)$`): the anchored-alternation regex is
    /// ENUMERATED into `property_names`, and the focused RHS is the tainted-value
    /// position (`cmd.CommandText = userInput` is SQL injection).
    ///
    /// Faithfulness (the whole point): this fires ONLY when (a) the LHS property
    /// name is in the enumerated set — `cmd.SomeOther = userInput` is silent (the
    /// property is not enumerated) — AND (b) the RHS carries taint —
    /// `cmd.CommandText = "literal"` is silent. A non-enumerated property and an
    /// untainted RHS are both silent, regardless of the receiver. Sink/sanitizer
    /// only — an assignment target is a data-flow destination, not a taint
    /// origin. Compiled solely for the C# engine; other engines carry the matcher
    /// in the spec but no-op it.
    PropertyAssignSink {
        property_names: Vec<String>,
        description: String,
    },

    /// Match a METHOD CALL on a receiver of a KNOWN INITIALIZATION PROVENANCE as
    /// a taint SOURCE — the Semgrep binding-linked source
    ///
    /// ```yaml
    /// pattern-sources:
    ///   - patterns:
    ///       - pattern-inside: |
    ///           $TYPE $MD = MessageDigest.getInstance("MD5");
    ///           ...
    ///       - pattern: $MD.digest(...)
    /// ```
    ///
    /// (the `md5-used-as-password` rule: the bytes produced by `.digest()` on a
    /// `MessageDigest` obtained via `MessageDigest.getInstance("MD5")` are an
    /// MD5 hash — flowing them into a password sink is the weakness).
    ///
    /// Fires on a method call `RECV.method(...)` ONLY when:
    /// - the call's final method name equals `method` (`digest`), AND
    /// - `RECV` is a plain identifier whose in-scope declaration initializes it
    ///   with a call `init_receiver.init_method(...)` whose first string-literal
    ///   argument equals `init_arg` (`MessageDigest.getInstance("MD5")`).
    ///
    /// Faithfulness (the whole point): the `init_arg` string discriminator is
    /// what distinguishes MD5 from a strong algorithm — a receiver initialized
    /// with `MessageDigest.getInstance("SHA-256")` does NOT match, so
    /// `sha.digest()` is correctly clean. The source fires on the `.digest()`
    /// call itself (not the receiver variable), so only the hash bytes become
    /// tainted. Source only — a digest call is a taint origin, not a
    /// destination. Compiled solely for the Java engine; other engines carry the
    /// matcher in the spec but no-op it.
    ReceiverProvenanceCall {
        init_receiver: String,
        init_method: String,
        init_arg: String,
        method: String,
        description: String,
    },

    /// Match an INLINE method call `<recv>.<method>("<arg>", ...)` as a taint
    /// SOURCE — the Semgrep inline hash-provenance source
    /// `$CRYPTO.createHash("md5")` (the JS `md5-used-as-password` rule: the
    /// digest of an MD5 hash created inline by `crypto.createHash("md5")` is a
    /// weak password hash). Fires on a call whose final method-name segment
    /// equals `method` (`createHash`) AND whose first string-literal argument
    /// equals `arg` (`md5`); the call result is seeded tainted, and the engine's
    /// method-chain propagation carries it through `.update(...).digest(...)` to
    /// the password sink.
    ///
    /// This is the INLINE analogue of [`NodeMatcher::ReceiverProvenanceCall`]
    /// (which needs a separately-declared receiver): here the provenance IS the
    /// call itself, so no receiver-declaration lookup is required.
    ///
    /// Faithfulness (the whole point): the `arg` string discriminator is what
    /// separates the weak algorithm from strong ones — a call
    /// `createHash("sha256")` does NOT match (its literal argument is not
    /// `arg`), so `sha256.digest()` stays clean. Matching requires BOTH the
    /// method name AND the literal argument, so an unrelated `createHash`
    /// receiver or a non-literal argument is silent. Source only — a hash call
    /// is a taint origin, not a destination. Compiled solely for the JS engine
    /// (the only registry rule with this inline shape is JS); other engines
    /// carry the matcher in the spec but no-op it.
    LiteralArgCall {
        method: String,
        arg: String,
        description: String,
    },
}

impl NodeMatcher {
    pub fn description(&self) -> &str {
        match self {
            NodeMatcher::Attribute { description, .. } => description,
            NodeMatcher::Call { description, .. } => description,
            NodeMatcher::ParamName { description, .. } => description,
            NodeMatcher::MethodName { description, .. } => description,
            NodeMatcher::CallRegex { description, .. } => description,
            NodeMatcher::MethodNameRegex { description, .. } => description,
            NodeMatcher::ReceiverCall { description, .. } => description,
            NodeMatcher::FieldName { description, .. } => description,
            NodeMatcher::Subscript { description, .. } => description,
            NodeMatcher::MemberAssign { description, .. } => description,
            NodeMatcher::BinopFormat { description, .. } => description,
            NodeMatcher::ObjectLiteralValue { description, .. } => description,
            NodeMatcher::ReturnValue { description, .. } => description,
            NodeMatcher::TypedName { description, .. } => description,
            NodeMatcher::TypedAssignTarget { description, .. } => description,
            NodeMatcher::LiteralString { description, .. } => description,
            NodeMatcher::LooseEquality { description } => description,
            NodeMatcher::TaintedCallee { description } => description,
            NodeMatcher::TaintedSubscriptKey { description, .. } => description,
            NodeMatcher::CallArgSource { description, .. } => description,
            NodeMatcher::FirstParamSource { description } => description,
            NodeMatcher::DecoratedParamSource { description, .. } => description,
            NodeMatcher::CallArgConcat { description, .. } => description,
            NodeMatcher::ConstructorArgSink { description, .. } => description,
            NodeMatcher::PropertyAssignSink { description, .. } => description,
            NodeMatcher::MethodArgSink { description, .. } => description,
            NodeMatcher::ReceiverProvenanceCall { description, .. } => description,
            NodeMatcher::LiteralArgCall { description, .. } => description,
        }
    }
}

/// Declarative taint specification consumed by the engine.
///
/// Sanitizers collapse to "clean" — the engine does not track a separate
/// "sanitized" state.
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    pub sources: Vec<NodeMatcher>,
    pub sinks: Vec<NodeMatcher>,
    pub sanitizers: Vec<NodeMatcher>,
}

/// A compiled taint **propagator**: a method call through which taint flows
/// from an argument to the receiver.
///
/// Compiled by the Semgrep YAML bridge from a `pattern-propagators` entry of
/// the "argument taints receiver" form
///
/// ```yaml
/// pattern-propagators:
///   - pattern: (StringBuilder $TO).append($FROM)
///     from: $FROM
///     to: $TO
/// ```
///
/// Semantics (the tractable, high-value subset): when a method call
/// `receiver.method(args)` is evaluated during the per-function walk and any
/// argument is tainted, the receiver variable becomes tainted. This is the
/// generalization of the existing method-call-on-tainted-*receiver* rule
/// (receiver → result) in the reverse direction (argument → receiver), letting
/// taint flow through container-mutating helpers such as
/// `StringBuilder.append`, `StringBuffer.append`, and `.concat` that would
/// otherwise drop the taint and cause false negatives.
///
/// `method = Some(name)` requires the invoked method name to match (e.g.
/// `append`, `concat`); `method = None` matches any method name (compiled from
/// a metavariable method like `$ANY`, e.g. C#'s
/// `(StringBuilder $B).$ANY(...,(string $X),...)`). Only the arg→receiver
/// direction with a plain-identifier receiver is compiled; other propagator
/// shapes (argument→argument, receiver→argument, and augmented-assignment
/// `$VAR += $FROM`, the latter already covered by the engine's assignment
/// propagation) are dropped by the bridge with a warning. A missing propagator
/// is a potential false NEGATIVE, never a false positive.
///
/// Applied only by the Java and C# engines today — the only registry rules
/// that use `pattern-propagators` target those two languages. Other language
/// engines carry the compiled propagator list but do not yet consult it.
#[derive(Debug, Clone)]
pub struct Propagator {
    /// The method name that must match, or `None` to match any method name
    /// (compiled from a metavariable method).
    pub method: Option<String>,
    /// Human-readable description for diagnostics.
    pub description: String,
}

/// A boolean expression over taint **labels** — the parsed form of a Semgrep
/// `requires:` string (advanced taint mode). Supports a bare label, `not X`,
/// `A and B`, `A or B`, and parenthesization, which is the full grammar the
/// registry's negation-tier rules use (`INPUT and not CLEAN`,
/// `TAINTED and not CONCAT and not CLEAN`,
/// `(EXPRESS and not CLEAN) or (EXPRESSTS and not CLEAN)`).
///
/// Evaluated against the set of labels a taint flow *carries* at the sink: a
/// finding fires only when [`RequiresExpr::eval`] returns `true`. The `not`
/// arm is what makes a sanitizer-relabel (a value that acquired `CLEAN`)
/// suppress the sink while an un-sanitized value (carrying only the primary
/// label) still fires — the whole point of the negation tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiresExpr {
    /// A bare label token — true iff the flow carries it.
    Label(String),
    /// `not X` — true iff `X` is *not* carried.
    Not(Box<RequiresExpr>),
    /// `A and B`.
    And(Box<RequiresExpr>, Box<RequiresExpr>),
    /// `A or B`.
    Or(Box<RequiresExpr>, Box<RequiresExpr>),
}

impl RequiresExpr {
    /// Evaluate this `requires:` expression against a flow's label set.
    pub fn eval(&self, labels: &BTreeSet<String>) -> bool {
        match self {
            RequiresExpr::Label(l) => labels.contains(l),
            RequiresExpr::Not(inner) => !inner.eval(labels),
            RequiresExpr::And(a, b) => a.eval(labels) && b.eval(labels),
            RequiresExpr::Or(a, b) => a.eval(labels) || b.eval(labels),
        }
    }

    /// Collect every label token referenced anywhere in the expression.
    pub fn referenced_labels(&self, out: &mut BTreeSet<String>) {
        match self {
            RequiresExpr::Label(l) => {
                out.insert(l.clone());
            }
            RequiresExpr::Not(inner) => inner.referenced_labels(out),
            RequiresExpr::And(a, b) | RequiresExpr::Or(a, b) => {
                a.referenced_labels(out);
                b.referenced_labels(out);
            }
        }
    }
}

/// A conditional relabel: when a value already carrying label `from` flows
/// through a string-building node (`+` / `+=` / `String.format` / `.concat` /
/// `StringBuilder.append` / `fmt.Sprintf`-family / …), it additionally acquires
/// label `to`. Compiled from a Semgrep source/propagator entry of the shape
/// `label: <to>, requires: <from>` (e.g. `label: CONCAT, requires: INPUT` or the
/// Go open-redirect `label: CLEAN, requires: INPUT`).
#[derive(Debug, Clone)]
pub struct Relabel {
    pub from: String,
    pub to: String,
}

/// A bounded taint-**labels** policy (Semgrep advanced taint mode).
///
/// See `docs/parity/taint-labels-design.md`. A source emits a named **label**;
/// sinks gate on a `requires:` boolean over labels. This models the tractable
/// single-primary-label shapes:
///
/// - every primary (unconditional) source emits `source_label` (e.g. `INPUT`);
/// - each [`Relabel`] adds a label to a value that carries its `from` label and
///   flows through a string-building node (the conditional-relabel mechanic
///   compiled from a source/propagator `label: L2, requires: L1` — e.g.
///   `INPUT → CONCAT` for the Java family, `INPUT → CLEAN` for the Go
///   open-redirect / tainted-url-host family);
/// - a sink fires ONLY when the reaching value's label set satisfies the
///   boolean [`RequiresExpr`] `sink_requires` — a single positive label
///   (`CONCAT`) for the Java family, or a negation (`INPUT and not CLEAN`) for
///   the Go family.
///
/// Consumed by the Java and Go engines. Shapes needing *multiple distinct
/// primary source labels* (the TS/JS `react-href-var` / `raw-html-format`
/// rules) are still refused by `detect_label_policy` and stay skipped.
#[derive(Debug, Clone)]
pub struct LabelPolicy {
    /// Label emitted by every primary (unconditional) source.
    pub source_label: String,
    /// Conditional string-building relabels (e.g. `INPUT → CONCAT`,
    /// `INPUT → CLEAN`). Usually one entry.
    pub relabels: Vec<Relabel>,
    /// Boolean gating expression: a sink fires only when the reaching value's
    /// label set satisfies it.
    pub sink_requires: RequiresExpr,
}

/// A single source→sink flow reported by the engine.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub sink_start_byte: usize,
    pub sink_end_byte: usize,
    pub sink_line: usize,
    pub sink_column: usize,
    pub sink_end_line: usize,
    pub sink_end_column: usize,
    pub source_description: String,
    pub sink_description: String,
    /// 1-indexed line where the taint source was introduced.
    pub source_line: usize,
    /// Byte range `[start, end)` of the AST node that introduced the taint
    /// (the node that matched a `pattern-sources` matcher), when known.
    /// Consumed by the source-side `pattern-inside` / `pattern-not` post-filter
    /// in `semgrep_taint.rs`. `None` when the origin has no single node span
    /// (a seeded parameter) or the engine path does not track it — the
    /// post-filter only reads this when the rule declares a source-side
    /// `pattern-inside`/`pattern-not`, so every other rule is unaffected.
    pub source_range: Option<(usize, usize)>,
    /// Optional rule id hint set by the batched analyzer so callers can
    /// dispatch a finding back to the correct rule.
    pub rule_id_hint: Option<String>,
    /// Approximate number of hops along the source→sink flow.
    pub hops: u8,
}

/// How cross-file findings should be attributed to rules.
#[derive(Clone)]
pub enum RuleFilter<'a> {
    /// Only emit cross-file findings whose `sink_rule_id` equals the
    /// given value.
    Single(&'a str),
    /// Emit cross-file findings whose `sink_rule_id` appears in the
    /// given set.
    Any(&'a HashSet<String>),
}

impl<'a> RuleFilter<'a> {
    pub fn allows(&self, rule_id: &str) -> bool {
        match self {
            RuleFilter::Single(id) => *id == rule_id,
            RuleFilter::Any(set) => set.contains(rule_id),
        }
    }
}

/// Compact same-file return-taint summary keyed by function symbol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReturnTaintSummary {
    /// Return value is tainted by a source found inside the function body,
    /// independent of caller arguments.
    pub direct_source: Option<String>,
    /// Caller argument indices that taint the return value.
    pub params_to_return: Vec<usize>,
}

/// Return-taint summary map keyed by a function symbol.
pub type ReturnSummary = HashMap<String, ReturnTaintSummary>;

/// Inputs to the batched taint analyzer.
pub struct BatchedRule<'a> {
    pub rule_id: &'a str,
    pub spec: &'a TaintSpec,
}

/// A merged sanitizer-compatible batch of taint rules.
pub(super) struct BatchedTaintGroup {
    pub spec: TaintSpec,
    pub sink_to_rules: HashMap<String, Vec<String>>,
    pub allowed_rule_ids: HashSet<String>,
}

/// Sink matcher result with the optional owning rule id used in batched mode.
pub(super) struct MatchedSink {
    pub description: String,
    pub attribution_key: Option<String>,
    pub rule_ids: Vec<String>,
}

// ─── Internal types (pub(super) for language engines) ────────────────────

#[derive(Clone, Debug)]
pub(super) struct TaintInfo {
    pub description: String,
    pub line: usize,
    /// Optional taint-**labels** set carried by this value (Semgrep advanced
    /// taint mode). `None` = the historical unlabeled/boolean behavior (every
    /// engine path and rule that does not activate a [`LabelPolicy`] is
    /// unchanged). `Some(set)` is populated only when a policy is active; a sink
    /// then fires only when the set satisfies the policy's `sink_requires`.
    pub labels: Option<BTreeSet<String>>,
    /// Byte range `[start, end)` of the AST node that originally introduced
    /// this taint (the node that matched a `pattern-sources` matcher). Threaded
    /// through assignment/with/destructuring propagation so that at a sink the
    /// engine can report WHERE the source was, enabling the source-side
    /// `pattern-inside` / `pattern-not` post-filter in `semgrep_taint.rs`.
    ///
    /// `None` when the origin has no single node span (e.g. a seeded parameter)
    /// or when the engine path does not track it — the historical behavior for
    /// every rule WITHOUT a source-side `pattern-inside` is unchanged, and the
    /// post-filter treats `None` conservatively (drops, FP-safe, for
    /// `pattern-inside`; keeps for `pattern-not`).
    pub source_range: Option<(usize, usize)>,
}

#[derive(Default)]
pub(super) struct TaintState {
    pub tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    /// Taint `name` with the historical unlabeled behavior (`labels = None`,
    /// `source_range = None`).
    pub fn taint(&mut self, name: String, description: String, line: usize) {
        self.tainted.insert(
            name,
            TaintInfo {
                description,
                line,
                labels: None,
                source_range: None,
            },
        );
    }

    /// Taint `name` carrying the byte range of the originating source node
    /// (used by the source-side `pattern-inside` post-filter). `labels = None`
    /// (unlabeled behavior). Callers that have the source node's span thread it
    /// here so it survives assignment propagation to the sink.
    pub fn taint_ranged(
        &mut self,
        name: String,
        description: String,
        line: usize,
        source_range: Option<(usize, usize)>,
    ) {
        self.tainted.insert(
            name,
            TaintInfo {
                description,
                line,
                labels: None,
                source_range,
            },
        );
    }

    /// Taint `name` carrying an explicit taint-labels set (Semgrep advanced
    /// taint mode). Used only on the label-aware engine paths.
    pub fn taint_labeled(
        &mut self,
        name: String,
        description: String,
        line: usize,
        labels: Option<BTreeSet<String>>,
    ) {
        self.tainted.insert(
            name,
            TaintInfo {
                description,
                line,
                labels,
                source_range: None,
            },
        );
    }

    pub fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    pub fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

/// Bundles the read-only context that every internal walker needs,
/// replacing the repeated `(source, spec, aliases, summaries)` tuple.
///
/// Generic over `CF`, the language-specific cross-file info type:
/// - JS/TS: `javascript_taint::CrossFileInfo`
/// - Python: `python_taint::CrossFileInfo`
/// - Go:    `go_taint::CrossFileInfo`
pub(super) struct AnalysisContext<'a, CF> {
    pub source: &'a str,
    pub spec: &'a TaintSpec,
    pub aliases: Option<&'a super::common::AliasTable>,
    pub summaries: &'a ReturnSummary,
    /// Cross-file info for resolving imported / same-package function calls.
    pub cross_file: Option<&'a CF>,
    /// When the batched analyzer merges sinks from multiple rules into a
    /// single `TaintSpec`, this map attributes each matched sink back to
    /// its owning rule id. `None` in single-rule mode.
    pub sink_to_rules: Option<&'a HashMap<String, Vec<String>>>,
    /// Active taint-**labels** policy (Semgrep advanced taint mode). `None`
    /// (the default for every existing path) is the historical unlabeled
    /// behavior. `Some(..)` enables label-aware source seeding, string-building
    /// relabels, and boolean `requires:` sink gating in engines that consult it
    /// (currently Go via the Semgrep bridge).
    pub label_policy: Option<&'a LabelPolicy>,
}

// ─── Language adapter trait ──────────────────────────────────────────────

/// Trait implemented by each language-specific taint engine.
///
/// Generic over `CF`, the language-specific cross-file info type.
/// The generic walk/analyze functions call into this trait to dispatch to
/// language-specific AST handling. Each language implements the trait on a
/// zero-sized marker type (e.g. `JsTaintAdapter`, `PyTaintAdapter`,
/// `GoTaintAdapter`) parameterized by its `CrossFileInfo`.
pub(super) trait TaintLanguageAdapter<CF> {
    /// Returns `true` if `kind` is a nested function scope that should be
    /// skipped during the walk (each scope is analyzed independently).
    fn is_nested_scope(kind: &str) -> bool;

    /// Dispatch a single AST node to language-specific handlers during the
    /// main analysis walk. Implementations should match on `node.kind()`
    /// and call their assignment/declaration/call handlers as appropriate.
    fn dispatch_walk_node(
        node: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
    );

    /// Dispatch a single AST node during the summary walk (pass 1).
    /// Same as `dispatch_walk_node` but also handles `return_statement`
    /// for return-taint detection.
    fn dispatch_summary_node(
        node: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
        return_taint: &mut Option<String>,
    );

    /// Evaluate whether `expr` is tainted. Returns `(description, line)` or `None`.
    #[allow(dead_code)]
    fn expression_taint(
        expr: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &TaintState,
    ) -> Option<(String, usize)>;

    /// Seed taint state from function parameters that match source matchers.
    fn seed_params(func_node: Node<'_>, ctx: &AnalysisContext<'_, CF>, state: &mut TaintState);

    /// Get the function body node. Returns `None` if the function has no body.
    fn get_body(func_node: Node<'_>) -> Option<Node<'_>> {
        func_node.child_by_field_name("body")
    }
}

// ─── Generic walk functions ─────────────────────────────────────────────

/// Generic body walker for the main analysis pass (pass 2).
///
/// Skips nested scopes (as determined by `T::is_nested_scope`),
/// dispatches to language-specific handlers, then recurses into children.
pub(super) fn walk_body_generic<T: TaintLanguageAdapter<CF>, CF>(
    node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    if T::is_nested_scope(node.kind()) {
        return;
    }
    T::dispatch_walk_node(node, ctx, state, findings);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_generic::<T, CF>(child, ctx, state, findings);
    }
}

/// Generic body walker for the summary pass (pass 1).
///
/// Same as `walk_body_generic` but also detects return-taint.
pub(super) fn walk_body_for_summary_generic<T: TaintLanguageAdapter<CF>, CF>(
    node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    return_taint: &mut Option<String>,
) {
    if T::is_nested_scope(node.kind()) {
        return;
    }
    T::dispatch_summary_node(node, ctx, state, findings, return_taint);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_for_summary_generic::<T, CF>(child, ctx, state, findings, return_taint);
    }
}

/// Generic per-function analysis (pass 2).
///
/// Seeds parameter taint, gets the body, and walks it with the main walker.
pub(super) fn analyze_function_generic<T: TaintLanguageAdapter<CF>, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    findings: &mut Vec<TaintFinding>,
) {
    let mut state = TaintState::default();
    T::seed_params(func_node, ctx, &mut state);
    let Some(body) = T::get_body(func_node) else {
        return;
    };
    walk_body_generic::<T, CF>(body, ctx, &mut state, findings);
}

/// Generic pass-1 summarizer: seed params, walk body, detect return taint.
///
/// Returns `Option<String>` -- the first tainted return expression's
/// description, or `None` if the function returns clean.
pub(super) fn summarize_function_generic<T, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
) -> Option<String>
where
    T: TaintLanguageAdapter<CF>,
{
    let mut state = TaintState::default();
    T::seed_params(func_node, ctx, &mut state);
    let body = T::get_body(func_node)?;
    let mut scratch: Vec<TaintFinding> = Vec::new();
    let mut return_taint: Option<String> = None;
    walk_body_for_summary_generic::<T, CF>(body, ctx, &mut state, &mut scratch, &mut return_taint);
    return_taint
}

/// Generic return-taint summary builder.
///
/// Computes:
/// 1. `direct_source`: does the function body contain a tainted return
///    independent of caller arguments?
/// 2. `params_to_return`: which parameter indices flow to a return value?
pub(super) fn summarize_function_return_generic<T, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    collect_param_names: impl Fn(Node<'_>, &str) -> Vec<String>,
) -> ReturnTaintSummary
where
    T: TaintLanguageAdapter<CF>,
{
    let direct_source = summarize_function_generic::<T, CF>(func_node, ctx);
    let mut summary = ReturnTaintSummary {
        direct_source,
        params_to_return: Vec::new(),
    };

    let empty_summary = ReturnSummary::new();
    for (param_idx, param_name) in collect_param_names(func_node, ctx.source)
        .into_iter()
        .enumerate()
    {
        let synthetic_spec = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec![param_name.clone()],
                description: format!("parameter '{}'", param_name),
            }],
            sinks: vec![],
            sanitizers: ctx.spec.sanitizers.clone(),
        };
        let param_ctx = AnalysisContext {
            source: ctx.source,
            spec: &synthetic_spec,
            aliases: ctx.aliases,
            summaries: &empty_summary,
            cross_file: None,
            sink_to_rules: None,
            label_policy: None,
        };
        if summarize_function_generic::<T, CF>(func_node, &param_ctx).is_some() {
            summary.params_to_return.push(param_idx);
        }
    }

    summary
}

/// Extract cross-file taint summaries for a single function.
///
/// For each parameter, treat it as a synthetic taint source and test
/// whether it flows to any sink (producing `ParamSinkFlow` entries) or
/// to a return value (producing `params_to_return` entries).
///
/// This is the shared inner loop of `extract_cross_file_summaries` for
/// JS, Python, and Go. Callers provide the function node, its name,
/// its parameter names, rule specs, aliases, source, and the adapter type.
pub(super) fn extract_cross_file_summary_for_function<T, CF>(
    func_node: Node<'_>,
    func_name: &str,
    param_names: &[String],
    source: &str,
    aliases: Option<&super::common::AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Option<FunctionTaintSummary>
where
    T: TaintLanguageAdapter<CF>,
{
    extract_cross_file_summary_for_function_cf::<T, CF>(
        func_node,
        func_name,
        param_names,
        source,
        aliases,
        rule_specs,
        None,
    )
}

/// Like [`extract_cross_file_summary_for_function`] but with an optional
/// cross-file context.
///
/// When `cross_file` is `Some`, calls *inside* the function body to helpers in
/// **other** files are resolved against the supplied summary map. This lets a
/// parameter that reaches a sink (or the return value) only *through* a
/// cross-file helper be recorded in the summary. It is the transitive-summary
/// composition step used by the scanner's bounded multi-hop fixpoint
/// (see `docs/taint-tracking.md`, "Bounded multi-hop cross-file taint").
///
/// Cross-file findings produced during this walk carry a decorated sink
/// description but a `rule_id_hint` naming the *resolved* sink rule; they are
/// attributed via that hint rather than via the local `sink_desc_to_rule` map.
///
/// With `cross_file = None` this is byte-for-byte equivalent to the historical
/// single-file summary extraction (no cross-file findings can be produced).
pub(super) fn extract_cross_file_summary_for_function_cf<T, CF>(
    func_node: Node<'_>,
    func_name: &str,
    param_names: &[String],
    source: &str,
    aliases: Option<&super::common::AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: Option<&CF>,
) -> Option<FunctionTaintSummary>
where
    T: TaintLanguageAdapter<CF>,
{
    if param_names.is_empty() {
        return None;
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    let mut params_to_return: Vec<usize> = Vec::new();

    // Partition rules: those without sanitizers can be batched into a
    // single analyze_function call per parameter; rules with sanitizers
    // must run individually to avoid incorrect taint clearing.
    let mut batched_sinks: Vec<NodeMatcher> = Vec::new();
    let mut sink_desc_to_rule: HashMap<&str, &str> = HashMap::new();
    let mut sanitizer_rules: Vec<(&str, &TaintSpec)> = Vec::new();
    for (rule_id, rule_spec) in rule_specs {
        if rule_spec.sanitizers.is_empty() {
            for sink in &rule_spec.sinks {
                sink_desc_to_rule.insert(sink.description(), rule_id);
                batched_sinks.push(sink.clone());
            }
        } else {
            sanitizer_rules.push((rule_id, rule_spec));
        }
    }

    let empty_summary = ReturnSummary::new();

    // Cross-file findings (produced by the language engine's cross-file call
    // handler when `cross_file` is Some) fire in whichever pass runs the walk,
    // independent of the batched/sanitizer partition above — the partition only
    // governs *same-file* sink matching. To keep those cross-file findings
    // sanitizer-correct, the batched and return passes must carry every rule's
    // sanitizers when composing. This over-approximates sanitization across
    // rules (a safe, false-negative-only direction), and only affects the
    // composed summaries: base single-file flows were already captured with the
    // precise per-rule partition and are merged in by union, so nothing is lost.
    let composition_sanitizers: Vec<NodeMatcher> = if cross_file.is_some() {
        let mut merged: Vec<NodeMatcher> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (_, rule_spec) in rule_specs {
            for s in &rule_spec.sanitizers {
                if seen.insert(matcher_fingerprint(s)) {
                    merged.push(s.clone());
                }
            }
        }
        merged
    } else {
        Vec::new()
    };

    // Pre-build reusable specs outside the per-param loop.
    let placeholder_source = NodeMatcher::ParamName {
        names: vec![],
        description: String::new(),
    };
    let mut return_spec = TaintSpec {
        sources: vec![placeholder_source.clone()],
        sinks: vec![],
        sanitizers: composition_sanitizers.clone(),
    };
    let mut batched_spec = TaintSpec {
        sources: vec![placeholder_source.clone()],
        sinks: batched_sinks,
        sanitizers: composition_sanitizers.clone(),
    };
    let mut sanitizer_specs: Vec<TaintSpec> = sanitizer_rules
        .iter()
        .map(|(_, rule_spec)| TaintSpec {
            sources: vec![placeholder_source.clone()],
            sinks: rule_spec.sinks.clone(),
            // During composition a cross-file finding for *any* rule can fire in
            // this pass (the cross-file handler is rule-filter-agnostic across
            // passes), so every pass must carry the full sanitizer union — not
            // just this rule's own sanitizers — or a value sanitized for rule A
            // would leak a cross-file finding through rule B's pass. Outside
            // composition (`cross_file` None) we keep the precise per-rule set.
            sanitizers: if cross_file.is_some() {
                composition_sanitizers.clone()
            } else {
                rule_spec.sanitizers.clone()
            },
        })
        .collect();

    for (param_idx, param_name) in param_names.iter().enumerate() {
        let synthetic_source = NodeMatcher::ParamName {
            names: vec![param_name.clone()],
            description: format!("parameter '{}'", param_name),
        };

        // Check return-taint: does this parameter flow to a return value?
        return_spec.sources[0] = synthetic_source.clone();
        let return_ctx = AnalysisContext {
            source,
            spec: &return_spec,
            aliases,
            summaries: &empty_summary,
            cross_file,
            sink_to_rules: None,
            label_policy: None,
        };
        let mut return_findings = Vec::new();
        let mut return_state = TaintState::default();
        T::seed_params(func_node, &return_ctx, &mut return_state);
        if let Some(body) = T::get_body(func_node) {
            let mut return_taint: Option<String> = None;
            walk_body_for_summary_generic::<T, CF>(
                body,
                &return_ctx,
                &mut return_state,
                &mut return_findings,
                &mut return_taint,
            );
            if return_taint.is_some() && !params_to_return.contains(&param_idx) {
                params_to_return.push(param_idx);
            }
        }

        let mut seen: HashSet<(usize, String)> = HashSet::new();

        // Batched pass: one call for all no-sanitizer rules. When a cross-file
        // context is present we run it even with no local sinks, so cross-file
        // sink findings (driven by the resolved summaries, not by
        // `batched_spec.sinks`) are still collected.
        if !batched_spec.sinks.is_empty() || cross_file.is_some() {
            batched_spec.sources[0] = synthetic_source.clone();
            let batched_ctx = AnalysisContext {
                source,
                spec: &batched_spec,
                aliases,
                summaries: &empty_summary,
                cross_file,
                sink_to_rules: None,
                label_policy: None,
            };
            let mut findings = Vec::new();
            analyze_function_generic::<T, CF>(func_node, &batched_ctx, &mut findings);
            for f in &findings {
                // Same-file sinks are attributed via their (undecorated)
                // description; cross-file findings carry a decorated
                // description but a `rule_id_hint` naming the resolved rule.
                let rule_id = match sink_desc_to_rule.get(f.sink_description.as_str()) {
                    Some(&r) => Some(r.to_string()),
                    None => f.rule_id_hint.clone(),
                };
                if let Some(rule_id) = rule_id {
                    if seen.insert((param_idx, rule_id.clone())) {
                        params_to_sink.push(ParamSinkFlow {
                            param_index: param_idx,
                            sink_rule_id: rule_id,
                            sink_description: f.sink_description.clone(),
                        });
                    }
                }
            }
        }

        // Individual pass: rules with sanitizers run separately.
        for (idx, (rule_id, _)) in sanitizer_rules.iter().enumerate() {
            sanitizer_specs[idx].sources[0] = synthetic_source.clone();
            let sink_ctx = AnalysisContext {
                source,
                spec: &sanitizer_specs[idx],
                aliases,
                summaries: &empty_summary,
                cross_file,
                sink_to_rules: None,
                label_policy: None,
            };
            let mut findings = Vec::new();
            analyze_function_generic::<T, CF>(func_node, &sink_ctx, &mut findings);
            for f in &findings {
                // A cross-file finding is attributed to its resolved rule (via
                // the hint); a same-file finding belongs to the sanitizer rule
                // under test. Dedup keeps one flow per (param, rule).
                let attributed = f
                    .rule_id_hint
                    .clone()
                    .unwrap_or_else(|| rule_id.to_string());
                if seen.insert((param_idx, attributed.clone())) {
                    params_to_sink.push(ParamSinkFlow {
                        param_index: param_idx,
                        sink_rule_id: attributed,
                        sink_description: f.sink_description.clone(),
                    });
                }
            }
        }
    }

    if params_to_sink.is_empty() && params_to_return.is_empty() {
        return None;
    }

    Some(FunctionTaintSummary {
        name: func_name.to_string(),
        params_to_return,
        params_to_sink,
    })
}

// ─── Utilities ───────────────────────────────────────────────────────────

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

/// Sentinel name used by the bridge to compile an "any function parameter"
/// taint source. Chosen to be a string no real identifier (including a PHP
/// `$`-variable like `$_GET`) can equal, so the use-site matchers never fire
/// on it — only `seed_params` interprets it (via [`param_names_are_wildcard`]).
pub const ANY_PARAM_WILDCARD: &str = "$<any-param>";

/// True when a `ParamName` matcher's name list designates the
/// "any function parameter" wildcard — i.e. it contains the
/// [`ANY_PARAM_WILDCARD`] sentinel.
///
/// This is the seed-time semantics for the Semgrep taint source shape
///
/// ```yaml
/// pattern-sources:
///   - patterns:
///       - pattern-inside: |
///           function ... (..., $ARG, ...) { ... }
///       - focus-metavariable: $ARG
/// ```
///
/// which means "every parameter of the enclosing function is a taint source".
/// The bridge ([`semgrep_taint`]) compiles such a block to
/// `ParamName { names: ["$PARAM"], .. }`; each engine's `seed_params` calls
/// this helper so a `$`-prefixed name seeds *all* parameters of the function
/// being analyzed, rather than only a literally-named one.
///
/// Discipline: the wildcard fires ONLY at parameter-seeding time. Use-site
/// matchers (`match_source`) compare against the literal name `$PARAM`, which
/// no real identifier equals, so the wildcard never broadens an expression-
/// position match — only function parameters become sources.
pub(super) fn param_names_are_wildcard(names: &[String]) -> bool {
    names.iter().any(|n| n == ANY_PARAM_WILDCARD)
}

pub(super) fn build_batched_taint_groups(rules: &[BatchedRule<'_>]) -> Vec<BatchedTaintGroup> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        let mut placed = false;
        for g in groups.iter_mut() {
            let rep = rules[g[0]].spec;
            if sanitizer_fingerprints_eq(&rep.sanitizers, &r.spec.sanitizers) {
                g.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            groups.push(vec![i]);
        }
    }

    let mut out = Vec::new();
    for group in groups {
        let mut merged_sources: Vec<NodeMatcher> = Vec::new();
        let mut merged_sinks: Vec<NodeMatcher> = Vec::new();
        let mut seen_source_keys: HashSet<String> = HashSet::new();
        let mut seen_sink_keys: HashSet<String> = HashSet::new();
        let mut sink_to_rules: HashMap<String, Vec<String>> = HashMap::new();
        let mut allowed_rule_ids: HashSet<String> = HashSet::new();

        for idx in &group {
            let rule = &rules[*idx];
            allowed_rule_ids.insert(rule.rule_id.to_string());
            for src in &rule.spec.sources {
                let source_key = matcher_fingerprint(src);
                if seen_source_keys.insert(source_key) {
                    merged_sources.push(src.clone());
                }
            }
            for sink in &rule.spec.sinks {
                let sink_key = matcher_fingerprint(sink);
                let rule_ids = sink_to_rules.entry(sink_key.clone()).or_default();
                if !rule_ids.iter().any(|id| id == rule.rule_id) {
                    rule_ids.push(rule.rule_id.to_string());
                }
                if seen_sink_keys.insert(sink_key) {
                    merged_sinks.push(sink.clone());
                }
            }
        }

        out.push(BatchedTaintGroup {
            spec: TaintSpec {
                sources: merged_sources,
                sinks: merged_sinks,
                sanitizers: rules[group[0]].spec.sanitizers.clone(),
            },
            sink_to_rules,
            allowed_rule_ids,
        });
    }
    out
}

pub(super) fn match_call_sink(
    spec: &TaintSpec,
    resolved_callee: &str,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    let final_segment = resolved_callee
        .rsplit('.')
        .next()
        .unwrap_or(resolved_callee);
    let root_segment = resolved_callee.split('.').next().unwrap_or(resolved_callee);
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::Call { canonical, .. } if canonical.as_str() == resolved_callee => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        NodeMatcher::MethodName { method, .. } if method == final_segment => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `$F(...)` + `metavariable-regex` on `$F`: match any call whose full
        // callee text matches the pinning regex (so dotted callee alternatives
        // such as `IO.popen` match against the whole `IO.popen` text).
        NodeMatcher::CallRegex { regex, .. } if regex.is_match(resolved_callee) => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `$OBJ.$M(...)` + `metavariable-regex` on `$M`: match any method call
        // whose final method name matches the pinning regex, any receiver.
        NodeMatcher::MethodNameRegex { regex, .. } if regex.is_match(final_segment) => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `os.$METHOD(...)` etc.: match any call whose callee root identifier
        // equals `receiver`. Requires a dotted callee (`receiver.method`) so a
        // bare call to a function literally named `receiver` does not match.
        NodeMatcher::ReceiverCall { receiver, .. }
            if root_segment == receiver.as_str() && resolved_callee.contains('.') =>
        {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

pub(super) fn match_member_assign_sink(
    spec: &TaintSpec,
    field_name: &str,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::MemberAssign { field, .. } if field == field_name => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

/// Return the first `BinopFormat` sink matcher in `spec`, if any. The engine
/// calls this when it has already confirmed (by inspecting the AST node) that a
/// string-building concatenation/format with a literal operand and a tainted
/// operand is present.
pub(super) fn match_binop_format_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::BinopFormat { .. } => Some(matched_sink_for_matcher(matcher, sink_to_rules)),
        _ => None,
    })
}

/// Return the first `ObjectLiteralValue` sink matcher in `spec`, if any. The
/// engine calls this when it has already confirmed (by inspecting the AST node)
/// that an object/dict literal is being constructed with at least one tainted
/// value position.
pub(super) fn match_object_literal_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::ObjectLiteralValue { .. } => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

/// Return the first `ReturnValue` sink matcher in `spec`, if any. The engine
/// calls this when it has confirmed (by inspecting the AST node) that a
/// `return` statement returns a tainted value.
pub(super) fn match_return_value_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::ReturnValue { .. } => Some(matched_sink_for_matcher(matcher, sink_to_rules)),
        _ => None,
    })
}

fn matched_sink_for_matcher(
    matcher: &NodeMatcher,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> MatchedSink {
    let key = matcher_fingerprint(matcher);
    let rule_ids = sink_to_rules
        .and_then(|map| map.get(&key).cloned())
        .unwrap_or_default();
    MatchedSink {
        attribution_key: if rule_ids.is_empty() { None } else { Some(key) },
        description: matcher.description().to_string(),
        rule_ids,
    }
}

pub(super) fn attribution_hint_for_sink(sink: &MatchedSink) -> Option<String> {
    match &sink.attribution_key {
        Some(key) => Some(key.clone()),
        None => match sink.rule_ids.as_slice() {
            [rule_id] => Some(rule_id.clone()),
            _ => None,
        },
    }
}

pub(super) fn push_attributed_findings(
    out: &mut Vec<(String, TaintFinding)>,
    findings: Vec<TaintFinding>,
    sink_to_rules: &HashMap<String, Vec<String>>,
) {
    for finding in findings {
        let Some(hint) = finding.rule_id_hint.clone() else {
            continue;
        };
        if let Some(rule_ids) = sink_to_rules.get(&hint) {
            for rule_id in rule_ids {
                let mut attributed = finding.clone();
                attributed.rule_id_hint = Some(rule_id.clone());
                out.push((rule_id.clone(), attributed));
            }
        } else {
            let mut attributed = finding;
            attributed.rule_id_hint = Some(hint.clone());
            out.push((hint, attributed));
        }
    }
}

pub(super) fn taint_finding_for_node(
    node: Node<'_>,
    source_description: String,
    sink_description: String,
    source_line: usize,
    rule_id_hint: Option<String>,
    hops: u8,
) -> TaintFinding {
    taint_finding_for_node_ranged(
        node,
        source_description,
        sink_description,
        source_line,
        rule_id_hint,
        hops,
        None,
    )
}

/// Same as [`taint_finding_for_node`] but records the originating source
/// node's byte range on the finding. Used by the Python engine to thread the
/// source span through to the source-side `pattern-inside`/`pattern-not`
/// post-filter; every other caller goes through [`taint_finding_for_node`]
/// (which passes `None`), so their behavior is unchanged.
pub(super) fn taint_finding_for_node_ranged(
    node: Node<'_>,
    source_description: String,
    sink_description: String,
    source_line: usize,
    rule_id_hint: Option<String>,
    hops: u8,
    source_range: Option<(usize, usize)>,
) -> TaintFinding {
    let start = node.start_position();
    let end = node.end_position();
    TaintFinding {
        sink_start_byte: node.start_byte(),
        sink_end_byte: node.end_byte(),
        sink_line: start.row + 1,
        sink_column: start.column + 1,
        sink_end_line: end.row + 1,
        sink_end_column: end.column + 1,
        source_description,
        sink_description,
        source_line,
        source_range,
        rule_id_hint,
        hops,
    }
}

pub(super) fn cross_file_taint_finding(
    node: Node<'_>,
    source_description: String,
    source_line: usize,
    sink_description: &str,
    callee_name: &str,
    sink_rule_id: &str,
) -> TaintFinding {
    taint_finding_for_node(
        node,
        source_description,
        format!("{sink_description} (via cross-file call to {callee_name})"),
        source_line,
        Some(sink_rule_id.to_string()),
        2,
    )
}

pub(super) fn sanitizer_fingerprints_eq(a: &[NodeMatcher], b: &[NodeMatcher]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let fingerprint = |matchers: &[NodeMatcher]| -> Vec<String> {
        let mut v: Vec<String> = matchers.iter().map(matcher_fingerprint).collect();
        v.sort();
        v
    };
    fingerprint(a) == fingerprint(b)
}

pub(super) fn matcher_fingerprint(m: &NodeMatcher) -> String {
    match m {
        NodeMatcher::Attribute {
            root,
            field,
            description,
        } => format!("A|{root}|{field}|{description}"),
        NodeMatcher::Call {
            canonical,
            description,
        } => format!("C|{canonical}|{description}"),
        NodeMatcher::ParamName { names, description } => {
            format!("P|{}|{description}", names.join(","))
        }
        NodeMatcher::MethodName {
            method,
            description,
        } => {
            format!("M|{method}|{description}")
        }
        NodeMatcher::CallRegex { regex, description } => {
            format!("CR|{}|{description}", regex.as_str())
        }
        NodeMatcher::MethodNameRegex { regex, description } => {
            format!("MR|{}|{description}", regex.as_str())
        }
        NodeMatcher::ReceiverCall {
            receiver,
            description,
        } => {
            format!("R|{receiver}|{description}")
        }
        NodeMatcher::FieldName { field, description } => {
            format!("F|{field}|{description}")
        }
        NodeMatcher::Subscript { base, description } => {
            format!("S|{}|{description}", base.as_deref().unwrap_or("*"))
        }
        NodeMatcher::MemberAssign { field, description } => {
            format!("MA|{field}|{description}")
        }
        NodeMatcher::BinopFormat { description } => {
            format!("BF|{description}")
        }
        NodeMatcher::ObjectLiteralValue { description } => {
            format!("OL|{description}")
        }
        NodeMatcher::ReturnValue { description } => {
            format!("RV|{description}")
        }
        NodeMatcher::TypedName {
            type_name,
            description,
        } => {
            format!("TN|{type_name}|{description}")
        }
        NodeMatcher::TypedAssignTarget {
            type_name,
            description,
        } => {
            format!("TAT|{type_name}|{description}")
        }
        NodeMatcher::LiteralString { description, regex } => {
            format!("LS|{}|{description}", regex.as_deref().unwrap_or(""))
        }
        NodeMatcher::LooseEquality { description } => {
            format!("LE|{description}")
        }
        NodeMatcher::TaintedCallee { description } => {
            format!("TC|{description}")
        }
        NodeMatcher::TaintedSubscriptKey { base, description } => {
            format!("TSK|{}|{description}", base.as_deref().unwrap_or("*"))
        }
        NodeMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => {
            format!("CAS|{method}|{arg_index}|{description}")
        }
        NodeMatcher::FirstParamSource { description } => {
            format!("FPS|{description}")
        }
        NodeMatcher::DecoratedParamSource {
            decorator,
            description,
        } => {
            format!("DPS|{decorator}|{description}")
        }
        NodeMatcher::CallArgConcat {
            method,
            description,
        } => {
            format!("CAC|{method}|{description}")
        }
        NodeMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => {
            format!("CTOR|{}|{arg_index}|{description}", class_names.join(","))
        }
        NodeMatcher::PropertyAssignSink {
            property_names,
            description,
        } => {
            format!("PAS|{}|{description}", property_names.join(","))
        }
        NodeMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => {
            format!("MAS|{}|{arg_index}|{description}", methods.join(","))
        }
        NodeMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => {
            format!("RPC|{init_receiver}.{init_method}({init_arg})|{method}|{description}")
        }
        NodeMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => {
            format!("LAC|{method}({arg})|{description}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_spec(source: NodeMatcher, sink: NodeMatcher) -> TaintSpec {
        TaintSpec {
            sources: vec![source],
            sinks: vec![sink],
            sanitizers: vec![],
        }
    }

    fn param_source(name: &str, description: &str) -> NodeMatcher {
        NodeMatcher::ParamName {
            names: vec![name.to_string()],
            description: description.to_string(),
        }
    }

    fn call_sink(canonical: &str, description: &str) -> NodeMatcher {
        NodeMatcher::Call {
            canonical: canonical.to_string(),
            description: description.to_string(),
        }
    }

    #[test]
    fn batched_group_keeps_distinct_matchers_with_same_description() {
        let spec_a = rule_spec(
            param_source("request", "input"),
            call_sink("a.exec", "exec"),
        );
        let spec_b = rule_spec(param_source("ctx", "input"), call_sink("b.exec", "exec"));
        let rules = [
            BatchedRule {
                rule_id: "rule-a",
                spec: &spec_a,
            },
            BatchedRule {
                rule_id: "rule-b",
                spec: &spec_b,
            },
        ];

        let groups = build_batched_taint_groups(&rules);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].spec.sources.len(), 2);
        assert_eq!(groups[0].spec.sinks.len(), 2);

        let matched = match_call_sink(&groups[0].spec, "a.exec", Some(&groups[0].sink_to_rules))
            .expect("a.exec should match");
        assert_eq!(matched.rule_ids, vec!["rule-a".to_string()]);
    }

    #[test]
    fn batched_group_fans_out_identical_sink_matchers_to_all_owner_rules() {
        let spec_a = rule_spec(param_source("request", "input"), call_sink("exec", "exec"));
        let spec_b = rule_spec(param_source("request", "input"), call_sink("exec", "exec"));
        let rules = [
            BatchedRule {
                rule_id: "rule-a",
                spec: &spec_a,
            },
            BatchedRule {
                rule_id: "rule-b",
                spec: &spec_b,
            },
        ];

        let groups = build_batched_taint_groups(&rules);
        let group = &groups[0];
        assert_eq!(group.spec.sources.len(), 1);
        assert_eq!(group.spec.sinks.len(), 1);

        let matched = match_call_sink(&group.spec, "exec", Some(&group.sink_to_rules))
            .expect("exec should match");
        assert_eq!(
            matched.rule_ids,
            vec!["rule-a".to_string(), "rule-b".to_string()]
        );

        let finding = TaintFinding {
            sink_start_byte: 0,
            sink_end_byte: 4,
            sink_line: 1,
            sink_column: 1,
            sink_end_line: 1,
            sink_end_column: 5,
            source_description: "input".to_string(),
            sink_description: "exec".to_string(),
            source_line: 1,
            source_range: None,
            rule_id_hint: attribution_hint_for_sink(&matched),
            hops: 1,
        };
        let mut out = Vec::new();
        push_attributed_findings(&mut out, vec![finding], &group.sink_to_rules);

        let rule_ids: Vec<String> = out.into_iter().map(|(rule_id, _)| rule_id).collect();
        assert_eq!(rule_ids, vec!["rule-a".to_string(), "rule-b".to_string()]);
    }
}
