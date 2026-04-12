use super::common::AliasTable;
use tree_sitter::{Node, Tree};

/// Build a Python import alias table from a parsed tree.
///
/// Maps a local identifier (as it appears in the source) to its canonical
/// dotted path. For example `import pickle as p` produces `p -> pickle`,
/// and `from pickle import loads as d` produces `d -> pickle.loads`.
///
/// Used by Python rules so that call sites like `p.loads(x)` or
/// `d(x)` resolve back to `pickle.loads` before comparison against sink lists,
/// closing the obvious aliasing bypasses.
///
/// Scope is intentionally file-level only: function-local rebindings like
/// `pickle = something_else` inside one function are not tracked. Dynamic
/// forms such as `importlib.import_module(...)` are also out of scope and
/// tracked separately under the dataflow roadmap.
pub fn from_tree(source: &str, tree: &Tree) -> AliasTable {
    let mut aliases = AliasTable::new();
    walk_for_imports(&mut aliases, tree.root_node(), source);
    aliases
}

fn walk_for_imports(aliases: &mut AliasTable, node: Node, source: &str) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_statement" => collect_import(aliases, child, source),
            "import_from_statement" => collect_import_from(aliases, child, source),
            // Recurse into top-level blocks so `if sys.version_info: import foo`
            // at the module level still contributes. Stop at function and class
            // bodies — alias resolution there is explicitly out of scope.
            "if_statement" | "try_statement" | "with_statement" | "block" | "module" => {
                walk_for_imports(aliases, child, source);
            }
            _ => {}
        }
    }
}

fn collect_import(aliases: &mut AliasTable, node: Node, source: &str) {
    // `import X`, `import X as Y`, `import X.Y`, `import X.Y as Z`
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        match name.kind() {
            "dotted_name" => {
                // `import urllib.request` makes the *first* identifier
                // (`urllib`) the accessible local name, and the full dotted
                // path (`urllib.request`) is what the source will write for
                // callees. Record both so either form resolves correctly.
                let full = node_text(name, source).to_string();
                if let Some(first) = name.child(0) {
                    let root = node_text(first, source).to_string();
                    aliases.entry_or_insert(root.clone(), root);
                }
                aliases.entry_or_insert(full.clone(), full);
            }
            "aliased_import" => {
                // `import X.Y as Z`  →  local `Z` → canonical `X.Y`
                let canonical = name
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source).to_string());
                let alias = name
                    .child_by_field_name("alias")
                    .map(|n| node_text(n, source).to_string());
                if let (Some(canonical), Some(alias)) = (canonical, alias) {
                    aliases.insert(alias, canonical);
                }
            }
            _ => {}
        }
    }
}

fn collect_import_from(aliases: &mut AliasTable, node: Node, source: &str) {
    // `from MODULE import NAME [as ALIAS], ...`
    let Some(module_node) = node.child_by_field_name("module_name") else {
        return;
    };
    let module = node_text(module_node, source).to_string();
    if module.is_empty() {
        return;
    }

    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        match name.kind() {
            "dotted_name" | "identifier" => {
                // `from pickle import loads`  →  `loads` → `pickle.loads`
                let local = node_text(name, source).to_string();
                if local.is_empty() {
                    continue;
                }
                let canonical = format!("{}.{}", module, local);
                aliases.insert(local, canonical);
            }
            "aliased_import" => {
                // `from pickle import loads as d`  →  `d` → `pickle.loads`
                let real = name
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source).to_string());
                let alias = name
                    .child_by_field_name("alias")
                    .map(|n| node_text(n, source).to_string());
                if let (Some(real), Some(alias)) = (real, alias) {
                    let canonical = format!("{}.{}", module, real);
                    aliases.insert(alias, canonical);
                }
            }
            _ => {}
        }
    }
}

/// Resolve Python imports to file paths for cross-file taint analysis.
///
/// Given the source of a Python file and the path of that file, returns a
/// mapping from local import names to the resolved file paths. Only resolves:
/// - `from . import foo` (relative sibling import) -> `<dir>/foo.py`
/// - `from .foo import bar` (relative import) -> `<dir>/foo.py`
/// - `import foo` / `from foo import bar` -> `<dir>/foo.py` (sibling only)
///
/// Does not attempt full Python package resolution (sys.path, site-packages).
pub fn resolve_imports_to_paths(
    source: &str,
    tree: &Tree,
    current_file: &std::path::Path,
) -> std::collections::HashMap<String, std::path::PathBuf> {
    let mut result = std::collections::HashMap::new();
    let Some(parent_dir) = current_file.parent() else {
        return result;
    };

    resolve_imports_walk(&mut result, tree.root_node(), source, parent_dir);
    result
}

fn resolve_imports_walk(
    result: &mut std::collections::HashMap<String, std::path::PathBuf>,
    node: Node,
    source: &str,
    parent_dir: &std::path::Path,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_from_statement" => {
                resolve_import_from(result, child, source, parent_dir);
            }
            "import_statement" => {
                resolve_plain_import(result, child, source, parent_dir);
            }
            "if_statement" | "try_statement" | "with_statement" | "block" | "module" => {
                resolve_imports_walk(result, child, source, parent_dir);
            }
            _ => {}
        }
    }
}

fn resolve_import_from(
    result: &mut std::collections::HashMap<String, std::path::PathBuf>,
    node: Node,
    source: &str,
    parent_dir: &std::path::Path,
) {
    let Some(module_node) = node.child_by_field_name("module_name") else {
        return;
    };
    let module = node_text(module_node, source);

    // `from . import queries` — module_name is ".", name is "queries"
    if module == "." {
        let mut cursor = node.walk();
        for name in node.children_by_field_name("name", &mut cursor) {
            let local = match name.kind() {
                "dotted_name" | "identifier" => node_text(name, source),
                "aliased_import" => {
                    // `from . import queries as q` — use the alias as the local name
                    // but resolve the real name to a file
                    if let Some(real_name) = name.child_by_field_name("name") {
                        let real = node_text(real_name, source);
                        let local = name
                            .child_by_field_name("alias")
                            .map(|a| node_text(a, source))
                            .unwrap_or(real);
                        let candidate = parent_dir.join(format!("{}.py", real));
                        if candidate.exists() {
                            result.insert(local.to_string(), candidate);
                        }
                        continue;
                    }
                    continue;
                }
                _ => continue,
            };
            let candidate = parent_dir.join(format!("{}.py", local));
            if candidate.exists() {
                result.insert(local.to_string(), candidate);
            }
        }
        return;
    }

    // `from .queries import run_query` — relative import with a module name
    if let Some(stripped) = module.strip_prefix('.') {
        if !stripped.is_empty() && !stripped.contains('.') {
            let candidate = parent_dir.join(format!("{}.py", stripped));
            if candidate.exists() {
                // Map each imported name to the module file
                let mut cursor = node.walk();
                for name in node.children_by_field_name("name", &mut cursor) {
                    let local = match name.kind() {
                        "dotted_name" | "identifier" => node_text(name, source),
                        "aliased_import" => name
                            .child_by_field_name("alias")
                            .or_else(|| name.child_by_field_name("name"))
                            .map(|n| node_text(n, source))
                            .unwrap_or(""),
                        _ => continue,
                    };
                    if !local.is_empty() {
                        // For `from .queries import run_query`, we want to be
                        // able to look up `run_query` as a function in `queries.py`.
                        // Store the module path keyed by the *module* name for
                        // attribute access (`queries.run_query`), but this form
                        // imports the function directly. We store it keyed by
                        // a special format: `__from_module__:<local_name>` ->
                        // file path, plus the module itself.
                        result.insert(
                            format!("__from__:{}:{}", stripped, local),
                            candidate.clone(),
                        );
                    }
                }
            }
        }
        return;
    }

    // `from queries import run_query` — bare module name, try sibling
    if !module.contains('.') {
        let candidate = parent_dir.join(format!("{}.py", module));
        if candidate.exists() {
            let mut cursor = node.walk();
            for name in node.children_by_field_name("name", &mut cursor) {
                let local = match name.kind() {
                    "dotted_name" | "identifier" => node_text(name, source),
                    "aliased_import" => name
                        .child_by_field_name("alias")
                        .or_else(|| name.child_by_field_name("name"))
                        .map(|n| node_text(n, source))
                        .unwrap_or(""),
                    _ => continue,
                };
                if !local.is_empty() {
                    result.insert(format!("__from__:{}:{}", module, local), candidate.clone());
                }
            }
        }
    }
}

fn resolve_plain_import(
    result: &mut std::collections::HashMap<String, std::path::PathBuf>,
    node: Node,
    source: &str,
    parent_dir: &std::path::Path,
) {
    // `import queries` — try sibling file
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        let (local, module_name) = match name.kind() {
            "dotted_name" => {
                let text = node_text(name, source);
                // Only resolve simple (non-dotted) module names to siblings
                if text.contains('.') {
                    continue;
                }
                (text.to_string(), text)
            }
            "aliased_import" => {
                let real = name
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source))
                    .unwrap_or("");
                let alias = name
                    .child_by_field_name("alias")
                    .map(|n| node_text(n, source))
                    .unwrap_or(real);
                if real.contains('.') {
                    continue;
                }
                (alias.to_string(), real)
            }
            _ => continue,
        };
        let candidate = parent_dir.join(format!("{}.py", module_name));
        if candidate.exists() {
            result.insert(local, candidate);
        }
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn build(source: &str) -> AliasTable {
        let tree = parse_file(source, Language::Python).expect("parse");
        from_tree(source, &tree)
    }

    #[test]
    fn plain_import_maps_root_to_itself() {
        let a = build("import pickle\n");
        assert_eq!(a.resolve("pickle.loads"), "pickle.loads");
        assert_eq!(a.resolve("pickle"), "pickle");
    }

    #[test]
    fn aliased_import_resolves_alias_to_module() {
        let a = build("import pickle as p\n");
        assert_eq!(a.resolve("p.loads"), "pickle.loads");
        assert_eq!(a.resolve("p.load"), "pickle.load");
    }

    #[test]
    fn from_import_resolves_bare_name_to_dotted_path() {
        let a = build("from pickle import loads\n");
        assert_eq!(a.resolve("loads"), "pickle.loads");
    }

    #[test]
    fn from_import_with_alias_resolves_alias() {
        let a = build("from pickle import loads as deserialize\n");
        assert_eq!(a.resolve("deserialize"), "pickle.loads");
    }

    #[test]
    fn from_import_multiple_names() {
        let a = build("from pickle import loads, load, dumps\n");
        assert_eq!(a.resolve("loads"), "pickle.loads");
        assert_eq!(a.resolve("load"), "pickle.load");
        assert_eq!(a.resolve("dumps"), "pickle.dumps");
    }

    #[test]
    fn cpickle_shadowing_pickle_resolves_to_cpickle() {
        // `import cPickle as pickle` is the classic shadowing form.
        let a = build("import cPickle as pickle\n");
        assert_eq!(a.resolve("pickle.loads"), "cPickle.loads");
    }

    #[test]
    fn dotted_module_import() {
        let a = build("import urllib.request\n");
        // `urllib.request.urlopen` should resolve untouched (not an alias).
        assert_eq!(
            a.resolve("urllib.request.urlopen"),
            "urllib.request.urlopen"
        );
    }

    #[test]
    fn dotted_module_import_with_alias() {
        let a = build("import urllib.request as ur\n");
        assert_eq!(a.resolve("ur.urlopen"), "urllib.request.urlopen");
    }

    #[test]
    fn unknown_identifier_passes_through_unchanged() {
        let a = build("import pickle\n");
        assert_eq!(a.resolve("json.loads"), "json.loads");
        assert_eq!(a.resolve("some_random_fn"), "some_random_fn");
    }

    #[test]
    fn multiple_imports_combine() {
        let a = build(
            r#"
import pickle as p
import yaml
from subprocess import Popen as SpawnProc
from hashlib import md5
"#,
        );
        assert_eq!(a.resolve("p.loads"), "pickle.loads");
        assert_eq!(a.resolve("yaml.load"), "yaml.load");
        assert_eq!(a.resolve("SpawnProc"), "subprocess.Popen");
        assert_eq!(a.resolve("md5"), "hashlib.md5");
    }

    #[test]
    fn from_import_with_alias_raw_map_stores_canonical() {
        let a = build("from pickle import loads as d\n");
        assert_eq!(a.get("d"), Some("pickle.loads"));
        assert_eq!(a.get("loads"), None);
    }

    #[test]
    fn empty_source_produces_empty_table() {
        let a = build("");
        assert_eq!(a.resolve("pickle.loads"), "pickle.loads");
    }
}
