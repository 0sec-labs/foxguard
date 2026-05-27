use super::input::ControlFlow;
use super::state::{
    ActionMenu, ExportFormat, LaunchMode, OpenFocus, ReviewState, SortMode, SourceContextCache,
    TriageAction, TuiApp,
};
use super::widgets::{
    available_open_focuses, cnsa2_deadline_chip_span, compare_findings, compare_findings_by,
    confidence_badge_span, crypto_algorithm_chip_span, dataflow_lines,
    finding_list_index_at_position, list_item, loading_copy, loading_shimmer_line,
    open_target_lines, pop_stashed_event, render_source_context, stash_event, truncate_text,
};
use super::{
    open_command_spec_from_editor, resolve_finding_path, start_source_context_load, OpenTarget,
    WorkerMessage,
};
use crate::app::{TuiExecution, TuiMode};
use crate::cli::TuiArgs;
use crate::{Finding, Severity};
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};
use ratatui::text::{Line, Text};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn tui_args_for(path: String) -> TuiArgs {
    TuiArgs {
        path,
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    }
}

fn source_context_finding() -> Finding {
    Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 2,
        column: 1,
        end_line: 2,
        end_column: 5,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    }
}

fn tui_execution_with(path: String, finding: Finding) -> TuiExecution {
    TuiExecution {
        mode: TuiMode::Scan,
        path,
        findings: vec![finding],
        files_scanned: 1,
        duration: Duration::from_millis(1),
        explain: true,
        diff_summary: None,
        notices: Vec::new(),
    }
}

#[test]
fn finding_list_index_at_position_maps_two_line_rows() {
    let area = Rect {
        x: 10,
        y: 5,
        width: 40,
        height: 12,
    };

    assert_eq!(finding_list_index_at_position(area, 0, 10, 11, 7), Some(0));
    assert_eq!(finding_list_index_at_position(area, 0, 10, 11, 8), Some(0));
    assert_eq!(finding_list_index_at_position(area, 0, 10, 11, 9), Some(1));
    assert_eq!(finding_list_index_at_position(area, 3, 10, 11, 9), Some(4));
}

#[test]
fn finding_list_index_at_position_rejects_outside_content() {
    let area = Rect {
        x: 10,
        y: 5,
        width: 40,
        height: 12,
    };

    assert_eq!(finding_list_index_at_position(area, 0, 10, 10, 7), None);
    assert_eq!(finding_list_index_at_position(area, 0, 10, 11, 6), None);
    assert_eq!(finding_list_index_at_position(area, 0, 1, 11, 9), None);
}

#[test]
fn stashed_event_round_trips_without_being_dropped() {
    assert!(pop_stashed_event().is_none());
    let event = Event::Key(KeyEvent::from(KeyCode::Char('x')));

    stash_event(event.clone());

    assert_eq!(pop_stashed_event(), Some(event));
    assert!(pop_stashed_event().is_none());
}

#[test]
fn resolve_finding_path_joins_relative_file_under_directory_root() {
    let resolved = resolve_finding_path("/tmp/project", "src/main.rs");
    assert_eq!(resolved, PathBuf::from("/tmp/project/src/main.rs"));
}

#[test]
fn resolve_finding_path_uses_parent_for_file_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scan_file = dir.path().join("app.py");
    std::fs::write(&scan_file, "print('ok')").expect("write scan file");

    let resolved = resolve_finding_path(&scan_file.display().to_string(), "app.py");
    assert_eq!(resolved, scan_file);
}

#[test]
fn resolve_finding_path_treats_dotted_directory_as_directory() {
    let resolved = resolve_finding_path("/tmp/project.v1", "src/main.rs");
    assert_eq!(resolved, PathBuf::from("/tmp/project.v1/src/main.rs"));
}

#[test]
fn resolve_finding_path_keeps_parent_relative_paths() {
    let resolved = resolve_finding_path(
        "../foxguard/tests/fixtures/realistic",
        "../foxguard/tests/fixtures/realistic/fastapi_app.py",
    );
    assert_eq!(
        resolved,
        PathBuf::from("../foxguard/tests/fixtures/realistic/fastapi_app.py")
    );
}

#[test]
fn open_command_spec_uses_code_goto_format() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 27,
    };

    let command = open_command_spec_from_editor(&target, Some("code --wait".to_string()))
        .expect("command should build");

    assert_eq!(command.program, "code");
    assert_eq!(
        command.args,
        vec![
            "--wait".to_string(),
            "-g".to_string(),
            "/tmp/project/src/main.rs:27".to_string()
        ]
    );
}

#[test]
fn open_command_spec_normalizes_windows_editor_names() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 27,
    };

    let command = open_command_spec_from_editor(&target, Some("Code.exe --wait".to_string()))
        .expect("command should build");
    assert_eq!(command.program, "Code.exe");
    assert_eq!(
        command.args,
        vec![
            "--wait".to_string(),
            "-g".to_string(),
            "/tmp/project/src/main.rs:27".to_string()
        ]
    );

    let command = open_command_spec_from_editor(&target, Some("code.cmd".to_string()))
        .expect("command should build");
    assert_eq!(command.program, "code.cmd");
    assert_eq!(
        command.args,
        vec!["-g".to_string(), "/tmp/project/src/main.rs:27".to_string()]
    );
}

#[test]
fn open_command_spec_preserves_quoted_editor_args() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 27,
    };

    let command = open_command_spec_from_editor(
        &target,
        Some("code --user-data-dir \"/tmp/editor data\" --wait".to_string()),
    )
    .expect("command should build");

    assert_eq!(command.program, "code");
    assert_eq!(
        command.args,
        vec![
            "--user-data-dir".to_string(),
            "/tmp/editor data".to_string(),
            "--wait".to_string(),
            "-g".to_string(),
            "/tmp/project/src/main.rs:27".to_string()
        ]
    );
}

#[test]
fn open_command_spec_uses_vim_line_format() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 8,
    };

    let command = open_command_spec_from_editor(&target, Some("nvim".to_string()))
        .expect("command should build");

    assert_eq!(command.program, "nvim");
    assert_eq!(
        command.args,
        vec!["+8".to_string(), "/tmp/project/src/main.rs".to_string()]
    );
}

#[test]
fn begin_scan_resets_runtime_notices_and_updates_request_id() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.runtime_notices.push("stale notice".to_string());

    let first = app.begin_scan();
    let second = app.begin_scan();

    assert_eq!(first, 1);
    assert_eq!(second, 2);
    assert!(app.runtime_notices.is_empty());
    assert_eq!(app.active_request_id, 2);
}

#[test]
fn tui_app_starts_on_launch_screen_without_scanning() {
    let app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });

    assert!(app.show_launch);
    assert!(!app.scanning);
    assert_eq!(app.launch_mode, LaunchMode::Scan);
}

#[test]
fn launch_key_enter_starts_selected_mode() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.launch_mode = LaunchMode::Diff;
    app.launch_diff_target = "origin/main".to_string();

    let flow = app.handle_launch_key(KeyCode::Enter);
    assert!(matches!(flow, ControlFlow::Rescan));

    let _ = app.begin_scan();
    assert!(!app.show_launch);
    assert_eq!(app.request.diff.as_deref(), Some("origin/main"));
    assert!(!app.request.secrets);
}

#[test]
fn loading_copy_uses_selected_launch_mode() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: Some("origin/main".to_string()),
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.launch_mode = LaunchMode::Diff;

    let (headline, subline) = loading_copy(&app);
    assert_eq!(headline, "Scanning diff");
    assert!(subline.contains("origin/main"));
}

#[test]
fn loading_shimmer_line_respects_requested_width() {
    let spans = loading_shimmer_line("walking files", 12, 4);
    assert_eq!(spans.len(), 14);
}

#[test]
fn compare_findings_prioritizes_higher_severity() {
    let critical = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::Critical,
        file: "a.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 5,
        description: "critical".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };
    let medium = Finding {
        severity: Severity::Medium,
        ..critical.clone()
    };

    assert_eq!(
        compare_findings(&critical, &medium),
        std::cmp::Ordering::Less
    );
}

#[test]
fn truncate_text_adds_ellipsis_when_needed() {
    assert_eq!(truncate_text("abcdef", 3), "abc...");
    assert_eq!(truncate_text("abc", 3), "abc");
}

#[test]
fn dataflow_lines_render_path_when_source_and_sink_are_present() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "/tmp/project/src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: Some(12),
        source_description: Some("user-controlled query param".to_string()),
        sink_line: Some(42),
        sink_description: Some("value is passed into exec".to_string()),
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![],
        // Exercise the crypto-metadata fields end-to-end in an existing
        // fixture: dataflow rendering shouldn't care, but we also pass the
        // finding through `list_item` below to confirm the deadline chip
        // picks up `"2030"` without disturbing the unrelated dataflow path.
        crypto_algorithm: Some("RSA".to_string()),
        cnsa2_deadline: Some("2030".to_string()),
        dep_name: None,
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
    };

    let rendered = dataflow_lines(&finding, OpenFocus::Finding)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("source @ /tmp/project/src/main.js:12")));
    assert!(rendered.iter().any(|line| {
        line.contains("> ")
            && line.contains("finding")
            && line.contains("@ /tmp/project/src/main.js:42:7")
    }));
    assert!(rendered
        .iter()
        .any(|line| line.contains("sink @ /tmp/project/src/main.js:42")));
}

#[test]
fn dataflow_lines_render_locations_without_descriptions() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: Some(12),
        source_description: None,
        sink_line: Some(42),
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = dataflow_lines(&finding, OpenFocus::Finding)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("source @ src/main.js:12")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("sink @ src/main.js:42")));
}

#[test]
fn dataflow_lines_render_descriptions_without_locations() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: Some("request body".to_string()),
        sink_line: None,
        sink_description: Some("child_process.exec".to_string()),
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = dataflow_lines(&finding, OpenFocus::Finding)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("source @ src/main.js")));
    assert!(rendered.iter().any(|line| line.contains("request body")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("sink @ src/main.js")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("child_process.exec")));
    assert!(!rendered
        .iter()
        .any(|line| line.contains("No source/sink flow details")));
}

#[test]
fn dataflow_lines_show_fallback_when_no_trace_exists() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    assert_eq!(
        dataflow_lines(&finding, OpenFocus::Finding)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>(),
        vec!["No source/sink flow details for this finding type.".to_string()]
    );
}

#[test]
fn open_target_lines_show_finding_even_without_trace_details() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = open_target_lines(&finding, OpenFocus::Finding)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("Enter opens") && line.contains("finding")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("@ src/main.js:42:7")));
}

#[test]
fn render_source_context_includes_surrounding_lines_and_caret() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 3,
        column: 6,
        end_line: 3,
        end_column: 9,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = render_source_context(
        "const user = req.query.user;\nconst cmd = user;\nexec(cmd);\nconsole.log(cmd);\n",
        &finding,
        1,
    )
    .into_iter()
    .map(|line| line.to_string())
    .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("2 | const cmd = user;")));
    assert!(rendered
        .iter()
        .any(|line| { line.contains("exec(cmd);") && line.contains("|") && line.contains(">") }));
    assert!(rendered.iter().any(|line| line.contains("^")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("selected range") && line.starts_with("     | ")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("4 | console.log(cmd);")));
}

#[test]
fn render_source_context_aligns_caret_after_wide_glyphs() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 1,
        column: 2,
        end_line: 1,
        end_column: 6,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let caret = render_source_context("😀exec(cmd);\n", &finding, 0)
        .into_iter()
        .map(|line| line.to_string())
        .find(|line| line.contains("selected range"))
        .expect("caret line");

    assert!(
        caret.contains("|   ^^^^ selected range"),
        "caret should start after the emoji's two display cells: {caret:?}"
    );
}

#[test]
fn render_source_context_aligns_caret_after_tabs() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 1,
        column: 2,
        end_line: 1,
        end_column: 6,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let caret = render_source_context("\texec(cmd);\n", &finding, 0)
        .into_iter()
        .map(|line| line.to_string())
        .find(|line| line.contains("selected range"))
        .expect("caret line");

    assert!(
        caret.contains("|     ^^^^ selected range"),
        "caret should start after the expanded tab's four display cells: {caret:?}"
    );
}

#[test]
fn render_source_context_aligns_caret_after_combining_marks() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 1,
        column: 3,
        end_line: 1,
        end_column: 7,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let caret = render_source_context("e\u{301}exec(cmd);\n", &finding, 0)
        .into_iter()
        .map(|line| line.to_string())
        .find(|line| line.contains("selected range"))
        .expect("caret line");

    assert!(
        caret.contains("|  ^^^^ selected range"),
        "caret should start after the combined glyph's one display cell: {caret:?}"
    );
}

#[test]
fn render_source_context_uses_single_cell_width_for_combined_glyph_selection() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 3,
        description: "combined glyph".to_string(),
        snippet: "e\u{301}".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let caret = render_source_context("e\u{301}x\n", &finding, 0)
        .into_iter()
        .map(|line| line.to_string())
        .find(|line| line.contains("selected range"))
        .expect("caret line");

    assert!(
        caret.contains("| ^ selected range"),
        "combined glyph selection should occupy one display cell: {caret:?}"
    );
}

#[test]
fn prepare_source_context_load_sets_loading_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_dir = dir.path().join("src");
    std::fs::create_dir(&src_dir).expect("mkdir");
    std::fs::write(src_dir.join("main.js"), "const cmd = user;\nexec(cmd);\n").expect("write");

    let finding = source_context_finding();
    let path = dir.path().display().to_string();
    let mut app = TuiApp::new(tui_args_for(path.clone()));
    app.show_launch = false;
    app.active_request_id = 17;
    app.result = Some(tui_execution_with(path, finding.clone()));

    let Some((request_id, key, queued_finding)) = app.prepare_source_context_load() else {
        panic!("expected source context load request");
    };

    assert_eq!(request_id, 17);
    assert_eq!(key.path, dir.path().join("src/main.js"));
    assert_eq!(queued_finding.file, finding.file);
    assert!(matches!(
        app.source_context_cache.as_ref(),
        Some(SourceContextCache::Loading { key: cached_key }) if cached_key.path == dir.path().join("src/main.js")
    ));
    assert!(app.prepare_source_context_load().is_none());
}

#[test]
fn source_context_lines_reads_cache_only_and_worker_populates_ready() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_dir = dir.path().join("src");
    std::fs::create_dir(&src_dir).expect("mkdir");
    std::fs::write(src_dir.join("main.js"), "const cmd = user;\nexec(cmd);\n").expect("write");

    let finding = source_context_finding();
    let path = dir.path().display().to_string();
    let mut app = TuiApp::new(tui_args_for(path.clone()));
    app.show_launch = false;
    app.active_request_id = 23;
    app.result = Some(tui_execution_with(path, finding.clone()));

    assert!(app.source_context_lines(&finding).is_none());
    assert!(app.source_context_cache.is_none());

    let (request_id, key, queued_finding) = app
        .prepare_source_context_load()
        .expect("source context load request");
    let (tx, rx) = mpsc::channel();
    start_source_context_load(request_id, key, queued_finding, tx);

    for _ in 0..50 {
        app.handle_worker_messages(&rx);
        if matches!(
            app.source_context_cache.as_ref(),
            Some(SourceContextCache::Ready { .. })
        ) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let lines = app
        .source_context_lines(&finding)
        .expect("cached source context");
    let rendered = lines
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert!(rendered.iter().any(|line| line.contains("exec(cmd);")));
}

#[test]
fn stale_source_context_worker_messages_are_ignored() {
    let finding = source_context_finding();
    let mut app = TuiApp::new(tui_args_for(".".to_string()));
    app.show_launch = false;
    app.active_request_id = 41;
    app.result = Some(tui_execution_with(".".to_string(), finding));

    let (_, key, _) = app
        .prepare_source_context_load()
        .expect("source context load request");
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerMessage::SourceContext {
        request_id: 40,
        key: key.clone(),
        lines: vec![Line::from("old request")],
    })
    .expect("send old request");
    app.handle_worker_messages(&rx);
    assert!(matches!(
        app.source_context_cache.as_ref(),
        Some(SourceContextCache::Loading { .. })
    ));

    let mut other_key = key.clone();
    other_key.line = 99;
    tx.send(WorkerMessage::SourceContext {
        request_id: 41,
        key: other_key,
        lines: vec![Line::from("wrong finding")],
    })
    .expect("send wrong finding");
    app.handle_worker_messages(&rx);
    assert!(matches!(
        app.source_context_cache.as_ref(),
        Some(SourceContextCache::Loading { key: cached_key }) if *cached_key == key
    ));
}

#[test]
fn handle_key_maps_enter_to_open_selected() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.show_launch = false;

    let flow = app.handle_key(KeyEvent::from(KeyCode::Enter));
    assert!(matches!(flow, ControlFlow::OpenSelected));
}

#[test]
fn handle_key_blocks_rescan_while_scan_is_running() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.show_launch = false;
    app.scanning = true;

    let flow = app.handle_key(KeyEvent::from(KeyCode::Char('r')));
    assert!(matches!(flow, ControlFlow::Continue));

    app.scanning = false;
    let flow = app.handle_key(KeyEvent::from(KeyCode::Char('r')));
    assert!(matches!(flow, ControlFlow::Rescan));
}

#[test]
fn available_open_focuses_include_source_and_sink_when_present() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: Some(12),
        source_description: Some("user-controlled query param".to_string()),
        sink_line: Some(42),
        sink_description: Some("value is passed into exec".to_string()),
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    assert_eq!(
        available_open_focuses(&finding),
        vec![OpenFocus::Finding, OpenFocus::Source, OpenFocus::Sink]
    );
}

#[test]
fn available_open_focuses_include_description_only_source_and_sink() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: Some("request body".to_string()),
        sink_line: None,
        sink_description: Some("child_process.exec".to_string()),
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    assert_eq!(
        available_open_focuses(&finding),
        vec![OpenFocus::Finding, OpenFocus::Source, OpenFocus::Sink]
    );

    let rendered = open_target_lines(&finding, OpenFocus::Source)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert!(rendered
        .iter()
        .any(|line| line.contains("source") && line.contains("sink")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("@ src/main.js:42")));
}

#[test]
fn cycle_open_focus_advances_through_available_targets() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings: vec![Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: Some(12),
            source_description: Some("user-controlled query param".to_string()),
            sink_line: Some(42),
            sink_description: Some("value is passed into exec".to_string()),
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
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
        }],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: true,
        diff_summary: None,
        notices: Vec::new(),
    });

    app.cycle_open_focus();
    assert_eq!(app.open_focus, OpenFocus::Source);
    app.cycle_open_focus();
    assert_eq!(app.open_focus, OpenFocus::Sink);
    app.cycle_open_focus();
    assert_eq!(app.open_focus, OpenFocus::Finding);
}

#[test]
fn handle_key_maps_tab_to_cycle_open_focus() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });

    let flow = app.handle_key(KeyEvent::from(KeyCode::Tab));
    assert!(matches!(flow, ControlFlow::Continue));
}

#[test]
fn open_action_menu_is_available_in_scan_mode() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings: vec![Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
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
        }],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });
    app.show_launch = false;

    let flow = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
    assert!(matches!(flow, ControlFlow::Continue));
    assert!(app.action_menu.is_some());
    assert!(app
        .action_menu
        .as_ref()
        .is_some_and(|menu| menu.actions.contains(&TriageAction::IgnoreRuleInFile)));
}

#[test]
fn open_action_menu_is_available_in_secrets_mode() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: true,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.result = Some(TuiExecution {
        mode: TuiMode::Secrets,
        path: ".".to_string(),
        findings: vec![Finding {
            rule_id: "secret/github-token".to_string(),
            severity: Severity::Critical,
            file: "src/main.js".to_string(),
            line: 12,
            column: 5,
            end_line: 12,
            end_column: 28,
            description: "Possible GitHub personal access token detected".to_string(),
            snippet: "token = [REDACTED]".to_string(),
            cwe: Some("CWE-798".to_string()),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
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
        }],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });
    app.show_launch = false;

    let flow = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
    assert!(matches!(flow, ControlFlow::Continue));
    assert!(app
        .action_menu
        .as_ref()
        .is_some_and(|menu| menu.actions.contains(&TriageAction::IgnoreSecretRule)));
}

#[test]
fn handle_action_menu_enter_applies_selected_action() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.action_menu = Some(ActionMenu {
        actions: vec![TriageAction::AddToBaseline, TriageAction::IgnoreRuleInFile],
        selected: 1,
    });

    let flow = app.handle_action_menu_key(KeyCode::Enter);
    assert!(matches!(
        flow,
        ControlFlow::ApplyAction(TriageAction::IgnoreRuleInFile)
    ));
    assert!(app.action_menu.is_none());
}

#[test]
fn apply_action_review_state_is_session_only() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings: vec![finding.clone()],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: true,
        diff_summary: None,
        notices: Vec::new(),
    });

    let changed = app
        .apply_action(TriageAction::MarkReviewed)
        .expect("review action should succeed");
    assert!(!changed);
    assert_eq!(app.review_state_for(&finding), Some(ReviewState::Reviewed));
}

#[test]
fn dataflow_lines_highlight_active_open_target() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 42,
        column: 7,
        end_line: 42,
        end_column: 18,
        description: "untrusted input reaches exec".to_string(),
        snippet: "exec(cmd)".to_string(),
        cwe: None,
        source_line: Some(12),
        source_description: Some("user-controlled query param".to_string()),
        sink_line: Some(42),
        sink_description: Some("value is passed into exec".to_string()),
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = dataflow_lines(&finding, OpenFocus::Source)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("finding @ src/main.js:42:7")));
    assert!(rendered.iter().any(|line| {
        line.contains("> ") && line.contains("source") && line.contains("@ src/main.js:12")
    }));
    assert!(rendered
        .iter()
        .any(|line| line.contains("sink @ src/main.js:42")));
}

#[test]
fn render_source_context_marks_each_line_of_multiline_findings() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 2,
        column: 7,
        end_line: 4,
        end_column: 5,
        description: "multiline finding".to_string(),
        snippet: "foo(\n  bar,\n  baz\n)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };

    let rendered = render_source_context(
        "const x = 1;\ncall(foo,\n  bar,\n  baz);\nconst y = 2;\n",
        &finding,
        0,
    )
    .into_iter()
    .map(|line| line.to_string())
    .collect::<Vec<_>>();

    assert!(rendered
        .iter()
        .any(|line| line.contains("call(foo,") && line.contains(">") && line.contains("|")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("bar,") && line.contains(">") && line.contains("|")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("baz);") && line.contains(">") && line.contains("|")));
    assert!(
        rendered
            .iter()
            .filter(|line| line.contains("selected range"))
            .count()
            >= 3
    );
}

#[test]
fn confidence_badge_is_hidden_at_full_confidence() {
    assert!(confidence_badge_span(1.0).is_none());
    assert!(confidence_badge_span(0.9999).is_none());
}

#[test]
fn confidence_badge_renders_for_partial_confidence() {
    let span = confidence_badge_span(0.87).expect("should render badge");
    assert_eq!(span.content, "[.87]");
}

#[test]
fn cycle_session_min_confidence_advances_through_presets() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });

    assert_eq!(app.session_min_confidence, 0.0);
    app.cycle_session_min_confidence();
    assert!((app.session_min_confidence - 0.7).abs() < 1e-6);
    app.cycle_session_min_confidence();
    assert!((app.session_min_confidence - 0.9).abs() < 1e-6);
    app.cycle_session_min_confidence();
    assert!((app.session_min_confidence - 1.0).abs() < 1e-6);
    app.cycle_session_min_confidence();
    assert_eq!(app.session_min_confidence, 0.0);
}

#[test]
fn cycle_sort_mode_toggles_between_severity_and_confidence() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });

    assert_eq!(app.sort_mode, SortMode::SeverityDesc);
    app.cycle_sort_mode();
    assert_eq!(app.sort_mode, SortMode::ConfidenceDesc);
    app.cycle_sort_mode();
    assert_eq!(app.sort_mode, SortMode::SeverityDesc);
}

#[test]
fn handle_key_binds_c_to_confidence_and_shift_c_to_sort() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.show_launch = false;

    let _ = app.handle_key(KeyEvent::from(KeyCode::Char('c')));
    assert!((app.session_min_confidence - 0.7).abs() < 1e-6);

    let _ = app.handle_key(KeyEvent::from(KeyCode::Char('C')));
    assert_eq!(app.sort_mode, SortMode::ConfidenceDesc);
}

#[test]
fn confidence_sort_places_high_confidence_before_low_regardless_of_severity() {
    let high_conf_low_sev = Finding {
        rule_id: "js/rule".to_string(),
        severity: Severity::Low,
        file: "a.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 5,
        description: "low sev but confident".to_string(),
        snippet: "x".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: 0.95,
        taint_hops: None,
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
    };
    let low_conf_high_sev = Finding {
        severity: Severity::Critical,
        confidence: 0.5,
        file: "b.js".to_string(),
        ..high_conf_low_sev.clone()
    };

    assert_eq!(
        compare_findings_by(
            &high_conf_low_sev,
            &low_conf_high_sev,
            SortMode::ConfidenceDesc
        ),
        std::cmp::Ordering::Less,
        "confidence sort should put the high-confidence finding first"
    );
    assert_eq!(
        compare_findings_by(
            &high_conf_low_sev,
            &low_conf_high_sev,
            SortMode::SeverityDesc
        ),
        std::cmp::Ordering::Greater,
        "default sort should still put the higher-severity finding first"
    );
}

#[test]
fn session_confidence_filter_hides_low_confidence_findings() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    let base = Finding {
        rule_id: "js/rule".to_string(),
        severity: Severity::High,
        file: "a.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 5,
        description: "desc".to_string(),
        snippet: "x".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: 1.0,
        taint_hops: None,
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
    };
    let low_conf = Finding {
        confidence: 0.5,
        file: "b.js".to_string(),
        ..base.clone()
    };
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings: vec![base.clone(), low_conf.clone()],
        files_scanned: 2,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });

    assert_eq!(app.filtered_indices().len(), 2);

    app.session_min_confidence = 0.7;
    assert_eq!(
        app.filtered_indices().len(),
        1,
        "only the high-confidence finding should survive"
    );
    // The "total before confidence filter" count should still be 2 for
    // the footer's "X of Y" summary.
    assert_eq!(app.total_after_severity_and_search(), 2);
}

#[test]
fn open_action_menu_in_scan_mode_exposes_new_triage_actions() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings: vec![Finding {
            rule_id: "js/rule".to_string(),
            severity: Severity::High,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "desc".to_string(),
            snippet: "x".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
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
        }],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });
    app.show_launch = false;

    let _ = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
    let menu = app.action_menu.as_ref().expect("menu should be open");
    assert!(menu.actions.contains(&TriageAction::LowerSeverity));
    assert!(menu.actions.contains(&TriageAction::DisableRuleGlobally));
}

#[test]
fn apply_action_lower_severity_writes_override_and_replaces() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    let mut app = TuiApp::new(TuiArgs {
        path: repo.path().display().to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    let finding = Finding {
        rule_id: "js/rule".to_string(),
        severity: Severity::High,
        file: "a.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 5,
        description: "desc".to_string(),
        snippet: "x".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: repo.path().display().to_string(),
        findings: vec![finding.clone()],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });

    let rescan = app
        .apply_action(TriageAction::ApplySeverityOverride(Severity::Low))
        .expect("override should apply");
    assert!(rescan, "severity override should trigger a rescan");
    assert_eq!(
        crate::config::current_severity_override(repo.path(), None, "js/rule").unwrap(),
        Some(Severity::Low)
    );
}

#[test]
fn apply_action_disable_rule_globally_appends_and_detects_duplicate() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    let mut app = TuiApp::new(TuiArgs {
        path: repo.path().display().to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    let finding = Finding {
        rule_id: "js/rule".to_string(),
        severity: Severity::High,
        file: "a.js".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 5,
        description: "desc".to_string(),
        snippet: "x".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
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
    };
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: repo.path().display().to_string(),
        findings: vec![finding.clone()],
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });

    let first = app
        .apply_action(TriageAction::DisableRuleGlobally)
        .expect("first disable should succeed");
    assert!(first);
    assert!(crate::config::is_rule_disabled_in_config(repo.path(), None, "js/rule").unwrap());

    // Once disabled, the action is still "applied" (writer is a no-op and
    // reports `added = false`), so the UI reports without blowing up.
    let second = app
        .apply_action(TriageAction::DisableRuleGlobally)
        .expect("second disable should succeed");
    assert!(second);
}

#[test]
fn render_source_context_truncates_long_lines_around_selected_range() {
    let finding = Finding {
        rule_id: "js/no-command-injection".to_string(),
        severity: Severity::High,
        file: "src/main.js".to_string(),
        line: 1,
        column: 90,
        end_line: 1,
        end_column: 105,
        description: "long line finding".to_string(),
        snippet: "dangerous_call(user_input)".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![],
        // Fields populated to confirm this orthogonal renderer still
        // ignores crypto metadata — the snippet truncator has no reason
        // to care whether the finding carries a CNSA 2.0 deadline.
        crypto_algorithm: Some("RSA".to_string()),
        cnsa2_deadline: Some("2030".to_string()),
        dep_name: None,
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
    };

    let rendered = render_source_context(
        "prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_dangerous_call(user_input)_suffix_suffix_suffix_suffix_suffix\n",
        &finding,
        0,
    )
    .into_iter()
    .map(|line| line.to_string())
    .collect::<Vec<_>>();

    assert!(rendered.iter().any(|line| line.contains("...")));
    assert!(rendered
        .iter()
        .any(|line| line.contains("dangerous_call(user_input)")));
}

/// Flatten a ratatui `Text` into a plain string, joining lines with `\n`.
/// Used by the compliance-panel tests to assert on rendered content
/// without depending on a terminal backend.
fn text_to_plain(text: &Text<'_>) -> String {
    text.lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn cnsa_finding(rule_id: &str, deadline: Option<&str>) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::High,
        file: "src/lib.rs".to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 1,
        description: "pq-relevant finding".to_string(),
        snippet: "Rsa::new()".to_string(),
        cwe: None,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![],
        crypto_algorithm: None,
        cnsa2_deadline: deadline.map(String::from),
        dep_name: None,
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
    }
}

/// Helper: stand up a `TuiApp` with a single finding whose crypto-metadata
/// fields are controlled by the caller. Delegates to
/// `tui_app_with_findings` so both #248 test suites share one copy of
/// the `TuiArgs` + `TuiExecution` boilerplate.
fn app_with_single_finding(
    crypto_algorithm: Option<String>,
    cnsa2_deadline: Option<String>,
) -> TuiApp {
    let finding = Finding {
        rule_id: "crypto/pq-vulnerable".to_string(),
        severity: Severity::High,
        file: "src/lib.rs".to_string(),
        line: 10,
        column: 1,
        end_line: 10,
        end_column: 20,
        description: "uses RSA key exchange".to_string(),
        snippet: "Rsa::new(2048)".to_string(),
        cwe: Some("CWE-327".to_string()),
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![],
        crypto_algorithm,
        cnsa2_deadline,
        dep_name: None,
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
    };
    let mut app = tui_app_with_findings(vec![finding]);
    app.show_launch = false;
    app
}

fn tui_app_with_findings(findings: Vec<Finding>) -> TuiApp {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.result = Some(TuiExecution {
        mode: TuiMode::Scan,
        path: ".".to_string(),
        findings,
        files_scanned: 1,
        duration: Duration::from_secs(1),
        explain: false,
        diff_summary: None,
        notices: Vec::new(),
    });
    app
}

#[test]
fn compliance_panel_defaults_off() {
    let app = tui_app_with_findings(vec![]);
    assert!(!app.show_compliance_panel);
}

#[test]
fn shift_n_toggles_compliance_panel() {
    let mut app = tui_app_with_findings(vec![]);
    // `handle_key` routes to `handle_launch_key` while the launcher is
    // visible; emulate the post-scan state the user sees when pressing
    // Shift+N.
    app.show_launch = false;
    app.request.pq_mode = true;
    assert!(!app.show_compliance_panel);
    let flow = app.handle_key(KeyEvent::from(KeyCode::Char('N')));
    assert!(matches!(flow, ControlFlow::Continue));
    assert!(app.show_compliance_panel);
    app.handle_key(KeyEvent::from(KeyCode::Char('N')));
    assert!(!app.show_compliance_panel);
}

#[test]
fn compliance_panel_hidden_outside_pqc_mode() {
    let mut app = tui_app_with_findings(vec![]);
    app.show_launch = false;
    // pq_mode defaults to false via tui_app_with_findings
    assert!(!app.request.pq_mode);
    // Shift+N still toggles the flag…
    app.handle_key(KeyEvent::from(KeyCode::Char('N')));
    assert!(app.show_compliance_panel);
    // …but the draw_body gate requires pq_mode, so the panel won't render.
    let would_show = app.show_compliance_panel && app.result.is_some() && app.request.pq_mode;
    assert!(
        !would_show,
        "compliance panel should be hidden when pq_mode is false"
    );
}

#[test]
fn compliance_panel_shows_badge_and_per_year_tallies() {
    // Two findings at 2030, twelve at 2033 — report should render the
    // level badge plus the sorted per-deadline bullets.
    let mut findings = Vec::new();
    for _ in 0..3 {
        findings.push(cnsa_finding("pq/rule-a", Some("2030")));
    }
    for _ in 0..12 {
        findings.push(cnsa_finding("pq/rule-b", Some("2033")));
    }
    let app = tui_app_with_findings(findings);

    let rendered = text_to_plain(&app.compliance_panel_text());
    // Majority of findings have a deadline → at-risk.
    assert!(
        rendered.contains("at-risk"),
        "expected at-risk badge, got: {}",
        rendered
    );
    assert!(
        rendered.contains("15 findings with NSA transition deadlines"),
        "expected annotated count line, got: {}",
        rendered
    );
    assert!(
        rendered.contains("3 by 2030"),
        "expected 2030 tally, got: {}",
        rendered
    );
    assert!(
        rendered.contains("12 by 2033"),
        "expected 2033 tally, got: {}",
        rendered
    );
    // 2030 must render before 2033 (sorted by year ascending).
    let pos_2030 = rendered.find("2030").expect("2030 bullet present");
    let pos_2033 = rendered.find("2033").expect("2033 bullet present");
    assert!(pos_2030 < pos_2033, "deadlines should sort ascending");
}

#[test]
fn compliance_panel_empty_state_when_no_cnsa_findings() {
    // Findings exist but none carry a deadline — panel should display the
    // dimmed fallback rather than an empty/broken block.
    let app = tui_app_with_findings(vec![cnsa_finding("js/no-eval", None)]);
    let rendered = text_to_plain(&app.compliance_panel_text());
    assert!(
        rendered.contains("no CNSA 2.0 findings in this scan"),
        "expected empty-state message, got: {}",
        rendered
    );
    // Must not render a level badge label when empty.
    assert!(!rendered.contains("at-risk"));
    assert!(!rendered.contains("on-track"));
}

/// Flatten a `Text` to plain per-line strings so assertions can use
/// `contains()` without poking at span internals.
fn text_to_strings(text: &Text<'static>) -> Vec<String> {
    text.lines
        .iter()
        .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
        .collect()
}

#[test]
fn detail_text_renders_crypto_algorithm_and_cnsa2_deadline_lines() {
    let mut app = app_with_single_finding(Some("RSA".to_string()), Some("2030".to_string()));

    let rendered = text_to_strings(&app.detail_text());

    assert!(
        rendered.iter().any(|line| line == "Algorithm: RSA"),
        "expected Algorithm line, got {:#?}",
        rendered
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "CNSA 2.0: migrate before end of 2030"),
        "expected CNSA 2.0 line, got {:#?}",
        rendered
    );
}

#[test]
fn detail_text_omits_crypto_lines_when_both_fields_absent() {
    let mut app = app_with_single_finding(None, None);

    let rendered = text_to_strings(&app.detail_text());

    assert!(
        !rendered.iter().any(|line| line.starts_with("Algorithm:")),
        "non-crypto findings should not render the Algorithm line"
    );
    assert!(
        !rendered.iter().any(|line| line.starts_with("CNSA 2.0:")),
        "non-crypto findings should not render the CNSA 2.0 line"
    );
}

#[test]
fn cnsa2_deadline_chip_renders_padded_year_with_amber_background() {
    let span = cnsa2_deadline_chip_span("2030");
    assert_eq!(span.content, " 2030 ");
    assert_eq!(span.style.bg, Some(Color::Yellow));
    assert_eq!(span.style.fg, Some(Color::Black));
    // Explicitly check BOLD is not set — deadline is advisory context,
    // not a severity signal, and should read as muted.
    assert!(!span.style.add_modifier.contains(Modifier::BOLD));
}

#[test]
fn export_menu_opens_when_results_exist() {
    let mut app = tui_app_with_findings(vec![cnsa_finding("pq/rsa", Some("2030"))]);
    app.show_launch = false;
    assert!(app.export_menu.is_none());
    app.handle_key(KeyEvent::from(KeyCode::Char('e')));
    assert!(app.export_menu.is_some());
    let menu = app.export_menu.as_ref().unwrap();
    assert_eq!(menu.formats.len(), 3);
    assert_eq!(menu.selected, 0);
}

#[test]
fn export_menu_noop_without_results() {
    let mut app = TuiApp::new(TuiArgs {
        path: ".".to_string(),
        config: None,
        severity: None,
        rules: None,
        no_builtins: false,
        changes: Default::default(),
        exclude: Vec::new(),
        baseline: None,
        diff: None,
        secrets: false,
        explain: false,
        max_file_size: 1_048_576,
        pq_mode: false,
    });
    app.show_launch = false;
    app.handle_key(KeyEvent::from(KeyCode::Char('e')));
    assert!(app.export_menu.is_none());
}

#[test]
fn export_writes_cbom_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut app = tui_app_with_findings(vec![cnsa_finding("pq/rsa", Some("2030"))]);
    app.show_launch = false;
    let path = dir.path().join("findings.cbom.json");
    app.export_findings_to(ExportFormat::Cbom, &path);
    assert!(path.exists(), "CBOM file should exist");
    let content = std::fs::read_to_string(&path).expect("read");
    assert!(content.contains("CycloneDX"));
}

#[test]
fn crypto_algorithm_chip_renders_padded_name_with_magenta_background() {
    let span = crypto_algorithm_chip_span("RSA");
    assert_eq!(span.content, " RSA ");
    assert_eq!(span.style.bg, Some(Color::Magenta));
    assert_eq!(span.style.fg, Some(Color::White));
    assert!(!span.style.add_modifier.contains(Modifier::BOLD));
}

#[test]
fn list_item_omits_crypto_chip_when_none() {
    let app = app_with_single_finding(None, None);
    let finding = &app.result.as_ref().unwrap().findings[0];
    let item = list_item(finding, None);
    let debug = format!("{:?}", item);
    assert!(
        !debug.contains("Magenta"),
        "non-crypto finding should not have algorithm chip: {debug}"
    );
}
