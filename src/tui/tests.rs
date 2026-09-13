use super::input::ControlFlow;
use super::state::{
    ActionMenu, ExportFormat, LaunchMode, OpenFocus, SortMode, SourceContextCache, TriageAction,
    TuiApp,
};
use super::widgets::{
    available_open_focuses, cnsa2_deadline_chip_span, compare_findings, compare_findings_by,
    confidence_badge_span, dataflow_lines, finding_list_index_at_position, pop_stashed_event,
    render_source_context, stash_event,
};
use super::{
    open_command_spec_from_editor, open_command_spec_with_environment, resolve_finding_path,
    start_source_context_load, OpenTarget, WorkerMessage,
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

fn install_result(app: &mut TuiApp, result: TuiExecution) {
    app.install_scan_result(result);
}

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
        crypto_material: None,
    }
}

fn tui_execution_with(path: String, finding: Finding) -> TuiExecution {
    TuiExecution {
        baseline_comparison: None,
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

    let command =
        open_command_spec_from_editor(&target, "code --wait").expect("command should build");

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

    let command =
        open_command_spec_from_editor(&target, "Code.exe --wait").expect("command should build");
    assert_eq!(command.program, "Code.exe");
    assert_eq!(
        command.args,
        vec![
            "--wait".to_string(),
            "-g".to_string(),
            "/tmp/project/src/main.rs:27".to_string()
        ]
    );

    let command = open_command_spec_from_editor(&target, "code.cmd").expect("command should build");
    assert_eq!(command.program, "code.cmd");
    assert_eq!(
        command.args,
        vec!["-g".to_string(), "/tmp/project/src/main.rs:27".to_string()]
    );
}

#[test]
fn open_command_spec_preserves_quoted_editor_args() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/file with spaces & punctuation.rs"),
        line: 27,
    };

    let command = open_command_spec_from_editor(
        &target,
        r#""/tmp/editor bin/code" --user-data-dir "/tmp/editor data" --wait"#,
    )
    .expect("command should build");

    assert_eq!(command.program, "/tmp/editor bin/code");
    assert_eq!(
        command.args,
        vec![
            "--user-data-dir".to_string(),
            "/tmp/editor data".to_string(),
            "--wait".to_string(),
            "-g".to_string(),
            "/tmp/project/src/file with spaces & punctuation.rs:27".to_string()
        ]
    );
}

#[test]
fn open_command_spec_uses_vim_line_format() {
    let target = OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 8,
    };

    let command = open_command_spec_from_editor(&target, "nvim").expect("command should build");

    assert_eq!(command.program, "nvim");
    assert_eq!(
        command.args,
        vec!["+8".to_string(), "/tmp/project/src/main.rs".to_string()]
    );
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
        crypto_material: None,
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
        crypto_material: None,
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
        crypto_material: None,
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
        crypto_material: None,
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
        crypto_material: None,
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
fn source_ranges_preserve_graphemes_and_expanded_tabs_inline() {
    for (source, column, end_column, selected) in [
        ("😀exec(cmd);", 2, 6, "exec"),
        ("\texec(cmd);", 2, 6, "exec"),
        ("e\u{301}exec(cmd);", 3, 7, "exec"),
        ("e\u{301}x", 1, 3, "e\u{301}"),
    ] {
        let mut finding = source_context_finding();
        finding.line = 1;
        finding.end_line = 1;
        finding.column = column;
        finding.end_column = end_column;
        let rendered = render_source_context(source, &finding, 0);
        assert_eq!(rendered.len(), 1, "one source row, without annotation rows");
        let highlighted: String = rendered[0]
            .spans
            .iter()
            .filter(|span| {
                span.style
                    .add_modifier
                    .contains(ratatui::style::Modifier::UNDERLINED)
            })
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(highlighted, selected, "{source:?}");
        assert!(rendered[0]
            .to_string()
            .ends_with(&source.replace('\t', "    ")));
    }
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
    install_result(&mut app, tui_execution_with(path, finding.clone()));

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
    install_result(&mut app, tui_execution_with(path, finding.clone()));

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
    install_result(&mut app, tui_execution_with(".".to_string(), finding));

    let (_, key, _) = app
        .prepare_source_context_load()
        .expect("source context load request");
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerMessage::SourceContext {
        request_id: 40,
        key: key.clone(),
        lines: Ok(vec![Line::from("old request")]),
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
        lines: Ok(vec![Line::from("wrong finding")]),
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
        crypto_material: None,
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
        crypto_material: None,
    };

    assert_eq!(
        available_open_focuses(&finding),
        vec![OpenFocus::Finding, OpenFocus::Source, OpenFocus::Sink]
    );
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
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
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
                crypto_material: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: true,
            diff_summary: None,
            notices: Vec::new(),
        },
    );

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
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
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
                crypto_material: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );
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
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
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
                crypto_material: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );
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
        crypto_material: None,
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
        crypto_material: None,
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
    assert_eq!(
        rendered.len(),
        3,
        "multiline ranges must not double source rows"
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
        crypto_material: None,
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
        crypto_material: None,
    };
    let low_conf = Finding {
        confidence: 0.5,
        file: "b.js".to_string(),
        ..base.clone()
    };
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![base.clone(), low_conf.clone()],
            files_scanned: 2,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );

    assert_eq!(app.filtered_indices().len(), 2);

    app.session_min_confidence = 0.7;
    app.clamp_selection();
    assert_eq!(
        app.filtered_indices().len(),
        1,
        "only the high-confidence finding should survive"
    );
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
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
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
                crypto_material: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );
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
        crypto_material: None,
    };
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
            mode: TuiMode::Scan,
            path: repo.path().display().to_string(),
            findings: vec![finding.clone()],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );

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
        crypto_material: None,
    };
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
            mode: TuiMode::Scan,
            path: repo.path().display().to_string(),
            findings: vec![finding.clone()],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );

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
        crypto_material: None,
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
        crypto_material: None,
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
        crypto_material: None,
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
    install_result(
        &mut app,
        TuiExecution {
            baseline_comparison: None,
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings,
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        },
    );
    app
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
    let app = app_with_single_finding(Some("RSA".to_string()), Some("2030".to_string()));

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
    let app = app_with_single_finding(None, None);

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
    app.export_findings_to_with_atomic_write(ExportFormat::Cbom, &path, false);
    assert!(path.exists(), "CBOM file should exist");
    let content = std::fs::read_to_string(&path).expect("read");
    assert!(content.contains("CycloneDX"));
}

#[test]
fn search_punctuation_is_text_and_does_not_open_help() {
    let mut app = TuiApp::new(tui_args_for(".".into()));
    app.show_launch = false;
    app.handle_key(KeyEvent::from(KeyCode::Char('/')));
    app.handle_key(KeyEvent::from(KeyCode::Char('?')));
    assert_eq!(app.search_query, "?");
    assert!(!app.show_help);
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    app.handle_key(KeyEvent::from(KeyCode::Char('?')));
    assert!(app.show_help);
}

#[test]
fn interrupt_exits_from_launch_findings_and_every_modal() {
    use crossterm::event::KeyModifiers;
    for mode in [
        "launch", "findings", "search", "help", "triage", "export", "severity",
    ] {
        let mut app = app_with_single_finding(None, None);
        app.show_launch = mode == "launch";
        match mode {
            "search" => app.search_mode = true,
            "help" => app.show_help = true,
            "triage" => {
                app.action_menu = Some(ActionMenu {
                    actions: vec![TriageAction::AddToBaseline],
                    selected: 0,
                });
            }
            "export" => {
                app.open_export_menu();
                assert!(app.export_menu.is_some());
            }
            "severity" => {
                app.open_severity_picker();
                assert!(app.severity_picker.is_some());
            }
            _ => {}
        }
        assert!(
            matches!(
                app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
                ControlFlow::Exit
            ),
            "{mode}"
        );
    }
}

#[test]
fn finding_home_and_end_respect_filtered_selection() {
    let mut app = app_with_single_finding(None, None);
    app.show_launch = false;
    let mut second = app.result.as_ref().unwrap().findings[0].clone();
    second.line += 1;
    app.result.as_mut().unwrap().findings.push(second);
    app.clamp_selection();
    app.handle_key(KeyEvent::from(KeyCode::End));
    assert_eq!(app.selected, 1);
    app.handle_key(KeyEvent::from(KeyCode::Home));
    assert_eq!(app.selected, 0);
    app.search_query = "no-such-finding-unique".into();
    app.clamp_selection();
    app.handle_key(KeyEvent::from(KeyCode::End));
    app.handle_key(KeyEvent::from(KeyCode::Home));
    assert_eq!(app.selected, 0);
    assert!(app.filtered_indices().is_empty());
}

#[test]
fn diff_target_accepts_letters_and_digits_reserved_by_navigation() {
    let mut app = TuiApp::new(tui_args_for(".".into()));
    app.launch_mode = LaunchMode::Diff;
    app.launch_diff_target.clear();
    for ch in "fix/jkq1234".chars() {
        assert!(matches!(
            app.handle_key(KeyEvent::from(KeyCode::Char(ch))),
            ControlFlow::Continue
        ));
    }
    assert_eq!(app.launch_diff_target, "fix/jkq1234");
    assert_eq!(app.launch_mode, LaunchMode::Diff);
}

fn render_app(app: &mut TuiApp, width: u16, height: u16) -> String {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn launch_keeps_every_mode_path_and_exit_visible_at_responsive_boundaries() {
    for (width, height) in [(100, 30), (60, 18), (40, 12)] {
        let mut app = TuiApp::new(tui_args_for(
            "/workspace/project/tests/fixtures/vulnerable.py".into(),
        ));
        let screen = render_app(&mut app, width, height);
        for required in [
            "Scan",
            "Diff",
            "Secrets",
            "PQC",
            "Path:",
            "vulnerable.py",
            "Enter",
            "quit",
        ] {
            assert!(
                screen.contains(required),
                "{width}x{height} hides {required}:\n{screen}"
            );
        }
    }
}

#[test]
fn narrow_detail_keeps_dataflow_and_fix_reachable_and_escape_returns_to_list() {
    let mut app = app_with_single_finding(None, None);
    let finding = &mut app.result.as_mut().unwrap().findings[0];
    finding.source_line = Some(1);
    finding.source_description = Some("untrusted source".into());
    finding.sink_line = Some(10);
    finding.sink_description = Some("dangerous sink".into());
    finding.fix_suggestion = Some("use_safe_api".into());
    let selected = app.selected_finding().unwrap().rule_id.clone();
    app.handle_key(KeyEvent::from(KeyCode::Char('v')));
    let mut pages = render_app(&mut app, 40, 12);
    for _ in 0..10 {
        app.handle_key(KeyEvent::from(KeyCode::PageDown));
        pages.push_str(&render_app(&mut app, 40, 12));
    }
    assert!(pages.contains("Dataflow"), "{pages}");
    assert!(pages.contains("use_safe_api"), "{pages}");
    assert!(render_app(&mut app, 40, 12).contains("use_safe_api"));
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(render_app(&mut app, 40, 12).contains("1/1"));
    assert_eq!(app.selected_finding().unwrap().rule_id, selected);
}

#[test]
fn editing_search_preserves_literal_u_and_cancellation_restores_applied_query() {
    use crossterm::event::KeyModifiers;
    let mut app = app_with_single_finding(None, None);
    app.handle_key(KeyEvent::from(KeyCode::Char('/')));
    for ch in "uses".chars() {
        app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
    }
    assert_eq!(app.filtered_indices().len(), 1);
    app.handle_key(KeyEvent::from(KeyCode::Enter));
    app.handle_key(KeyEvent::from(KeyCode::Char('/')));
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    for ch in "unmatched".chars() {
        app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
    }
    assert!(render_app(&mut app, 60, 18).contains("/unmatched"));
    assert!(app.filtered_indices().is_empty());
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(app.search_query, "uses");
    assert_eq!(
        app.selected_finding().unwrap().rule_id,
        "crypto/pq-vulnerable"
    );
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    assert!(!app.has_active_filter());
    review_keys(
        &mut app,
        [KeyCode::Char('/'), KeyCode::Char('z'), KeyCode::Esc],
    );
    assert!(app.search_query.is_empty());
    assert!(!app.has_active_filter());
}

#[test]
fn review_queue_advances_identity_and_rejects_previous_source_context() {
    let mut app = app_with_single_finding(None, None);
    let mut second = app.selected_finding().unwrap().clone();
    second.file = "other.rs".into();
    second.rule_id = "other/rule".into();
    second.severity = Severity::Low;
    app.result.as_mut().unwrap().findings.push(second);
    app.clamp_selection();
    app.handle_key(KeyEvent::from(KeyCode::Char('f')));
    let (request_id, old_key, _) = app.prepare_source_context_load().unwrap();
    app.apply_action(TriageAction::MarkReviewed).unwrap();
    assert_eq!(app.selected_finding().unwrap().rule_id, "other/rule");
    assert!(render_app(&mut app, 60, 18).contains("1/2"));
    let (_, new_key, _) = app.prepare_source_context_load().unwrap();
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerMessage::SourceContext {
        request_id,
        key: old_key,
        lines: Ok(vec![Line::from("stale source")]),
    })
    .unwrap();
    tx.send(WorkerMessage::SourceContext {
        request_id,
        key: new_key,
        lines: Ok(vec![Line::from("current source")]),
    })
    .unwrap();
    app.handle_worker_messages(&rx);
    let detail = text_to_strings(&app.detail_text()).join("\n");
    assert!(detail.contains("current source"));
    assert!(!detail.contains("stale source"));
    app.handle_key(KeyEvent::from(KeyCode::Char('f'))); // Todo
    assert!(app.selected_finding().is_none());
    app.handle_key(KeyEvent::from(KeyCode::Char('f'))); // Reviewed
    assert_eq!(
        app.selected_finding().unwrap().rule_id,
        "crypto/pq-vulnerable"
    );
    app.handle_key(KeyEvent::from(KeyCode::Char('f'))); // Ignore
    assert!(app.selected_finding().is_none());
    app.handle_key(KeyEvent::from(KeyCode::Char('f'))); // All
    assert_eq!(app.filtered_indices().len(), 2);
}

#[test]
fn sort_changes_preserve_the_finding_not_its_previous_row() {
    let mut app = app_with_single_finding(None, None);
    app.result.as_mut().unwrap().findings[0].confidence = 0.3;
    let mut second = app.selected_finding().unwrap().clone();
    second.rule_id = "other/rule".into();
    second.severity = Severity::Low;
    second.confidence = 0.95;
    app.result.as_mut().unwrap().findings.push(second);
    app.clamp_selection();
    app.handle_key(KeyEvent::from(KeyCode::Char('j')));
    app.handle_key(KeyEvent::from(KeyCode::Char('C')));
    assert_eq!(app.selected_finding().unwrap().rule_id, "other/rule");
    app.handle_key(KeyEvent::from(KeyCode::Char('3')));
    assert_eq!(
        app.selected_finding().unwrap().rule_id,
        "crypto/pq-vulnerable"
    );
}

#[test]
fn export_requires_explicit_confirmation_and_cancellation_preserves_report() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.json");
    std::fs::write(&path, "previous report").unwrap();
    let mut app = app_with_single_finding(None, None);
    app.export_with_overwrite_check(ExportFormat::Json, path.clone());
    assert!(render_app(&mut app, 40, 12).contains("Confirm overwrite"));
    app.handle_key(KeyEvent::from(KeyCode::Enter));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous report");
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous report");
    app.export_with_overwrite_check(ExportFormat::Json, path.clone());
    app.handle_key(KeyEvent::from(KeyCode::Char('y')));
    let report: Vec<Finding> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(report[0].rule_id, "crypto/pq-vulnerable");
}

#[cfg(unix)]
#[test]
fn export_rejects_dangling_symlinks_and_rechecks_after_confirmation() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("unrelated.json");
    let path = dir.path().join("findings.json");
    std::fs::write(&target, "unrelated report").unwrap();
    std::fs::write(&path, "previous report").unwrap();
    let mut app = app_with_single_finding(None, None);
    app.export_with_overwrite_check(ExportFormat::Json, path.clone());
    std::fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();
    app.handle_key(KeyEvent::from(KeyCode::Char('y')));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "unrelated report"
    );
    assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
    std::fs::remove_file(&target).unwrap();
    app.export_with_overwrite_check(ExportFormat::Json, path.clone());
    assert!(!target.exists());
    assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(app.export_menu.is_none());
}

#[test]
fn newest_notice_is_visible_in_a_small_review_view() {
    let mut app = app_with_single_finding(None, None);
    for index in 0..10 {
        app.push_runtime_notice(format!("earlier notification {index}"));
    }
    app.push_runtime_notice("latest notification".into());
    assert!(render_app(&mut app, 40, 12).contains("latest notification"));
}

fn review_keys(app: &mut TuiApp, keys: impl IntoIterator<Item = KeyCode>) {
    for key in keys {
        match app.handle_key(KeyEvent::from(key)) {
            ControlFlow::Continue => {}
            ControlFlow::ApplyBatch => {
                app.apply_batch().unwrap();
            }
            _ => panic!("unexpected control flow while reviewing"),
        }
    }
}

#[test]
fn batch_confirmation_preserves_hidden_targets_without_retargeting_the_queue() {
    let findings = ["alpha.js", "beta.js", "gamma.js"].map(|file| {
        let mut finding = source_context_finding();
        finding.file = file.into();
        finding
    });
    let mut app = tui_app_with_findings(findings.to_vec());
    app.show_launch = false;
    review_keys(
        &mut app,
        [KeyCode::Char(' '), KeyCode::Down, KeyCode::Char(' ')],
    );
    app.search_query = "gamma.js".into();
    app.clamp_selection();
    review_keys(
        &mut app,
        [
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Enter,
            KeyCode::Esc,
        ],
    );
    app.search_query.clear();
    app.review_filter = super::state::ReviewFilter::Reviewed;
    app.clamp_selection();
    assert!(
        app.filtered_indices().is_empty(),
        "Enter and cancellation must not mark anything"
    );

    app.review_filter = super::state::ReviewFilter::Unreviewed;
    app.search_query = "gamma.js".into();
    app.clamp_selection();
    review_keys(
        &mut app,
        [KeyCode::Char('x'), KeyCode::Enter, KeyCode::Char('y')],
    );
    app.search_query.clear();
    app.review_filter = super::state::ReviewFilter::Reviewed;
    app.clamp_selection();
    assert_eq!(app.filtered_indices(), &[0, 1]);
    app.review_filter = super::state::ReviewFilter::Unreviewed;
    app.clamp_selection();
    assert_eq!(app.filtered_indices(), &[2]);
}

#[test]
fn batch_rejects_replaced_findings_even_when_result_indices_are_reused() {
    let mut app = tui_app_with_findings(vec![source_context_finding()]);
    app.show_launch = false;
    review_keys(
        &mut app,
        [KeyCode::Char('a'), KeyCode::Char('x'), KeyCode::Enter],
    );
    let mut replacement = source_context_finding();
    replacement.file = "different.js".into();
    install_result(&mut app, tui_execution_with(".".into(), replacement));
    assert!(app.apply_batch().is_err());
    app.review_filter = super::state::ReviewFilter::Reviewed;
    app.clamp_selection();
    assert!(app.filtered_indices().is_empty());
    app.review_filter = super::state::ReviewFilter::Unreviewed;
    app.clamp_selection();
    assert_eq!(app.selected_finding().unwrap().file, "different.js");
}

#[test]
fn named_review_queue_survives_restart_through_a_project_path_alias() {
    let project = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let findings: Vec<_> = [
        ("tracked/alpha.js", "alpha", Severity::High, 0.9),
        ("tracked/low-confidence.js", "alpha", Severity::High, 0.5),
        ("tracked/beta.js", "beta", Severity::High, 0.9),
        ("tracked/low-severity.js", "alpha", Severity::Low, 0.9),
        ("pending/alpha.js", "alpha", Severity::High, 0.9),
    ]
    .into_iter()
    .map(|(file, description, severity, confidence)| {
        let mut finding = source_context_finding();
        finding.file = project.path().join(file).to_string_lossy().into_owned();
        finding.description = description.into();
        finding.severity = severity;
        finding.confidence = confidence;
        finding
    })
    .collect();
    let open = |path: String| {
        let mut app = TuiApp::new(tui_args_for(path.clone()));
        app.session_root = Some(storage.path().to_path_buf());
        app.activate_review_session();
        let mut result = tui_execution_with(path, findings[0].clone());
        result.findings = findings.clone();
        install_result(&mut app, result);
        app.show_launch = false;
        app
    };
    let mut first = open(project.path().to_string_lossy().into_owned());
    first.search_query = "tracked/".into();
    first.clamp_selection();
    review_keys(
        &mut first,
        [
            KeyCode::Char('a'),
            KeyCode::Char('x'),
            KeyCode::Enter,
            KeyCode::Char('y'),
        ],
    );
    first.search_query = "alpha".into();
    first.min_severity = Some(Severity::High);
    first.session_min_confidence = 0.7;
    first.review_filter = super::state::ReviewFilter::Reviewed;
    first.clamp_selection();
    assert_eq!(first.filtered_indices(), &[0]);
    review_keys(
        &mut first,
        [KeyCode::Char('F'), KeyCode::Char('s')]
            .into_iter()
            .chain("alpha queue".chars().map(KeyCode::Char))
            .chain([KeyCode::Enter, KeyCode::Esc]),
    );
    drop(first);

    let mut reopened = open(project.path().join(".").to_string_lossy().into_owned());
    review_keys(&mut reopened, [KeyCode::Char('F'), KeyCode::Enter]);
    assert_eq!(reopened.filtered_indices(), &[0]);
    assert_eq!(reopened.selected_finding().unwrap().file, findings[0].file);
    reopened.review_filter = super::state::ReviewFilter::Unreviewed;
    reopened.clamp_selection();
    assert_eq!(reopened.filtered_indices(), &[4]);
}

#[test]
fn batch_config_partial_failure_preserves_success_and_failed_selection() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().to_string_lossy().into_owned();
    let config = project.path().join(".foxguard.yml");
    let mut args = tui_args_for(path.clone());
    args.config = Some(config.to_string_lossy().into_owned());
    let mut app = TuiApp::new(args);
    let mut first = source_context_finding();
    first.file = project.path().join("a.js").to_string_lossy().into_owned();
    let mut second = first.clone();
    second.file = project.path().join("b.js").to_string_lossy().into_owned();
    let mut result = tui_execution_with(path, first.clone());
    result.findings.push(second);
    install_result(&mut app, result);
    app.show_launch = false;
    // A config edited after scanning can fail for one rule/file pair only.
    std::fs::write(
        &config,
        "scan:\n  ignore_rules:\n    - path: b.js\n      rules: invalid\n",
    )
    .unwrap();
    review_keys(&mut app, [KeyCode::Char('a'), KeyCode::Char('x')]);
    review_keys(&mut app, std::iter::repeat_n(KeyCode::Down, 5));
    review_keys(&mut app, [KeyCode::Enter, KeyCode::Char('y')]);

    let saved: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    let ignores = saved["scan"]["ignore_rules"].as_sequence().unwrap();
    assert!(ignores
        .iter()
        .any(|entry| entry["path"].as_str() == Some("a.js")
            && entry["rules"].as_sequence().is_some_and(|rules| rules
                .iter()
                .any(|rule| rule.as_str() == Some(first.rule_id.as_str())))));
    assert!(ignores
        .iter()
        .any(|entry| entry["path"].as_str() == Some("b.js")
            && entry["rules"].as_str() == Some("invalid")));
    app.search_query = "b.js".into();
    app.clamp_selection();
    assert!(render_app(&mut app, 100, 30).contains("[x]"));
    app.search_query = "a.js".into();
    app.clamp_selection();
    assert!(!render_app(&mut app, 100, 30).contains("[x]"));
}

#[test]
fn resolved_entries_remain_read_only_and_reachable_in_a_narrow_terminal() {
    let mut result = tui_execution_with(".".into(), source_context_finding());
    result.baseline_comparison = Some(crate::baseline::BaselineComparison {
        introduced: vec![0],
        recurring: Vec::new(),
        resolved: (0..8)
            .map(|index| crate::baseline::BaselineEntry {
                fingerprint: format!("{index:064x}"),
                rule_id: format!("historical/rule-{index}"),
                file: format!("retired-{index}.js"),
                line: index + 1,
            })
            .collect(),
    });
    let mut app = TuiApp::new(tui_args_for(".".into()));
    install_result(&mut app, result);
    app.show_launch = false;
    app.set_baseline_filter(super::state::BaselineFilter::Resolved);
    review_keys(&mut app, [KeyCode::End]);
    assert!(render_app(&mut app, 40, 12).contains("retired-7.js:8"));
    review_keys(
        &mut app,
        [
            KeyCode::Char(' '),
            KeyCode::Char('a'),
            KeyCode::Char('x'),
            KeyCode::Char('i'),
            KeyCode::Char('e'),
        ],
    );
    assert!(app.selected_finding().is_none());
    assert!(app.batch_menu.is_none());
    assert!(app.action_menu.is_none());
    assert!(app.export_menu.is_none());
    app.show_notices = false;
    review_keys(&mut app, [KeyCode::Char('v')]);
    assert!(render_app(&mut app, 40, 12).contains("retired-7.js"));
    review_keys(&mut app, [KeyCode::PageDown]);
    assert!(!render_app(&mut app, 40, 12).contains("retired-7.js"));
    review_keys(&mut app, [KeyCode::PageUp]);
    assert!(render_app(&mut app, 40, 12).contains("retired-7.js"));
}

#[test]
fn enter_release_and_repeat_do_not_dispatch_actions() {
    let mut app = app_with_single_finding(None, None);
    for kind in [
        crossterm::event::KeyEventKind::Release,
        crossterm::event::KeyEventKind::Repeat,
    ] {
        let mut key = KeyEvent::from(KeyCode::Enter);
        key.kind = kind;
        assert!(matches!(app.handle_key(key), ControlFlow::Continue));
    }
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::OpenSelected
    ));
}

#[test]
fn repeat_events_preserve_navigation_and_search_input() {
    let mut app = app_with_single_finding(None, None);
    let mut second = app.selected_finding().unwrap().clone();
    second.file = "other.rs".into();
    second.rule_id = "other/rule".into();
    app.result.as_mut().unwrap().findings.push(second);
    app.clamp_selection();
    for (code, selected) in [(KeyCode::Down, 1), (KeyCode::Char('k'), 0)] {
        let mut key = KeyEvent::from(code);
        key.kind = crossterm::event::KeyEventKind::Repeat;
        assert!(matches!(app.handle_key(key), ControlFlow::Continue));
        assert_eq!(app.selected, selected);
    }
    app.handle_key(KeyEvent::from(KeyCode::Char('/')));
    for _ in 0..3 {
        let mut key = KeyEvent::from(KeyCode::Char('e'));
        key.kind = crossterm::event::KeyEventKind::Repeat;
        assert!(matches!(app.handle_key(key), ControlFlow::Continue));
    }
    assert_eq!(app.search_query, "eee");
}

#[test]
fn enter_is_consumed_by_help_and_triage_dialogs() {
    let mut app = app_with_single_finding(None, None);
    app.handle_key(KeyEvent::from(KeyCode::Char('?')));
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::Continue
    ));
    assert!(app.show_help);
    app.handle_key(KeyEvent::from(KeyCode::Esc));
    app.handle_key(KeyEvent::from(KeyCode::Char('i')));
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::ApplyAction(_)
    ));
    app.open_severity_picker();
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::ApplyAction(TriageAction::ApplySeverityOverride(_))
    ));
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::OpenSelected
    ));
}

#[test]
fn enter_waits_for_scan_completion_before_opening_findings() {
    let mut app = TuiApp::new(tui_args_for(".".into()));
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::Rescan
    ));
    app.begin_scan();
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::Continue
    ));
    install_result(
        &mut app,
        tui_execution_with(".".into(), source_context_finding()),
    );
    app.scanning = false;
    assert!(matches!(
        app.handle_key(KeyEvent::from(KeyCode::Enter)),
        ControlFlow::OpenSelected
    ));
}

fn finding_target() -> OpenTarget {
    OpenTarget {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        line: 27,
    }
}

#[test]
fn editor_configuration_precedes_fallback_and_ignores_blank_visual() {
    let target = finding_target();
    let selected = open_command_spec_with_environment(
        &target,
        Some("hx"),
        Some("code --wait"),
        Some("xdg-open"),
        |_| true,
    )
    .unwrap();
    assert_eq!(selected.program, "hx");
    let selected = open_command_spec_with_environment(
        &target,
        Some(" \t"),
        Some("code --wait"),
        Some("xdg-open"),
        |_| true,
    )
    .unwrap();
    assert_eq!(selected.program, "code");
}

#[test]
fn invalid_explicit_editors_never_fall_back_or_expose_arguments() {
    let target = finding_target();
    for (visual, editor, variable) in [
        (
            Some("missing --token sensitive-value"),
            Some("vim"),
            "VISUAL",
        ),
        (None, Some("missing --token sensitive-value"), "EDITOR"),
        (Some("hx --token 'sensitive-value"), Some("vim"), "VISUAL"),
        (Some("''"), Some("vim"), "VISUAL"),
    ] {
        let error = open_command_spec_with_environment(
            &target,
            visual,
            editor,
            Some("xdg-open"),
            |program| matches!(program, "nvim" | "vim" | "xdg-open"),
        )
        .err()
        .expect("invalid editor selection must fail");
        assert!(error.contains(variable));
        assert!(!error.contains("sensitive-value"));
    }
}

#[test]
fn terminal_editor_priority_precedes_desktop_fallback() {
    let target = finding_target();
    for (available, expected) in [
        (&["nvim", "vim", "xdg-open"][..], "nvim"),
        (&["vi", "xdg-open"][..], "vi"),
    ] {
        let selected =
            open_command_spec_with_environment(&target, None, None, Some("xdg-open"), |program| {
                available.contains(&program)
            })
            .unwrap();
        assert_eq!(selected.program, expected);
        assert_eq!(selected.args, ["+27", "/tmp/project/src/main.rs"]);
    }
}

#[test]
fn desktop_fallback_requires_permission_and_an_available_opener() {
    let target = finding_target();
    let selected =
        open_command_spec_with_environment(&target, None, None, Some("xdg-open"), |program| {
            program == "xdg-open"
        })
        .unwrap();
    assert_eq!(selected.program, "xdg-open");
    assert_eq!(selected.args, ["/tmp/project/src/main.rs"]);
    for desktop in [None, Some("xdg-open")] {
        let error = open_command_spec_with_environment(&target, None, None, desktop, |program| {
            matches!(program, "open" | "notepad")
        })
        .err()
        .expect("invalid editor selection must fail");
        assert!(error.contains("VISUAL"));
        assert!(error.contains("EDITOR"));
    }
}

#[test]
fn helix_receives_the_line_as_part_of_the_filename_argument() {
    let selected = open_command_spec_from_editor(&finding_target(), "hx").unwrap();
    assert_eq!(selected.args, ["/tmp/project/src/main.rs:27"]);
}

#[cfg(unix)]
#[test]
fn executable_probe_requires_a_regular_executable_file() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("editor");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!super::executable_available(
        directory.path().to_str().unwrap()
    ));
    assert!(!super::executable_available(path.to_str().unwrap()));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(super::executable_available(path.to_str().unwrap()));
}

#[test]
fn notice_scrolling_reaches_wrapped_tail_and_returns_to_start() {
    let mut app = app_with_single_finding(None, None);
    // This fits the outer panel width but wraps after horizontal padding.
    app.push_runtime_notice(format!("{} XYZ", "x".repeat(95)));
    let _ = render_app(&mut app, 100, 30);
    app.handle_key(KeyEvent::from(KeyCode::Char(']')));
    assert!(render_app(&mut app, 100, 30).contains("XYZ"));
    for _ in 0..10 {
        app.handle_key(KeyEvent::from(KeyCode::Char(']')));
    }
    assert!(render_app(&mut app, 100, 30).contains("XYZ"));
    app.handle_key(KeyEvent::from(KeyCode::Char('[')));
    assert!(render_app(&mut app, 100, 30).contains("xxxxxxxx"));
}

#[test]
fn unavailable_source_keeps_the_saved_finding_snippet() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().display().to_string();
    let finding = source_context_finding();
    let mut app = TuiApp::new(tui_args_for(path.clone()));
    install_result(&mut app, tui_execution_with(path, finding.clone()));
    let (request_id, key, queued) = app.prepare_source_context_load().unwrap();
    let (tx, rx) = mpsc::channel();
    start_source_context_load(request_id, key, queued, tx.clone());
    let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    tx.send(result).unwrap();
    app.handle_worker_messages(&rx);
    assert!(app.source_context_lines(&finding).is_none());
    assert!(text_to_plain(&app.detail_text()).contains(&finding.snippet));
    assert_eq!(app.notice_count(), 1);
}

#[test]
fn compact_detail_keeps_location_suffix_and_opening_controls_while_scrolling() {
    let mut finding = source_context_finding();
    finding.file = "a/very/long/directory/that/does/not/fit/in/a/compact/pane/main.js".into();
    finding.line = 1234;
    finding.column = 56;
    finding.description = "Long explanation ".repeat(40);
    let mut app = tui_app_with_findings(vec![finding]);
    app.show_launch = false;
    app.show_detail_view = true;
    let initial = render_app(&mut app, 40, 12);
    assert!(initial.contains("main.js:1234:56"));
    app.handle_key(KeyEvent::from(KeyCode::PageDown));
    let scrolled = render_app(&mut app, 40, 12);
    assert!(scrolled.contains("main.js:1234:56"));
    assert!(scrolled.contains("Enter"));
    assert_ne!(initial, scrolled);
}
