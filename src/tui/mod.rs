mod baseline_view;
mod input;
mod loading;
mod persist;
mod review;
mod state;
#[cfg(test)]
mod tests;
mod views;
mod widgets;

use self::input::ControlFlow;
use self::state::{SourceContextCacheKey, TuiApp};
use self::widgets::{has_stashed_event, pop_stashed_event_or_read, render_source_context};
use crate::app::{execute_tui, TuiExecution};
use crate::cli::TuiArgs;
use crate::Finding;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::text::Line;
use ratatui::Terminal;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

pub fn run_scan_tui(args: &TuiArgs) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("foxguard tui requires an interactive terminal".to_string());
    }

    let mut session = TerminalSession::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = TuiApp::new(args.clone());
    match persist::state_directory() {
        Ok(root) => app.session_root = Some(root),
        Err(error) => app.session_error = Some(error),
    }
    let mut redraw = true;

    loop {
        redraw |= app.handle_worker_messages(&rx);
        if let Some((request_id, key, finding)) = app.prepare_source_context_load() {
            start_source_context_load(request_id, key, finding, tx.clone());
            redraw = true;
        }

        if redraw || app.scanning {
            session
                .terminal
                .draw(|frame| app.draw(frame))
                .map_err(|e| e.to_string())?;
            redraw = false;
        }

        if has_stashed_event()
            || event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())?
        {
            let ev = pop_stashed_event_or_read().map_err(|e| e.to_string())?;
            redraw = true;

            if let Event::Mouse(mouse) = ev {
                if app.can_handle_finding_mouse() {
                    app.handle_mouse(mouse);
                }
                continue;
            }

            let Event::Key(key) = ev else {
                continue;
            };

            if key.kind != KeyEventKind::Press {
                continue;
            }

            match app.handle_key(key) {
                ControlFlow::Continue => {}
                ControlFlow::Rescan => {
                    let request_id = app.begin_scan();
                    start_tui_execution(request_id, app.request.clone(), tx.clone())
                }
                ControlFlow::OpenSelected => {
                    if let Err(error) = app.open_selected_finding(&mut session) {
                        app.push_runtime_notice(format!("open failed: {}", error));
                    }
                }
                ControlFlow::ApplyAction(action) => match app.apply_action(action) {
                    Ok(true) => {
                        let notices = std::mem::take(&mut app.runtime_notices);
                        let request_id = app.begin_scan();
                        app.runtime_notices.extend(notices);
                        start_tui_execution(request_id, app.request.clone(), tx.clone())
                    }
                    Ok(false) => {}
                    Err(error) => app.push_runtime_notice(format!("action failed: {}", error)),
                },
                ControlFlow::ApplyBatch => match app.apply_batch() {
                    Ok(true) => {
                        let notices = std::mem::take(&mut app.runtime_notices);
                        let request_id = app.begin_scan();
                        app.runtime_notices.extend(notices);
                        start_tui_execution(request_id, app.request.clone(), tx.clone())
                    }
                    Ok(false) => {}
                    Err(error) => app.push_runtime_notice(format!("batch failed: {error}")),
                },
                ControlFlow::Exit => break,
            }
        }

        if app.scanning {
            app.advance_spinner();
        }
    }

    if let Some(error) = app.error.take() {
        return Err(error);
    }

    let finding_count = app
        .result
        .as_ref()
        .map(|result| result.findings.len())
        .unwrap_or(0);
    Ok(if finding_count > 0 { 1 } else { 0 })
}

enum WorkerMessage {
    Scan {
        request_id: u64,
        result: Result<TuiExecution, String>,
    },
    SourceContext {
        request_id: u64,
        key: SourceContextCacheKey,
        lines: Result<Vec<Line<'static>>, String>,
    },
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalSession {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
            rollback_terminal_setup();
            return Err(error.to_string());
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                rollback_terminal_setup();
                return Err(error.to_string());
            }
        };
        Ok(Self {
            terminal,
            active: true,
        })
    }

    fn suspend(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }

        disable_raw_mode().map_err(|e| e.to_string())?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )
        .map_err(|e| e.to_string())?;
        self.terminal.show_cursor().map_err(|e| e.to_string())?;
        self.active = false;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), String> {
        if self.active {
            return Ok(());
        }

        enable_raw_mode().map_err(|e| e.to_string())?;
        execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            EnableMouseCapture
        )
        .map_err(|error| {
            rollback_terminal_setup();
            error.to_string()
        })?;
        self.terminal.clear().map_err(|error| {
            rollback_terminal_setup();
            error.to_string()
        })?;
        self.active = true;
        Ok(())
    }
}

fn rollback_terminal_setup() {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
    let _ = disable_raw_mode();
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

fn start_tui_execution(request_id: u64, args: TuiArgs, tx: Sender<WorkerMessage>) {
    std::thread::spawn(move || {
        let _ = tx.send(WorkerMessage::Scan {
            request_id,
            result: execute_tui(&args),
        });
    });
}

fn start_source_context_load(
    request_id: u64,
    key: SourceContextCacheKey,
    finding: Finding,
    tx: Sender<WorkerMessage>,
) {
    std::thread::spawn(move || {
        let lines = fs::read_to_string(&key.path)
            .map_err(|error| format!("Unable to load source context: {error}"))
            .and_then(|source| {
                let lines = render_source_context(&source, &finding, 2);
                if source.is_empty() || lines.is_empty() {
                    Err("Finding location is outside the current source file".to_string())
                } else {
                    Ok(lines)
                }
            });

        let _ = tx.send(WorkerMessage::SourceContext {
            request_id,
            key,
            lines,
        });
    });
}

struct OpenTarget {
    path: PathBuf,
    line: usize,
}

struct CommandSpec {
    program: String,
    args: Vec<String>,
}

fn open_command_spec(target: &OpenTarget) -> Result<CommandSpec, String> {
    let visual = std::env::var("VISUAL").ok();
    let editor = std::env::var("EDITOR").ok();
    let nonblank_env = |name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty());
    let ssh = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .into_iter()
        .any(nonblank_env);
    let desktop = if cfg!(target_os = "linux")
        && (nonblank_env("DISPLAY") || nonblank_env("WAYLAND_DISPLAY"))
    {
        Some("xdg-open")
    } else if cfg!(target_os = "macos") && !ssh {
        Some("open")
    } else if cfg!(target_os = "windows") && !ssh {
        Some("notepad")
    } else {
        None
    };
    open_command_spec_with_environment(
        target,
        visual.as_deref(),
        editor.as_deref(),
        desktop,
        executable_available,
    )
}

fn open_command_spec_from_editor(target: &OpenTarget, editor: &str) -> Result<CommandSpec, String> {
    let mut parts =
        shlex::split(editor).ok_or_else(|| "invalid quoting in editor command".to_string())?;
    if parts.is_empty() || parts[0].is_empty() {
        return Err("editor command has no program".to_string());
    }

    let program = parts.remove(0);
    let basename = normalized_editor_basename(&program);
    let mut args = parts;

    match basename.as_str() {
        "code" | "code-insiders" | "cursor" | "codium" | "windsurf" => {
            args.push("-g".to_string());
            args.push(format!("{}:{}", target.path.display(), target.line));
        }
        "hx" | "helix" => {
            args.push(format!("{}:{}", target.path.display(), target.line));
        }
        "vim" | "nvim" | "vi" | "nano" | "emacs" => {
            args.push(format!("+{}", target.line));
            args.push(target.path.display().to_string());
        }
        _ => {
            args.push(target.path.display().to_string());
        }
    }

    Ok(CommandSpec { program, args })
}

/// Explicit configuration wins; the caller gates desktop launch by session.
fn open_command_spec_with_environment(
    target: &OpenTarget,
    visual: Option<&str>,
    editor: Option<&str>,
    desktop: Option<&str>,
    is_available: impl Fn(&str) -> bool,
) -> Result<CommandSpec, String> {
    let configured = visual
        .filter(|value| !value.trim().is_empty())
        .map(|command| ("VISUAL", command))
        .or_else(|| {
            editor
                .filter(|value| !value.trim().is_empty())
                .map(|command| ("EDITOR", command))
        });
    if let Some((variable, command)) = configured {
        let spec = open_command_spec_from_editor(target, command)
            .map_err(|error| format!("${variable}: {error}; set it to a valid editor command"))?;
        if is_available(&spec.program) {
            return Ok(spec);
        }
        return Err(format!(
            "${variable} selects {:?}, which is not executable or not on PATH; set it to an installed editor",
            spec.program,
        ));
    }
    for candidate in ["nvim", "vim", "nano", "vi"] {
        if is_available(candidate) {
            return open_command_spec_from_editor(target, candidate);
        }
    }
    if let Some(program) = desktop.filter(|program| is_available(program)) {
        return Ok(CommandSpec {
            program: program.to_string(),
            args: vec![target.path.display().to_string()],
        });
    }
    Err("no editor available; set VISUAL or EDITOR to an installed editor, or install nvim/vim/nano/vi".into())
}

fn executable_available(program: &str) -> bool {
    let runnable = |path: &Path| {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    let candidate_available = |path: &Path| {
        #[cfg(windows)]
        if path.extension().is_none() {
            // Command only infers .exe; other extensions must be explicit.
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(".exe");
            return runnable(Path::new(&candidate));
        }
        runnable(path)
    };
    let path = Path::new(program);
    if path.is_absolute() || path.components().count() > 1 {
        return candidate_available(path);
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| candidate_available(&directory.join(path)))
    })
}

fn normalized_editor_basename(program: &str) -> String {
    let basename = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program);
    let basename = basename.to_ascii_lowercase();

    for extension in [".exe", ".cmd", ".bat"] {
        if let Some(stem) = basename.strip_suffix(extension) {
            return stem.to_string();
        }
    }

    basename
}

fn resolve_finding_path(scan_path: &str, finding_file: &str) -> PathBuf {
    let finding_path = Path::new(finding_file);
    if finding_path.is_absolute() {
        return finding_path.to_path_buf();
    }

    if finding_path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return finding_path.to_path_buf();
    }

    let scan_root = Path::new(scan_path);
    if finding_path.starts_with(scan_root) {
        return finding_path.to_path_buf();
    }

    let scan_root_is_file = scan_root.is_file();
    let base = if scan_root_is_file {
        scan_root.parent().unwrap_or_else(|| Path::new("."))
    } else {
        scan_root
    };

    base.join(finding_path)
}
