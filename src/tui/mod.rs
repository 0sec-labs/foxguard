mod input;
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
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
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

    loop {
        app.handle_worker_messages(&rx);
        if let Some((request_id, key, finding)) = app.prepare_source_context_load() {
            start_source_context_load(request_id, key, finding, tx.clone());
        }

        session
            .terminal
            .draw(|frame| app.draw(frame))
            .map_err(|e| e.to_string())?;

        if has_stashed_event()
            || event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())?
        {
            let ev = pop_stashed_event_or_read().map_err(|e| e.to_string())?;

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
                        let request_id = app.begin_scan();
                        start_tui_execution(request_id, app.request.clone(), tx.clone())
                    }
                    Ok(false) => {}
                    Err(error) => app.push_runtime_notice(format!("action failed: {}", error)),
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
        lines: Vec<Line<'static>>,
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
        let lines = match fs::read_to_string(&key.path) {
            Ok(source) => render_source_context(&source, &finding, 2),
            Err(error) => vec![Line::from(Span::styled(
                format!("Unable to load source context: {}", error),
                Style::default().fg(Color::DarkGray),
            ))],
        };

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
    open_command_spec_from_editor(
        target,
        std::env::var_os("EDITOR")
            .as_ref()
            .map(|editor| editor.to_string_lossy().into_owned()),
    )
}

fn open_command_spec_from_editor(
    target: &OpenTarget,
    editor: Option<String>,
) -> Result<CommandSpec, String> {
    if let Some(editor) = editor {
        let mut parts =
            shlex::split(&editor).ok_or_else(|| "failed to parse $EDITOR".to_string())?;
        if parts.is_empty() {
            return Err("$EDITOR is set but empty".to_string());
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

        return Ok(CommandSpec { program, args });
    }

    if cfg!(target_os = "macos") {
        return Ok(CommandSpec {
            program: "open".to_string(),
            args: vec![target.path.display().to_string()],
        });
    }

    if cfg!(target_os = "windows") {
        return Ok(CommandSpec {
            program: "cmd".to_string(),
            args: vec![
                "/C".to_string(),
                "start".to_string(),
                String::new(),
                target.path.display().to_string(),
            ],
        });
    }

    Ok(CommandSpec {
        program: "xdg-open".to_string(),
        args: vec![target.path.display().to_string()],
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
