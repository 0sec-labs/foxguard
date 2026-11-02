//! Shared helper for running child processes with piped stdout/stderr
//! while enforcing a timeout.
//!
//! The classic pitfall with `Command::new(..).stdout(Stdio::piped()).spawn()`
//! is that the parent waits for the child to exit *before* draining the pipes.
//! If the child produces more output than the OS pipe buffer (~64 KB), the
//! child blocks on its write and the parent blocks on its wait -- a deadlock.
//!
//! [`wait_with_output_timeout`] avoids this by spawning reader threads that
//! drain stdout and stderr concurrently while the main thread enforces the
//! timeout.

use std::io::Read;
use std::process::{Child, ExitStatus, Output};
use std::time::Duration;

use wait_timeout::ChildExt;

/// Outcome of [`wait_with_output_timeout`].
pub enum TimedOutput {
    /// The child exited (possibly unsuccessfully) within the deadline.
    Finished(Output),
    /// The child did not exit in time and was killed. The captured output
    /// contains whatever was read before the kill.
    TimedOut { stdout: Vec<u8>, stderr: Vec<u8> },
}

impl TimedOutput {
    /// Returns `true` when the child exceeded the deadline.
    pub fn timed_out(&self) -> bool {
        matches!(self, TimedOutput::TimedOut { .. })
    }

    /// Consume into the captured stdout bytes regardless of outcome.
    pub fn stdout(self) -> Vec<u8> {
        match self {
            TimedOutput::Finished(output) => output.stdout,
            TimedOutput::TimedOut { stdout, .. } => stdout,
        }
    }

    /// Borrow the exit status (only available when the child finished).
    pub fn status(&self) -> Option<ExitStatus> {
        match self {
            TimedOutput::Finished(output) => Some(output.status),
            TimedOutput::TimedOut { .. } => None,
        }
    }
}

const MAX_CAPTURED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Retain a bounded prefix while draining the entire stream so the child
/// cannot block on a full pipe. The boolean reports that bytes were omitted.
fn read_bounded(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut exceeded_limit = false;

    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let available = MAX_CAPTURED_OUTPUT_BYTES.saturating_sub(captured.len());
        let retained = read.min(available);
        captured.extend_from_slice(&chunk[..retained]);
        exceeded_limit |= retained < read;
    }

    (captured, exceeded_limit)
}

/// Drain stdout/stderr of `child` on background threads while enforcing
/// `timeout` on the child process.
///
/// Returns [`TimedOutput::Finished`] when the child exits in time, or
/// [`TimedOutput::TimedOut`] after killing a child that exceeded the deadline.
///
/// # Errors
///
/// Returns `Err` only for OS-level failures (e.g. the child could not be
/// waited on). Callers are expected to inspect the exit status themselves.
pub fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<TimedOutput, std::io::Error> {
    // Take the pipe handles so the reader threads own them.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || {
        stdout_pipe.map(read_bounded).unwrap_or_default()
    });

    let stderr_thread = std::thread::spawn(move || {
        stderr_pipe.map(read_bounded).unwrap_or_default()
    });

    let status = child.wait_timeout(timeout)?;

    match status {
        Some(exit_status) => {
            // Child exited within the deadline. The reader threads will
            // finish once the pipes hit EOF (which happens on child exit).
            let (stdout, stdout_exceeded_limit) = stdout_thread.join().unwrap_or_default();
            let (stderr, stderr_exceeded_limit) = stderr_thread.join().unwrap_or_default();
            if stdout_exceeded_limit || stderr_exceeded_limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "child output exceeded the capture limit",
                ));
            }

            Ok(TimedOutput::Finished(Output {
                status: exit_status,
                stdout,
                stderr,
            }))
        }
        None => {
            // Timed out -- kill the child so the pipes close.
            let _ = child.kill();
            let _ = child.wait();

            let (stdout, _) = stdout_thread.join().unwrap_or_default();
            let (stderr, _) = stderr_thread.join().unwrap_or_default();

            Ok(TimedOutput::TimedOut { stdout, stderr })
        }
    }
}
