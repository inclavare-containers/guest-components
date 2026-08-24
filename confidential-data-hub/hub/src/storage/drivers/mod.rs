// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use log::debug;

pub mod filesystem;
pub mod luks2;
pub mod zfs;

/// Run a command without invoking a shell and return its stdout and stderr.
///
/// Secrets are accepted only through stdin and are never included in errors or
/// debug output.
pub fn run_command(
    command: &str,
    args: &[&str],
    inputs: Option<Vec<u8>>,
) -> Result<(String, String)> {
    let mut child = Command::new(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args)
        .spawn()
        .with_context(|| format!("command `{command}` not found or could not be started"))?;

    if let Some(inputs) = inputs {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to get command stdin"))?;
        stdin
            .write_all(&inputs)
            .context("failed to write command stdin")?;
        stdin.flush().context("failed to flush command stdin")?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for command `{command}`"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace('\n', "\n\t");
    let stderr = String::from_utf8_lossy(&output.stderr).replace('\n', "\n\t");

    if !output.status.success() {
        bail!(
            "command `{command}` failed with args {args:#?} and status {}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
    }

    debug!(
        "command `{command}` with args {args:#?} succeeded\n\tstdout: {stdout}\n\tstderr: {stderr}"
    );
    Ok((stdout, stderr))
}

#[cfg(test)]
pub struct TempFileLoopDevice {
    _file: tempfile::NamedTempFile,
    loop_path: String,
}

#[cfg(test)]
impl TempFileLoopDevice {
    pub fn new(size_bytes: u64) -> Result<Self> {
        let file = tempfile::NamedTempFile::new()?;
        file.as_file().set_len(size_bytes)?;
        let path = file
            .path()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("failed to get temporary file path"))?;
        let (stdout, _) = run_command("losetup", &["--find", "--show", path], None)?;
        Ok(Self {
            _file: file,
            loop_path: stdout.trim().to_string(),
        })
    }

    pub fn dev_path(&self) -> &str {
        &self.loop_path
    }
}

#[cfg(test)]
impl Drop for TempFileLoopDevice {
    fn drop(&mut self) {
        let _ = run_command("losetup", &["-d", self.loop_path.as_str()], None);
    }
}

#[cfg(test)]
mod tests {
    use super::run_command;

    #[test]
    fn command_captures_stdout_stderr_and_status() {
        let error = run_command(
            "sh",
            &["-c", "printf stdout; printf stderr >&2; exit 7"],
            None,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("status exit status: 7"), "{message}");
        assert!(message.contains("stdout"), "{message}");
        assert!(message.contains("stderr"), "{message}");
    }

    #[test]
    fn command_reports_a_missing_binary() {
        let command = "cdh-command-that-does-not-exist";
        let error = run_command(command, &[], None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(command), "{message}");
        assert!(message.contains("not found"), "{message}");
    }

    #[test]
    fn command_writes_binary_stdin() {
        let (stdout, _) = run_command("wc", &["-c"], Some(vec![0, 1, 2, 3, 4])).unwrap();
        assert_eq!(stdout.trim(), "5");
    }
}
