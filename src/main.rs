use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
const PORT: u16 = 19999;

#[cfg(unix)]
const SOCKET_PATH: &str = "/tmp/coocon.sock";

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_NAME_LEN: usize = 40;
const DEFAULT_MAX_CODE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DEFAULT_MEMORY_MB: u64 = 256;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Strict,
    Balanced,
    Dev,
}

fn default_security_mode() -> SecurityMode {
    SecurityMode::Balanced
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    #[serde(default = "default_allowed_languages")]
    pub allowed_languages: Vec<String>,
    #[serde(default = "default_max_code_bytes")]
    pub max_code_bytes: usize,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default = "default_policy_max_memory_mb")]
    pub max_memory_mb: u64,
    #[serde(default = "default_policy_max_timeout_secs")]
    pub max_timeout_secs: u64,
    #[serde(default)]
    pub allow_network: bool,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            allowed_languages: default_allowed_languages(),
            max_code_bytes: default_max_code_bytes(),
            max_output_bytes: default_max_output_bytes(),
            max_memory_mb: 1024,
            max_timeout_secs: 300,
            allow_network: false,
        }
    }
}

impl ExecutionPolicy {
    fn validate(&self) -> Result<(), String> {
        if self.allowed_languages.is_empty() {
            return Err("policy.allowed_languages cannot be empty".to_string());
        }
        if self.max_code_bytes == 0 || self.max_code_bytes > 5 * 1024 * 1024 {
            return Err("policy.max_code_bytes must be in range 1..=5242880".to_string());
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > 5 * 1024 * 1024 {
            return Err("policy.max_output_bytes must be in range 1..=5242880".to_string());
        }
        if !(32..=8192).contains(&self.max_memory_mb) {
            return Err("policy.max_memory_mb must be between 32 and 8192".to_string());
        }
        if !(1..=900).contains(&self.max_timeout_secs) {
            return Err("policy.max_timeout_secs must be between 1 and 900".to_string());
        }
        Ok(())
    }

    fn allows_language(&self, language: Language) -> bool {
        let key = language.canonical_name();
        self.allowed_languages
            .iter()
            .any(|item| item.eq_ignore_ascii_case(key))
    }
}

fn default_allowed_languages() -> Vec<String> {
    vec!["python".to_string(), "bash".to_string()]
}

fn default_max_code_bytes() -> usize {
    DEFAULT_MAX_CODE_BYTES
}

fn default_max_output_bytes() -> usize {
    DEFAULT_MAX_OUTPUT_BYTES
}

fn default_policy_max_memory_mb() -> u64 {
    1024
}

fn default_policy_max_timeout_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub name: String,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub network: bool,
    #[serde(default = "default_security_mode")]
    pub security_mode: SecurityMode,
    #[serde(default)]
    pub policy: Option<ExecutionPolicy>,
}

fn default_memory() -> u64 {
    DEFAULT_MEMORY_MB
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: i32,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SandboxState {
    Ready,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub name: String,
    pub state: SandboxState,
    pub created_at: u64,
    pub executions: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Create { config: SandboxConfig },
    Execute { name: String, code: String, language: String },
    ExecuteFile { name: String, content: String, filename: String },
    Destroy { name: String },
    List,
    Info,
    Ping,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Created { name: String },
    Executed(ExecutionResult),
    Destroyed { name: String },
    List { sandboxes: Vec<SandboxInfo> },
    Info {
        version: String,
        platform: String,
        security: Vec<String>,
        capabilities: Vec<String>,
    },
    Pong,
    Error { message: String },
    Ok,
}

#[derive(Clone, Copy)]
enum Language {
    Python,
    Bash,
}

impl Language {
    fn from_user(input: &str) -> Result<Self, String> {
        match input {
            "python" | "python3" | "py" => Ok(Self::Python),
            "bash" | "sh" => Ok(Self::Bash),
            _ => Err(format!("Unsupported language: {input}")),
        }
    }

    fn from_filename(filename: &str) -> Self {
        match Path::new(filename).extension().and_then(|e| e.to_str()) {
            Some("sh") => Self::Bash,
            _ => Self::Python,
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Python => "program.py",
            Self::Bash => "program.sh",
        }
    }

    fn command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Python => ("python3", &[]),
            Self::Bash => ("bash", &["--noprofile", "--norc"]),
        }
    }

    fn canonical_name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Bash => "bash",
        }
    }
}

struct Sandbox {
    config: SandboxConfig,
    policy: ExecutionPolicy,
    state: SandboxState,
    created_at: u64,
    executions: u32,
    sandbox_dir: PathBuf,
}

#[derive(Clone, Copy)]
struct Capabilities {
    hard_limits: bool,
    network_isolation: bool,
    strong_isolation: bool,
    is_wsl: bool,
}

fn detect_capabilities() -> Capabilities {
    #[cfg(target_os = "linux")]
    {
        let is_wsl = is_wsl();
        let strong_isolation = !is_wsl && has_bwrap();
        Capabilities {
            hard_limits: true,
            network_isolation: false,
            strong_isolation,
            is_wsl,
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        Capabilities {
            hard_limits: true,
            network_isolation: false,
            strong_isolation: false,
            is_wsl: false,
        }
    }
    #[cfg(not(unix))]
    {
        Capabilities {
            hard_limits: false,
            network_isolation: false,
            strong_isolation: false,
            is_wsl: false,
        }
    }
}

#[cfg(target_os = "linux")]
fn is_wsl() -> bool {
    let candidates = ["/proc/sys/kernel/osrelease", "/proc/version"];
    for path in candidates {
        if let Ok(contents) = fs::read_to_string(path) {
            if contents.to_ascii_lowercase().contains("microsoft") {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn has_bwrap() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn should_use_bwrap(config: &SandboxConfig) -> bool {
    let caps = detect_capabilities();
    if !caps.strong_isolation {
        return false;
    }
    matches!(config.security_mode, SecurityMode::Strict | SecurityMode::Balanced)
}

impl Sandbox {
    fn new(config: SandboxConfig) -> Result<Self, String> {
        validate_sandbox_name(&config.name)?;
        validate_limits(config.memory_mb, config.timeout_secs)?;
        let policy = resolve_policy(&config)?;
        validate_policy_support(&config, &policy)?;

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Clock error: {e}"))?
            .as_secs();

        let base = std::env::temp_dir().join("coocon");
        fs::create_dir_all(&base).map_err(|e| format!("Cannot create sandbox base dir: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&base, fs::Permissions::from_mode(0o700));
        }

        let unique = format!("{}-{}-{}", config.name, created_at, std::process::id());
        let sandbox_dir = base.join(unique);
        fs::create_dir(&sandbox_dir).map_err(|e| format!("Cannot create sandbox dir: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&sandbox_dir, fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            config,
            policy,
            state: SandboxState::Ready,
            created_at,
            executions: 0,
            sandbox_dir,
        })
    }

    fn execute(&mut self, code: &str, language: &str) -> Result<ExecutionResult, String> {
        let lang = Language::from_user(language)?;
        if !self.policy.allows_language(lang) {
            return Err(format!(
                "Language '{}' blocked by sandbox policy",
                lang.canonical_name()
            ));
        }
        self.execute_impl(code, lang)
    }

    fn execute_file(&mut self, content: &str, filename: &str) -> Result<ExecutionResult, String> {
        let lang = Language::from_filename(filename);
        if !self.policy.allows_language(lang) {
            return Err(format!(
                "Language '{}' blocked by sandbox policy",
                lang.canonical_name()
            ));
        }
        self.execute_impl(content, lang)
    }

    fn execute_impl(&mut self, code: &str, lang: Language) -> Result<ExecutionResult, String> {
        if code.len() > self.policy.max_code_bytes {
            return Err(format!(
                "Code size {} bytes exceeds limit {} bytes",
                code.len(),
                self.policy.max_code_bytes
            ));
        }

        self.state = SandboxState::Running;
        self.executions += 1;

        let start = Instant::now();
        let result = self.run_script(code, lang);
        let elapsed = start.elapsed().as_millis() as u64;

        self.state = SandboxState::Ready;

        match result {
            Ok((status, out, err)) => {
                let success = status == 0;
                let mut output = out;
                let mut error = err;

                truncate_string(&mut output, self.policy.max_output_bytes);
                truncate_string(&mut error, self.policy.max_output_bytes);

                Ok(ExecutionResult {
                    success,
                    output,
                    error: if error.trim().is_empty() { None } else { Some(error) },
                    exit_code: status,
                    execution_time_ms: elapsed,
                })
            }
            Err(e) => Ok(ExecutionResult {
                success: false,
                output: String::new(),
                error: Some(e),
                exit_code: 1,
                execution_time_ms: elapsed,
            }),
        }
    }

    fn run_script(&self, code: &str, lang: Language) -> Result<(i32, String, String), String> {
        let script_path = self.sandbox_dir.join(lang.file_name());
        fs::write(&script_path, code).map_err(|e| format!("Cannot write script: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&script_path, fs::Permissions::from_mode(0o600));
        }

        let (bin, args) = lang.command();

        #[cfg(target_os = "linux")]
        let use_bwrap = should_use_bwrap(&self.config);
        #[cfg(not(target_os = "linux"))]
        let use_bwrap = false;

        let mut command = if use_bwrap {
            #[cfg(target_os = "linux")]
            {
                let script_in_sandbox = Path::new("/work").join(lang.file_name());
                build_bwrap_command(&self.sandbox_dir, &script_in_sandbox, bin, args)
            }
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("bwrap is only supported on Linux");
            }
        } else {
            let mut cmd = Command::new(bin);
            cmd.args(args)
                .arg(&script_path)
                .current_dir(&self.sandbox_dir)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.sandbox_dir)
                .env("LANG", "C")
                .env("LC_ALL", "C");
            cmd
        };

        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(unix)]
        {
            apply_unix_restrictions(&mut command, &self.config)?;
        }

        let mut child = command
            .spawn()
            .map_err(|e| format!("Cannot spawn process: {e}"))?;

        #[cfg(windows)]
        let _job_guard = apply_windows_restrictions(&child, &self.config)?;

        let timeout = Duration::from_secs(self.config.timeout_secs);
        let wait_started = Instant::now();

        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if wait_started.elapsed() > timeout {
                        kill_child(&mut child);
                        return Err(format!("Execution timed out after {} seconds", self.config.timeout_secs));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    kill_child(&mut child);
                    return Err(format!("Process wait error: {e}"));
                }
            }
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_end(&mut stdout);
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_end(&mut stderr);
        }

        let out_str = String::from_utf8_lossy(&stdout).to_string();
        let err_str = String::from_utf8_lossy(&stderr).to_string();
        let code = status.code().unwrap_or(1);

        Ok((code, out_str, err_str))
    }

    fn info(&self) -> SandboxInfo {
        SandboxInfo {
            name: self.config.name.clone(),
            state: self.state.clone(),
            created_at: self.created_at,
            executions: self.executions,
        }
    }

    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.sandbox_dir);
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(unix)]
fn apply_unix_restrictions(command: &mut Command, config: &SandboxConfig) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let memory_bytes = config
        .memory_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "Memory limit overflow".to_string())?;
    let cpu_secs = config.timeout_secs.max(1);

    let security_mode = config.security_mode;

    unsafe {
        command.pre_exec(move || {
            let lim_as = libc::rlimit {
                rlim_cur: memory_bytes as libc::rlim_t,
                rlim_max: memory_bytes as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &lim_as) != 0 {
                return Err(io::Error::last_os_error());
            }

            let lim_cpu = libc::rlimit {
                rlim_cur: cpu_secs as libc::rlim_t,
                rlim_max: cpu_secs as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &lim_cpu) != 0 {
                return Err(io::Error::last_os_error());
            }

            let lim_nofile = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim_nofile) != 0 {
                return Err(io::Error::last_os_error());
            }

            let lim_nproc = libc::rlimit {
                rlim_cur: 32,
                rlim_max: 32,
            };
            let _ = libc::setrlimit(libc::RLIMIT_NPROC, &lim_nproc);

            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }

            #[cfg(target_os = "linux")]
            {
                if matches!(security_mode, SecurityMode::Strict | SecurityMode::Balanced) {
                    apply_linux_seccomp().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
            }

            Ok(())
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_seccomp() -> Result<(), String> {
    use libseccomp::{ScmpAction, ScmpFilter, ScmpSyscall};

    let mut filter = ScmpFilter::new_filter(ScmpAction::Allow)
        .map_err(|e| format!("seccomp init failed: {e}"))?;

    let deny = [
        "ptrace",
        "mount",
        "umount2",
        "pivot_root",
        "setns",
        "unshare",
        "reboot",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "swapon",
        "swapoff",
        "iopl",
        "ioperm",
        "syslog",
        "perf_event_open",
        "bpf",
        "userfaultfd",
        "open_by_handle_at",
        "name_to_handle_at",
    ];

    for name in deny {
        if let Ok(syscall) = ScmpSyscall::from_name(name) {
            let _ = filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall);
        }
    }

    filter.load().map_err(|e| format!("seccomp load failed: {e}"))?;
    Ok(())
}

#[cfg(windows)]
struct WindowsJobGuard {
    handle: isize,
}

#[cfg(windows)]
impl Drop for WindowsJobGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn apply_windows_restrictions(child: &std::process::Child, config: &SandboxConfig) -> Result<WindowsJobGuard, String> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if job == 0 {
        return Err("CreateJobObject failed".to_string());
    }

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    let memory_bytes = config
        .memory_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "Memory limit overflow".to_string())?;

    info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.ProcessMemoryLimit = memory_bytes as usize;
    info.JobMemoryLimit = memory_bytes as usize;

    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == FALSE {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(job);
        }
        return Err("SetInformationJobObject failed".to_string());
    }

    let child_handle = child.as_raw_handle() as isize;
    let ok = unsafe { AssignProcessToJobObject(job, child_handle) };
    if ok == FALSE {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(job);
        }
        return Err("AssignProcessToJobObject failed".to_string());
    }

    Ok(WindowsJobGuard { handle: job })
}

#[cfg(target_os = "linux")]
fn add_ro_bind_if_exists(command: &mut Command, path: &str) {
    if Path::new(path).exists() {
        command.arg("--ro-bind").arg(path).arg(path);
    }
}

#[cfg(target_os = "linux")]
fn build_bwrap_command(
    sandbox_dir: &Path,
    script_in_sandbox: &Path,
    bin: &str,
    args: &[&str],
) -> Command {
    let mut command = Command::new("bwrap");
    command
        .arg("--die-with-parent")
        .arg("--new-session")
        .arg("--unshare-all")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--bind")
        .arg(sandbox_dir)
        .arg("/work")
        .arg("--chdir")
        .arg("/work")
        .arg("--clearenv")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/bin:/bin")
        .arg("--setenv")
        .arg("HOME")
        .arg("/work")
        .arg("--setenv")
        .arg("LANG")
        .arg("C")
        .arg("--setenv")
        .arg("LC_ALL")
        .arg("C");

    add_ro_bind_if_exists(&mut command, "/usr");
    add_ro_bind_if_exists(&mut command, "/bin");
    add_ro_bind_if_exists(&mut command, "/lib");
    add_ro_bind_if_exists(&mut command, "/lib64");
    add_ro_bind_if_exists(&mut command, "/usr/lib");
    add_ro_bind_if_exists(&mut command, "/usr/lib64");
    add_ro_bind_if_exists(&mut command, "/usr/local");
    add_ro_bind_if_exists(&mut command, "/etc");

    command
        .arg("--")
        .arg(bin)
        .args(args)
        .arg(script_in_sandbox);

    command
}

fn kill_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        unsafe {
            let _ = libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

fn truncate_string(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }

    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }

    s.truncate(end);
    s.push_str("\n[truncated]");
}

fn validate_sandbox_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Sandbox name cannot be empty".to_string());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("Sandbox name too long (max {MAX_NAME_LEN})"));
    }
    if name.starts_with('-') {
        return Err("Sandbox name cannot start with '-'".to_string());
    }

    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        return Err("Sandbox name allows only [A-Za-z0-9_-]".to_string());
    }

    Ok(())
}

fn validate_limits(memory_mb: u64, timeout_secs: u64) -> Result<(), String> {
    if !(32..=8192).contains(&memory_mb) {
        return Err("memory_mb must be between 32 and 8192".to_string());
    }
    if !(1..=900).contains(&timeout_secs) {
        return Err("timeout_secs must be between 1 and 900".to_string());
    }
    Ok(())
}

fn resolve_policy(config: &SandboxConfig) -> Result<ExecutionPolicy, String> {
    let policy = config.policy.clone().unwrap_or_default();
    policy.validate()?;
    if config.memory_mb > policy.max_memory_mb {
        return Err(format!(
            "Requested memory_mb {} exceeds policy max_memory_mb {}",
            config.memory_mb, policy.max_memory_mb
        ));
    }
    if config.timeout_secs > policy.max_timeout_secs {
        return Err(format!(
            "Requested timeout_secs {} exceeds policy max_timeout_secs {}",
            config.timeout_secs, policy.max_timeout_secs
        ));
    }
    if config.network && !policy.allow_network {
        return Err("Requested network=true but sandbox policy forbids network".to_string());
    }
    Ok(policy)
}

fn validate_policy_support(config: &SandboxConfig, policy: &ExecutionPolicy) -> Result<(), String> {
    let caps = detect_capabilities();
    match config.security_mode {
        SecurityMode::Strict => {
            if !caps.hard_limits {
                return Err("strict mode requires hard resource limits on this OS".to_string());
            }
            if !caps.strong_isolation {
                return Err("strict mode requires a Linux namespace sandbox (bubblewrap)".to_string());
            }
            if policy.allow_network && !caps.network_isolation {
                return Err("strict mode forbids enabling network without OS network isolation".to_string());
            }
        }
        SecurityMode::Balanced => {
            if policy.allow_network && !caps.network_isolation {
                return Err("balanced mode forbids --network because isolation is unavailable".to_string());
            }
        }
        SecurityMode::Dev => {}
    }
    Ok(())
}

struct Manager {
    sandboxes: HashMap<String, Sandbox>,
}

impl Manager {
    fn new() -> Self {
        Self {
            sandboxes: HashMap::new(),
        }
    }

    fn create(&mut self, config: SandboxConfig) -> Result<String, String> {
        let name = config.name.clone();
        if self.sandboxes.contains_key(&name) {
            return Err(format!("'{name}' already exists"));
        }

        let sandbox = Sandbox::new(config)?;
        self.sandboxes.insert(name.clone(), sandbox);
        Ok(name)
    }

    fn execute(&mut self, name: &str, code: &str, lang: &str) -> Result<ExecutionResult, String> {
        self.sandboxes
            .get_mut(name)
            .ok_or_else(|| format!("'{name}' not found"))?
            .execute(code, lang)
    }

    fn execute_file(&mut self, name: &str, content: &str, filename: &str) -> Result<ExecutionResult, String> {
        self.sandboxes
            .get_mut(name)
            .ok_or_else(|| format!("'{name}' not found"))?
            .execute_file(content, filename)
    }

    fn destroy(&mut self, name: &str) -> Result<(), String> {
        self.sandboxes
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| format!("'{name}' not found"))
    }

    fn list(&self) -> Vec<SandboxInfo> {
        self.sandboxes.values().map(|s| s.info()).collect()
    }
}

fn handle(req: Request, mgr: &Arc<Mutex<Manager>>, stop: &Arc<AtomicBool>) -> Response {
    match req {
        Request::Create { config } => match mgr.lock().unwrap().create(config) {
            Ok(name) => Response::Created { name },
            Err(e) => Response::Error { message: e },
        },
        Request::Execute {
            name,
            code,
            language,
        } => match mgr.lock().unwrap().execute(&name, &code, &language) {
            Ok(r) => Response::Executed(r),
            Err(e) => Response::Error { message: e },
        },
        Request::ExecuteFile {
            name,
            content,
            filename,
        } => match mgr.lock().unwrap().execute_file(&name, &content, &filename) {
            Ok(r) => Response::Executed(r),
            Err(e) => Response::Error { message: e },
        },
        Request::Destroy { name } => match mgr.lock().unwrap().destroy(&name) {
            Ok(_) => Response::Destroyed { name },
            Err(e) => Response::Error { message: e },
        },
        Request::List => Response::List {
            sandboxes: mgr.lock().unwrap().list(),
        },
        Request::Info => Response::Info {
            version: VERSION.to_string(),
            platform: std::env::consts::OS.to_string(),
            security: {
                let caps = detect_capabilities();
                let mut items = vec![
                    "Strict sandbox name validation".into(),
                    "No shell interpolation for user code".into(),
                    "Per-execution CPU/memory/process/file-descriptor limits".into(),
                    "Ephemeral isolated workspace under /tmp/coocon".into(),
                    "Environment variables cleared before execution".into(),
                ];
                if cfg!(target_os = "linux") {
                    items.push("Linux seccomp denylist (strict/balanced)".into());
                }
                if cfg!(windows) {
                    items.push("Windows Job Object limits (best effort)".into());
                }
                if caps.strong_isolation {
                    items.push("Linux namespace sandbox via bubblewrap".into());
                } else if cfg!(target_os = "linux") {
                    items.push("No Linux namespace sandbox (bubblewrap missing or WSL)".into());
                } else {
                    items.push("No OS namespace sandbox on this platform".into());
                }
                items
            },
            capabilities: {
                let caps = detect_capabilities();
                vec![
                    format!("hard_limits={}", caps.hard_limits),
                    format!("network_isolation={}", caps.network_isolation),
                    format!("strong_isolation={}", caps.strong_isolation),
                    format!("is_wsl={}", caps.is_wsl),
                    "security_modes=strict,balanced,dev".into(),
                    "policy_fields=allowed_languages,max_code_bytes,max_output_bytes,max_memory_mb,max_timeout_secs,allow_network".into(),
                ]
            },
        },
        Request::Ping => Response::Pong,
        Request::Shutdown => {
            stop.store(true, Ordering::SeqCst);
            Response::Ok
        }
    }
}

fn parse_request_line(line: &str) -> Result<Request, String> {
    if line.len() > 1024 * 1024 {
        return Err("Request too large".to_string());
    }
    serde_json::from_str(line).map_err(|e| format!("Invalid JSON request: {e}"))
}

#[cfg(windows)]
fn run_server(mgr: Arc<Mutex<Manager>>, stop: Arc<AtomicBool>) -> io::Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(format!("127.0.0.1:{PORT}"))?;
    listener.set_nonblocking(true)?;

    println!("coocon daemon {VERSION} listening on 127.0.0.1:{PORT}");

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let m = Arc::clone(&mgr);
                let s = Arc::clone(&stop);
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
                    let mut reader = BufReader::new(match stream.try_clone() {
                        Ok(c) => c,
                        Err(_) => return,
                    });

                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }

                    let response = match parse_request_line(&line) {
                        Ok(req) => handle(req, &m, &s),
                        Err(e) => Response::Error { message: e },
                    };

                    let _ = writeln!(stream, "{}", serde_json::to_string(&response).unwrap());
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    println!("coocon daemon stopped");
    Ok(())
}

#[cfg(unix)]
fn run_server(mgr: Arc<Mutex<Manager>>, stop: Arc<AtomicBool>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    println!("coocon daemon {VERSION} listening on {SOCKET_PATH}");

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let m = Arc::clone(&mgr);
                let s = Arc::clone(&stop);
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
                    let mut reader = BufReader::new(match stream.try_clone() {
                        Ok(c) => c,
                        Err(_) => return,
                    });

                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }

                    let response = match parse_request_line(&line) {
                        Ok(req) => handle(req, &m, &s),
                        Err(e) => Response::Error { message: e },
                    };

                    let _ = writeln!(stream, "{}", serde_json::to_string(&response).unwrap());
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    let _ = fs::remove_file(SOCKET_PATH);
    println!("coocon daemon stopped");
    Ok(())
}

fn main() {
    let mgr = Arc::new(Mutex::new(Manager::new()));
    let stop = Arc::new(AtomicBool::new(false));

    if let Err(e) = run_server(mgr, stop) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
