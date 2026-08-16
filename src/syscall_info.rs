use crate::arch::parse_args;
use crate::style::StyleConfig;
use libc::{c_ulonglong, user_regs_struct};
use libc::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE,
    MAP_SHARED, MAP_STACK, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE,
};
use nix::unistd::Pid;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow::{self, Borrowed, Owned};
use std::fmt::{Debug, Display};
use std::io;
use std::io::Write;
use std::time::Duration;
use syscalls::Sysno;

/// A syscall number as reported by the kernel.
///
/// The running kernel may know syscalls that the `syscalls` crate used to
/// build lurk does not.  Keeping the raw number prevents a new syscall from
/// crashing the tracer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SyscallId {
    raw: u64,
    known: Option<Sysno>,
}

impl SyscallId {
    pub fn from_raw(raw: u64) -> Self {
        Self {
            raw,
            known: usize::try_from(raw).ok().and_then(Sysno::new),
        }
    }

    pub fn from_raw_for_native_abi(raw: u64, native_abi: bool) -> Self {
        if native_abi {
            Self::from_raw(raw)
        } else {
            Self { raw, known: None }
        }
    }

    pub const fn from_known(syscall: Sysno) -> Self {
        Self {
            raw: syscall.id() as u64,
            known: Some(syscall),
        }
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }

    pub const fn known(self) -> Option<Sysno> {
        self.known
    }

    pub fn is(self, syscall: Sysno) -> bool {
        self.known == Some(syscall)
    }

    pub fn name(self) -> String {
        self.known.map_or_else(
            || {
                if u32::try_from(self.raw).is_ok() {
                    format!("syscall_{}", self.raw)
                } else {
                    format!("syscall_{:#x}", self.raw)
                }
            },
            |syscall| syscall.name().to_owned(),
        )
    }
}

impl From<Sysno> for SyscallId {
    fn from(value: Sysno) -> Self {
        Self::from_known(value)
    }
}

impl Display for SyscallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.known {
            Some(syscall) => Display::fmt(&syscall, f),
            None if u32::try_from(self.raw).is_ok() => write!(f, "syscall_{}", self.raw),
            None => write!(f, "syscall_{:#x}", self.raw),
        }
    }
}

#[derive(Debug)]
pub struct SyscallInfo {
    pub typ: &'static str,
    pub pid: Pid,
    pub syscall: SyscallId,
    pub args: SyscallArgs,
    pub result: RetCode,
    pub duration: Duration,
}

impl SyscallInfo {
    pub fn new(
        pid: Pid,
        syscall: Sysno,
        ret_code: RetCode,
        registers: user_regs_struct,
        duration: Duration,
    ) -> Self {
        Self {
            typ: "SYSCALL",
            pid,
            syscall: syscall.into(),
            args: parse_args(pid, syscall, registers),
            result: ret_code,
            duration,
        }
    }

    pub fn write_syscall(
        &self,
        style: StyleConfig,
        string_limit: Option<usize>,
        show_syscall_num: bool,
        show_duration: bool,
        output: &mut dyn Write,
    ) -> anyhow::Result<()> {
        if style.use_colors {
            write!(output, "[{}] ", style.pid.apply_to(&self.pid.to_string()))?;
        } else {
            write!(output, "[{}] ", self.pid)?;
        }
        if show_syscall_num {
            write!(output, "{:>3} ", self.syscall.raw())?;
        }
        if style.use_colors {
            let styled = style.syscall.apply_to(self.syscall.to_string());
            write!(output, "{styled}(")
        } else {
            write!(output, "{}(", self.syscall)
        }?;
        for (idx, arg) in self.args.0.iter().enumerate() {
            if idx > 0 {
                write!(output, ", ")?;
            }
            // Special-case a few syscalls for more readable output
            let exec_env_index = if self.syscall.is(Sysno::execve) {
                Some(2)
            } else if self.syscall.is(Sysno::execveat) {
                Some(3)
            } else {
                None
            };
            if let Some(env_index) = exec_env_index {
                match (idx, arg) {
                    // argv: show array (possibly truncated by `string_limit` via write)
                    (1, SyscallArg::StrVec(_, _)) if self.syscall.is(Sysno::execve) => {
                        arg.write(output, string_limit)?
                    }
                    (2, SyscallArg::StrVec(_, _)) if self.syscall.is(Sysno::execveat) => {
                        arg.write(output, string_limit)?
                    }
                    // envp: summarize like strace: print original pointer and count
                    (arg_idx, SyscallArg::StrVec(vs, maybe_addr)) if arg_idx == env_index => {
                        if let Some(addr) = maybe_addr {
                            let count = if !vs.is_empty() {
                                vs.len()
                            } else {
                                // try a best-effort pointer-only count if the strings couldn't be read
                                crate::arch::read_string_array_count(self.pid, *addr as c_ulonglong)
                            };
                            write!(output, "{:#x} /* {} vars */", *addr, count)?
                        } else {
                            // fall back to printing the array
                            arg.write(output, string_limit)?;
                        }
                    }
                    (arg_idx, SyscallArg::StrArraySummary(count, addr)) if arg_idx == env_index => {
                        write!(output, "{addr:#x} /* {count} vars */")?
                    }
                    // default
                    _ => arg.write(output, string_limit)?,
                }
            } else if self.syscall.is(Sysno::mmap) {
                // mmap(addr, len, prot, flags, fd, offset)
                // produce symbolic prot and flags
                let parts = format_mmap_args(&self.args.0, string_limit);
                write!(
                    output,
                    "{}",
                    parts.get(idx).map(|s| s.as_str()).unwrap_or("")
                )?;
            } else {
                arg.write(output, string_limit)?;
            }
        }
        write!(output, ") = ")?;
        if self.syscall.is(Sysno::exit) || self.syscall.is(Sysno::exit_group) {
            write!(output, "?")?;
        } else {
            if style.use_colors {
                let style = style.from_ret_code(self.result);
                // TODO: it would be great if we can force termcolor to write
                //       the styling prefix and suffix into the formatter.
                //       This would allow us to use the same code for both cases,
                //       and avoid additional string alloc
                write!(output, "{}", style.apply_to(self.result.to_string()))
            } else {
                write!(output, "{}", self.result)
            }?;
            if show_duration {
                // TODO: add an option to control each syscall duration scaling, e.g. ms, us, ns
                write!(output, " <{:.6}ns>", self.duration.as_nanos())?;
            }
        }
        Ok(writeln!(output)?)
    }
}

impl Serialize for SyscallInfo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("type", &self.typ)?;
        map.serialize_entry("pid", &self.pid.as_raw())?;
        map.serialize_entry("num", &self.syscall.raw())?;
        map.serialize_entry("syscall", &self.syscall.to_string())?;
        map.serialize_entry("args", &self.args)?;
        match self.result {
            RetCode::Ok(value) => map.serialize_entry("success", &value)?,
            RetCode::Err(value) => map.serialize_entry("error", &value)?,
            RetCode::Address(value) => map.serialize_entry("result", &value)?,
        }
        map.serialize_entry("duration", &self.duration.as_secs_f64())?;
        map.end()
    }
}

#[derive(Clone, Debug)]
pub struct SyscallArgs(pub Vec<SyscallArg>);

impl Serialize for SyscallArgs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for arg in &self.0 {
            let value = match arg {
                SyscallArg::Int(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Str(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Bytes(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Addr(v) => Value::String(format!("{v:#x}")),
                SyscallArg::StrVec(vs, _addr) => serde_json::to_value(vs).unwrap(),
                SyscallArg::StrArraySummary(count, address) => {
                    serde_json::json!({"address": format!("{address:#x}"), "count": count})
                }
            };
            seq.serialize_element(&value)?;
        }
        seq.end()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RetCode {
    Ok(i64),
    Err(i32),
    Address(u64),
}

impl RetCode {
    pub fn from_raw(ret_code: c_ulonglong) -> Self {
        let signed = ret_code as i64;
        if (-4095..=-1).contains(&signed) {
            Self::Err(signed as i32)
        } else {
            Self::Ok(signed)
        }
    }

    pub fn from_exit(ret_code: i64, is_error: bool, returns_address: bool) -> Self {
        if is_error {
            Self::Err(ret_code as i32)
        } else if returns_address {
            Self::Address(ret_code as u64)
        } else {
            Self::Ok(ret_code)
        }
    }
}

impl Display for RetCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok(v) => Display::fmt(v, f),
            Self::Err(v) => Display::fmt(v, f),
            Self::Address(v) => write!(f, "{v:#X}"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum SyscallArg {
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    // store optional original pointer address for arrays so we can summarize like strace
    StrVec(Vec<String>, Option<usize>),
    /// A NULL-terminated string array whose contents are intentionally not
    /// copied (used for potentially sensitive environment vectors).
    StrArraySummary(usize, usize),
    Addr(usize),
}

impl SyscallArg {
    pub fn write(&self, f: &mut dyn Write, string_limit: Option<usize>) -> io::Result<()> {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(v) => {
                let value: Value = match string_limit {
                    Some(width) => trim_str(v, width),
                    None => Borrowed(v.as_ref()),
                }
                .into();
                write!(f, "{value}")
            }
            Self::Bytes(bytes) => write_bytes(f, bytes, string_limit),
            Self::StrVec(vs, _addr) => {
                // format vector as JSON-like array, applying trimming to each element
                let mut parts = Vec::with_capacity(vs.len());
                for s in vs {
                    let trimmed = match string_limit {
                        Some(width) => trim_str(s, width).into_owned(),
                        None => s.clone(),
                    };
                    parts.push(serde_json::to_string(&trimmed).unwrap());
                }
                write!(f, "[{}]", parts.join(", "))
            }
            Self::StrArraySummary(count, address) => {
                write!(f, "{address:#x} /* {count} entries */")
            }
            Self::Addr(v) => write!(f, "{v:#X}"),
        }
    }
}

fn write_bytes(f: &mut dyn Write, bytes: &[u8], limit: Option<usize>) -> io::Result<()> {
    let shown = limit.map_or(bytes.len(), |limit| limit.min(bytes.len()));
    write!(f, "\"")?;
    for byte in &bytes[..shown] {
        match byte {
            b'\\' => write!(f, "\\\\")?,
            b'\"' => write!(f, "\\\"")?,
            b'\n' => write!(f, "\\n")?,
            b'\r' => write!(f, "\\r")?,
            b'\t' => write!(f, "\\t")?,
            0x20..=0x7e => write!(f, "{}", char::from(*byte))?,
            _ => write!(f, "\\x{byte:02x}")?,
        }
    }
    write!(f, "\"")?;
    if shown < bytes.len() {
        write!(f, "...")?;
    }
    Ok(())
}

fn trim_str(string: &str, limit: usize) -> Cow<'_, str> {
    if string.chars().count() <= limit {
        Borrowed(string)
    } else {
        Owned(format!(
            "{}...",
            string.chars().take(limit).collect::<String>()
        ))
    }
}

fn format_prot(flags: i64) -> String {
    let mut parts = Vec::new();
    if flags & (PROT_READ as i64) != 0 {
        parts.push("PROT_READ");
    }
    if flags & (PROT_WRITE as i64) != 0 {
        parts.push("PROT_WRITE");
    }
    if flags & (PROT_EXEC as i64) != 0 {
        parts.push("PROT_EXEC");
    }
    if flags == (PROT_NONE as i64) {
        parts.push("PROT_NONE");
    }
    if parts.is_empty() {
        format!("{flags}")
    } else {
        parts.join("|")
    }
}

fn format_map_flags(flags: i64) -> String {
    let mut parts = Vec::new();
    if flags & (MAP_SHARED as i64) != 0 {
        parts.push("MAP_SHARED");
    }
    if flags & (MAP_PRIVATE as i64) != 0 {
        parts.push("MAP_PRIVATE");
    }
    if flags & (MAP_ANONYMOUS as i64) != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if flags & (MAP_FIXED as i64) != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & (MAP_STACK as i64) != 0 {
        parts.push("MAP_STACK");
    }
    if flags & (MAP_NORESERVE as i64) != 0 {
        parts.push("MAP_NORESERVE");
    }
    if flags & (MAP_LOCKED as i64) != 0 {
        parts.push("MAP_LOCKED");
    }
    if flags & (MAP_POPULATE as i64) != 0 {
        parts.push("MAP_POPULATE");
    }
    if flags & (MAP_NONBLOCK as i64) != 0 {
        parts.push("MAP_NONBLOCK");
    }
    if parts.is_empty() {
        format!("{flags}")
    } else {
        parts.join("|")
    }
}

fn format_mmap_args(args: &[SyscallArg], string_limit: Option<usize>) -> Vec<String> {
    // Expect 6 args: addr, len, prot, flags, fd, offset
    let mut out = vec![String::new(); args.len()];
    for (i, a) in args.iter().enumerate() {
        match (i, a) {
            (0, SyscallArg::Addr(addr)) => {
                if *addr == 0 {
                    out[i] = "NULL".to_string();
                } else {
                    out[i] = format!("{:#X}", addr);
                }
            }
            (1, SyscallArg::Int(len)) => out[i] = format!("{}", len),
            (2, SyscallArg::Int(prot)) => out[i] = format_prot(*prot),
            (3, SyscallArg::Int(flags)) => out[i] = format_map_flags(*flags),
            (4, SyscallArg::Int(fd)) => out[i] = format!("{}", fd),
            (5, SyscallArg::Int(off)) => out[i] = format!("{}", off),
            // fall back to default write for other or unexpected types
            (_, other) => {
                let mut buf = Vec::new();
                other.write(&mut buf, string_limit).ok();
                out[i] = String::from_utf8_lossy(&buf).to_string();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_values_are_not_truncated_or_guessed_to_be_pointers() {
        assert_eq!(RetCode::from_raw(1_u64 << 40), RetCode::Ok(1_i64 << 40));
        assert_eq!(RetCode::from_raw((-2_i64) as u64), RetCode::Err(-2));
    }

    #[test]
    fn raw_syscall_numbers_keep_the_kernel_word_size() {
        let raw = u64::MAX;
        let syscall = SyscallId::from_raw(raw);
        assert_eq!(syscall.raw(), raw);
        assert_eq!(syscall.known(), None);
        assert_eq!(syscall.to_string(), "syscall_0xffffffffffffffff");

        let compat_read = SyscallId::from_raw_for_native_abi(3, false);
        assert_eq!(compat_read.raw(), 3);
        assert_eq!(compat_read.known(), None);
    }

    #[test]
    fn unicode_trimming_uses_character_boundaries() {
        assert_eq!(trim_str("ééé", 2), "éé...");
    }

    #[test]
    fn execveat_uses_the_correct_argv_and_environment_positions() {
        let info = SyscallInfo {
            typ: "SYSCALL",
            pid: Pid::from_raw(1),
            syscall: Sysno::execveat.into(),
            args: SyscallArgs(vec![
                SyscallArg::Int(-100),
                SyscallArg::Str("/bin/true".to_owned()),
                SyscallArg::StrVec(vec!["true".to_owned()], Some(0x1000)),
                SyscallArg::StrArraySummary(3, 0x2000),
                SyscallArg::Int(0),
            ]),
            result: RetCode::Ok(0),
            duration: Duration::ZERO,
        };
        let mut output = Vec::new();
        let style = StyleConfig {
            use_colors: false,
            ..StyleConfig::default()
        };
        info.write_syscall(style, None, false, false, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("[\"true\"], 0x2000 /* 3 vars */"),
            "{output}"
        );
    }
}
