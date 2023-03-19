use crate::arch::{get_arg_value, read_string, SyscallArgType, SYSCALLS};
use ansi_term::Color::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use libc::{c_ulonglong, user_regs_struct};
use nix::unistd::Pid;
use serde::ser::SerializeSeq;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::borrow::Cow::{Borrowed, Owned};
use std::io;
use std::time::Duration;
use syscalls::Sysno;

#[derive(Debug, Serialize)]
pub struct SyscallInfo {
    #[serde(rename = "type")]
    pub typ: &'static str,
    pub pid: ProcessId,
    #[serde(rename = "num")]
    pub sys_no: Sysno,
    pub syscall: SyscallName,

    #[serde(serialize_with = "SyscallInfo::serialize_args")]
    pub args: Vec<SyscallArg>,

    #[serde(flatten)]
    pub result: RetCode,

    #[serde(serialize_with = "SyscallInfo::serialize_duration")]
    pub duration: Duration,
}

impl SyscallInfo {
    pub fn new(
        pid: Pid,
        sys_no: Sysno,
        ret_code: RetCode,
        registers: user_regs_struct,
        duration: Duration,
    ) -> Self {
        Self {
            typ: "SYSCALL",
            pid: ProcessId(pid),
            sys_no,
            syscall: SyscallName(sys_no),
            args: SYSCALLS[sys_no.id() as usize]
                .1
                .iter()
                .filter_map(Option::as_ref)
                .enumerate()
                .map(|(idx, arg)| (arg, get_arg_value(registers, idx)))
                .map(|(arg, value)| match arg {
                    SyscallArgType::Int => SyscallArg::Int(value as i128),
                    SyscallArgType::Str => SyscallArg::Str(read_string(pid, value)),
                    SyscallArgType::Addr => SyscallArg::Addr(value as usize),
                })
                .collect(),
            result: ret_code,
            duration,
        }
    }

    fn serialize_args<S>(args: &Vec<SyscallArg>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(args.len()))?;
        for arg in args {
            let value = match arg {
                SyscallArg::Int(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Str(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Addr(v) => Value::String(format!("{v:#x}")),
            };
            seq.serialize_element(&value)?;
        }
        seq.end()
    }

    fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_f64(duration.as_secs_f64())
    }
}

#[derive(Debug, Copy, Clone, Serialize)]
pub enum RetCode {
    #[serde(rename = "success")]
    Ok(i32),
    #[serde(rename = "error")]
    Err(i32),
    #[serde(rename = "result")]
    Address(usize),
}

impl RetCode {
    pub fn new(ret_code: c_ulonglong) -> Self {
        let ret_i32 = ret_code as isize;
        if ret_i32.abs() > 0x8000 {
            Self::Address(ret_code as usize)
        } else if ret_i32 < 0 {
            Self::Err(ret_i32 as i32)
        } else {
            Self::Ok(ret_i32 as i32)
        }
    }
}

/// Formatting hacks: if alternative mode is enabled, use colors
impl RetCode {
    pub fn write(&self, f: &mut dyn io::Write, use_colors: bool) -> io::Result<()> {
        if use_colors {
            let style = match self {
                RetCode::Ok(_) => Green.bold(),
                RetCode::Err(_) => Red.bold(),
                RetCode::Address(_) => Yellow.bold(),
            };
            // TODO: it would be great if we can force termcolor to write
            //       the styling prefix and suffix into the formatter.
            //       This would allow us to use the same code for both cases,
            //       and avoid additional string alloc
            let value = match self {
                Self::Ok(v) | Self::Err(v) => v.to_string(),
                Self::Address(v) => format!("{v:#X}"),
            };
            write!(f, "{}", style.paint(value))
        } else {
            match self {
                Self::Ok(v) | Self::Err(v) => write!(f, "{v}"),
                Self::Address(v) => write!(f, "{v:#X}"),
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub enum SyscallArg {
    Int(i128),
    Str(String),
    Addr(usize),
}

impl SyscallArg {
    pub fn write(&self, f: &mut dyn io::Write, string_limit: Option<usize>) -> io::Result<()> {
        match self {
            Self::Int(v) => {
                // ignoring formatter params
                write!(f, "{v}")
            }
            Self::Str(v) => {
                // Use JSON string escaping
                let value: Value = match string_limit {
                    Some(width) => trim_str(v, width),
                    None => Borrowed(v.as_ref()),
                }
                .into();
                // ignoring formatter params
                write!(f, "{value}")
            }
            Self::Addr(v) => {
                // ignoring formatter params
                write!(f, "{:#X}", v)
            }
        }
    }
}

#[derive(Debug)]
pub struct ProcessId(Pid);

impl Serialize for ProcessId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_raw().serialize(serializer)
    }
}

impl ProcessId {
    pub fn write(&self, f: &mut dyn io::Write, use_colors: bool) -> io::Result<()> {
        write!(f, "[")?;
        if use_colors {
            write!(f, "{}", Blue.bold().paint(self.0.to_string()))?;
        } else {
            write!(f, "{}", self.0)?;
        }
        write!(f, "]")
    }
}

#[derive(Debug)]
pub struct SyscallName(Sysno);

impl SyscallName {
    pub fn write(&self, f: &mut dyn io::Write, use_colors: bool) -> io::Result<()> {
        if use_colors {
            write!(f, "{}", Style::new().bold().paint(self.0.to_string()))
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl Serialize for SyscallName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_string().serialize(serializer)
    }
}

fn trim_str(string: &str, limit: usize) -> Cow<str> {
    match string.chars().as_str().get(..limit) {
        None => Borrowed(string),
        Some(s) => Owned(format!("{s}...")),
    }
}
