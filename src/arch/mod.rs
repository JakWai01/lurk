use crate::syscall_info::{SyscallArg, SyscallArgs};
use libc::{c_long, c_ulonglong, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::unistd::Pid;
use std::ffi::c_void;
use syscalls::Sysno;

#[cfg(any(target_arch = "aarch64", feature = "aarch64"))]
pub mod aarch64;
// #[cfg(any(target_arch = "arm", feature = "arm"))]
// pub mod arm;
// #[cfg(any(target_arch = "mips", feature = "mips"))]
// pub mod mips;
// #[cfg(any(target_arch = "mips64", feature = "mips64"))]
// pub mod mips64;
// #[cfg(any(target_arch = "powerpc", feature = "powerpc"))]
// pub mod powerpc;
// #[cfg(any(target_arch = "powerpc64", feature = "powerpc64"))]
// pub mod powerpc64;
#[cfg(any(target_arch = "riscv64", feature = "riscv64"))]
pub mod riscv64;
// #[cfg(any(target_arch = "s390x", feature = "s390x"))]
// pub mod s390x;
// #[cfg(any(target_arch = "sparc", feature = "sparc"))]
// pub mod sparc;
// #[cfg(any(target_arch = "sparc64", feature = "sparc64"))]
// pub mod sparc64;
// #[cfg(any(target_arch = "x86", feature = "x86"))]
// pub mod x86;
#[cfg(any(target_arch = "x86_64", feature = "x86_64"))]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
// #[cfg(target_arch = "arm")]
// pub use arm::*;
// #[cfg(target_arch = "mips")]
// pub use mips::*;
// #[cfg(target_arch = "mips64")]
// pub use mips64::*;
// #[cfg(target_arch = "powerpc")]
// pub use powerpc::*;
// #[cfg(target_arch = "powerpc64")]
// pub use powerpc64::*;
#[cfg(target_arch = "riscv64")]
pub use riscv64::*;
// #[cfg(target_arch = "s390x")]
// pub use s390x::*;
// #[cfg(target_arch = "sparc")]
// pub use sparc::*;
// #[cfg(target_arch = "sparc64")]
// pub use sparc64::*;
// #[cfg(target_arch = "x86")]
// pub use x86::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[derive(Debug, Copy, Clone)]
pub enum SyscallArgType {
    // Integer can be used to represent int, fd and size_t
    Int,
    // String can be used to represent *buf
    Str,
    // Array of strings, e.g. argv or envp
    StrArray,
    // String array that must not be copied into trace output (e.g. envp).
    StrArraySummary,
    // Input/output buffers.  The contained index points to the length arg.
    InputBuffer(usize),
    OutputBuffer(usize),
    // Address can be used to represent *statbuf
    Addr,
}

const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_ARRAY_ELEMENTS: usize = 1024;

pub fn read_string(pid: Pid, address: c_ulonglong) -> String {
    read_string_limited(pid, address, MAX_CAPTURE_BYTES)
}

pub fn read_string_limited(pid: Pid, address: c_ulonglong, limit: usize) -> String {
    if address == 0 {
        return "NULL".to_owned();
    }

    let mut bytes = Vec::new();
    let limit = limit.min(MAX_CAPTURE_BYTES);
    while bytes.len() < limit {
        let read_address = address.wrapping_add(bytes.len() as u64) as usize as *mut c_void;
        let word = match ptrace::read(pid, read_address) {
            Ok(word) => word,
            Err(_) if bytes.is_empty() => return format!("{address:#x}"),
            Err(_) => break,
        };
        for byte in word.to_ne_bytes() {
            if byte == 0 || bytes.len() == limit {
                return String::from_utf8_lossy(&bytes).into_owned();
            }
            bytes.push(byte);
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn ptrace_options(follow_forks: bool) -> Options {
    let mut options =
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_TRACEEXEC;
    if follow_forks {
        options |= Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE;
    }
    options
}

pub fn ptrace_init_options(pid: Pid) -> nix::Result<()> {
    ptrace::setoptions(pid, ptrace_options(false))
}

pub fn ptrace_init_options_fork(pid: Pid) -> nix::Result<()> {
    ptrace::setoptions(pid, ptrace_options(true))
}

#[allow(clippy::cast_sign_loss)]
#[must_use]
// SAFTEY: In get_register_data we make sure that the syscall number will never be negative.
pub fn parse_args(pid: Pid, syscall: Sysno, registers: user_regs_struct) -> SyscallArgs {
    parse_entry_args(pid, syscall, registers, None)
}

pub fn register_args(registers: user_regs_struct) -> [u64; 6] {
    std::array::from_fn(|idx| get_arg_value(registers, idx))
}

pub fn unknown_args(registers: user_regs_struct) -> SyscallArgs {
    unknown_args_from_values(register_args(registers))
}

pub fn unknown_args_from_values(values: [u64; 6]) -> SyscallArgs {
    SyscallArgs(
        values
            .into_iter()
            .map(|value| SyscallArg::Addr(value as usize))
            .collect(),
    )
}

pub fn parse_entry_args(
    pid: Pid,
    syscall: Sysno,
    registers: user_regs_struct,
    string_limit: Option<usize>,
) -> SyscallArgs {
    let values = register_args(registers);
    parse_args_from_values(pid, syscall, values, string_limit, false, 0)
}

pub fn parse_exit_args(
    pid: Pid,
    syscall: Sysno,
    registers: user_regs_struct,
    string_limit: Option<usize>,
    result: i64,
    entry_args: &SyscallArgs,
) -> SyscallArgs {
    let values = register_args(registers);
    let mut args = entry_args.clone();
    let syscall_index = usize::try_from(syscall.id()).expect("syscall IDs are non-negative");
    let Some((_, types)) = SYSCALLS.get(syscall_index).and_then(Option::as_ref) else {
        return args;
    };
    for (idx, arg_type) in types.iter().enumerate() {
        if let Some(arg_type @ SyscallArgType::OutputBuffer(_)) = *arg_type {
            if let Some(slot) = args.0.get_mut(idx) {
                *slot = map_arg(pid, values, idx, arg_type, string_limit, true, result);
            }
        }
    }
    args
}

fn parse_args_from_values(
    pid: Pid,
    syscall: Sysno,
    values: [u64; 6],
    string_limit: Option<usize>,
    at_exit: bool,
    result: i64,
) -> SyscallArgs {
    let syscall_index = usize::try_from(syscall.id()).expect("syscall IDs are non-negative");
    SYSCALLS
        .get(syscall_index)
        .and_then(|option| option.as_ref())
        .map_or_else(
            || SyscallArgs(vec![]),
            |(_, args)| {
                SyscallArgs(
                    args.iter()
                        .enumerate()
                        .filter_map(|(idx, arg_type)| {
                            arg_type.map(|arg_type| {
                                map_arg(pid, values, idx, arg_type, string_limit, at_exit, result)
                            })
                        })
                        .collect(),
                )
            },
        )
}

fn map_arg(
    pid: Pid,
    values: [u64; 6],
    idx: usize,
    arg: SyscallArgType,
    string_limit: Option<usize>,
    at_exit: bool,
    result: i64,
) -> SyscallArg {
    let value = values[idx];
    let capture_limit = string_limit
        .map_or(MAX_CAPTURE_BYTES, |limit| limit.saturating_add(1))
        .min(MAX_CAPTURE_BYTES);
    match arg {
        SyscallArgType::Int => {
            let narrow = u32::try_from(value).ok();
            let value = narrow
                .filter(|value| *value >= u32::MAX - 4095)
                .map_or(value as i64, |value| i64::from(value as i32));
            SyscallArg::Int(value)
        }
        SyscallArgType::Str => SyscallArg::Str(read_string_limited(pid, value, capture_limit)),
        SyscallArgType::StrArray => SyscallArg::StrVec(
            read_string_array_limited(pid, value, capture_limit),
            Some(value as usize),
        ),
        SyscallArgType::StrArraySummary => {
            SyscallArg::StrArraySummary(read_string_array_count(pid, value), value as usize)
        }
        SyscallArgType::InputBuffer(length_idx) if value != 0 => SyscallArg::Bytes(read_buffer(
            pid,
            value,
            values[length_idx] as usize,
            capture_limit,
        )),
        SyscallArgType::InputBuffer(_) => SyscallArg::Addr(0),
        SyscallArgType::OutputBuffer(length_idx) if at_exit && result >= 0 => {
            let length = (values[length_idx] as usize)
                .min(usize::try_from(result).expect("non-negative syscall result"));
            if value == 0 {
                SyscallArg::Addr(0)
            } else {
                SyscallArg::Bytes(read_buffer(pid, value, length, capture_limit))
            }
        }
        SyscallArgType::OutputBuffer(_) | SyscallArgType::Addr => SyscallArg::Addr(value as usize),
    }
}

fn read_buffer(pid: Pid, address: u64, length: usize, capture_limit: usize) -> Vec<u8> {
    let length = length.min(capture_limit).min(MAX_CAPTURE_BYTES);
    let mut bytes = Vec::with_capacity(length);
    let word_size = std::mem::size_of::<c_long>();
    for offset in (0..length).step_by(word_size) {
        let read_address = address.wrapping_add(offset as u64) as usize as *mut c_void;
        let Ok(word) = ptrace::read(pid, read_address) else {
            break;
        };
        let remaining = length - bytes.len();
        bytes.extend_from_slice(&word.to_ne_bytes()[..remaining.min(word_size)]);
    }
    bytes
}

pub fn read_string_array(pid: Pid, address: c_ulonglong) -> Vec<String> {
    read_string_array_limited(pid, address, MAX_CAPTURE_BYTES)
}

pub fn read_string_array_limited(
    pid: Pid,
    address: c_ulonglong,
    string_limit: usize,
) -> Vec<String> {
    let mut vec = Vec::new();
    if address == 0 {
        return vec;
    }

    // safety limit to avoid infinite loops on corrupt pointers
    let mut remaining = MAX_CAPTURE_BYTES;
    for offset in 0..MAX_ARRAY_ELEMENTS {
        let ptr_addr = address.wrapping_add((offset * std::mem::size_of::<usize>()) as u64) as usize
            as *mut c_void;
        let res: c_long = match ptrace::read(pid, ptr_addr) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ptr_value = c_ulonglong::from_ne_bytes(res.to_ne_bytes());
        if ptr_value == 0 {
            break;
        }
        if remaining == 0 {
            break;
        }
        let value = read_string_limited(pid, ptr_value, string_limit.min(remaining));
        remaining = remaining.saturating_sub(value.len().saturating_add(1));
        vec.push(value);
    }

    vec
}

/// Count pointers in a NULL-terminated `char * const *` array without attempting
/// to dereference the strings. This is more robust when the tracee's memory
/// cannot be fully read, but the pointer array itself is accessible.
pub fn read_string_array_count(pid: Pid, address: c_ulonglong) -> usize {
    if address == 0 {
        return 0;
    }

    let mut count = 0usize;
    for offset in 0..MAX_ARRAY_ELEMENTS {
        let ptr_addr = address.wrapping_add((offset * std::mem::size_of::<usize>()) as u64) as usize
            as *mut c_void;
        let res: c_long = match ptrace::read(pid, ptr_addr) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ptr_value = c_ulonglong::from_ne_bytes(res.to_ne_bytes());
        if ptr_value == 0 {
            break;
        }
        count += 1;
    }

    count
}

pub fn escape_to_string(buf: &Vec<u8>) -> String {
    let mut string = String::new();
    for c in buf {
        let code = *c;
        if (0x20..=0x7f).contains(&code) {
            if code == b'\\' {
                string.push_str("\\\\");
            } else {
                string.push(char::from(code));
            }
        } else {
            string.push_str(format!("\\{c:x}").as_str());
        }
    }
    string
}
