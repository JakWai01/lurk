use byteorder::{LittleEndian, WriteBytesExt};
use libc::{c_long, c_ulonglong, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::unistd::Pid;
use std::ffi::c_void;
use syscalls::Sysno;

#[cfg(any(target_arch = "aarch64", feature = "aarch64"))]
pub mod aarch64;
#[cfg(any(target_arch = "arm", feature = "arm"))]
pub mod arm;
#[cfg(any(target_arch = "mips", feature = "mips"))]
pub mod mips;
#[cfg(any(target_arch = "mips64", feature = "mips64"))]
pub mod mips64;
#[cfg(any(target_arch = "powerpc", feature = "powerpc"))]
pub mod powerpc;
#[cfg(any(target_arch = "powerpc64", feature = "powerpc64"))]
pub mod powerpc64;
#[cfg(any(target_arch = "s390x", feature = "s390x"))]
pub mod s390x;
#[cfg(any(target_arch = "sparc", feature = "sparc"))]
pub mod sparc;
#[cfg(any(target_arch = "sparc64", feature = "sparc64"))]
pub mod sparc64;
#[cfg(any(target_arch = "x86", feature = "x86"))]
pub mod x86;
#[cfg(any(target_arch = "x86_64", feature = "x86_64"))]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "arm")]
pub use arm::*;

#[cfg(target_arch = "mips")]
pub use mips::*;

#[cfg(target_arch = "mips64")]
pub use mips64::*;

#[cfg(target_arch = "powerpc")]
pub use powerpc::*;

#[cfg(target_arch = "powerpc64")]
pub use powerpc64::*;

#[cfg(target_arch = "s390x")]
pub use s390x::*;

#[cfg(target_arch = "sparc")]
pub use sparc::*;

#[cfg(target_arch = "sparc64")]
pub use sparc64::*;

#[cfg(target_arch = "x86")]
pub use x86::*;

use crate::syscall_info::{SyscallArg, SyscallArgs};
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[derive(Debug, Copy, Clone)]
pub enum SyscallArgType {
    // Integer can be used to represent int, fd and size_t
    Int,
    // String can be used to represent *buf
    Str,
    // Address can be used to represent *statbuf
    Addr,
}

pub fn read_string(pid: Pid, address: c_ulonglong) -> String {
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let address = unsafe { (address as *mut c_void).offset(count) };

        let res: c_long = match ptrace::read(pid, address) {
            Ok(c_long) => c_long,
            Err(_) => break 'done,
        };

        let mut bytes: Vec<u8> = vec![];
        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {res} as i64 LittleEndian: {err}");
        });
        for b in bytes {
            if b == 0 {
                break 'done;
            }
            string.push(b as char);
        }

        count += word_size;
    }

    string
}

pub fn enable_follow_forks(pid: Pid) -> nix::Result<()> {
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACEFORK | Options::PTRACE_O_TRACEVFORK | Options::PTRACE_O_TRACECLONE,
    )
}

pub fn parse_args(pid: Pid, syscall: Sysno, registers: user_regs_struct) -> SyscallArgs {
    #[allow(clippy::cast_sign_loss)]
    SyscallArgs(
        SYSCALLS[syscall.id() as usize]
            .1
            .iter()
            .filter_map(Option::as_ref)
            .enumerate()
            .map(|(idx, arg)| (arg, get_arg_value(registers, idx)))
            .map(|(arg, value)| match arg {
                SyscallArgType::Int => SyscallArg::Int(value as i64),
                SyscallArgType::Str => SyscallArg::Str(read_string(pid, value)),
                SyscallArgType::Addr => SyscallArg::Addr(value as usize),
            })
            .collect(),
    )
}
