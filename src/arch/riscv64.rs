#![allow(
    clippy::cast_sign_loss,
    clippy::type_complexity,
    clippy::used_underscore_binding
)]

use crate::arch::SyscallArgType;
#[cfg(target_arch = "riscv64")]
use libc::{c_ulonglong, user_regs_struct};
use std::ops::Index;
use syscalls::riscv64::Sysno;
#[cfg(target_arch = "riscv64")]
use syscalls::SysnoSet;

#[allow(clippy::enum_glob_use)]
#[cfg(target_arch = "riscv64")]
use syscalls::riscv64::Sysno::*;

#[cfg(target_arch = "riscv64")]
pub static TRACE_DESC: SysnoSet = SysnoSet::new(&[
    // strace/src/linux/64/syscallent.h
    fsetxattr,
    fgetxattr,
    flistxattr,
    fremovexattr,
    eventfd2,
    epoll_create1,
    epoll_ctl,
    epoll_pwait,
    dup,
    dup3,
    fcntl,
    inotify_init1,
    inotify_add_watch,
    inotify_rm_watch,
    ioctl,
    flock,
    mknodat,
    mkdirat,
    unlinkat,
    symlinkat,
    linkat,
    fstatfs,
    ftruncate,
    fallocate,
    faccessat,
    fchdir,
    fchmod,
    fchmodat,
    fchownat,
    fchown,
    openat,
    close,
    pipe2,
    getdents64,
    lseek,
    read,
    write,
    readv,
    writev,
    pread64,
    pwrite64,
    preadv,
    pwritev,
    sendfile,
    pselect6,
    ppoll,
    signalfd4,
    vmsplice,
    splice,
    tee,
    readlinkat,
    fstat,
    fsync,
    fdatasync,
    sync_file_range,
    timerfd_create,
    timerfd_settime,
    timerfd_gettime,
    utimensat,
    mq_open,
    mq_timedsend,
    mq_timedreceive,
    mq_notify,
    mq_getsetattr,
    readahead,
    mmap,
    fadvise64,
    perf_event_open,
    fanotify_init,
    fanotify_mark,
    name_to_handle_at,
    open_by_handle_at,
    syncfs,
    setns,
    finit_module,
    renameat2,
    memfd_create,
    bpf,
    execveat,
    userfaultfd,
    copy_file_range,
    preadv2,
    pwritev2,
    statx,
    kexec_file_load,
    // strace/src/linux/generic/syscallent-common.h
    pidfd_send_signal,
    io_uring_setup,
    io_uring_enter,
    io_uring_register,
    open_tree,
    move_mount,
    fsopen,
    fsconfig,
    fsmount,
    fspick,
    pidfd_open,
    openat2,
    pidfd_getfd,
    faccessat2,
    process_madvise,
    epoll_pwait2,
    mount_setattr,
    quotactl_fd,
    landlock_create_ruleset,
    landlock_add_rule,
    landlock_restrict_self,
    memfd_secret,
    process_mrelease,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_FILE: SysnoSet = SysnoSet::new(&[
    // strace/src/linux/64/syscallent.h
    setxattr,
    lsetxattr,
    getxattr,
    lgetxattr,
    listxattr,
    llistxattr,
    removexattr,
    lremovexattr,
    getcwd,
    inotify_add_watch,
    mknodat,
    mkdirat,
    unlinkat,
    symlinkat,
    linkat,
    umount2,
    mount,
    pivot_root,
    statfs,
    fstatfs,
    truncate,
    faccessat,
    chdir,
    chroot,
    fchmodat,
    fchownat,
    openat,
    quotactl,
    readlinkat,
    fstat,
    utimensat,
    acct,
    execve,
    swapon,
    swapoff,
    fanotify_mark,
    name_to_handle_at,
    renameat2,
    execveat,
    statx,
    // strace/src/linux/generic/syscallent-common.h
    open_tree,
    move_mount,
    fsconfig,
    fspick,
    openat2,
    faccessat2,
    mount_setattr,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_IPC: SysnoSet = SysnoSet::new(&[
    msgget, msgctl, msgrcv, msgsnd, semget, semctl, semtimedop, semop, shmget, shmctl, shmat, shmdt,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_NETWORK: SysnoSet = SysnoSet::new(&[
    sendfile,
    socket,
    socketpair,
    bind,
    listen,
    accept,
    connect,
    getsockname,
    getpeername,
    sendto,
    recvfrom,
    setsockopt,
    getsockopt,
    shutdown,
    sendmsg,
    recvmsg,
    accept4,
    recvmmsg,
    sendmmsg,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_PROCESS: SysnoSet = SysnoSet::new(&[
    // strace/src/linux/64/syscallent.h
    exit,
    exit_group,
    waitid,
    kill,
    tkill,
    tgkill,
    rt_sigqueueinfo,
    clone,
    execve,
    rt_tgsigqueueinfo,
    wait4,
    execveat,
    // strace/src/linux/generic/syscallent-common.h
    pidfd_send_signal,
    clone3,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_SIGNAL: SysnoSet = SysnoSet::new(&[
    // strace/src/linux/64/syscallent.h
    signalfd4,
    kill,
    tkill,
    tgkill,
    sigaltstack,
    rt_sigsuspend,
    rt_sigaction,
    rt_sigprocmask,
    rt_sigpending,
    rt_sigtimedwait,
    rt_sigqueueinfo,
    rt_sigreturn,
    rt_tgsigqueueinfo,
    // strace/src/linux/generic/syscallent-common.h
    pidfd_send_signal,
    io_uring_enter,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_MEMORY: SysnoSet = SysnoSet::new(&[
    // strace/src/linux/64/syscallent.h
    io_setup,
    io_destroy,
    shmat,
    shmdt,
    brk,
    munmap,
    mremap,
    mmap,
    mprotect,
    msync,
    mlock,
    munlock,
    mlockall,
    munlockall,
    mincore,
    madvise,
    remap_file_pages,
    mbind,
    get_mempolicy,
    set_mempolicy,
    migrate_pages,
    move_pages,
    mlock2,
    pkey_mprotect,
    // strace/src/linux/generic/syscallent-common.h
    io_uring_register,
    set_mempolicy_home_node,
    // strace/src/linux/riscv64/syscallent.h
    // riscv_flush_icache,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_STAT: SysnoSet = SysnoSet::new(&[fstat, statx]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_LSTAT: SysnoSet = SysnoSet::new(&[]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_FSTAT: SysnoSet = SysnoSet::new(&[fstat, statx]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_STAT_LIKE: SysnoSet = SysnoSet::new(&[fstat, statx]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_STATFS: SysnoSet = SysnoSet::new(&[statfs, fstatfs]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_FSTATFS: SysnoSet = SysnoSet::new(&[fstatfs]);
#[cfg(target_arch = "riscv64")]
pub static TRACE_STATFS_LIKE: SysnoSet = SysnoSet::new(&[statfs, fstatfs]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_PURE: SysnoSet =
    SysnoSet::new(&[getpid, getppid, getuid, geteuid, getgid, getegid, gettid]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_CREDS: SysnoSet = SysnoSet::new(&[
    capget, capset, setregid, setgid, setreuid, setuid, setresuid, getresuid, setresgid, getresgid,
    setfsuid, setfsgid, getgroups, setgroups, prctl, getuid, geteuid, getgid, getegid,
]);

#[cfg(target_arch = "riscv64")]
pub static TRACE_CLOCK: SysnoSet = SysnoSet::new(&[
    clock_settime,
    clock_gettime,
    clock_getres,
    gettimeofday,
    settimeofday,
    adjtimex,
    clock_adjtime,
]);

macro_rules! syscall {
    ($name:ident $(,)?) => {
        Some((Sysno::$name, [None, None, None, None, None, None]))
    };
    ($name:ident, $arg0:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, None, None, None, None, None]))
    };
    ($name:ident, $arg0:ident, $arg1:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, $arg1, None, None, None, None]))
    };
    ($name:ident, $arg0:ident, $arg1:ident, $arg2:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, $arg1, $arg2, None, None, None]))
    };
    ($name:ident, $arg0:ident, $arg1:ident, $arg2:ident, $arg3:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, $arg1, $arg2, $arg3, None, None]))
    };
    ($name:ident, $arg0:ident, $arg1:ident, $arg2:ident, $arg3:ident, $arg4:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, $arg1, $arg2, $arg3, $arg4, None]))
    };
    ($name:ident, $arg0:ident, $arg1:ident, $arg2:ident, $arg3:ident, $arg4:ident, $arg5:ident $(,)?) => {
        Some((Sysno::$name, [$arg0, $arg1, $arg2, $arg3, $arg4, $arg5]))
    };
}

const ADDR: Option<SyscallArgType> = Some(SyscallArgType::Addr);
const INT: Option<SyscallArgType> = Some(SyscallArgType::Int);
const STR: Option<SyscallArgType> = Some(SyscallArgType::Str);
const STRV: Option<SyscallArgType> = Some(SyscallArgType::StrArray);
const STRVS: Option<SyscallArgType> = Some(SyscallArgType::StrArraySummary);
const IN1: Option<SyscallArgType> = Some(SyscallArgType::InputBuffer(1));
const IN2: Option<SyscallArgType> = Some(SyscallArgType::InputBuffer(2));
const IN3: Option<SyscallArgType> = Some(SyscallArgType::InputBuffer(3));
const OUT1: Option<SyscallArgType> = Some(SyscallArgType::OutputBuffer(1));
const OUT2: Option<SyscallArgType> = Some(SyscallArgType::OutputBuffer(2));
const OUT3: Option<SyscallArgType> = Some(SyscallArgType::OutputBuffer(3));

pub struct Riscv64Syscalls {
    _0: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 38],
    _39: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 40],
    _80: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 164],
    _258: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 37],
    _424: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 28],
}

impl Riscv64Syscalls {
    pub fn get(&self, index: usize) -> Option<&Option<(Sysno, [Option<SyscallArgType>; 6])>> {
        let result = match index {
            0..=37 => &self._0[index],
            39..=78 => &self._39[index - 39],
            80..=243 => &self._80[index - 80],
            258..=294 => &self._258[index - 258],
            424..=451 => &self._424[index - 424],
            _ => return None,
        };
        Some(result)
    }
}

impl Index<usize> for Riscv64Syscalls {
    type Output = Option<(Sysno, [Option<SyscallArgType>; 6])>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("unimplemented syscall")
    }
}

pub static SYSCALLS: Riscv64Syscalls = Riscv64Syscalls {
    _0: [
        syscall!(io_setup, INT, ADDR),
        syscall!(io_destroy, INT),
        syscall!(io_submit, INT, INT, ADDR),
        syscall!(io_cancel, INT, ADDR, ADDR),
        syscall!(io_getevents, INT, INT, INT, ADDR, ADDR),
        syscall!(setxattr, STR, STR, IN3, INT, INT),
        syscall!(lsetxattr, STR, STR, IN3, INT, INT),
        syscall!(fsetxattr, INT, STR, IN3, INT, INT),
        syscall!(getxattr, STR, STR, OUT3, INT),
        syscall!(lgetxattr, STR, STR, OUT3, INT),
        syscall!(fgetxattr, INT, STR, OUT3, INT),
        syscall!(listxattr, STR, OUT2, INT),
        syscall!(llistxattr, STR, OUT2, INT),
        syscall!(flistxattr, INT, OUT2, INT),
        syscall!(removexattr, STR, STR),
        syscall!(lremovexattr, STR, STR),
        syscall!(fremovexattr, INT, STR),
        syscall!(getcwd, OUT1, INT),
        syscall!(lookup_dcookie, INT, OUT2, INT),
        syscall!(eventfd2, INT, INT),
        syscall!(epoll_create1, INT),
        syscall!(epoll_ctl, INT, INT, INT, ADDR),
        syscall!(epoll_pwait, INT, ADDR, INT, INT, ADDR, INT),
        syscall!(dup, INT),
        syscall!(dup3, INT, INT, INT),
        syscall!(fcntl, INT, INT, INT),
        syscall!(inotify_init1, INT),
        syscall!(inotify_add_watch, INT, STR, INT),
        syscall!(inotify_rm_watch, INT, INT),
        syscall!(ioctl, INT, INT, INT),
        syscall!(ioprio_set, INT, INT, INT),
        syscall!(ioprio_get, INT, INT),
        syscall!(flock, INT, INT),
        syscall!(mknodat, INT, STR, INT, INT),
        syscall!(mkdirat, INT, STR, INT),
        syscall!(unlinkat, INT, STR, INT),
        syscall!(symlinkat, STR, INT, STR),
        syscall!(linkat, INT, STR, INT, STR, INT),
    ],
    _39: [
        syscall!(umount2, STR, INT),
        syscall!(mount, STR, STR, STR, INT, ADDR),
        syscall!(pivot_root, STR, STR),
        syscall!(nfsservctl, INT, ADDR, ADDR),
        syscall!(statfs, STR, ADDR),
        syscall!(fstatfs, INT, ADDR),
        syscall!(truncate, STR, INT),
        syscall!(ftruncate, INT, INT),
        syscall!(fallocate, INT, INT, INT, INT),
        syscall!(faccessat, INT, STR, INT),
        syscall!(chdir, STR),
        syscall!(fchdir, INT),
        syscall!(chroot, STR),
        syscall!(fchmod, INT, INT),
        syscall!(fchmodat, INT, STR, INT),
        syscall!(fchownat, INT, STR, INT, INT, INT),
        syscall!(fchown, INT, INT, INT),
        syscall!(openat, INT, STR, INT, INT),
        syscall!(close, INT),
        syscall!(vhangup),
        syscall!(pipe2, ADDR, INT),
        syscall!(quotactl, INT, STR, INT, ADDR),
        syscall!(getdents64, INT, ADDR, INT),
        syscall!(lseek, INT, INT, INT),
        syscall!(read, INT, OUT2, INT),
        syscall!(write, INT, IN2, INT),
        syscall!(readv, INT, ADDR, INT),
        syscall!(writev, INT, ADDR, INT),
        syscall!(pread64, INT, OUT2, INT, INT),
        syscall!(pwrite64, INT, IN2, INT, INT),
        syscall!(preadv, INT, ADDR, INT, INT, INT),
        syscall!(pwritev, INT, ADDR, INT, INT, INT),
        syscall!(sendfile, INT, INT, ADDR, INT),
        syscall!(pselect6, INT, ADDR, ADDR, ADDR, ADDR, ADDR),
        syscall!(ppoll, ADDR, INT, ADDR, ADDR, INT),
        syscall!(signalfd4, INT, ADDR, INT, INT),
        syscall!(vmsplice, INT, ADDR, INT, INT),
        syscall!(splice, INT, ADDR, INT, ADDR, INT, INT),
        syscall!(tee, INT, INT, INT, INT),
        syscall!(readlinkat, INT, STR, OUT3, INT),
    ],
    _80: [
        syscall!(fstat, INT, ADDR),
        syscall!(sync),
        syscall!(fsync, INT),
        syscall!(fdatasync, INT),
        syscall!(sync_file_range, INT, INT, INT, INT),
        syscall!(timerfd_create, INT, INT),
        syscall!(timerfd_settime, INT, INT, ADDR, ADDR),
        syscall!(timerfd_gettime, INT, ADDR),
        syscall!(utimensat, INT, STR, ADDR, INT),
        syscall!(acct, STR),
        syscall!(capget, ADDR, ADDR),
        syscall!(capset, ADDR, ADDR),
        syscall!(personality, INT),
        syscall!(exit, INT),
        syscall!(exit_group, INT),
        syscall!(waitid, INT, INT, ADDR, INT, ADDR),
        syscall!(set_tid_address, ADDR),
        syscall!(unshare, INT),
        syscall!(futex, ADDR, INT, INT, ADDR, ADDR, INT),
        syscall!(set_robust_list, ADDR, INT),
        syscall!(get_robust_list, INT, ADDR, ADDR),
        syscall!(nanosleep, ADDR, ADDR),
        syscall!(getitimer, INT, ADDR),
        syscall!(setitimer, INT, ADDR, ADDR),
        syscall!(kexec_load, INT, INT, ADDR, INT),
        syscall!(init_module, ADDR, INT, STR),
        syscall!(delete_module, STR, INT),
        syscall!(timer_create, INT, ADDR, ADDR),
        syscall!(timer_gettime, INT, ADDR),
        syscall!(timer_getoverrun, INT),
        syscall!(timer_settime, INT, INT, ADDR, ADDR),
        syscall!(timer_delete, INT),
        syscall!(clock_settime, INT, ADDR),
        syscall!(clock_gettime, INT, ADDR),
        syscall!(clock_getres, INT, ADDR),
        syscall!(clock_nanosleep, INT, INT, ADDR, ADDR),
        syscall!(syslog, INT, OUT2, INT),
        syscall!(ptrace, INT, INT, INT, INT),
        syscall!(sched_setparam, INT, ADDR),
        syscall!(sched_setscheduler, INT, INT, ADDR),
        syscall!(sched_getscheduler, INT),
        syscall!(sched_getparam, INT, ADDR),
        syscall!(sched_setaffinity, INT, INT, ADDR),
        syscall!(sched_getaffinity, INT, INT, ADDR),
        syscall!(sched_yield),
        syscall!(sched_get_priority_max, INT),
        syscall!(sched_get_priority_min, INT),
        syscall!(sched_rr_get_interval, INT, ADDR),
        syscall!(restart_syscall),
        syscall!(kill, INT, INT),
        syscall!(tkill, INT, INT),
        syscall!(tgkill, INT, INT, INT),
        syscall!(sigaltstack, ADDR, ADDR),
        syscall!(rt_sigsuspend, ADDR, INT),
        syscall!(rt_sigaction, INT, ADDR, ADDR, INT),
        syscall!(rt_sigprocmask, INT, ADDR, ADDR, INT),
        syscall!(rt_sigpending, ADDR, INT),
        syscall!(rt_sigtimedwait, ADDR, ADDR, ADDR, INT),
        syscall!(rt_sigqueueinfo, INT, INT, ADDR),
        syscall!(rt_sigreturn),
        syscall!(setpriority, INT, INT, INT),
        syscall!(getpriority, INT, INT),
        syscall!(reboot, INT, INT, INT, ADDR),
        syscall!(setregid, INT, INT),
        syscall!(setgid, INT),
        syscall!(setreuid, INT, INT),
        syscall!(setuid, INT),
        syscall!(setresuid, INT, INT, INT),
        syscall!(getresuid, ADDR, ADDR, ADDR),
        syscall!(setresgid, INT, INT, INT),
        syscall!(getresgid, ADDR, ADDR, ADDR),
        syscall!(setfsuid, INT),
        syscall!(setfsgid, INT),
        syscall!(times, ADDR),
        syscall!(setpgid, INT, INT),
        syscall!(getpgid, INT),
        syscall!(getsid, INT),
        syscall!(setsid),
        syscall!(getgroups, INT, ADDR),
        syscall!(setgroups, INT, ADDR),
        syscall!(uname, ADDR),
        syscall!(sethostname, IN1, INT),
        syscall!(setdomainname, IN1, INT),
        syscall!(getrlimit, INT, ADDR),
        syscall!(setrlimit, INT, ADDR),
        syscall!(getrusage, INT, ADDR),
        syscall!(umask, INT),
        syscall!(prctl, INT, INT, INT, INT, INT),
        syscall!(getcpu, ADDR, ADDR, ADDR),
        syscall!(gettimeofday, ADDR, ADDR),
        syscall!(settimeofday, ADDR, ADDR),
        syscall!(adjtimex, ADDR),
        syscall!(getpid),
        syscall!(getppid),
        syscall!(getuid),
        syscall!(geteuid),
        syscall!(getgid),
        syscall!(getegid),
        syscall!(gettid),
        syscall!(sysinfo, ADDR),
        syscall!(mq_open, STR, INT, INT, ADDR),
        syscall!(mq_unlink, STR),
        syscall!(mq_timedsend, INT, IN2, INT, INT, ADDR),
        syscall!(mq_timedreceive, INT, OUT2, INT, ADDR, ADDR),
        syscall!(mq_notify, INT, ADDR),
        syscall!(mq_getsetattr, INT, ADDR, ADDR),
        syscall!(msgget, INT, INT),
        syscall!(msgctl, INT, INT, ADDR),
        syscall!(msgrcv, INT, ADDR, INT, INT, INT),
        syscall!(msgsnd, INT, ADDR, INT, INT),
        syscall!(semget, INT, INT, INT),
        syscall!(semctl, INT, INT, INT, INT),
        syscall!(semtimedop, INT, ADDR, INT, ADDR),
        syscall!(semop, INT, ADDR, INT),
        syscall!(shmget, INT, INT, INT),
        syscall!(shmctl, INT, INT, ADDR),
        syscall!(shmat, INT, STR, INT),
        syscall!(shmdt, STR),
        syscall!(socket, INT, INT, INT),
        syscall!(socketpair, INT, INT, INT, ADDR),
        syscall!(bind, INT, ADDR, INT),
        syscall!(listen, INT, INT),
        syscall!(accept, INT, ADDR, ADDR),
        syscall!(connect, INT, ADDR, INT),
        syscall!(getsockname, INT, ADDR, ADDR),
        syscall!(getpeername, INT, ADDR, ADDR),
        syscall!(sendto, INT, IN2, INT, INT, ADDR, INT),
        syscall!(recvfrom, INT, OUT2, INT, INT, ADDR, ADDR),
        syscall!(setsockopt, INT, INT, INT, ADDR, INT),
        syscall!(getsockopt, INT, INT, INT, ADDR, ADDR),
        syscall!(shutdown, INT, INT),
        syscall!(sendmsg, INT, ADDR, INT),
        syscall!(recvmsg, INT, ADDR, INT),
        syscall!(readahead, INT, INT, INT),
        syscall!(brk, INT),
        syscall!(munmap, INT, INT),
        syscall!(mremap, INT, INT, INT, INT, INT),
        syscall!(add_key, STR, STR, IN3, INT, INT),
        syscall!(request_key, STR, STR, STR, INT),
        syscall!(keyctl, INT, INT, INT, INT, INT),
        syscall!(clone, INT, INT, ADDR, INT, ADDR),
        syscall!(execve, STR, STRV, STRVS),
        syscall!(mmap, ADDR, INT, INT, INT, INT, INT),
        syscall!(fadvise64, INT, INT, INT, INT),
        syscall!(swapon, STR, INT),
        syscall!(swapoff, STR),
        syscall!(mprotect, INT, INT, INT),
        syscall!(msync, INT, INT, INT),
        syscall!(mlock, INT, INT),
        syscall!(munlock, INT, INT),
        syscall!(mlockall, INT),
        syscall!(munlockall),
        syscall!(mincore, INT, INT, ADDR),
        syscall!(madvise, INT, INT, INT),
        syscall!(remap_file_pages, INT, INT, INT, INT, INT),
        syscall!(mbind, INT, INT, INT, ADDR, INT, INT),
        syscall!(get_mempolicy, ADDR, ADDR, INT, INT, INT),
        syscall!(set_mempolicy, INT, ADDR, INT),
        syscall!(migrate_pages, INT, INT, ADDR, ADDR),
        syscall!(move_pages, INT, INT, ADDR, ADDR, ADDR, INT),
        syscall!(rt_tgsigqueueinfo, INT, INT, INT, ADDR),
        syscall!(perf_event_open, ADDR, INT, INT, INT, INT),
        syscall!(accept4, INT, ADDR, ADDR, INT),
        syscall!(recvmmsg, INT, ADDR, INT, INT, ADDR),
    ],
    _258: [
        syscall!(riscv_hwprobe, ADDR, INT, INT, ADDR, INT),
        syscall!(riscv_flush_icache, ADDR, ADDR, INT),
        syscall!(wait4, INT, ADDR, INT, ADDR),
        syscall!(prlimit64, INT, INT, ADDR, ADDR),
        syscall!(fanotify_init, INT, INT),
        syscall!(fanotify_mark, INT, INT, INT, INT, STR),
        syscall!(name_to_handle_at, INT, STR, ADDR, INT, INT),
        syscall!(open_by_handle_at, INT, ADDR, INT),
        syscall!(clock_adjtime, INT, ADDR),
        syscall!(syncfs, INT),
        syscall!(setns, INT, INT),
        syscall!(sendmmsg, INT, ADDR, INT, INT),
        syscall!(process_vm_readv, INT, ADDR, INT, ADDR, INT, INT),
        syscall!(process_vm_writev, INT, ADDR, INT, ADDR, INT, INT),
        syscall!(kcmp, INT, INT, INT, INT, INT),
        syscall!(finit_module, INT, STR, INT),
        syscall!(sched_setattr, INT, ADDR, INT),
        syscall!(sched_getattr, INT, ADDR, INT, INT),
        syscall!(renameat2, INT, STR, INT, STR, INT),
        syscall!(seccomp, INT, INT, ADDR),
        syscall!(getrandom, OUT1, INT, INT),
        syscall!(memfd_create, STR, INT),
        syscall!(bpf, INT, ADDR, INT),
        syscall!(execveat, INT, STR, STRV, STRVS, INT),
        syscall!(userfaultfd, INT),
        syscall!(membarrier, INT, INT, INT),
        syscall!(mlock2, INT, INT, INT),
        syscall!(copy_file_range, INT, ADDR, INT, ADDR, INT, INT),
        syscall!(preadv2, INT, ADDR, INT, INT, INT, INT),
        syscall!(pwritev2, INT, ADDR, INT, INT, INT, INT),
        syscall!(pkey_mprotect, INT, INT, INT, INT),
        syscall!(pkey_alloc, INT, INT),
        syscall!(pkey_free, INT),
        syscall!(statx, INT, STR, INT, INT, ADDR),
        syscall!(io_pgetevents, INT, INT, INT, ADDR, ADDR, ADDR),
        syscall!(rseq, ADDR, INT, INT, INT),
        syscall!(kexec_file_load, INT, INT, INT, STR, INT),
    ],
    _424: [
        syscall!(pidfd_send_signal, INT, INT, ADDR, INT),
        syscall!(io_uring_setup, INT, ADDR),
        syscall!(io_uring_enter, INT, INT, INT, INT, ADDR, INT),
        syscall!(io_uring_register, INT, INT, ADDR, INT),
        syscall!(open_tree, INT, STR, INT),
        syscall!(move_mount, INT, STR, INT, STR, INT),
        syscall!(fsopen, STR, INT),
        syscall!(fsconfig, INT, INT, STR, ADDR, INT),
        syscall!(fsmount, INT, INT, INT),
        syscall!(fspick, INT, STR, INT),
        syscall!(pidfd_open, INT, INT),
        syscall!(clone3, ADDR, INT),
        syscall!(close_range, INT, INT, INT),
        syscall!(openat2, INT, STR, ADDR, INT),
        syscall!(pidfd_getfd, INT, INT, INT),
        syscall!(faccessat2, INT, STR, INT, INT),
        syscall!(process_madvise, INT, ADDR, INT, INT, INT),
        syscall!(epoll_pwait2, INT, ADDR, INT, ADDR, ADDR, INT),
        syscall!(mount_setattr, INT, STR, INT, ADDR, INT),
        syscall!(quotactl_fd, INT, INT, INT, ADDR),
        syscall!(landlock_create_ruleset, ADDR, INT, INT),
        syscall!(landlock_add_rule, INT, ADDR, ADDR, INT),
        syscall!(landlock_restrict_self, INT, INT),
        syscall!(memfd_secret, INT),
        syscall!(process_mrelease, INT, INT),
        syscall!(futex_waitv, ADDR, INT, INT, ADDR, INT),
        syscall!(set_mempolicy_home_node, INT, INT, INT, INT),
        syscall!(cachestat, INT, INT, INT, INT),
    ],
};

#[cfg(target_arch = "riscv64")]
pub fn get_arg_value(registers: user_regs_struct, i: usize) -> c_ulonglong {
    match i {
        0 => registers.a0,
        1 => registers.a1,
        2 => registers.a2,
        3 => registers.a3,
        4 => registers.a4,
        5 => registers.a5,
        v => panic!("Invalid system call index {v}!"),
    }
}

// test that all syscalls match their syscall number
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_numbers() {
        for (i, sysno, ..) in SYSCALLS._0.iter().enumerate() {
            if let Some((sysno, _)) = sysno {
                assert_eq!(i, sysno.id() as usize);
            }
        }
        for (i, sysno, ..) in SYSCALLS._258.iter().enumerate() {
            if let Some((sysno, _)) = sysno {
                assert_eq!(i + 258, sysno.id() as usize);
            }
        }
        for (i, sysno, ..) in SYSCALLS._424.iter().enumerate() {
            if let Some((sysno, _)) = sysno {
                assert_eq!(i + 424, sysno.id() as usize);
            }
        }
    }
}
