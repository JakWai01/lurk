use crate::arch::SyscallArgType;
use libc::{c_ulonglong, user_regs_struct};
use syscalls::x86_64::Sysno;
use syscalls::SysnoSet;

#[allow(clippy::enum_glob_use)]
use syscalls::x86_64::Sysno::*;

pub static TRACE_DESC: SysnoSet = SysnoSet::new(&[
    read,
    write,
    open,
    close,
    fstat,
    poll,
    lseek,
    mmap,
    pread64,
    pwrite64,
    readv,
    writev,
    pipe,
    select,
    dup,
    dup2,
    sendfile,
    fcntl,
    flock,
    fsync,
    fdatasync,
    ftruncate,
    getdents,
    fchdir,
    creat,
    fchmod,
    fchown,
    readahead,
    fsetxattr,
    fgetxattr,
    flistxattr,
    fremovexattr,
    epoll_create,
    getdents64,
    fadvise64,
    epoll_wait,
    epoll_ctl,
    mq_open,
    mq_timedsend,
    mq_timedreceive,
    mq_notify,
    mq_getsetattr,
    inotify_init,
    inotify_add_watch,
    inotify_rm_watch,
    openat,
    mkdirat,
    mknodat,
    fchownat,
    futimesat,
    newfstatat,
    unlinkat,
    renameat,
    linkat,
    symlinkat,
    readlinkat,
    fchmodat,
    faccessat,
    pselect6,
    ppoll,
    splice,
    tee,
    sync_file_range,
    vmsplice,
    utimensat,
    epoll_pwait,
    signalfd,
    timerfd_create,
    eventfd,
    fallocate,
    timerfd_settime,
    timerfd_gettime,
    signalfd4,
    eventfd2,
    epoll_create1,
    dup3,
    pipe2,
    inotify_init1,
    preadv,
    pwritev,
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
    kexec_file_load,
    bpf,
    execveat,
    userfaultfd,
    copy_file_range,
    preadv2,
    pwritev2,
    statx,
]);

pub static TRACE_FILE: SysnoSet = SysnoSet::new(&[
    open,
    stat,
    lstat,
    access,
    shmget,
    truncate,
    getcwd,
    chdir,
    rename,
    mkdir,
    rmdir,
    creat,
    link,
    unlink,
    symlink,
    readlink,
    chmod,
    chown,
    lchown,
    utime,
    mknod,
    uselib,
    statfs,
    fstatfs,
    pivot_root,
    chroot,
    acct,
    mount,
    umount2,
    swapon,
    swapoff,
    quotactl,
    setxattr,
    lsetxattr,
    getxattr,
    lgetxattr,
    listxattr,
    llistxattr,
    removexattr,
    lremovexattr,
    utimes,
    inotify_add_watch,
    openat,
    mkdirat,
    mknodat,
    fchownat,
    futimesat,
    newfstatat,
    unlinkat,
    renameat,
    linkat,
    symlinkat,
    readlinkat,
    fchmodat,
    faccessat,
    utimensat,
    fanotify_mark,
    name_to_handle_at,
    renameat2,
    statx,
]);

pub static TRACE_IPC: SysnoSet = SysnoSet::new(&[
    shmget, shmat, shmctl, semget, semop, semctl, shmdt, msgget, msgsnd, msgrcv, msgctl, semtimedop,
]);

pub static TRACE_NETWORK: SysnoSet = SysnoSet::new(&[
    socket,
    connect,
    accept,
    sendto,
    recvfrom,
    sendmsg,
    recvmsg,
    shutdown,
    bind,
    listen,
    getsockname,
    getpeername,
    socketpair,
    setsockopt,
    getsockopt,
    getpmsg,
    putpmsg,
    recvmmsg,
    sendmmsg,
]);

pub static TRACE_PROCESS: SysnoSet = SysnoSet::new(&[
    clone,
    fork,
    vfork,
    execve,
    exit,
    wait4,
    kill,
    rt_sigqueueinfo,
    tkill,
    exit_group,
    tgkill,
    waitid,
    rt_tgsigqueueinfo,
    execveat,
]);

pub static TRACE_SIGNAL: SysnoSet = SysnoSet::new(&[
    rt_sigaction,
    rt_sigprocmask,
    rt_sigreturn,
    pause,
    rt_sigpending,
    rt_sigtimedwait,
    rt_sigqueueinfo,
    rt_sigsuspend,
    sigaltstack,
    tkill,
    signalfd,
    signalfd4,
    rt_tgsigqueueinfo,
    pidfd_send_signal,
]);

pub static TRACE_MEMORY: SysnoSet = SysnoSet::new(&[
    mmap,
    mprotect,
    munmap,
    brk,
    mremap,
    msync,
    mincore,
    madvise,
    shmat,
    mlock,
    munlock,
    mlockall,
    munlockall,
    io_setup,
    io_destroy,
    remap_file_pages,
    mbind,
    set_mempolicy,
    get_mempolicy,
    migrate_pages,
    move_pages,
    mlock2,
    pkey_mprotect,
]);

pub static TRACE_STAT: SysnoSet = SysnoSet::new(&[stat]);
pub static TRACE_LSTAT: SysnoSet = SysnoSet::new(&[lstat]);
pub static TRACE_FSTAT: SysnoSet = SysnoSet::new(&[fstat, newfstatat, statx]);
pub static TRACE_STAT_LIKE: SysnoSet = SysnoSet::new(&[stat, fstat, lstat, newfstatat, statx]);
pub static TRACE_STATFS: SysnoSet = SysnoSet::new(&[statfs]);
pub static TRACE_FSTATFS: SysnoSet = SysnoSet::new(&[fstatfs]);
pub static TRACE_STATFS_LIKE: SysnoSet = SysnoSet::new(&[ustat, statfs, fstatfs]);

pub static TRACE_PURE: SysnoSet = SysnoSet::new(&[
    getpid, getuid, getgid, geteuid, getegid, getppid, getpgrp, gettid,
]);

pub static TRACE_CREDS: SysnoSet = SysnoSet::new(&[
    getuid, getgid, setuid, setgid, geteuid, getegid, setreuid, setregid, getgroups, setgroups,
    setresuid, getresuid, setresgid, getresgid, setfsuid, setfsgid, capget, capset, prctl,
]);

pub static TRACE_CLOCK: SysnoSet = SysnoSet::new(&[
    gettimeofday,
    adjtimex,
    settimeofday,
    time,
    clock_settime,
    clock_gettime,
    clock_getres,
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
const VEC_STR: Option<SyscallArgType> = Some(SyscallArgType::VecStr);

pub static SYSCALLS: [Option<(Sysno, [Option<SyscallArgType>; 6])>; 452] = [
    // DESC
    syscall!(read, INT, STR, INT),
    // DESC
    syscall!(write, INT, STR, INT),
    // DESC, FILE
    syscall!(open, STR, INT, INT),
    // DESC
    syscall!(close, INT),
    // FILE, STAT, STAT_LIKE
    syscall!(stat, STR, ADDR),
    // DESC, FSTAT, STAT_LIKE
    syscall!(fstat, INT, ADDR),
    // FILE, LSTAT, STAT_LIKE
    syscall!(lstat, STR, ADDR),
    // DESC
    syscall!(poll, ADDR, INT, INT),
    // DESC
    syscall!(lseek, INT, INT, INT),
    // DESC, MEMORY
    syscall!(mmap, ADDR, INT, INT, INT, INT, INT),
    // MEMORY
    syscall!(mprotect, ADDR, INT, INT),
    // MEMORY
    syscall!(munmap, ADDR, INT),
    // MEMORY
    syscall!(brk, ADDR),
    // SIGNAL
    syscall!(rt_sigaction, INT, ADDR, ADDR),
    // SIGNAL
    syscall!(rt_sigprocmask, INT, ADDR, ADDR, INT),
    // SIGNAL
    syscall!(rt_sigreturn),
    syscall!(ioctl, INT, INT, ADDR),
    // DESC
    syscall!(pread64, INT, STR, INT, INT),
    // DESC
    syscall!(pwrite64, INT, STR, INT, INT),
    // DESC
    syscall!(readv, INT, ADDR, INT),
    // DESC
    syscall!(writev, INT, ADDR, INT),
    // FILE
    syscall!(access, STR, INT),
    // DESC
    syscall!(pipe, INT, INT),
    // DESC
    syscall!(select, INT, ADDR, ADDR, ADDR, ADDR),
    syscall!(sched_yield, ADDR),
    // MEMORY
    syscall!(mremap, ADDR, INT, INT, INT, ADDR),
    // MEMORY
    syscall!(msync, ADDR, INT, INT),
    // MEMORY
    syscall!(mincore, ADDR, INT, ADDR),
    // MEMORY
    syscall!(madvise, ADDR, INT, INT),
    // FILE, IPC
    syscall!(shmget, INT, INT, INT),
    // IPC, MEMORY
    syscall!(shmat, INT, ADDR, INT),
    // IPC
    syscall!(shmctl, INT, INT, STR),
    // DESC
    syscall!(dup, INT),
    // DESC
    syscall!(dup2, INT, INT),
    // SIGNAL
    syscall!(pause, ADDR),
    syscall!(nanosleep, ADDR, ADDR),
    syscall!(getitimer, INT, ADDR),
    syscall!(alarm, INT),
    syscall!(setitimer, INT, ADDR),
    // PURE
    syscall!(getpid, ADDR),
    // DESC
    syscall!(sendfile, INT, INT, ADDR, INT),
    // NETWORK
    syscall!(socket, INT, INT, INT),
    // NETWORK
    syscall!(connect, INT, ADDR, INT),
    // NETWORK
    syscall!(accept, INT, ADDR, ADDR),
    // NETWORK
    syscall!(sendto, INT, STR, INT, INT),
    // NETWORK
    syscall!(recvfrom, INT, STR, INT, INT, ADDR, ADDR),
    // NETWORK
    syscall!(sendmsg, INT, ADDR, INT),
    // NETWORK
    syscall!(recvmsg, INT, ADDR, INT),
    // NETWORK
    syscall!(shutdown, INT, INT),
    // NETWORK
    syscall!(bind, INT, ADDR, INT),
    // NETWORK
    syscall!(listen, INT, INT),
    // NETWORK
    syscall!(getsockname, INT, ADDR, ADDR),
    // NETWORK
    syscall!(getpeername, INT, ADDR, ADDR),
    // NETWORK
    syscall!(socketpair, INT, INT, INT, INT),
    // NETWORK
    syscall!(setsockopt, INT, INT, INT, ADDR, INT),
    // NETWORK
    syscall!(getsockopt, INT, INT, INT, ADDR, ADDR),
    // PROCESS
    syscall!(clone, ADDR, INT),
    // PROCESS
    syscall!(fork, ADDR),
    // PROCESS
    syscall!(vfork, ADDR),
    // PROCESS
    syscall!(execve, STR, VEC_STR, VEC_STR),
    // PROCESS
    syscall!(exit, INT),
    // PROCESS
    syscall!(wait4, INT, INT, INT, ADDR),
    // PROCESS
    syscall!(kill, INT, INT),
    syscall!(uname, ADDR),
    // IPC
    syscall!(semget, INT, INT, INT),
    // IPC
    syscall!(semop, INT, ADDR, INT),
    // IPC
    syscall!(semctl, INT, INT, INT),
    // IPC
    syscall!(shmdt, INT, ADDR, INT),
    // IPC
    syscall!(msgget, INT, INT),
    // IPC
    syscall!(msgsnd, INT, ADDR, INT, INT),
    // IPC
    syscall!(msgrcv, INT, ADDR, INT, INT, INT),
    // IPC
    syscall!(msgctl, INT, INT, ADDR),
    // DESC
    syscall!(fcntl, INT, INT),
    // DESC
    syscall!(flock, INT, INT),
    // DESC
    syscall!(fsync, INT),
    // DESC
    syscall!(fdatasync, INT),
    // FILE
    syscall!(truncate, STR, INT),
    // DESC
    syscall!(ftruncate, INT, INT),
    // DESC
    syscall!(getdents, INT, ADDR, INT),
    // FILE
    syscall!(getcwd, STR, INT),
    // FILE
    syscall!(chdir, STR),
    // DESC
    syscall!(fchdir, INT),
    // FILE
    syscall!(rename, STR, STR),
    // FILE
    syscall!(mkdir, STR, INT),
    // FILE
    syscall!(rmdir, STR),
    // DESC, FILE
    syscall!(creat, STR, INT),
    // FILE
    syscall!(link, STR, STR),
    // FILE
    syscall!(unlink, STR),
    // FILE
    syscall!(symlink, STR, STR),
    // FILE
    syscall!(readlink, STR, STR, INT),
    // FILE
    syscall!(chmod, STR, INT),
    // DESC
    syscall!(fchmod, INT, INT),
    // FILE
    syscall!(chown, STR, INT, INT),
    // DESC
    syscall!(fchown, INT, INT, INT),
    // FILE
    syscall!(lchown, STR, INT, INT),
    syscall!(umask, INT),
    // CLOCK
    syscall!(gettimeofday, ADDR, ADDR),
    syscall!(getrlimit, INT, ADDR),
    syscall!(getrusage, INT, ADDR),
    syscall!(sysinfo, ADDR),
    syscall!(times, ADDR),
    syscall!(ptrace, ADDR, INT, ADDR, ADDR),
    // CREDS, PURE
    syscall!(getuid, ADDR),
    syscall!(syslog, INT, STR, INT),
    // CREDS, PURE
    syscall!(getgid, ADDR),
    // CREDS
    syscall!(setuid, INT),
    // CREDS
    syscall!(setgid, INT),
    // CREDS, PURE
    syscall!(geteuid, ADDR),
    // CREDS, PURE
    syscall!(getegid, ADDR),
    syscall!(setpgid, INT, INT, INT),
    // PURE
    syscall!(getppid, ADDR),
    // PURE
    syscall!(getpgrp, ADDR),
    syscall!(setsid, ADDR),
    // CREDS
    syscall!(setreuid, INT, INT),
    // CREDS
    syscall!(setregid, INT, INT),
    // CREDS
    syscall!(getgroups, INT, INT),
    // CREDS
    syscall!(setgroups, INT, INT),
    // CREDS
    syscall!(setresuid, INT, INT, INT),
    // CREDS
    syscall!(getresuid, INT, INT, INT),
    // CREDS
    syscall!(setresgid, INT, INT, INT),
    // CREDS
    syscall!(getresgid, INT, INT, INT),
    syscall!(getpgid, INT),
    // CREDS
    syscall!(setfsuid, INT),
    // CREDS
    syscall!(setfsgid, INT),
    syscall!(getsid, INT),
    // CREDS
    syscall!(capget, ADDR, ADDR),
    // CREDS
    syscall!(capset, ADDR, ADDR),
    // SIGNAL
    syscall!(rt_sigpending, ADDR),
    // SIGNAL
    syscall!(rt_sigtimedwait, ADDR, ADDR, ADDR),
    // PROCESS, SIGNAL
    syscall!(rt_sigqueueinfo, INT, INT, ADDR),
    // SIGNAL
    syscall!(rt_sigsuspend, INT),
    // SIGNAL
    syscall!(sigaltstack, ADDR, ADDR),
    // FILE
    syscall!(utime, STR, ADDR, INT),
    // FILE
    syscall!(mknod, STR, INT, INT),
    // FILE
    syscall!(uselib, ADDR),
    syscall!(personality, INT),
    // STATFS_LIKE
    syscall!(ustat, INT, ADDR),
    // FILE, STATFS, STATFS_LIKE
    syscall!(statfs, STR, ADDR),
    // FILE, FSTATFS, STATFS_LIKE
    syscall!(fstatfs, INT, ADDR),
    syscall!(sysfs, INT, STR),
    syscall!(getpriority, INT, INT),
    syscall!(setpriority, INT, INT, INT),
    syscall!(sched_setparam, INT, ADDR),
    syscall!(sched_getparam, INT, ADDR),
    syscall!(sched_setscheduler, INT, INT, ADDR),
    syscall!(sched_getscheduler, INT),
    syscall!(sched_get_priority_max, INT),
    syscall!(sched_get_priority_min, INT),
    syscall!(sched_rr_get_interval, INT, ADDR),
    // MEMORY
    syscall!(mlock, ADDR, INT),
    // MEMORY
    syscall!(munlock, ADDR, INT),
    // MEMORY
    syscall!(mlockall, INT),
    // MEMORY
    syscall!(munlockall, ADDR),
    syscall!(vhangup, ADDR),
    syscall!(modify_ldt, INT, ADDR, INT),
    // FILE
    syscall!(pivot_root, STR, STR),
    syscall!(_sysctl, ADDR),
    // CREDS
    syscall!(prctl, INT, INT, INT, INT, INT),
    syscall!(arch_prctl, INT, ADDR),
    // CLOCK
    syscall!(adjtimex, STR),
    syscall!(setrlimit, INT, ADDR),
    // FILE
    syscall!(chroot, STR),
    syscall!(sync, INT),
    // FILE
    syscall!(acct, STR),
    // CLOCK
    syscall!(settimeofday, ADDR, ADDR),
    // FILE
    syscall!(mount, STR, STR, STR, INT, ADDR),
    // FILE
    syscall!(umount2, STR, INT),
    // FILE
    syscall!(swapon, STR, INT),
    // FILE
    syscall!(swapoff, STR),
    syscall!(reboot, INT, INT, INT, ADDR),
    syscall!(sethostname, STR, INT),
    syscall!(setdomainname, STR, INT),
    syscall!(iopl, INT),
    syscall!(ioperm, INT, INT, INT),
    syscall!(create_module, STR, INT),
    syscall!(init_module, ADDR, INT, STR),
    syscall!(delete_module, STR, INT),
    syscall!(get_kernel_syms, ADDR),
    syscall!(query_module, STR, INT, STR, INT, INT),
    // FILE
    syscall!(quotactl, INT, STR, INT, ADDR),
    syscall!(nfsservctl, INT, ADDR, ADDR),
    // NETWORK
    syscall!(getpmsg),
    // NETWORK
    syscall!(putpmsg),
    syscall!(afs_syscall),
    syscall!(tuxcall),
    syscall!(security),
    // PURE
    syscall!(gettid, ADDR),
    // DESC
    syscall!(readahead, INT, INT, INT),
    // FILE
    syscall!(setxattr, STR, STR, ADDR, INT, INT),
    // FILE
    syscall!(lsetxattr, STR, STR, ADDR, INT, INT),
    // DESC
    syscall!(fsetxattr, INT, STR, ADDR, INT, INT),
    // FILE
    syscall!(getxattr, STR, STR, ADDR, INT),
    // FILE
    syscall!(lgetxattr, STR, STR, ADDR, INT),
    // DESC
    syscall!(fgetxattr, INT, STR, ADDR, INT),
    // FILE
    syscall!(listxattr, STR, STR, INT),
    // FILE
    syscall!(llistxattr, STR, STR, INT),
    // DESC
    syscall!(flistxattr, INT, STR, INT),
    // FILE
    syscall!(removexattr, STR, STR),
    // FILE
    syscall!(lremovexattr, STR, STR),
    // DESC
    syscall!(fremovexattr, INT, STR),
    // PROCESS, SIGNAL
    syscall!(tkill, INT, INT),
    // CLOCK
    syscall!(time, INT),
    syscall!(futex, ADDR, INT, INT, ADDR, INT, INT),
    syscall!(sched_setaffinity, INT, INT, INT),
    syscall!(sched_getaffinity, INT, INT, INT),
    syscall!(set_thread_area, ADDR),
    // MEMORY
    syscall!(io_setup, INT, ADDR),
    // MEMORY
    syscall!(io_destroy, INT),
    syscall!(io_getevents, INT, INT, INT, ADDR, INT),
    syscall!(io_submit, INT, INT, ADDR),
    syscall!(io_cancel, INT, ADDR, ADDR),
    syscall!(get_thread_area, ADDR),
    syscall!(lookup_dcookie, INT, STR, INT),
    // DESC
    syscall!(epoll_create, INT),
    syscall!(epoll_ctl_old, INT, INT, INT, ADDR),
    syscall!(epoll_wait_old, INT, ADDR, INT, INT),
    // MEMORY
    syscall!(remap_file_pages, ADDR, INT, INT, INT, INT),
    // DESC
    syscall!(getdents64, INT, ADDR, INT),
    syscall!(set_tid_address, ADDR),
    syscall!(restart_syscall, ADDR),
    // IPC
    syscall!(semtimedop, INT, ADDR, INT),
    // DESC
    syscall!(fadvise64, INT, INT, INT, INT),
    syscall!(timer_create, INT, ADDR, INT),
    syscall!(timer_settime, INT, INT, ADDR, ADDR),
    syscall!(timer_gettime, INT, ADDR),
    syscall!(timer_getoverrun, INT),
    syscall!(timer_delete, INT),
    // CLOCK
    syscall!(clock_settime, INT, ADDR),
    // CLOCK
    syscall!(clock_gettime, INT, ADDR),
    // CLOCK
    syscall!(clock_getres, INT, ADDR),
    syscall!(clock_nanosleep, INT, INT, ADDR, ADDR),
    // PROCESS
    syscall!(exit_group, INT),
    // DESC
    syscall!(epoll_wait, INT, ADDR, INT, INT),
    // DESC
    syscall!(epoll_ctl, INT, INT, INT, ADDR),
    // PROCESS
    syscall!(tgkill, INT, INT, INT),
    // FILE
    syscall!(utimes, STR, ADDR),
    syscall!(vserver),
    // MEMORY
    syscall!(mbind, ADDR, INT, INT, INT, INT, INT),
    // MEMORY
    syscall!(set_mempolicy, INT, INT, INT),
    // MEMORY
    syscall!(get_mempolicy, INT, INT, INT, ADDR, INT),
    // DESC
    syscall!(mq_open, STR, INT),
    syscall!(mq_unlink, STR),
    // DESC
    syscall!(mq_timedsend, INT, STR, INT, INT),
    // DESC
    syscall!(mq_timedreceive, INT, ADDR, INT, INT, ADDR),
    // DESC
    syscall!(mq_notify, INT, ADDR),
    // DESC
    syscall!(mq_getsetattr, INT, ADDR, ADDR),
    syscall!(kexec_load, INT, INT, ADDR, INT),
    // PROCESS
    syscall!(waitid, INT, INT, INT, INT),
    syscall!(add_key, STR, STR, ADDR, INT, INT),
    syscall!(request_key, STR, STR, STR, INT),
    syscall!(keyctl, INT),
    syscall!(ioprio_set, INT, INT),
    syscall!(ioprio_get, INT, INT),
    // DESC
    syscall!(inotify_init, ADDR),
    // DESC, FILE
    syscall!(inotify_add_watch, INT, STR, INT),
    // DESC
    syscall!(inotify_rm_watch, INT, INT),
    // MEMORY
    syscall!(migrate_pages, INT, INT, INT, INT),
    // DESC, FILE
    syscall!(openat, INT, STR, INT),
    // DESC, FILE
    syscall!(mkdirat, INT, STR, INT),
    // DESC, FILE
    syscall!(mknodat, INT, STR, INT, INT),
    // DESC, FILE
    syscall!(fchownat, INT, STR, INT, INT, INT),
    // DESC, FILE
    syscall!(futimesat, INT, STR, ADDR),
    // DESC, FILE, FSTAT, STAT_LIKE
    syscall!(newfstatat, INT, STR, ADDR, INT),
    // DESC, FILE
    syscall!(unlinkat, INT, STR, INT),
    // DESC, FILE
    syscall!(renameat, INT, STR, INT, STR),
    // DESC, FILE
    syscall!(linkat, INT, STR, INT, STR, INT),
    // DESC, FILE
    syscall!(symlinkat, STR, INT, STR),
    // DESC, FILE
    syscall!(readlinkat, INT, STR, STR, INT),
    // DESC, FILE
    syscall!(fchmodat, INT, STR, INT, INT),
    // DESC, FILE
    syscall!(faccessat, INT, STR, INT, INT),
    // DESC
    syscall!(pselect6, INT, INT, INT, INT, ADDR, INT),
    // DESC
    syscall!(ppoll, INT, INT, ADDR, INT),
    syscall!(unshare, INT),
    syscall!(set_robust_list, ADDR, INT),
    syscall!(get_robust_list, INT, ADDR, INT),
    // DESC
    syscall!(splice, INT, INT, INT, INT, INT, INT),
    // DESC
    syscall!(tee, INT, INT, INT, INT),
    // DESC
    syscall!(sync_file_range, INT, INT, INT, INT),
    // DESC
    syscall!(vmsplice, INT, ADDR, INT, INT),
    // MEMORY
    syscall!(move_pages, INT, INT, ADDR, INT, INT, INT),
    // DESC, FILE
    syscall!(utimensat, INT, STR, ADDR, INT),
    // DESC
    syscall!(epoll_pwait, INT, ADDR, INT, INT, INT),
    // DESC, SIGNAL
    syscall!(signalfd, INT, INT, INT),
    // DESC
    syscall!(timerfd_create, INT, INT),
    // DESC
    syscall!(eventfd, INT, INT),
    // DESC
    syscall!(fallocate, INT, INT, INT, INT),
    // DESC
    syscall!(timerfd_settime, INT, INT, ADDR),
    // DESC
    syscall!(timerfd_gettime, INT, ADDR),
    syscall!(accept4, INT, ADDR, INT),
    // DESC, SIGNAL
    syscall!(signalfd4, INT, INT, INT),
    // DESC
    syscall!(eventfd2, INT, INT),
    // DESC
    syscall!(epoll_create1, INT),
    // DESC
    syscall!(dup3, INT, INT, INT),
    // DESC
    syscall!(pipe2, INT, INT),
    // DESC
    syscall!(inotify_init1, INT),
    // DESC
    syscall!(preadv, INT, ADDR, INT, INT),
    // DESC
    syscall!(pwritev, INT, ADDR, INT, INT),
    // PROCESS, SIGNAL
    syscall!(rt_tgsigqueueinfo, INT, INT, INT),
    // DESC
    syscall!(perf_event_open, ADDR, INT, INT, INT, INT),
    // NETWORK
    syscall!(recvmmsg, INT, ADDR, INT, INT, ADDR),
    // DESC
    syscall!(fanotify_init, INT, INT),
    // DESC, FILE
    syscall!(fanotify_mark, INT, INT, INT, INT, STR),
    syscall!(prlimit64, INT, INT, ADDR, ADDR),
    // DESC, FILE
    syscall!(name_to_handle_at, INT, STR, ADDR, INT, INT),
    // DESC
    syscall!(open_by_handle_at, INT, ADDR, INT),
    // CLOCK
    syscall!(clock_adjtime, ADDR),
    // DESC
    syscall!(syncfs, INT),
    // NETWORK
    syscall!(sendmmsg, INT, ADDR, INT, INT),
    // DESC
    syscall!(setns, INT, INT),
    syscall!(getcpu, INT, INT, ADDR),
    syscall!(process_vm_readv, INT, ADDR, INT, ADDR, INT, INT),
    syscall!(process_vm_writev, INT, ADDR, INT, ADDR, INT, INT),
    syscall!(kcmp, INT, INT, INT, INT, INT),
    // DESC
    syscall!(finit_module, INT, STR, INT),
    syscall!(sched_setattr, INT, ADDR, INT),
    syscall!(sched_getattr, INT, ADDR, INT, INT),
    // DESC, FILE
    syscall!(renameat2, INT, STR, INT, STR),
    syscall!(seccomp, INT, INT, ADDR),
    syscall!(getrandom, STR, INT, INT),
    // DESC
    syscall!(memfd_create, STR, INT),
    // DESC
    syscall!(kexec_file_load, INT, INT, ADDR, INT),
    // DESC
    syscall!(bpf, INT, ADDR, INT),
    // DESC, PROCESS
    syscall!(execveat, INT, STR, STR, STR, INT),
    // DESC
    syscall!(userfaultfd, INT),
    syscall!(membarrier, INT, INT, INT),
    // MEMORY
    syscall!(mlock2, ADDR, INT, INT),
    // DESC
    syscall!(copy_file_range, INT, INT, INT, INT, INT, INT),
    // DESC
    syscall!(preadv2, INT, ADDR, INT, INT, INT),
    // DESC
    syscall!(pwritev2, INT, ADDR, INT, INT, INT),
    // MEMORY
    syscall!(pkey_mprotect, ADDR, INT, INT, INT),
    syscall!(pkey_alloc, INT, INT),
    syscall!(pkey_free, INT),
    // DESC, FILE, FSTAT, STAT_LIKE
    syscall!(statx, INT, STR, INT, INT, STR),
    syscall!(io_pgetevents),
    syscall!(rseq),
    // We jump from syscall number 334 to 424 here
    // See: https://git.musl-libc.org/cgit/musl/commit/?id=f3f96f2daa4d00f0e38489fb465cd0244b531abe
    //      https://github.com/torvalds/linux/commit/0d6040d4681735dfc47565de288525de405a5c99
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
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
    syscall!(landlock_add_rule, INT, INT, ADDR, INT),
    syscall!(landlock_restrict_self, INT, INT),
    syscall!(memfd_secret, INT),
    syscall!(process_mrelease, INT, INT),
    syscall!(futex_waitv, ADDR, INT, INT, ADDR, INT),
    syscall!(set_mempolicy_home_node, INT, INT, INT, INT),
    syscall!(cachestat, INT, INT, INT, INT),
];

pub fn get_arg_value(registers: user_regs_struct, i: usize) -> c_ulonglong {
    match i {
        0 => registers.rdi,
        1 => registers.rsi,
        2 => registers.rdx,
        3 => registers.r10,
        4 => registers.r8,
        5 => registers.r9,
        v => panic!("Invalid system call index {v}!"),
    }
}

// test that all syscalls match their syscall number
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn test_syscall_numbers() {
        for (i, sysno, ..) in SYSCALLS.iter().enumerate() {
            if let Some((sysno, _)) = sysno {
                assert_eq!(i, sysno.id() as usize);
            }
        }
    }
}
