# lurk

[![CICD](https://github.com/JakWai01/lurk/actions/workflows/CICD.yml/badge.svg)](https://github.com/JakWai01/lurk/actions/workflows/CICD.yml)

A simple and pretty alternative to strace

## Demo

![Demo](assets/screencast.svg)

## Features

- Supports an opinionated subset of strace flags.
- Uses colorized, formatted output ;-).

## Installation

```
$ curl -L -o /tmp/lurk.tar.gz "https://github.com/JakWai01/lurk/releases/latest/download/lurk-x86_64-unknown-linux-gnu.tar.gz"
$ tar -xzf /tmp/lurk.tar.gz
$ sudo install /tmp/lurk /usr/local/bin
```

## Usage

To get a quick overview, you can run `lurk --help`: 

```
lurk 0.0.7

USAGE:
    lurk [OPTIONS] [command]...

ARGS:
    <command>...    Trace command

OPTIONS:
    -c, --summary-only
            Report a summary instead of the regular output

    -C, --summary
            Report a summary in addition to the regular output

    -e, --expr <expr>
            A qualifying expression which modifies which events to trace or how to trace them.

    -E, --env <env>
            --env var=val adds an environment variable. --env var removes an environment variable.

    -f, --follow-forks
            Trace child processes as they are created by currently traced processes.

    -h, --help
            Print help information

    -n, --syscall-number
            Display system call numbers

    -o, --file <file>
            Name of the file to print output to

    -p, --attach <attach>
            Attach to a running process

    -s, --string-limit <string-limit>
            Maximum string size to print

    -T, --syscall-times
            Show the time spent in system calls in ms.

    -u, --username <username>
            Run the command with uid, gid and supplementary groups of username.

    -v, --no-abbrev
            Print unabbreviated versions of strings

    -V, --version
            Print version information

    -z, --successful-only
            Print only syscalls that returned without an error code

    -Z, --failed-only
            Print only syscalls that returned with an error code
```

### Basic trace

Basically, there are two ways of tracing system calls. You can either execute a command directly or attach to a running process by providing the process ID (PID) via `--attach`. In the latter case, the command has to be run with escalated priviledges (`sudo`).

#### Executing a command

```
$ lurk ls
[54605] execve("", "", "") = 0
[54605] brk(NULL) = 0x55578000
[54605] arch_prctl(12289, 0xffffe780) = -22
[54605] access("", 4) = -2
[54605] openat(4294967196, "/etc/ld.so.cache", 524288) = 3
[54605] newfstatat(3, "", 0xffffd9a0, 4096) = 0
[54605] mmap(NULL, 92599, 1, 2, 3, 0) = 0xf7fa9000
...
```

#### Attaching to a running process

```
$ sudo lurk --attach $PID
[54683] epoll_wait(5, 0xd01a3c20, 8, 4294967295) = -4
[54683] recvmsg(3, 0x4a4a0020, 0) = -11
[54683] recvmsg(3, 0x4a4a0020, 0) = -11
[54683] clock_gettime(1, 0x4a49df40) = 0
[54683] clock_gettime(1, 0x4a4a0220) = 0
[54683] recvmsg(3, 0x4a4a0050, 0) = -11
...
```

### Filtering with `--expr`

Unlike in `strace`, `lurk` only supports `--expr trace`. Since this flag behaves almost exactly like in `strace`, here a short, slightly changed, excerpt of the `strace` manpage on how to use `lurk --expr trace`: 

```
 -e trace=syscall_set
       --trace=syscall_set
              Trace only the specified set of system calls.  syscall_set
              is defined as [!]value[,value], and value can be one of
              the following:

              syscall
                     Trace specific syscall, specified by its name (but
                     see NOTES).

              ?value Question mark before the syscall qualification
                     allows suppression of error in case no syscalls
                     matched the qualification provided.

              /regex Trace only those system calls that match the regex.
                     You can use POSIX Extended Regular Expression
                     syntax (see regex(7)).

              %file
              file   Trace all system calls which take a file name as an
                     argument.  You can think of this as an abbreviation
                     for -e trace=open,stat,chmod,unlink,...  which is
                     useful to seeing what files the process is
                     referencing.  Furthermore, using the abbreviation
                     will ensure that you don't accidentally forget to
                     include a call like lstat(2) in the list.  Betchya
                     woulda forgot that one.  The syntax without a
                     preceding percent sign ("-e trace=file") is
                     deprecated.

              %process
              process
                     Trace system calls associated with process
                     lifecycle (creation, exec, termination).  The
                     syntax without a preceding percent sign ("-e
                     trace=process") is deprecated.

              %net
              %network
              network
                     Trace all the network related system calls.  The
                     syntax without a preceding percent sign ("-e
                     trace=network") is deprecated.

              %signal
              signal Trace all signal related system calls.  The syntax
                     without a preceding percent sign ("-e
                     trace=signal") is deprecated.

              %ipc
              ipc    Trace all IPC related system calls.  The syntax
                     without a preceding percent sign ("-e trace=ipc")
                     is deprecated.

              %desc
              desc   Trace all file descriptor related system calls.
                     The syntax without a preceding percent sign ("-e
                     trace=desc") is deprecated.

              %memory
              memory Trace all memory mapping related system calls.  The
                     syntax without a preceding percent sign ("-e
                     trace=memory") is deprecated.

              %creds Trace system calls that read or modify user and
                     group identifiers or capability sets.

              %stat  Trace stat syscall variants.

              %lstat Trace lstat syscall variants.

              %fstat Trace fstat, fstatat, and statx syscall variants.

              %%stat Trace syscalls used for requesting file status
                     (stat, lstat, fstat, fstatat, statx, and their
                     variants).

              %statfs
                     Trace statfs, statfs64, statvfs, osf_statfs, and
                     osf_statfs64 system calls.  The same effect can be
                     achieved with -e trace=/^(.*_)?statv?fs regular
                     expression.

              %fstatfs
                     Trace fstatfs, fstatfs64, fstatvfs, osf_fstatfs,
                     and osf_fstatfs64 system calls.  The same effect
                     can be achieved with -e trace=/fstatv?fs regular
                     expression.

              %%statfs
                     Trace syscalls related to file system statistics
                     (statfs-like, fstatfs-like, and ustat).  The same
                     effect can be achieved with
                     -e trace=/statv?fs|fsstat|ustat regular expression.

              %clock Trace system calls that read or modify system
                     clocks.

              %pure  Trace syscalls that always succeed and have no
                     arguments.  Currently, this list includes
                     arc_gettls(2), getdtablesize(2), getegid(2),
                     getegid32(2), geteuid(2), geteuid32(2), getgid(2),
                     getgid32(2), getpagesize(2), getpgrp(2), getpid(2),
                     getppid(2), get_thread_area(2) (on architectures
                     other than x86), gettid(2), get_tls(2), getuid(2),
                     getuid32(2), getxgid(2), getxpid(2), getxuid(2),
                     kern_features(2), and metag_get_tls(2) syscalls.

              The -c option is useful for determining which system calls
              might be useful to trace.  For example,
              trace=open,close,read,write means to only trace those four
              system calls.  Be careful when making inferences about the
              user/kernel boundary if only a subset of system calls are
              being monitored.  The default is trace=all.

```

**Note**: When negating a statement with `!`, make sure to escape it (`\!`) when using bash.

#### Filtering for system calls not containing the letter `o`

```
$ lurk --expr trace=\!/o ls
[55155] execve("", "", "") = 0
[55155] brk(NULL) = 0x55578000
[55155] arch_prctl(12289, 0xffffe780) = -22
[55155] access("", 4) = -2
[55155] newfstatat(3, "", 0xffffd9a0, 4096) = 0
[55155] mmap(NULL, 92599, 1, 2, 3, 0) = 0xf7fa9000
[55155] read(3, "\u{7f}ELF\u{2}\u{1}\u{1}", 832) = 832
...
```

#### Filtering only for all system calls taking a file as an argument

```
$ lurk --expr trace=%file
[55121] access("", 4) = -2
[55121] openat(4294967196, "/etc/ld.so.cache", 524288) = 3
[55121] newfstatat(3, "", 0xffffd9a0, 4096) = 0
[55121] openat(4294967196, "/usr/lib/libcap.so.2", 524288) = 3
[55121] newfstatat(3, "", 0xffffd9a0, 4096) = 0
[55121] openat(4294967196, "/usr/lib/libc.so.6", 524288) = 3
[55121] newfstatat(3, "", 0xffffd980, 4096) = 0
...
```

## License

lurk (c) 2022 Jakob Waibel and contributors

SPDX-License-Identifier: AGPL-3.0
