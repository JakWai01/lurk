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

## License

lurk (c) 2022 Jakob Waibel and contributors

SPDX-License-Identifier: AGPL-3.0
